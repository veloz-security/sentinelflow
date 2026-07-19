package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/adminapi"
	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/hilartifactstore"
	"github.com/devwooops/sentinelflow/internal/hilstore"
	"github.com/devwooops/sentinelflow/internal/investigationapi"
	"github.com/devwooops/sentinelflow/internal/investigationstore"
	"github.com/devwooops/sentinelflow/internal/notificationstore"
)

type managementClock struct{}

func (managementClock) Now() time.Time { return time.Now().UTC() }

// managementRouter keeps administrator mutations in adminapi and exposes the
// investigation surface only through adminapi's database-touched session
// middleware. It deliberately has no internal-ingest route or fallback proxy.
type managementRouter struct {
	admin         http.Handler
	investigation http.Handler
}

func (router *managementRouter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if router == nil || router.admin == nil || router.investigation == nil ||
		request == nil || request.URL == nil || request.URL.RawPath != "" {
		writeNotFound(writer)
		return
	}
	switch {
	case isAdministratorRoute(request.URL.Path):
		router.admin.ServeHTTP(writer, request)
	case isInvestigationRoute(request.URL.Path):
		router.investigation.ServeHTTP(writer, request)
	default:
		writeNotFound(writer)
	}
}

func isAdministratorRoute(path string) bool {
	switch path {
	case adminapi.LoginPath, adminapi.LogoutPath, adminapi.StepUpPath, adminapi.SessionPath:
		return true
	}
	return (strings.HasPrefix(path, "/api/v1/policies/") &&
		(strings.HasSuffix(path, "/decision-challenges") || strings.HasSuffix(path, "/decisions"))) ||
		(strings.HasPrefix(path, "/api/v1/enforcement-actions/") &&
			(strings.HasSuffix(path, "/revocation-challenges") || strings.HasSuffix(path, "/revocations")))
}

func isInvestigationRoute(path string) bool {
	switch path {
	case "/api/v1/incidents", "/api/v1/audit-events", "/api/v1/events/stream":
		return true
	}
	for _, prefix := range []string{
		"/api/v1/incidents/", "/api/v1/policies/", "/api/v1/enforcement-actions/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func configureManagementAPI(cfg config.Config, pool *pgxpool.Pool) (http.Handler, error) {
	return configureManagementAPIWithClock(cfg, pool, managementClock{})
}

// configureManagementAPIWithClock is an internal test seam for environments
// where the API test process and PostgreSQL run in different clock domains.
// Production always enters through configureManagementAPI and therefore keeps
// the process system clock. The injected clock does not relax any session,
// HIL, rate-limit, or exact-artifact time check.
func configureManagementAPIWithClock(
	cfg config.Config,
	pool *pgxpool.Pool,
	clock adminauth.Clock,
) (http.Handler, error) {
	if pool == nil {
		return nil, errors.New("api: management database is required")
	}
	if clock == nil {
		return nil, errors.New("api: management clock is required")
	}
	credentials, err := adminauth.NewCredentialVerifier(
		cfg.Admin.Username,
		"administrator",
		cfg.Admin.PasswordArgon2idHash.Reveal(),
	)
	if err != nil {
		return nil, errors.New("api: configure administrator credentials")
	}
	sessionKey, err := decodeSessionHMACKey(cfg.Admin.SessionHMACKey)
	if err != nil {
		return nil, err
	}
	defer clear(sessionKey)
	sessions, err := adminauth.NewSessionManager(sessionKey, rand.Reader, clock)
	if err != nil {
		return nil, errors.New("api: configure administrator sessions")
	}
	loginLimiter, err := adminauth.NewLoginLimiter(clock, 0)
	if err != nil {
		return nil, errors.New("api: configure administrator login limiter")
	}
	decisionLimiter, err := adminauth.NewDecisionLimiter(clock, 0)
	if err != nil {
		return nil, errors.New("api: configure administrator decision limiter")
	}
	origins, err := adminauth.NewOriginPolicy(cfg.Admin.AllowedOrigins)
	if err != nil {
		return nil, errors.New("api: configure administrator origins")
	}
	boundary, err := adminauth.NewBoundary(credentials, sessions, loginLimiter, decisionLimiter, origins)
	if err != nil {
		return nil, errors.New("api: configure administrator boundary")
	}
	cookies, err := adminauth.NewCookiePolicy(cfg.Admin.SessionCookieName, cookieTransport(cfg.Admin.CookieTransport))
	if err != nil {
		return nil, errors.New("api: configure administrator cookie")
	}
	sessionStore, err := adminstore.NewPostgreSQLStore(pool)
	if err != nil {
		return nil, errors.New("api: configure administrator session store")
	}

	exactStore, err := hilartifactstore.NewPostgreSQLStore(pool)
	if err != nil {
		return nil, errors.New("api: configure exact artifact store")
	}
	exactReader, err := adminapi.NewExactArtifactStoreAdapter(exactStore, clock)
	if err != nil {
		return nil, errors.New("api: configure exact artifact reader")
	}
	persistenceStore, err := hilstore.NewPostgreSQLStore(pool, rand.Reader)
	if err != nil {
		return nil, errors.New("api: configure HIL persistence")
	}
	persistence, err := adminapi.NewHILStoreAdapter(persistenceStore)
	if err != nil {
		return nil, errors.New("api: configure HIL adapter")
	}
	revocations, err := adminapi.NewRevocationStoreAdapter(persistenceStore)
	if err != nil {
		return nil, errors.New("api: configure revocation adapter")
	}
	administrator, err := adminapi.NewHandler(adminapi.Config{
		Boundary: boundary, Sessions: sessionStore, Cookies: cookies,
		ExactArtifacts: exactReader, HIL: persistence, Revocations: revocations,
	})
	if err != nil {
		return nil, errors.New("api: configure administrator HTTP handler")
	}

	reader, err := investigationstore.NewPostgreSQLStore(pool)
	if err != nil {
		return nil, errors.New("api: configure investigation store")
	}
	events, err := notificationstore.NewPostgreSQLStore(pool)
	if err != nil {
		return nil, errors.New("api: configure notification store")
	}
	investigation, err := investigationapi.NewHandler(investigationapi.Config{
		Reader: reader, Principals: newSessionPrincipalProvider(), Events: events,
		Leases: events,
	})
	if err != nil {
		return nil, errors.New("api: configure investigation handler")
	}
	return &managementRouter{
		admin:         administrator,
		investigation: administrator.SessionMiddleware(investigation),
	}, nil
}

func cookieTransport(value config.AdminCookieTransport) adminauth.CookieTransport {
	if value == config.AdminCookieTransportTLS {
		return adminauth.CookieTransportTLS
	}
	if value == config.AdminCookieTransportLocalTest {
		return adminauth.CookieTransportExplicitLocalTest
	}
	return 0
}

func decodeSessionHMACKey(secret config.Secret) ([]byte, error) {
	encoded := secret.Reveal()
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(decoded) < 32 {
		clear(decoded)
		return nil, errors.New("api: invalid administrator session key")
	}
	return decoded, nil
}
