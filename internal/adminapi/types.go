// Package adminapi implements the strict administrator HTTP session boundary.
// It owns browser credential parsing and session lifecycle transport, but not
// HIL artifact or enforcement-domain behavior.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
)

const (
	LoginPath   = "/api/v1/session/login"
	LogoutPath  = "/api/v1/session/logout"
	StepUpPath  = "/api/v1/session/step-up"
	SessionPath = "/api/v1/session"

	MaxRequestBodyBytes int64 = 4096
)

// AuthenticationBoundary is implemented by adminauth.Boundary. Keeping the
// adapter contract narrow also permits HTTP fault tests without weakening the
// production Argon2/session implementation.
type AuthenticationBoundary interface {
	ValidateOrigin(string) error
	Login(netip.Addr, string, []byte) (adminauth.IssuedSession, error)
	ValidateSession(adminauth.SessionRecord, string) (adminauth.SessionRecord, error)
	ValidateBrowserRequest(adminauth.SessionRecord, string, string, string) (adminauth.SessionRecord, error)
	RecoverCSRFToken(adminauth.SessionRecord, string) (string, error)
	RequiresStepUp(adminauth.SessionRecord) (bool, error)
	StepUp(adminauth.SessionRecord, string, []byte) (adminauth.SessionRotation, error)
	RotateAfterPrivilege(adminauth.SessionRecord, string) (adminauth.SessionRotation, error)
	AllowDecision(adminauth.SessionID) error
}

// SessionStore is the exact-CAS database contract implemented by
// adminstore.PostgreSQLStore. Plaintext browser secrets cannot enter it.
type SessionStore interface {
	LoadByID(context.Context, adminauth.SessionID) (adminauth.SessionRecord, error)
	InsertLogin(context.Context, adminauth.SessionRecord) (adminauth.SessionRecord, error)
	Touch(context.Context, adminauth.SessionRecord) (adminauth.SessionRecord, error)
	Revoke(context.Context, adminauth.SessionRecord) (adminauth.SessionRecord, error)
	Rotate(context.Context, adminauth.SessionRecord, adminauth.SessionRecord) (adminauth.SessionRecord, error)
}

// HistoricalDecisionReplayBoundary and HistoricalDecisionReplaySessionStore
// are deliberately separate from ordinary live-session interfaces. They only
// authenticate a recently revoked privileged parent whose unique rotation
// child remains live, and cannot reactivate or mutate that parent.
type HistoricalDecisionReplayBoundary interface {
	ValidateRevokedBrowserReplay(adminauth.SessionRecord, string, string, string) (adminauth.SessionRecord, error)
}

type HistoricalDecisionReplaySessionStore interface {
	LoadRevokedDecisionReplayParent(context.Context, adminauth.SessionID) (adminauth.SessionRecord, error)
}

type Config struct {
	Boundary       AuthenticationBoundary
	Sessions       SessionStore
	Cookies        adminauth.CookiePolicy
	ExactArtifacts ExactArtifactReader
	HIL            HILPersistence
	Revocations    RevocationPersistence
}

type Handler struct {
	boundary       AuthenticationBoundary
	sessions       SessionStore
	cookies        adminauth.CookiePolicy
	exactArtifacts ExactArtifactReader
	hil            HILPersistence
	revocations    RevocationPersistence
}

func NewHandler(config Config) (*Handler, error) {
	if config.Boundary == nil || config.Sessions == nil || !config.Cookies.Valid() {
		return nil, errors.New("administrator API configuration is invalid")
	}
	return &Handler{
		boundary: config.Boundary, sessions: config.Sessions, cookies: config.Cookies,
		exactArtifacts: config.ExactArtifacts, hil: config.HIL, revocations: config.Revocations,
	}, nil
}

func (*Handler) String() string {
	return "adminapi.Handler{credentials:[REDACTED],store:configured}"
}

func (handler *Handler) GoString() string { return handler.String() }

// SessionProjection is the only administrator identity exposed outside this
// package. It contains no token, CSRF value, password, or persisted digest.
type SessionProjection struct {
	ActorID         string    `json:"actor_id"`
	SessionID       string    `json:"session_id"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func project(record adminauth.SessionRecord) SessionProjection {
	return SessionProjection{
		ActorID: record.ActorID, SessionID: record.ID.String(),
		AuthenticatedAt: record.AuthenticatedAt.UTC(), ExpiresAt: record.ExpiresAt.UTC(),
	}
}

type browserContextKey struct{}

// authenticatedBrowser is deliberately package-private. Future HIL handlers
// in adminapi may consume the exact touched row and presented token, while
// other packages can retrieve only SessionProjection.
type authenticatedBrowser struct {
	record         adminauth.SessionRecord
	presentedToken []byte
}

func (authenticatedBrowser) String() string {
	return "adminapi.authenticatedBrowser{session:[REDACTED],token:[REDACTED]}"
}

func (value authenticatedBrowser) GoString() string { return value.String() }

func (authenticatedBrowser) MarshalJSON() ([]byte, error) {
	return nil, errors.New("administrator browser context cannot be serialized")
}

func authenticatedFromContext(ctx context.Context) (authenticatedBrowser, bool) {
	if ctx == nil {
		return authenticatedBrowser{}, false
	}
	value, ok := ctx.Value(browserContextKey{}).(authenticatedBrowser)
	if !ok || value.record.ID.IsZero() || len(value.presentedToken) == 0 {
		return authenticatedBrowser{}, false
	}
	return value, true
}

// allowDecisionFromContext is intentionally package-private: only an HIL
// handler in this package may consume the limiter using the exact authenticated
// session, while other packages receive only SessionProjection.
func (handler *Handler) allowDecisionFromContext(ctx context.Context) error {
	value, ok := authenticatedFromContext(ctx)
	if !ok || handler == nil || handler.boundary == nil {
		return adminauth.ErrSessionInvalid
	}
	return handler.boundary.AllowDecision(value.record.ID)
}

func (handler *Handler) requiresStepUpFromContext(ctx context.Context) (bool, error) {
	value, ok := authenticatedFromContext(ctx)
	if !ok || handler == nil || handler.boundary == nil {
		return false, adminauth.ErrSessionInvalid
	}
	return handler.boundary.RequiresStepUp(value.record)
}

// SessionFromContext returns only the safe actor/session projection.
func SessionFromContext(ctx context.Context) (SessionProjection, bool) {
	value, ok := authenticatedFromContext(ctx)
	if !ok {
		return SessionProjection{}, false
	}
	return project(value.record), true
}

func withAuthenticatedBrowser(request *http.Request, record adminauth.SessionRecord, token string) (*http.Request, func()) {
	presented := []byte(token)
	value := authenticatedBrowser{record: record, presentedToken: presented}
	ctx := context.WithValue(request.Context(), browserContextKey{}, value)
	bound := request.Clone(ctx)
	// Downstream packages receive the safe projection only. Raw browser
	// credentials remain package-private and are removed from the request view
	// before the next handler can log, format, serialize, or reuse them.
	bound.Header.Del("Cookie")
	bound.Header.Del("X-CSRF-Token")
	bound.Header.Del("Authorization")
	bound.Header.Del("Proxy-Authorization")
	bound.Header.Del("Origin")
	bound.Header.Del("Forwarded")
	bound.Header.Del("X-Forwarded-For")
	bound.Header.Del("X-Forwarded-Host")
	bound.Header.Del("X-Forwarded-Port")
	bound.Header.Del("X-Forwarded-Proto")
	bound.Header.Del("X-Real-IP")
	bound.Header.Del("X-SentinelFlow-Request-ID")
	bound.Header.Del("X-SentinelFlow-Trace-ID")
	bound.Header.Del("X-Request-ID")
	bound.Header.Del("X-Trace-ID")
	bound.Header.Del("Traceparent")
	bound.Header.Del("Tracestate")
	return bound, func() { clear(presented) }
}

func (value SessionProjection) String() string {
	return fmt.Sprintf("adminapi.SessionProjection{actor_id:%s session_id:%s}", value.ActorID, value.SessionID)
}

var _ json.Marshaler = authenticatedBrowser{}
