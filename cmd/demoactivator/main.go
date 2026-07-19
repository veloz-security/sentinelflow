// Command demoactivator is a one-shot demo-only authority. It verifies the
// run-scoped signed history proof and atomically creates or exactly reattaches
// both consumer activations. It has no prepare, AI, HIL, admin, dispatcher, or
// executor authority.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	configpkg "github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	activatorURLName      = "DATABASE_DEMO_ACTIVATOR_URL"
	analysisSecretName    = "DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE"
	validationSecretName  = "DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE"
	activatorDatabaseRole = "sentinelflow_demo_activator"
	signedEnvelopePath    = "/run/sentinelflow-demo-history/signed-manifest.json"
	bootstrapFenceTimeout = 12 * time.Second
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	runPattern  = regexp.MustCompile(`^sentinelflow-demo-run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type runtimeConfig struct {
	databaseURL      string
	analysisSecret   string
	validationSecret string
	proof            demohistoryproof.Config
}

type activatorPool interface {
	Ping(context.Context) error
	QueryRow(context.Context, string, ...any) pgx.Row
	Close()
}

type activatorDependencies struct {
	lookup     func(string) (string, bool)
	environ    func() []string
	openPool   func(context.Context, *pgxpool.Config) (activatorPool, error)
	loadSecret func(string) (demohistoryactivation.Secret, error)
	activate   func(context.Context, demohistoryproof.Config, validation.DemoHistoryActivationDB,
		demohistoryactivation.Secret, demohistoryactivation.Secret) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, defaultActivatorDependencies()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow demo activation failed")
		os.Exit(1)
	}
}

func defaultActivatorDependencies() activatorDependencies {
	return activatorDependencies{
		lookup: os.LookupEnv, environ: os.Environ,
		openPool: func(ctx context.Context, config *pgxpool.Config) (activatorPool, error) {
			return pgxpool.NewWithConfig(ctx, config)
		},
		loadSecret: demohistoryactivation.Load,
		activate: func(
			ctx context.Context,
			config demohistoryproof.Config,
			db validation.DemoHistoryActivationDB,
			analysisSecret demohistoryactivation.Secret,
			validationSecret demohistoryactivation.Secret,
		) error {
			pair, err := demohistoryproof.CreatePair(ctx, config, db, analysisSecret, validationSecret)
			if err != nil {
				return err
			}
			if _, ok := pair.Analysis(); !ok {
				return validation.ErrDemoHistoryActivationRejected
			}
			if _, ok := pair.Validation(); !ok {
				return validation.ErrDemoHistoryActivationRejected
			}
			return nil
		},
	}
}

func run(ctx context.Context, deps activatorDependencies) (resultErr error) {
	if ctx == nil || deps.lookup == nil || deps.environ == nil || deps.openPool == nil ||
		deps.loadSecret == nil || deps.activate == nil {
		return errors.New("demo activator dependencies rejected")
	}
	// Connect using only the exact activator URL first. Every subsequent
	// environment, mount, public-proof, or capability failure can then close the
	// short-lived database authority through the two committed fence phases.
	databaseURL, _ := deps.lookup(activatorURLName)
	if validateDatabaseURL(databaseURL) != nil {
		return errors.New("demo activator database configuration rejected")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil || poolConfig.ConnConfig.User != activatorDatabaseRole ||
		poolConfig.ConnConfig.Host != "postgres" || poolConfig.ConnConfig.Port != 5432 ||
		poolConfig.ConnConfig.Database != "sentinelflow" || poolConfig.ConnConfig.Password == "" ||
		len(poolConfig.ConnConfig.RuntimeParams) != 0 {
		return errors.New("demo activator database configuration rejected")
	}
	poolConfig.MaxConns, poolConfig.MinConns = 1, 1
	poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime = 5*time.Minute, time.Minute
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-demo-activator"
	pool, err := deps.openPool(ctx, poolConfig)
	if err != nil || pool == nil {
		return errors.New("demo activator database unavailable")
	}
	defer pool.Close()
	fenced := false
	defer func() {
		if fenced {
			return
		}
		if err := fenceBootstrapAuthority(pool); err != nil {
			resultErr = errors.New("demo activator authority fence failed")
		}
	}()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("demo activator database unavailable")
	}
	var currentRole string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&currentRole); err != nil ||
		currentRole != activatorDatabaseRole {
		return errors.New("demo activator database role rejected")
	}
	config, err := loadConfig(deps.lookup, deps.environ)
	if err != nil || config.databaseURL != databaseURL {
		return errors.New("demo activator environment rejected")
	}
	analysisSecret, err := deps.loadSecret(config.analysisSecret)
	if err != nil {
		return errors.New("demo activator analysis capability rejected")
	}
	validationSecret, err := deps.loadSecret(config.validationSecret)
	if err != nil {
		return errors.New("demo activator validation capability rejected")
	}
	if err := deps.activate(ctx, config.proof, pool, analysisSecret, validationSecret); err != nil {
		return errors.New("demo activation pair rejected")
	}
	if err := fenceBootstrapAuthority(pool); err != nil {
		return errors.New("demo activator authority fence failed")
	}
	fenced = true
	// Phase one committed both bootstrap roles as NOLOGIN/password-null with an
	// expired credential; phase two terminated every other bootstrap session.
	// This sole excluded caller is closed by the deferred pool.Close immediately
	// after returning from this one-shot command.
	return nil
}

func fenceBootstrapAuthority(pool activatorPool) error {
	if pool == nil {
		return demohistoryactivation.ErrAuthorityFence
	}
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapFenceTimeout)
	defer cancel()
	return demohistoryactivation.FenceBootstrap(ctx, pool)
}

func loadConfig(lookup func(string) (string, bool), environ func() []string) (runtimeConfig, error) {
	if lookup == nil || environ == nil {
		return runtimeConfig{}, errors.New("demo activator environment rejected")
	}
	allowed := map[string]bool{
		"SENTINELFLOW_ENV": true, activatorURLName: true,
		analysisSecretName: true, validationSecretName: true,
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE": true,
		"DEMO_HISTORY_PUBLIC_KEY_B64URL":    true, "DEMO_HISTORY_RUN_SCOPE": true,
		"DEMO_HISTORY_IMPORT_ID": true, "DEMO_HISTORY_CLOCK_AT": true,
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST": true,
	}
	for _, entry := range environ() {
		name, value, _ := strings.Cut(entry, "=")
		if value == "" || allowed[name] {
			continue
		}
		if strings.HasPrefix(name, "DATABASE_") || strings.HasPrefix(name, "OPENAI_") ||
			strings.HasPrefix(name, "ADMIN_") || strings.HasPrefix(name, "SESSION_") ||
			strings.HasPrefix(name, "HIL_") || strings.HasPrefix(name, "DISPATCHER_") ||
			strings.HasPrefix(name, "EXECUTOR_") || strings.HasPrefix(name, "NFT_") ||
			strings.HasPrefix(name, "AUTH_") || strings.HasPrefix(name, "GATEWAY_") ||
			strings.HasPrefix(name, "PG") || strings.HasPrefix(name, "POSTGRES_") ||
			strings.HasPrefix(name, "DEMO_HISTORY_") {
			return runtimeConfig{}, errors.New("demo activator inherited authority rejected")
		}
	}
	value := func(name string) string {
		current, _ := lookup(name)
		return current
	}
	clockAt, err := time.Parse("2006-01-02T15:04:05.000Z", value("DEMO_HISTORY_CLOCK_AT"))
	publicKeyValue := value("DEMO_HISTORY_PUBLIC_KEY_B64URL")
	publicKey, publicKeyErr := base64.RawURLEncoding.Strict().DecodeString(publicKeyValue)
	config := runtimeConfig{
		databaseURL: value(activatorURLName), analysisSecret: value(analysisSecretName),
		validationSecret: value(validationSecretName),
		proof: demohistoryproof.Config{
			SignedEnvelopeFile: value("DEMO_HISTORY_SIGNED_ENVELOPE_FILE"),
			PublicKeyB64URL:    value("DEMO_HISTORY_PUBLIC_KEY_B64URL"),
			RunScope:           value("DEMO_HISTORY_RUN_SCOPE"), ImportID: value("DEMO_HISTORY_IMPORT_ID"),
			ClockAt: clockAt, ImpactSourceHealthDigest: value("DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"),
		},
	}
	if err != nil || publicKeyErr != nil || len(publicKey) != 32 ||
		base64.RawURLEncoding.EncodeToString(publicKey) != publicKeyValue ||
		publicKeyValue == validation.PinnedDemoHistoryFixturePublicKey ||
		value("SENTINELFLOW_ENV") != "demo" ||
		validateDatabaseURL(config.databaseURL) != nil ||
		config.proof.SignedEnvelopeFile != signedEnvelopePath ||
		config.analysisSecret != configpkg.DemoHistoryAnalysisActivationPath ||
		config.validationSecret != configpkg.DemoHistoryValidationActivationPath ||
		config.analysisSecret == config.validationSecret || !runPattern.MatchString(config.proof.RunScope) ||
		!uuidPattern.MatchString(config.proof.ImportID) ||
		config.proof.ImpactSourceHealthDigest != validation.PinnedDemoHistoryImpactSourceHealthDigest {
		return runtimeConfig{}, errors.New("demo activator environment rejected")
	}
	return config, nil
}

func validateDatabaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgresql" || parsed.User == nil ||
		parsed.User.Username() != activatorDatabaseRole || parsed.Hostname() != "postgres" ||
		parsed.Port() != "5432" || parsed.Path != "/sentinelflow" ||
		parsed.RawQuery != "sslmode=disable" || parsed.Fragment != "" || parsed.String() != raw {
		return errors.New("invalid demo activator database URL")
	}
	password, ok := parsed.User.Password()
	if !ok || password == "" {
		return errors.New("invalid demo activator database URL")
	}
	return nil
}
