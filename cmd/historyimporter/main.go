// Command historyimporter performs one fresh, verified, atomic import of the
// fixed synthetic demo-history dataset. It has no listener, AI, administrator,
// dispatcher, executor, event-key, or signing-key authority.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryimport"
	"github.com/devwooops/sentinelflow/internal/demohistoryseal"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	datasetRoot           = "/app"
	bundleRoot            = "/run/sentinelflow-demo-history"
	datasetFile           = "/app/contracts/fixtures/demo_history_dataset_v1.json"
	envelopeFile          = "/run/sentinelflow-demo-history/signed-manifest.json"
	importerDatabaseRole  = "sentinelflow_demo_importer"
	bootstrapFenceTimeout = 12 * time.Second
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	runPattern  = regexp.MustCompile(`^sentinelflow-demo-run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type runtimeConfig struct {
	databaseURL              string
	publicKeyB64URL          string
	runScope                 string
	importID                 string
	clockAt                  time.Time
	impactSourceHealthDigest string
}

type databasePool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Ping(context.Context) error
	Close()
}

type dependencies struct {
	getenv      func(string) string
	environ     func() []string
	openPool    func(context.Context, string) (databasePool, error)
	readBundle  func(string) ([]byte, []byte, error)
	newReader   func(string) (demohistoryimport.DatasetReader, error)
	output      io.Writer
	datasetRoot string
	bundleRoot  string
}

type safeResult struct {
	AuthRecordCount     int                           `json:"auth_record_count"`
	CompletedAt         string                        `json:"completed_at"`
	DatasetID           string                        `json:"dataset_id"`
	Disposition         demohistoryimport.Disposition `json:"disposition"`
	GatewayRecordCount  int                           `json:"gateway_record_count"`
	ImportID            string                        `json:"import_id"`
	ImportedRecordCount uint64                        `json:"imported_record_count"`
	ManifestID          string                        `json:"manifest_id"`
	SourceCoverageCount int                           `json:"source_coverage_count"`
	Status              string                        `json:"status"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, productionDependencies()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow demo history import failed")
		os.Exit(1)
	}
}

func productionDependencies() dependencies {
	return dependencies{
		getenv: os.Getenv, environ: os.Environ,
		openPool: func(ctx context.Context, databaseURL string) (databasePool, error) {
			if err := validateImporterDatabaseURL(databaseURL); err != nil {
				return nil, errors.New("invalid importer database configuration")
			}
			config, err := pgxpool.ParseConfig(databaseURL)
			if err != nil || config.ConnConfig.User != importerDatabaseRole ||
				config.ConnConfig.Host != "postgres" || config.ConnConfig.Port != 5432 ||
				config.ConnConfig.Database != "sentinelflow" || config.ConnConfig.Password == "" ||
				len(config.ConnConfig.RuntimeParams) != 0 {
				return nil, errors.New("invalid worker database configuration")
			}
			config.MaxConns = 1
			config.MinConns = 1
			config.MaxConnLifetime = 5 * time.Minute
			config.MaxConnIdleTime = time.Minute
			config.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-history-importer"
			return pgxpool.NewWithConfig(ctx, config)
		},
		readBundle: demohistoryseal.ReadBundle,
		newReader: func(root string) (demohistoryimport.DatasetReader, error) {
			return demohistoryimport.NewFixedDatasetFile(root)
		},
		output: os.Stdout, datasetRoot: datasetRoot, bundleRoot: bundleRoot,
	}
}

func run(ctx context.Context, deps dependencies) (resultErr error) {
	if ctx == nil || deps.getenv == nil || deps.environ == nil || deps.openPool == nil || deps.readBundle == nil ||
		deps.newReader == nil || deps.output == nil || !filepath.IsAbs(deps.datasetRoot) || !filepath.IsAbs(deps.bundleRoot) {
		return errors.New("history importer dependencies rejected")
	}
	// Establish only the exact importer connection first. Once authenticated,
	// every later configuration, mount, proof, import, or output failure can
	// close this short-lived database authority instead of leaving it reusable.
	databaseURL := deps.getenv("DATABASE_DEMO_IMPORTER_URL")
	if validateImporterDatabaseURL(databaseURL) != nil {
		return errors.New("history importer database configuration rejected")
	}
	pool, err := deps.openPool(ctx, databaseURL)
	if err != nil || pool == nil {
		return errors.New("history importer database unavailable")
	}
	defer pool.Close()
	fenced := false
	defer func() {
		if fenced {
			return
		}
		if err := fenceImporterAuthority(pool); err != nil {
			resultErr = errors.New("history importer authority fence failed")
		}
	}()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("history importer database readiness failed")
	}
	var currentRole string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&currentRole); err != nil || currentRole != importerDatabaseRole {
		return errors.New("history importer database role rejected")
	}

	config, err := loadRuntimeConfig(deps.getenv, deps.environ)
	if err != nil || config.databaseURL != databaseURL {
		return errors.New("history importer public configuration rejected")
	}
	envelope, assertionBytes, err := deps.readBundle(deps.bundleRoot)
	if err != nil {
		return errors.New("history importer public bundle rejected")
	}
	assertions, err := demohistoryseal.ParseAssertions(assertionBytes)
	if err != nil || !publicHandoffMatches(config, assertions) {
		return errors.New("history importer public assertions rejected")
	}
	reader, err := deps.newReader(deps.datasetRoot)
	if err != nil {
		return errors.New("history importer fixed dataset rejected")
	}
	rawDataset, err := reader.ReadPinnedDataset(ctx)
	if err != nil {
		return errors.New("history importer fixed dataset unavailable")
	}
	verifier, verifiedAssertions, err := demohistoryseal.VerifyBundleImmutable(ctx, rawDataset, envelope, assertionBytes)
	clear(rawDataset)
	if err != nil || verifier == nil || !publicHandoffMatches(config, verifiedAssertions) {
		return errors.New("history importer authority verification failed")
	}
	importer, err := demohistoryimport.New(pool, reader, verifier)
	if err != nil {
		return errors.New("history importer configuration rejected")
	}
	result, err := importer.ImportOrAttachExisting(ctx, envelope)
	if err != nil || result.ImportID() != config.importID {
		return errors.New("history importer atomic import failed")
	}
	switch result.Disposition() {
	case demohistoryimport.DispositionApplied:
		if result.VerifiedBinding().HistoryCutoff().At().IsZero() {
			return errors.New("history importer atomic import failed")
		}
	case demohistoryimport.DispositionHistorical:
		if !result.VerifiedBinding().HistoryCutoff().At().IsZero() {
			return errors.New("history importer atomic import failed")
		}
	default:
		return errors.New("history importer atomic import failed")
	}
	if err := fenceImporterAuthority(pool); err != nil {
		return errors.New("history importer authority fence failed")
	}
	fenced = true
	encoded := safeResult{
		AuthRecordCount: result.AuthRecordCount(), CompletedAt: result.CompletedAt().Format(time.RFC3339Nano),
		DatasetID: result.DatasetID(), Disposition: result.Disposition(), GatewayRecordCount: result.GatewayRecordCount(),
		ImportID: result.ImportID(), ImportedRecordCount: result.ImportedRecordCount(), ManifestID: result.ManifestID(),
		SourceCoverageCount: result.SourceCoverageCount(), Status: result.Status(),
	}
	if err := json.NewEncoder(deps.output).Encode(encoded); err != nil {
		return errors.New("history importer safe result output failed")
	}
	return nil
}

func fenceImporterAuthority(pool databasePool) error {
	if pool == nil {
		return demohistoryactivation.ErrAuthorityFence
	}
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapFenceTimeout)
	defer cancel()
	return demohistoryactivation.FenceImporter(ctx, pool)
}

func loadRuntimeConfig(getenv func(string) string, environ func() []string) (runtimeConfig, error) {
	if getenv == nil || environ == nil {
		return runtimeConfig{}, errors.New("history importer environment rejected")
	}
	for _, forbidden := range []string{
		"OPENAI_API_KEY", "DATABASE_API_URL", "DATABASE_MIGRATION_URL", "DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL", "POSTGRES_PASSWORD", "ADMIN_USERNAME", "ADMIN_PASSWORD_ARGON2ID_HASH",
		"SESSION_HMAC_KEY", "GATEWAY_EVENT_HMAC_KEY", "AUTH_EVENT_HMAC_KEY", "AUTH_ACCOUNT_HASH_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE", "EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE", "DISPATCHER_RESULT_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE", "DEMO_HISTORY_PUBLIC_KEY_FILE",
	} {
		if getenv(forbidden) != "" {
			return runtimeConfig{}, errors.New("history importer forbidden authority present")
		}
	}
	for _, entry := range environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "" || getenv(name) == "" {
			continue
		}
		if strings.HasPrefix(name, "PG") || strings.HasPrefix(name, "POSTGRES_") ||
			(strings.HasPrefix(name, "DATABASE_") && name != "DATABASE_DEMO_IMPORTER_URL") ||
			strings.HasPrefix(name, "OPENAI_") || strings.HasPrefix(name, "ADMIN_") ||
			strings.HasPrefix(name, "SESSION_") || strings.HasPrefix(name, "GATEWAY_") ||
			strings.HasPrefix(name, "AUTH_") || strings.HasPrefix(name, "DISPATCHER_") ||
			strings.HasPrefix(name, "EXECUTOR_") || strings.HasPrefix(name, "NFT_") ||
			strings.HasPrefix(name, "VALIDATOR_") || strings.HasPrefix(name, "PROTECTED_") ||
			strings.HasPrefix(name, "HIL_") || name == "SENTINELFLOW_ADMIN_PASSWORD" ||
			(strings.HasPrefix(name, "DEMO_HISTORY_") && !allowedDemoHistoryEnvironment(name)) {
			return runtimeConfig{}, errors.New("history importer inherited authority present")
		}
	}
	if getenv("DEMO_HISTORY_FIXTURE_DATASET") != datasetFile ||
		getenv("DEMO_HISTORY_SIGNED_ENVELOPE_FILE") != envelopeFile ||
		getenv("SENTINELFLOW_ENV") != "demo" {
		return runtimeConfig{}, errors.New("history importer fixed path rejected")
	}
	publicKeyValue := getenv("DEMO_HISTORY_PUBLIC_KEY_B64URL")
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(publicKeyValue)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != publicKeyValue ||
		publicKeyValue == validation.PinnedDemoHistoryFixturePublicKey {
		return runtimeConfig{}, errors.New("history importer public key rejected")
	}
	clockValue := getenv("DEMO_HISTORY_CLOCK_AT")
	clockAt, err := time.Parse("2006-01-02T15:04:05.000Z", clockValue)
	if err != nil || clockAt.Format("2006-01-02T15:04:05.000Z") != clockValue {
		return runtimeConfig{}, errors.New("history importer clock rejected")
	}
	config := runtimeConfig{
		databaseURL: getenv("DATABASE_DEMO_IMPORTER_URL"), publicKeyB64URL: publicKeyValue,
		runScope: getenv("DEMO_HISTORY_RUN_SCOPE"), importID: getenv("DEMO_HISTORY_IMPORT_ID"),
		clockAt: clockAt.UTC(), impactSourceHealthDigest: getenv("DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"),
	}
	if validateImporterDatabaseURL(config.databaseURL) != nil || !runPattern.MatchString(config.runScope) || !uuidPattern.MatchString(config.importID) ||
		config.impactSourceHealthDigest != validation.PinnedDemoHistoryImpactSourceHealthDigest {
		return runtimeConfig{}, errors.New("history importer public configuration rejected")
	}
	poolConfig, err := pgxpool.ParseConfig(config.databaseURL)
	if err != nil || poolConfig.ConnConfig.User != importerDatabaseRole ||
		poolConfig.ConnConfig.Host != "postgres" || poolConfig.ConnConfig.Port != 5432 ||
		poolConfig.ConnConfig.Database != "sentinelflow" || poolConfig.ConnConfig.Password == "" ||
		len(poolConfig.ConnConfig.RuntimeParams) != 0 {
		return runtimeConfig{}, errors.New("history importer worker database URL rejected")
	}
	return config, nil
}

func validateImporterDatabaseURL(raw string) error {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return errors.New("invalid database URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Opaque != "" ||
		parsed.User == nil || parsed.User.Username() != importerDatabaseRole ||
		parsed.Hostname() != "postgres" || parsed.Port() != "5432" || parsed.Host != "postgres:5432" ||
		parsed.Path != "/sentinelflow" || parsed.RawPath != "" || parsed.Fragment != "" ||
		parsed.RawFragment != "" || parsed.ForceQuery || parsed.RawQuery != "sslmode=disable" {
		return errors.New("invalid database URL")
	}
	password, hasPassword := parsed.User.Password()
	port, portErr := strconv.Atoi(parsed.Port())
	if !hasPassword || password == "" || portErr != nil || port != 5432 || strconv.Itoa(port) != parsed.Port() ||
		parsed.String() != raw {
		return errors.New("invalid database URL")
	}
	return nil
}

func allowedDemoHistoryEnvironment(name string) bool {
	switch name {
	case "DEMO_HISTORY_FIXTURE_DATASET", "DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL", "DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT", "DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST":
		return true
	default:
		return false
	}
}

func publicHandoffMatches(config runtimeConfig, assertions demohistoryseal.Assertions) bool {
	return config.publicKeyB64URL == assertions.PublicKeyB64URL() &&
		config.runScope == assertions.RunScope() && config.importID == assertions.ImportID() &&
		config.clockAt.Equal(assertions.ClockAt()) &&
		config.impactSourceHealthDigest == assertions.ImpactSourceHealthDigest()
}
