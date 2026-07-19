// Package stubworkerconfig loads the deliberately narrow configuration for
// the offline deterministic analysis worker. It accepts one least-privilege
// PostgreSQL credential and bounded runner controls; model, administrator,
// signing, HIL, validator, and executor authority are rejected.
package stubworkerconfig

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	DatabaseWorkerURLName = "DATABASE_WORKER_URL"
	LeaseDurationName     = "STUB_WORKER_LEASE_DURATION"
	PollIntervalName      = "STUB_WORKER_POLL_INTERVAL"
	MaxConcurrencyName    = "STUB_WORKER_MAX_CONCURRENCY"
	EnvironmentName       = "SENTINELFLOW_ENV"
	HistoryEnvelopeName   = "DEMO_HISTORY_SIGNED_ENVELOPE_FILE"
	HistoryPublicKeyName  = "DEMO_HISTORY_PUBLIC_KEY_B64URL"
	HistoryRunScopeName   = "DEMO_HISTORY_RUN_SCOPE"
	HistoryImportIDName   = "DEMO_HISTORY_IMPORT_ID"
	HistoryClockAtName    = "DEMO_HISTORY_CLOCK_AT"
	HistoryImpactName     = "DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"
	HistoryActivationName = "DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE"

	defaultLeaseDuration = 30 * time.Second
	defaultPollInterval  = 250 * time.Millisecond
	defaultConcurrency   = 2
	minimumLeaseDuration = 5 * time.Second
	minimumPollInterval  = 25 * time.Millisecond
	maximumPollInterval  = 5 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("stub worker configuration rejected")
	ErrForbiddenAuthority   = errors.New("stub worker forbidden authority rejected")
	databaseNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	uuidPattern             = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	runScopePattern         = regexp.MustCompile(`^sentinelflow-demo-run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// LookupFunc matches os.LookupEnv and permits deterministic configuration tests.
type LookupFunc func(string) (string, bool)

type secret struct{ value string }

func (s secret) reveal() string { return s.value }
func (s secret) String() string {
	if s.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}
func (s secret) GoString() string               { return s.String() }
func (s secret) MarshalText() ([]byte, error)   { return []byte(s.String()), nil }
func (s secret) MarshalJSON() ([]byte, error)   { return json.Marshal(s.String()) }
func (s secret) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(s.String())) }

// Config is immutable outside this package so a caller cannot bypass the URL,
// TLS, role, or runner-bound validation performed by LoadFrom.
type Config struct {
	databaseURL      secret
	leaseDuration    time.Duration
	pollInterval     time.Duration
	concurrency      int
	environment      string
	demoHistoryProof demohistoryproof.Config
	demoActivation   string
}

func (c Config) DatabaseURL() string          { return c.databaseURL.reveal() }
func (c Config) LeaseDuration() time.Duration { return c.leaseDuration }
func (c Config) PollInterval() time.Duration  { return c.pollInterval }
func (c Config) MaxConcurrency() int          { return c.concurrency }
func (c Config) DemoMode() bool               { return c.environment == "demo" }
func (c Config) DemoHistoryProof() (demohistoryproof.Config, bool) {
	if !c.DemoMode() {
		return demohistoryproof.Config{}, false
	}
	return c.demoHistoryProof, true
}
func (c Config) DemoHistoryActivationSecretFile() (string, bool) {
	if !c.DemoMode() || c.demoActivation == "" {
		return "", false
	}
	return c.demoActivation, true
}
func (c Config) String() string {
	return fmt.Sprintf("stubworkerconfig{database_url:%s lease_duration:%s poll_interval:%s concurrency:%d environment:%s demo_history_proof:%t}",
		c.databaseURL.String(), c.leaseDuration, c.pollInterval, c.concurrency, c.environment, c.DemoMode())
}
func (c Config) GoString() string               { return c.String() }
func (c Config) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(c.String())) }

func (c Config) Valid() bool {
	baseValid := validateDatabaseURL(c.databaseURL.reveal()) == nil &&
		c.leaseDuration >= minimumLeaseDuration && c.leaseDuration <= worker.MaxLeaseDuration &&
		c.pollInterval >= minimumPollInterval && c.pollInterval <= maximumPollInterval &&
		c.concurrency >= 1 && c.concurrency <= 2 && validEnvironment(c.environment)
	if !baseValid {
		return false
	}
	if c.DemoMode() {
		return validDemoProof(c.demoHistoryProof) &&
			c.demoActivation == config.DemoHistoryAnalysisActivationPath
	}
	return c.demoHistoryProof == (demohistoryproof.Config{}) && c.demoActivation == ""
}

func Load() (Config, error) { return LoadFrom(os.LookupEnv) }

func LoadFrom(lookup LookupFunc) (Config, error) {
	if lookup == nil {
		return Config{}, ErrInvalidConfiguration
	}
	if inheritedAuthority(lookup) {
		return Config{}, ErrForbiddenAuthority
	}
	databaseURL, ok := lookup(DatabaseWorkerURLName)
	if !ok || validateDatabaseURL(databaseURL) != nil {
		return Config{}, ErrInvalidConfiguration
	}
	leaseDuration, err := durationValue(lookup, LeaseDurationName, defaultLeaseDuration,
		minimumLeaseDuration, worker.MaxLeaseDuration)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	pollInterval, err := durationValue(lookup, PollIntervalName, defaultPollInterval,
		minimumPollInterval, maximumPollInterval)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	concurrency, err := integerValue(lookup, MaxConcurrencyName, defaultConcurrency, 1, 2)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	environment, proof, activation, err := publicProof(lookup)
	if err != nil {
		return Config{}, err
	}
	result := Config{
		databaseURL: secret{value: databaseURL}, leaseDuration: leaseDuration,
		pollInterval: pollInterval, concurrency: concurrency,
		environment: environment, demoHistoryProof: proof, demoActivation: activation,
	}
	if !result.Valid() {
		return Config{}, ErrInvalidConfiguration
	}
	return result, nil
}

func publicProof(lookup LookupFunc) (string, demohistoryproof.Config, string, error) {
	environment, ok := lookup(EnvironmentName)
	if !ok || environment == "" {
		environment = "development"
	}
	if !validEnvironment(environment) {
		return "", demohistoryproof.Config{}, "", ErrInvalidConfiguration
	}
	names := []string{
		HistoryEnvelopeName, HistoryPublicKeyName, HistoryRunScopeName,
		HistoryImportIDName, HistoryClockAtName, HistoryImpactName, HistoryActivationName,
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		if value, present := lookup(name); present {
			values[name] = value
		}
	}
	if environment != "demo" {
		if len(values) != 0 {
			return "", demohistoryproof.Config{}, "", ErrForbiddenAuthority
		}
		return environment, demohistoryproof.Config{}, "", nil
	}
	for _, name := range names {
		if values[name] == "" || values[name] != strings.TrimSpace(values[name]) {
			return "", demohistoryproof.Config{}, "", ErrInvalidConfiguration
		}
	}
	clockAt, err := time.Parse(time.RFC3339Nano, values[HistoryClockAtName])
	if err != nil || clockAt.Location() != time.UTC ||
		clockAt.Format("2006-01-02T15:04:05.000Z") != values[HistoryClockAtName] {
		return "", demohistoryproof.Config{}, "", ErrInvalidConfiguration
	}
	proof := demohistoryproof.Config{
		SignedEnvelopeFile:       values[HistoryEnvelopeName],
		PublicKeyB64URL:          values[HistoryPublicKeyName],
		RunScope:                 values[HistoryRunScopeName],
		ImportID:                 values[HistoryImportIDName],
		ClockAt:                  clockAt,
		ImpactSourceHealthDigest: values[HistoryImpactName],
	}
	if !validDemoProof(proof) {
		return "", demohistoryproof.Config{}, "", ErrInvalidConfiguration
	}
	return environment, proof, values[HistoryActivationName], nil
}

func validEnvironment(value string) bool {
	return value == "development" || value == "test" || value == "demo" || value == "production"
}

func validDemoProof(value demohistoryproof.Config) bool {
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(value.PublicKeyB64URL)
	return value.SignedEnvelopeFile != "" && filepath.IsAbs(value.SignedEnvelopeFile) &&
		filepath.Clean(value.SignedEnvelopeFile) == value.SignedEnvelopeFile &&
		err == nil && len(publicKey) == 32 &&
		base64.RawURLEncoding.EncodeToString(publicKey) == value.PublicKeyB64URL &&
		runScopePattern.MatchString(value.RunScope) && uuidPattern.MatchString(value.ImportID) &&
		!value.ClockAt.IsZero() && value.ClockAt.Equal(value.ClockAt.Round(0).UTC()) &&
		value.ImpactSourceHealthDigest == validation.PinnedDemoHistoryImpactSourceHealthDigest
}

func validateDatabaseURL(raw string) error {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return ErrInvalidConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Opaque != "" ||
		parsed.User == nil || parsed.User.Username() != "sentinelflow_worker" ||
		parsed.Hostname() == "" || parsed.Port() == "" || parsed.Fragment != "" ||
		parsed.RawFragment != "" || parsed.RawPath != "" || parsed.ForceQuery {
		return ErrInvalidConfiguration
	}
	password, hasPassword := parsed.User.Password()
	if !hasPassword || password == "" {
		return ErrInvalidConfiguration
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != parsed.Port() {
		return ErrInvalidConfiguration
	}
	databaseName := strings.TrimPrefix(parsed.Path, "/")
	if parsed.Path != "/"+databaseName || !databaseNamePattern.MatchString(databaseName) {
		return ErrInvalidConfiguration
	}
	// Only an explicit non-downgrading TLS policy or an explicit isolated-network
	// opt-out is accepted. All session/runtime parameters are rejected.
	if parsed.RawQuery != "sslmode=verify-full" && parsed.RawQuery != "sslmode=disable" {
		return ErrInvalidConfiguration
	}
	if parsed.String() != raw {
		return ErrInvalidConfiguration
	}
	return nil
}

func durationValue(
	lookup LookupFunc,
	name string,
	fallback, minimum, maximum time.Duration,
) (time.Duration, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value.String() != raw || value < minimum || value > maximum {
		return 0, ErrInvalidConfiguration
	}
	return value, nil
}

func integerValue(lookup LookupFunc, name string, fallback, minimum, maximum int) (int, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || strconv.Itoa(value) != raw || value < minimum || value > maximum {
		return 0, ErrInvalidConfiguration
	}
	return value, nil
}

func inheritedAuthority(lookup LookupFunc) bool {
	for _, name := range forbiddenNames {
		if value, ok := lookup(name); ok && value != "" {
			return true
		}
	}
	return false
}

var forbiddenNames = []string{
	"DATABASE_MIGRATION_URL", "DATABASE_API_URL", "DATABASE_READ_URL", "DATABASE_DISPATCHER_URL",
	"DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL",
	"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_MODEL", "OPENAI_REASONING_EFFORT",
	"OPENAI_STORE", "OPENAI_INPUT_SCHEMA_FILE", "OPENAI_SYSTEM_PROMPT_FILE", "OPENAI_OUTPUT_SCHEMA_FILE",
	"OPENAI_MAX_EVIDENCE_REFS", "OPENAI_MAX_INPUT_BYTES", "OPENAI_MAX_OUTPUT_TOKENS", "OPENAI_TIMEOUT",
	"OPENAI_MAX_TRANSIENT_RETRIES", "OPENAI_MAX_CONCURRENCY", "OPENAI_DAILY_BUDGET_USD",
	"OPENAI_RATE_CARD_VERSION", "OPENAI_INPUT_USD_PER_1M_TOKENS",
	"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS", "OPENAI_OUTPUT_USD_PER_1M_TOKENS", "OPENAI_BUDGET_TIMEZONE",
	"ADMIN_USERNAME", "ADMIN_PASSWORD_ARGON2ID_HASH", "ADMIN_ALLOWED_ORIGINS", "ADMIN_SESSION_COOKIE_NAME",
	"ADMIN_COOKIE_TRANSPORT", "SESSION_HMAC_KEY", "SESSION_TTL", "SESSION_IDLE_TIMEOUT",
	"GATEWAY_EVENT_HMAC_KEY", "GATEWAY_EVENT_HMAC_KEY_ID", "AUTH_EVENT_HMAC_KEY",
	"AUTH_EVENT_HMAC_KEY_ID", "AUTH_ACCOUNT_HASH_KEY", "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
	"DISPATCHER_RESULT_PUBLIC_KEY_FILE", "DISPATCH_CAPABILITY_TTL", "EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
	"EXECUTOR_RESULT_PRIVATE_KEY_FILE", "EXECUTOR_SOCKET", "EXECUTOR_STARTUP_MODE", "EXECUTOR_IO_TIMEOUT",
	"EXECUTOR_MAX_FRAME_BYTES", "EXECUTOR_REPLAY_JOURNAL", "NFT_BINARY", "NFT_BINARY_EXPECTED_SHA256",
	"NFT_EXPECTED_VERSION", "NFT_VALIDATOR_SOCKET", "NFT_BASE_CHAIN_CONTRACT", "NFT_BASE_CHAIN_EXPECTED_SHA256",
	"NFT_BASE_CHAIN_LIVE_CONTRACT", "NFT_BASE_CHAIN_LIVE_EXPECTED_SHA256", "NFT_BASE_CHAIN_SCHEMA_VERSION",
	"NFT_FAMILY", "NFT_TABLE", "NFT_BLACKLIST_SET", "NFT_INPUT_CHAIN", "NFT_INPUT_PRIORITY",
	"NFT_PROTECTED_TCP_PORT", "DEMO_HISTORY_PUBLIC_KEY_FILE", "DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
	"DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE", "DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE",
	"DEMO_HISTORY_PRIVATE_KEY", "DEMO_HISTORY_PRIVATE_KEY_FILE",
	"DEMO_HISTORY_SIGNING_PRIVATE_KEY_FILE", "DEMO_HISTORY_SIGNER_PRIVATE_KEY_FILE",
	"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	"HIL_DECISION_RATE_LIMIT_PER_MINUTE", "PROTECTED_CURRENT_ADMIN_IPV4", "PROTECTED_EXECUTOR_IPV4",
	// pgx/libpq inheritance could otherwise change the target, role, TLS policy,
	// password source, or startup session parameters behind the validated URL.
	"PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGAPPNAME", "PGSSLMODE", "PGSSLROOTCERT",
	"PGSSLCERT", "PGSSLKEY", "PGTARGETSESSIONATTRS",
}
