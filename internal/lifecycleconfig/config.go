// Package lifecycleconfig loads the dedicated, least-privilege lifecycle
// scheduler configuration. It deliberately rejects every mutation, AI,
// administrator, signing, executor, validator, and unrelated database
// authority before a PostgreSQL connection is opened.
package lifecycleconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DatabaseURLName    = "DATABASE_LIFECYCLE_URL"
	EnvironmentName    = "SENTINELFLOW_ENV"
	SchedulerIDName    = "LIFECYCLE_SCHEDULER_ID"
	LeaseOwnerName     = "LIFECYCLE_LEASE_OWNER"
	LeaseDurationName  = "LIFECYCLE_LEASE_DURATION"
	RetryBackoffName   = "LIFECYCLE_RETRY_BACKOFF"
	PollIntervalName   = "LIFECYCLE_POLL_INTERVAL"
	CleanupTimeoutName = "LIFECYCLE_CLEANUP_TIMEOUT"

	defaultSchedulerID    = "lifecycle-scheduler-v1"
	defaultLeaseOwner     = "lifecycleworker-01"
	defaultLeaseDuration  = 10 * time.Second
	defaultRetryBackoff   = time.Second
	defaultPollInterval   = 250 * time.Millisecond
	defaultCleanupTimeout = time.Second

	minimumLeaseDuration  = time.Second
	maximumLeaseDuration  = 60 * time.Second
	minimumRetryBackoff   = time.Second
	maximumRetryBackoff   = time.Minute
	minimumPollInterval   = 10 * time.Millisecond
	maximumPollInterval   = time.Minute
	minimumCleanupTimeout = 100 * time.Millisecond
	maximumCleanupTimeout = 5 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("lifecycle configuration rejected")
	ErrForbiddenAuthority   = errors.New("lifecycle forbidden authority rejected")
	databaseNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	identityPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// LookupFunc and EnvironFunc permit deterministic tests without mutating the
// process environment.
type LookupFunc func(string) (string, bool)
type EnvironFunc func() []string

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

// Config is immutable outside this package so callers cannot bypass the
// canonical URL, role, TLS, identity, or duration validation performed here.
type Config struct {
	databaseURL    secret
	environment    string
	schedulerID    string
	leaseOwner     string
	leaseDuration  time.Duration
	retryBackoff   time.Duration
	pollInterval   time.Duration
	cleanupTimeout time.Duration
}

func (c Config) DatabaseURL() string           { return c.databaseURL.reveal() }
func (c Config) Environment() string           { return c.environment }
func (c Config) SchedulerID() string           { return c.schedulerID }
func (c Config) LeaseOwner() string            { return c.leaseOwner }
func (c Config) LeaseDuration() time.Duration  { return c.leaseDuration }
func (c Config) RetryBackoff() time.Duration   { return c.retryBackoff }
func (c Config) PollInterval() time.Duration   { return c.pollInterval }
func (c Config) CleanupTimeout() time.Duration { return c.cleanupTimeout }
func (c Config) String() string {
	return "lifecycleconfig.Config{database_url:[REDACTED],settings:[REDACTED]}"
}
func (c Config) GoString() string               { return c.String() }
func (c Config) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(c.String())) }
func (c Config) MarshalJSON() ([]byte, error)   { return json.Marshal(c.String()) }
func (c Config) MarshalText() ([]byte, error)   { return []byte(c.String()), nil }

// Valid rechecks every immutable field without exposing its value.
func (c Config) Valid() bool {
	return validateDatabaseURL(c.databaseURL.reveal(), c.environment) == nil &&
		validEnvironment(c.environment) && identityPattern.MatchString(c.schedulerID) &&
		identityPattern.MatchString(c.leaseOwner) && c.schedulerID != c.leaseOwner &&
		bounded(c.leaseDuration, minimumLeaseDuration, maximumLeaseDuration) &&
		c.leaseDuration%time.Second == 0 &&
		bounded(c.retryBackoff, minimumRetryBackoff, maximumRetryBackoff) &&
		c.retryBackoff%time.Second == 0 &&
		bounded(c.pollInterval, minimumPollInterval, maximumPollInterval) &&
		bounded(c.cleanupTimeout, minimumCleanupTimeout, maximumCleanupTimeout)
}

func Load() (Config, error) { return LoadFrom(os.LookupEnv, os.Environ) }

func LoadFrom(lookup LookupFunc, environ EnvironFunc) (Config, error) {
	if lookup == nil || environ == nil {
		return Config{}, ErrInvalidConfiguration
	}
	if inheritedAuthority(lookup, environ) {
		return Config{}, ErrForbiddenAuthority
	}
	environment, ok := lookup(EnvironmentName)
	if !ok || !validEnvironment(environment) {
		return Config{}, ErrInvalidConfiguration
	}
	databaseURL, ok := lookup(DatabaseURLName)
	if !ok || validateDatabaseURL(databaseURL, environment) != nil {
		return Config{}, ErrInvalidConfiguration
	}
	schedulerID, err := identityValue(lookup, SchedulerIDName, defaultSchedulerID)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	leaseOwner, err := identityValue(lookup, LeaseOwnerName, defaultLeaseOwner)
	if err != nil || leaseOwner == schedulerID {
		return Config{}, ErrInvalidConfiguration
	}
	leaseDuration, err := durationValue(
		lookup, LeaseDurationName, defaultLeaseDuration,
		minimumLeaseDuration, maximumLeaseDuration,
	)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	retryBackoff, err := durationValue(
		lookup, RetryBackoffName, defaultRetryBackoff,
		minimumRetryBackoff, maximumRetryBackoff,
	)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	pollInterval, err := durationValue(
		lookup, PollIntervalName, defaultPollInterval,
		minimumPollInterval, maximumPollInterval,
	)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	cleanupTimeout, err := durationValue(
		lookup, CleanupTimeoutName, defaultCleanupTimeout,
		minimumCleanupTimeout, maximumCleanupTimeout,
	)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	result := Config{
		databaseURL: secret{value: databaseURL}, environment: environment,
		schedulerID: schedulerID, leaseOwner: leaseOwner,
		leaseDuration: leaseDuration, retryBackoff: retryBackoff,
		pollInterval: pollInterval, cleanupTimeout: cleanupTimeout,
	}
	if !result.Valid() {
		return Config{}, ErrInvalidConfiguration
	}
	return result, nil
}

func validateDatabaseURL(raw, environment string) error {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return ErrInvalidConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Opaque != "" ||
		parsed.User == nil || parsed.User.Username() != "sentinelflow_lifecycle" ||
		parsed.Hostname() == "" || parsed.Port() == "" || parsed.Fragment != "" ||
		parsed.RawFragment != "" || parsed.RawPath != "" || parsed.ForceQuery {
		return ErrInvalidConfiguration
	}
	password, hasPassword := parsed.User.Password()
	if !hasPassword || password == "" ||
		parsed.User.String() != url.UserPassword("sentinelflow_lifecycle", password).String() ||
		parsed.Hostname() != strings.ToLower(parsed.Hostname()) ||
		parsed.Host != net.JoinHostPort(parsed.Hostname(), parsed.Port()) {
		return ErrInvalidConfiguration
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != parsed.Port() {
		return ErrInvalidConfiguration
	}
	databaseName := strings.TrimPrefix(parsed.Path, "/")
	if parsed.Path != "/"+databaseName || databaseName != "sentinelflow" ||
		!databaseNamePattern.MatchString(databaseName) {
		return ErrInvalidConfiguration
	}
	if parsed.RawQuery != "sslmode=verify-full" &&
		(environment == "production" || parsed.RawQuery != "sslmode=disable") {
		return ErrInvalidConfiguration
	}
	if parsed.String() != raw {
		return ErrInvalidConfiguration
	}
	return nil
}

func validEnvironment(value string) bool {
	return value == "development" || value == "test" || value == "production"
}

func identityValue(lookup LookupFunc, name, fallback string) (string, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	if !identityPattern.MatchString(raw) {
		return "", ErrInvalidConfiguration
	}
	return raw, nil
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
	if err != nil || !canonicalDurationText(raw, value) || !bounded(value, minimum, maximum) {
		return 0, ErrInvalidConfiguration
	}
	return value, nil
}

func canonicalDurationText(raw string, value time.Duration) bool {
	if value.String() == raw {
		return true
	}
	for _, unit := range []struct {
		duration time.Duration
		suffix   string
	}{
		{duration: time.Hour, suffix: "h"},
		{duration: time.Minute, suffix: "m"},
		{duration: time.Second, suffix: "s"},
		{duration: time.Millisecond, suffix: "ms"},
	} {
		if value > 0 && value%unit.duration == 0 &&
			raw == strconv.FormatInt(int64(value/unit.duration), 10)+unit.suffix {
			return true
		}
	}
	return false
}

func bounded(value, minimum, maximum time.Duration) bool {
	return value >= minimum && value <= maximum
}

func inheritedAuthority(lookup LookupFunc, environ EnvironFunc) bool {
	for _, name := range forbiddenNames {
		if value, ok := lookup(name); ok && value != "" {
			return true
		}
	}
	for _, entry := range environ() {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name == "" || value == "" || allowedEnvironmentName(name) {
			continue
		}
		if sensitiveDatabaseName(name) {
			return true
		}
		for _, prefix := range forbiddenPrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
}

func sensitiveDatabaseName(name string) bool {
	upper := strings.ToUpper(name)
	return strings.Contains(upper, "DATABASE_URL") ||
		strings.HasSuffix(upper, "_DB_URL") || upper == "PGURL"
}

func allowedEnvironmentName(name string) bool {
	switch name {
	case DatabaseURLName, EnvironmentName, SchedulerIDName, LeaseOwnerName,
		LeaseDurationName, RetryBackoffName, PollIntervalName, CleanupTimeoutName:
		return true
	default:
		return false
	}
}

var forbiddenPrefixes = []string{
	"PG", "POSTGRES_", "DATABASE_", "OPENAI_", "ADMIN_", "SESSION_",
	"GATEWAY_", "AUTH_", "DISPATCHER_", "EXECUTOR_", "NFT_", "VALIDATOR_",
	"PROTECTED_", "HIL_", "DEMO_HISTORY_", "RETENTION_", "METRICS_",
	"CONTROL_METRICS_", "LIFECYCLE_", "SENTINELFLOW_",
}

var forbiddenNames = []string{
	"SENTINELFLOW_ADMIN_PASSWORD", "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
	"DISPATCHER_RESULT_PUBLIC_KEY_FILE", "EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
	"EXECUTOR_RESULT_PRIVATE_KEY_FILE", "AUTH_ACCOUNT_HASH_KEY",
	"GATEWAY_EVENT_HMAC_KEY", "AUTH_EVENT_HMAC_KEY", "SESSION_HMAC_KEY",
}
