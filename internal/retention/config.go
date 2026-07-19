// Package retention implements the least-privilege runtime that invokes the
// database-owned retention transaction. It never receives AI, administrator,
// dispatcher, executor, validator, event-signing, or nftables authority.
package retention

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DatabaseURLName = "DATABASE_RETENTION_URL"
	EnvironmentName = "SENTINELFLOW_ENV"
	IntervalName    = "RETENTION_INTERVAL"
	RunTimeoutName  = "RETENTION_RUN_TIMEOUT"
	MaxRowsName     = "RETENTION_MAX_ROWS"

	defaultInterval   = time.Hour
	defaultRunTimeout = 5 * time.Minute
	defaultMaxRows    = 1000
	minimumInterval   = time.Minute
	maximumInterval   = 24 * time.Hour
	minimumRunTimeout = time.Second
	maximumRunTimeout = 15 * time.Minute
)

var (
	ErrInvalidConfiguration = errors.New("retention configuration rejected")
	ErrForbiddenAuthority   = errors.New("retention forbidden authority rejected")
	databaseNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// LookupFunc and EnvironFunc permit deterministic configuration tests without
// mutating the process environment.
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

// Config is immutable outside this package so callers cannot bypass the URL,
// role, TLS, schedule, or batch-bound validation performed by LoadFrom.
type Config struct {
	databaseURL secret
	environment string
	interval    time.Duration
	runTimeout  time.Duration
	maxRows     int
}

func (c Config) DatabaseURL() string       { return c.databaseURL.reveal() }
func (c Config) Environment() string       { return c.environment }
func (c Config) Interval() time.Duration   { return c.interval }
func (c Config) RunTimeout() time.Duration { return c.runTimeout }
func (c Config) MaxRows() int              { return c.maxRows }
func (c Config) String() string {
	return fmt.Sprintf(
		"retention.Config{database_url:%s environment:%q interval:%s run_timeout:%s max_rows:%d}",
		c.databaseURL.String(), c.environment, c.interval, c.runTimeout, c.maxRows,
	)
}
func (c Config) GoString() string               { return c.String() }
func (c Config) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(c.String())) }

func (c Config) Valid() bool {
	return validateDatabaseURL(c.databaseURL.reveal(), c.environment) == nil &&
		validEnvironment(c.environment) &&
		c.interval >= minimumInterval && c.interval <= maximumInterval &&
		c.runTimeout >= minimumRunTimeout && c.runTimeout <= maximumRunTimeout &&
		c.maxRows >= 1 && c.maxRows <= 10000
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
	interval, err := durationValue(
		lookup, IntervalName, defaultInterval, minimumInterval, maximumInterval,
	)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	runTimeout, err := durationValue(
		lookup, RunTimeoutName, defaultRunTimeout, minimumRunTimeout, maximumRunTimeout,
	)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	maxRows, err := integerValue(lookup, MaxRowsName, defaultMaxRows, 1, 10000)
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	result := Config{
		databaseURL: secret{value: databaseURL}, environment: environment,
		interval: interval, runTimeout: runTimeout, maxRows: maxRows,
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
		parsed.User == nil || parsed.User.Username() != "sentinelflow_retention" ||
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
	if err != nil || !canonicalDurationText(raw, value) || value < minimum || value > maximum {
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
		for _, prefix := range forbiddenPrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
}

func allowedEnvironmentName(name string) bool {
	switch name {
	case DatabaseURLName, EnvironmentName, IntervalName, RunTimeoutName, MaxRowsName:
		return true
	default:
		return false
	}
}

var forbiddenPrefixes = []string{
	"PG", "POSTGRES_", "DATABASE_", "OPENAI_", "ADMIN_", "SESSION_",
	"GATEWAY_", "AUTH_", "DISPATCHER_", "EXECUTOR_", "NFT_", "VALIDATOR_",
	"PROTECTED_", "HIL_", "DEMO_HISTORY_", "RETENTION_", "SENTINELFLOW_",
}

var forbiddenNames = []string{
	"SENTINELFLOW_ADMIN_PASSWORD", "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
	"DISPATCHER_RESULT_PUBLIC_KEY_FILE", "EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
	"EXECUTOR_RESULT_PRIVATE_KEY_FILE", "AUTH_ACCOUNT_HASH_KEY",
	"GATEWAY_EVENT_HMAC_KEY", "AUTH_EVENT_HMAC_KEY", "SESSION_HMAC_KEY",
}
