// Package controlmetrics exports aggregate control-plane state through one
// migration-owned PostgreSQL function. It never accepts model, administrator,
// dispatcher, executor, nftables, event-signing, or mutation authority.
package controlmetrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DatabaseURLName   = "DATABASE_METRICS_URL"
	EnvironmentName   = "SENTINELFLOW_ENV"
	ListenAddressName = "CONTROL_METRICS_LISTEN_ADDR"
	ScrapeTimeoutName = "CONTROL_METRICS_SCRAPE_TIMEOUT"

	defaultListenAddress = "127.0.0.1:9091"
	defaultScrapeTimeout = 2 * time.Second
	minimumScrapeTimeout = 100 * time.Millisecond
	maximumScrapeTimeout = 5 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("control metrics configuration rejected")
	ErrForbiddenAuthority   = errors.New("control metrics forbidden authority rejected")
)

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

// Config is immutable outside this package, preserving the URL, listener,
// timeout, and inherited-authority checks performed by LoadFrom.
type Config struct {
	databaseURL   secret
	environment   string
	listenAddress string
	scrapeTimeout time.Duration
}

func (c Config) DatabaseURL() string          { return c.databaseURL.reveal() }
func (c Config) Environment() string          { return c.environment }
func (c Config) ListenAddress() string        { return c.listenAddress }
func (c Config) ScrapeTimeout() time.Duration { return c.scrapeTimeout }
func (c Config) String() string {
	return fmt.Sprintf("controlmetrics.Config{database_url:%s environment:%q listen_address:%q scrape_timeout:%s}",
		c.databaseURL.String(), c.environment, c.listenAddress, c.scrapeTimeout)
}
func (c Config) GoString() string               { return c.String() }
func (c Config) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(c.String())) }

func (c Config) Valid() bool {
	return validateDatabaseURL(c.databaseURL.reveal(), c.environment) == nil &&
		validEnvironment(c.environment) && validateListenAddress(c.listenAddress) == nil &&
		c.scrapeTimeout >= minimumScrapeTimeout && c.scrapeTimeout <= maximumScrapeTimeout
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
	rawURL, ok := lookup(DatabaseURLName)
	if !ok || validateDatabaseURL(rawURL, environment) != nil {
		return Config{}, ErrInvalidConfiguration
	}
	listenAddress := defaultListenAddress
	if value, exists := lookup(ListenAddressName); exists && value != "" {
		listenAddress = value
	}
	if validateListenAddress(listenAddress) != nil {
		return Config{}, ErrInvalidConfiguration
	}
	scrapeTimeout := defaultScrapeTimeout
	if value, exists := lookup(ScrapeTimeoutName); exists && value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed.String() != value || parsed < minimumScrapeTimeout || parsed > maximumScrapeTimeout {
			return Config{}, ErrInvalidConfiguration
		}
		scrapeTimeout = parsed
	}
	config := Config{databaseURL: secret{rawURL}, environment: environment,
		listenAddress: listenAddress, scrapeTimeout: scrapeTimeout}
	if !config.Valid() {
		return Config{}, ErrInvalidConfiguration
	}
	return config, nil
}

func validateDatabaseURL(raw, environment string) error {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return ErrInvalidConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Opaque != "" || parsed.User == nil ||
		parsed.User.Username() != "sentinelflow_metrics" || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.Path != "/sentinelflow" || parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.RawPath != "" || parsed.ForceQuery {
		return ErrInvalidConfiguration
	}
	password, hasPassword := parsed.User.Password()
	port, portErr := strconv.Atoi(parsed.Port())
	if !hasPassword || password == "" || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != parsed.Port() {
		return ErrInvalidConfiguration
	}
	if parsed.RawQuery != "sslmode=verify-full" && (environment == "production" || parsed.RawQuery != "sslmode=disable") {
		return ErrInvalidConfiguration
	}
	if parsed.String() != raw {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateListenAddress(raw string) error {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return ErrInvalidConfiguration
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil || host == "" || portText == "" {
		return ErrInvalidConfiguration
	}
	address, err := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || !address.Is4() || address.Is4In6() ||
		(!address.IsLoopback() && !address.IsPrivate()) ||
		portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText ||
		net.JoinHostPort(address.String(), portText) != raw {
		return ErrInvalidConfiguration
	}
	return nil
}

func validEnvironment(value string) bool {
	return value == "development" || value == "test" || value == "production"
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
	return name == DatabaseURLName || name == EnvironmentName ||
		name == ListenAddressName || name == ScrapeTimeoutName
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
