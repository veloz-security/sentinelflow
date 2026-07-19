package retention

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testDatabaseURL = "postgresql://sentinelflow_retention:retention-secret@postgres:5432/sentinelflow?sslmode=disable"

func TestLoadFromAcceptsOnlyBoundedRetentionSettings(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		DatabaseURLName: testDatabaseURL,
		EnvironmentName: "test",
	}
	config, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Valid() || config.Interval() != time.Hour ||
		config.RunTimeout() != 5*time.Minute || config.MaxRows() != 1000 {
		t.Fatalf("unexpected defaults: %s", config)
	}
	values[IntervalName] = "1h"
	values[RunTimeoutName] = "5m"
	values[MaxRowsName] = "1000"
	composeDefaults, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil || composeDefaults.Interval() != time.Hour ||
		composeDefaults.RunTimeout() != 5*time.Minute || composeDefaults.MaxRows() != 1000 {
		t.Fatalf("compose defaults = %s err=%v", composeDefaults, err)
	}
	values[IntervalName] = "1m"
	values[RunTimeoutName] = "1s"
	values[MaxRowsName] = "10000"
	configured, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil || configured.Interval() != time.Minute ||
		configured.RunTimeout() != time.Second || configured.MaxRows() != 10000 {
		t.Fatalf("configured values = %s err=%v", configured, err)
	}
}

func TestLoadFromRejectsAuthorityAndURLDriftWithoutLeaks(t *testing.T) {
	t.Parallel()
	base := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	for _, name := range []string{
		"PGHOST", "PGPASSWORD", "POSTGRES_PASSWORD", "DATABASE_WORKER_URL",
		"OPENAI_API_KEY", "ADMIN_PASSWORD_ARGON2ID_HASH", "SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY", "AUTH_EVENT_HMAC_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE", "EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"NFT_BINARY", "VALIDATOR_SOCKET", "PROTECTED_EXECUTOR_IPV4", "HIL_SECRET",
		"RETENTION_UNRECOGNIZED", "SENTINELFLOW_ADMIN_TOKEN",
	} {
		values := cloneValues(base)
		values[name] = "inherited-secret-or-authority"
		_, err := LoadFrom(mapLookup(values), mapEnviron(values))
		if !errors.Is(err, ErrForbiddenAuthority) || strings.Contains(err.Error(), values[name]) {
			t.Fatalf("unsafe authority rejection for %s: %v", name, err)
		}
	}
	for _, candidate := range []string{
		"postgres://sentinelflow_retention:retention-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://other:retention-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_retention@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_retention:retention-secret@postgres/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_retention:retention-secret@postgres:05432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_retention:retention-secret@postgres:5432/other?sslmode=disable",
		"postgresql://sentinelflow_retention:retention-secret@postgres:5432/sentinelflow",
		"postgresql://sentinelflow_retention:retention-secret@postgres:5432/sentinelflow?sslmode=prefer",
		"postgresql://sentinelflow_retention:retention-secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dadmin",
	} {
		values := cloneValues(base)
		values[DatabaseURLName] = candidate
		_, err := LoadFrom(mapLookup(values), mapEnviron(values))
		if !errors.Is(err, ErrInvalidConfiguration) || strings.Contains(err.Error(), "retention-secret") {
			t.Fatalf("unsafe URL rejection for %q: %v", candidate, err)
		}
	}
}

func TestLoadFromProductionRequiresVerifyFullAndExactBounds(t *testing.T) {
	t.Parallel()
	production := map[string]string{
		DatabaseURLName: strings.Replace(testDatabaseURL, "sslmode=disable", "sslmode=verify-full", 1),
		EnvironmentName: "production",
	}
	if _, err := LoadFrom(mapLookup(production), mapEnviron(production)); err != nil {
		t.Fatal(err)
	}
	production[DatabaseURLName] = testDatabaseURL
	if _, err := LoadFrom(mapLookup(production), mapEnviron(production)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("production accepted disabled TLS")
	}
	base := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	for name, candidates := range map[string][]string{
		EnvironmentName: {"", "prod", " test"},
		IntervalName:    {"59s", "25h", " 1h", "01h", "1.0h"},
		RunTimeoutName:  {"999ms", "16m", " 5m", "05m", "5.0m"},
		MaxRowsName:     {"0", "10001", "01", " 1000"},
	} {
		for _, candidate := range candidates {
			values := cloneValues(base)
			values[name] = candidate
			if _, err := LoadFrom(mapLookup(values), mapEnviron(values)); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("%s=%q accepted", name, candidate)
			}
		}
	}
}

func TestConfigFormattingAlwaysRedactsDatabaseURL(t *testing.T) {
	t.Parallel()
	values := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	config, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config)} {
		if strings.Contains(formatted, "retention-secret") || strings.Contains(formatted, testDatabaseURL) {
			t.Fatalf("configuration formatting leaked URL: %s", formatted)
		}
	}
}

func mapLookup(values map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func mapEnviron(values map[string]string) EnvironFunc {
	return func() []string {
		result := make([]string, 0, len(values))
		for name, value := range values {
			result = append(result, name+"="+value)
		}
		return result
	}
}

func cloneValues(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}
