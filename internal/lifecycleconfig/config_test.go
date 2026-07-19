package lifecycleconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testDatabaseURL = "postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow?sslmode=disable"

func TestLoadFromAcceptsOnlyBoundedLifecycleSettings(t *testing.T) {
	t.Parallel()
	values := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	config, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Valid() || config.SchedulerID() != defaultSchedulerID ||
		config.LeaseOwner() != defaultLeaseOwner || config.LeaseDuration() != 10*time.Second ||
		config.RetryBackoff() != time.Second || config.PollInterval() != 250*time.Millisecond ||
		config.CleanupTimeout() != time.Second {
		t.Fatalf("unexpected defaults: %s", config)
	}
	values[SchedulerIDName] = "scheduler-a"
	values[LeaseOwnerName] = "worker-a"
	values[LeaseDurationName] = "60s"
	values[RetryBackoffName] = "60s"
	values[PollIntervalName] = "10ms"
	values[CleanupTimeoutName] = "5s"
	configured, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil || !configured.Valid() || configured.SchedulerID() != "scheduler-a" ||
		configured.LeaseOwner() != "worker-a" || configured.LeaseDuration() != time.Minute ||
		configured.RetryBackoff() != time.Minute ||
		configured.PollInterval() != 10*time.Millisecond ||
		configured.CleanupTimeout() != 5*time.Second {
		t.Fatalf("configured value rejected: %s err=%v", configured, err)
	}
}

func TestLoadFromRejectsInheritedAuthorityAndUnknownDatabaseURLs(t *testing.T) {
	t.Parallel()
	base := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	for _, name := range []string{
		"PGHOST", "PGPASSWORD", "POSTGRES_PASSWORD", "DATABASE_MIGRATION_URL",
		"DATABASE_API_URL", "DATABASE_WORKER_URL", "DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL", "DATABASE_RETENTION_URL", "DATABASE_METRICS_URL",
		"DATABASE_LIFECYCLE_PASSWORD", "UNRELATED_DATABASE_URL", "CUSTOM_DB_URL",
		"OPENAI_API_KEY", "ADMIN_PASSWORD_ARGON2ID_HASH", "SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY", "AUTH_EVENT_HMAC_KEY", "AUTH_ACCOUNT_HASH_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE", "EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"NFT_BINARY", "NFT_VALIDATOR_SOCKET", "PROTECTED_GATEWAY_IPV4", "HIL_SECRET",
		"RETENTION_INTERVAL", "METRICS_LISTEN_ADDR", "LIFECYCLE_UNRECOGNIZED",
		"SENTINELFLOW_ADMIN_TOKEN",
	} {
		values := cloneValues(base)
		values[name] = "inherited-secret-or-authority"
		_, err := LoadFrom(mapLookup(values), mapEnviron(values))
		if !errors.Is(err, ErrForbiddenAuthority) || strings.Contains(err.Error(), values[name]) {
			t.Fatalf("unsafe authority rejection for %s: %v", name, err)
		}
	}
}

func TestLoadFromRejectsURLAndBoundDriftWithoutLeaks(t *testing.T) {
	t.Parallel()
	base := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	for _, candidate := range []string{
		"postgres://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://%73entinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_lifecycle:lifecycle%2Dsecret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://other:lifecycle-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_lifecycle@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:05432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@POSTGRES:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/other?sslmode=disable",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow?sslmode=prefer",
		"postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dadmin",
	} {
		values := cloneValues(base)
		values[DatabaseURLName] = candidate
		_, err := LoadFrom(mapLookup(values), mapEnviron(values))
		if !errors.Is(err, ErrInvalidConfiguration) || strings.Contains(err.Error(), "lifecycle-secret") {
			t.Fatalf("unsafe URL rejection: %v", err)
		}
	}
	for name, candidates := range map[string][]string{
		EnvironmentName:    {"", "demo", "prod", " test"},
		SchedulerIDName:    {"bad value", "Uppercase", strings.Repeat("a", 65)},
		LeaseOwnerName:     {defaultSchedulerID, "bad/value", strings.Repeat("b", 65)},
		LeaseDurationName:  {"999ms", "61s", "1.5s", " 10s", "010s", "10.0s"},
		RetryBackoffName:   {"999ms", "61s", "1.5s", " 1s", "01s", "1.0s"},
		PollIntervalName:   {"9ms", "61s", " 250ms", "0250ms", "0.25s"},
		CleanupTimeoutName: {"99ms", "6s", " 1s", "01s", "1.0s"},
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

func TestLoadFromProductionRequiresVerifyFull(t *testing.T) {
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
}

func TestConfigurationFormattingAndEncodingAlwaysRedacts(t *testing.T) {
	t.Parallel()
	values := map[string]string{DatabaseURLName: testDatabaseURL, EnvironmentName: "test"}
	config, err := LoadFrom(mapLookup(values), mapEnviron(values))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{
		fmt.Sprint(config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config), string(encoded),
	} {
		if strings.Contains(formatted, "lifecycle-secret") || strings.Contains(formatted, testDatabaseURL) ||
			strings.Contains(formatted, config.SchedulerID()) || strings.Contains(formatted, config.LeaseOwner()) {
			t.Fatalf("configuration formatting leaked detail: %s", formatted)
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
