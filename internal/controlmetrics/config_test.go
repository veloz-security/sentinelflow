package controlmetrics

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testReadURL = "postgresql://sentinelflow_metrics:metrics-secret@postgres:5432/sentinelflow?sslmode=disable"

func TestLoadFromAcceptsBoundedReadOnlyConfiguration(t *testing.T) {
	t.Parallel()
	values := map[string]string{DatabaseURLName: testReadURL, EnvironmentName: "test"}
	config, err := LoadFrom(testLookup(values), testEnviron(values))
	if err != nil || !config.Valid() || config.ListenAddress() != defaultListenAddress ||
		config.ScrapeTimeout() != defaultScrapeTimeout {
		t.Fatalf("config=%s err=%v", config, err)
	}
	values[ListenAddressName] = "10.20.30.40:9100"
	values[ScrapeTimeoutName] = "500ms"
	config, err = LoadFrom(testLookup(values), testEnviron(values))
	if err != nil || config.ListenAddress() != "10.20.30.40:9100" || config.ScrapeTimeout() != 500*time.Millisecond {
		t.Fatalf("configured=%s err=%v", config, err)
	}
}

func TestLoadFromRejectsPublicListenerURLDriftAndAuthorityWithoutLeaks(t *testing.T) {
	t.Parallel()
	base := map[string]string{DatabaseURLName: testReadURL, EnvironmentName: "test"}
	for _, address := range []string{"0.0.0.0:9091", "8.8.8.8:9091", "localhost:9091", "[::1]:9091", "127.0.0.1:09091", "127.0.0.1:0"} {
		values := clone(base)
		values[ListenAddressName] = address
		if _, err := LoadFrom(testLookup(values), testEnviron(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("listener %q accepted: %v", address, err)
		}
	}
	for _, rawURL := range []string{
		"postgresql://sentinelflow_worker:metrics-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_metrics@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_metrics:metrics-secret@postgres:5432/other?sslmode=disable",
		"postgresql://sentinelflow_metrics:metrics-secret@postgres:05432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_metrics:metrics-secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dsentinelflow_worker",
	} {
		values := clone(base)
		values[DatabaseURLName] = rawURL
		_, err := LoadFrom(testLookup(values), testEnviron(values))
		if !errors.Is(err, ErrInvalidConfiguration) || strings.Contains(fmt.Sprint(err), "metrics-secret") {
			t.Fatalf("unsafe URL rejection: %v", err)
		}
	}
	for _, name := range []string{
		"PGPASSWORD", "POSTGRES_PASSWORD", "DATABASE_WORKER_URL", "DATABASE_API_URL", "DATABASE_READ_URL",
		"OPENAI_API_KEY", "ADMIN_PASSWORD_ARGON2ID_HASH", "SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY", "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE", "NFT_BINARY", "VALIDATOR_SOCKET",
		"HIL_SECRET", "RETENTION_MAX_ROWS", "SENTINELFLOW_ADMIN_TOKEN",
	} {
		values := clone(base)
		values[name] = "secret-authority"
		_, err := LoadFrom(testLookup(values), testEnviron(values))
		if !errors.Is(err, ErrForbiddenAuthority) || strings.Contains(fmt.Sprint(err), values[name]) {
			t.Fatalf("unsafe authority rejection for %s: %v", name, err)
		}
	}
}

func TestLoadFromProductionRequiresVerifyFullAndFormattingRedacts(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		DatabaseURLName: strings.Replace(testReadURL, "sslmode=disable", "sslmode=verify-full", 1),
		EnvironmentName: "production",
	}
	config, err := LoadFrom(testLookup(values), testEnviron(values))
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config)} {
		if strings.Contains(formatted, "metrics-secret") || strings.Contains(formatted, testReadURL) {
			t.Fatalf("configuration leaked: %s", formatted)
		}
	}
	values[DatabaseURLName] = testReadURL
	if _, err := LoadFrom(testLookup(values), testEnviron(values)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("production accepted disabled TLS")
	}
}

func testLookup(values map[string]string) LookupFunc {
	return func(name string) (string, bool) { value, ok := values[name]; return value, ok }
}

func testEnviron(values map[string]string) EnvironFunc {
	return func() []string {
		result := make([]string, 0, len(values))
		for name, value := range values {
			result = append(result, name+"="+value)
		}
		return result
	}
}

func clone(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}
