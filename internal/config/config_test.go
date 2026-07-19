package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoadFromRoleDefaultsAndRequiredSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		role Role
		env  map[string]string
	}{
		{name: "gateway", role: RoleGateway, env: map[string]string{"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g')}},
		{name: "api", role: RoleAPI, env: withAPISourceIdentity(map[string]string{
			"DATABASE_API_URL":             testDatabaseURL("api-password"),
			"GATEWAY_EVENT_HMAC_KEY":       testBase64Key('g'),
			"AUTH_EVENT_HMAC_KEY":          testBase64Key('a'),
			"ADMIN_PASSWORD_ARGON2ID_HASH": testArgon2idPHC(),
			"SESSION_HMAC_KEY":             testBase64Key('s'),
		})},
		{name: "detector", role: RoleDetector, env: map[string]string{
			"DATABASE_WORKER_URL": testDatabaseURL("detector-password"),
		}},
		{name: "worker", role: RoleWorker, env: map[string]string{
			"DATABASE_WORKER_URL":                   testDatabaseURL("worker-password"),
			"OPENAI_API_KEY":                        "sk-test-worker-secret",
			"OPENAI_RATE_CARD_VERSION":              "operator-2026-07-18",
			"OPENAI_INPUT_USD_PER_1M_TOKENS":        "1.25",
			"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS": "0.25",
			"OPENAI_OUTPUT_USD_PER_1M_TOKENS":       "5.00",
		}},
		{name: "validation-worker", role: RoleValidationWorker, env: map[string]string{
			"DATABASE_WORKER_URL":          testWorkerDatabaseURL("validation-worker-password"),
			"NFT_BINARY_EXPECTED_SHA256":   strings.Repeat("a", 64),
			"NFT_EXPECTED_VERSION":         "nftables v1.1.1",
			"PROTECTED_CURRENT_ADMIN_IPV4": "8.8.8.8",
		}},
		{name: "validator", role: RoleValidator, env: map[string]string{
			"NFT_BINARY_EXPECTED_SHA256": strings.Repeat("a", 64),
			"NFT_EXPECTED_VERSION":       "nftables v1.1.1",
			"NFT_VALIDATOR_SOCKET":       "/run/sentinelflow-validator/validator.sock",
		}},
		{name: "dispatcher", role: RoleDispatcher, env: map[string]string{
			"DATABASE_DISPATCHER_URL":             testDatabaseURL("dispatcher-password"),
			"DISPATCHER_SIGNING_PRIVATE_KEY_FILE": "/run/secrets/dispatcher-private",
			"DISPATCHER_RESULT_PUBLIC_KEY_FILE":   "/run/secrets/executor-result-public",
		}},
		{name: "executor", role: RoleExecutor, env: map[string]string{
			"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE": "/run/secrets/dispatcher-public",
			"EXECUTOR_RESULT_PRIVATE_KEY_FILE":  "/run/secrets/executor-result-private",
			"NFT_BINARY_EXPECTED_SHA256":        strings.Repeat("a", 64),
			"NFT_EXPECTED_VERSION":              "nftables v1.1.1",
		}},
		{name: "simulator", role: RoleSimulator, env: map[string]string{
			"AUTH_EVENT_HMAC_KEY":                     testBase64Key('a'),
			"AUTH_ACCOUNT_HASH_KEY":                   testBase64Key('h'),
			"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE": "/run/secrets/demo-history-private",
		}},
		{name: "demo-app", role: RoleDemoApp, env: map[string]string{
			"AUTH_EVENT_HMAC_KEY":     testBase64Key('a'),
			"AUTH_ACCOUNT_HASH_KEY":   testBase64Key('h'),
			"DEMO_GATEWAY_PEER_CIDRS": "172.30.0.2/32",
		}},
		{name: "migrator", role: RoleMigrator, env: map[string]string{"DATABASE_MIGRATION_URL": testDatabaseURL("migration-password")}},
		{name: "reader", role: RoleReader, env: map[string]string{"DATABASE_READ_URL": testDatabaseURL("reader-password")}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := LoadFrom(tt.role, mapLookup(tt.env))
			if err != nil {
				t.Fatalf("LoadFrom() error = %v", err)
			}
			if cfg.Role != tt.role {
				t.Fatalf("Role = %q, want %q", cfg.Role, tt.role)
			}
			if cfg.Environment != EnvironmentDevelopment {
				t.Fatalf("Environment = %q", cfg.Environment)
			}
			if cfg.Gateway.MaxHeaderBytes != 32768 || cfg.Gateway.MaxBodyBytes != 10485760 {
				t.Fatalf("unexpected gateway limits: %+v", cfg.Gateway)
			}
			if cfg.Gateway.MetricsListenAddr != "127.0.0.1:9090" {
				t.Fatalf("unsafe Gateway metrics listener: %q", cfg.Gateway.MetricsListenAddr)
			}
			if cfg.Gateway.HeaderReadTimeout != 5*time.Second || cfg.Gateway.EventFlushInterval != 100*time.Millisecond {
				t.Fatalf("unexpected gateway durations: %+v", cfg.Gateway)
			}
			if cfg.OpenAI.Model != "gpt-5.6-sol" || cfg.OpenAI.Store {
				t.Fatalf("unsafe OpenAI defaults: %+v", cfg.OpenAI)
			}
			if len(cfg.Admin.AllowedOrigins) != 2 || cfg.Admin.AllowedOrigins[0] != "http://localhost:4173" ||
				cfg.Admin.CookieTransport != AdminCookieTransportLocalTest || cfg.Admin.SessionCookieName != "sentinelflow_admin" {
				t.Fatalf("unsafe administrator browser defaults: %+v", cfg.Admin)
			}
			if cfg.Enforcement.HostEnforcementEnabled {
				t.Fatal("host enforcement must default to false")
			}
			if cfg.Enforcement.BaseChainContract != "contracts/enforcement/nft_base_chain_v1.nft" {
				t.Fatalf("raw base-chain path = %q", cfg.Enforcement.BaseChainContract)
			}
		})
	}
}

func TestControlAndPrivilegedRolesRejectDemoRuntimeAuthority(t *testing.T) {
	t.Parallel()
	roles := []struct {
		name string
		role Role
		base map[string]string
	}{
		{name: "api", role: RoleAPI, base: withAPISourceIdentity(map[string]string{
			"DATABASE_API_URL": testDatabaseURL("api-password"), "GATEWAY_EVENT_HMAC_KEY": testBase64Key('g'),
			"AUTH_EVENT_HMAC_KEY": testBase64Key('a'), "ADMIN_PASSWORD_ARGON2ID_HASH": testArgon2idPHC(),
			"SESSION_HMAC_KEY": testBase64Key('s'),
		})},
		{name: "dispatcher", role: RoleDispatcher, base: map[string]string{
			"DATABASE_DISPATCHER_URL":             testDatabaseURL("dispatcher-password"),
			"DISPATCHER_SIGNING_PRIVATE_KEY_FILE": "/run/secrets/dispatcher-private",
			"DISPATCHER_RESULT_PUBLIC_KEY_FILE":   "/run/secrets/executor-result-public",
		}},
		{name: "executor", role: RoleExecutor, base: map[string]string{
			"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE": "/run/secrets/dispatcher-public",
			"EXECUTOR_RESULT_PRIVATE_KEY_FILE":  "/run/secrets/executor-result-private",
			"NFT_BINARY_EXPECTED_SHA256":        strings.Repeat("a", 64), "NFT_EXPECTED_VERSION": "nftables v1.1.1",
		}},
	}
	for _, roleCase := range roles {
		roleCase := roleCase
		t.Run(roleCase.name, func(t *testing.T) {
			t.Parallel()
			for _, field := range []string{
				"DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL",
				"DEMO_HISTORY_SIGNED_ENVELOPE_FILE", "DEMO_HISTORY_PUBLIC_KEY_B64URL",
				"DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID", "DEMO_HISTORY_CLOCK_AT",
				"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
				"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
				"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
			} {
				env := cloneEnvironment(roleCase.base)
				if strings.HasPrefix(field, "DATABASE_") {
					env[field] = testDatabaseURL("forbidden-demo-role")
				} else {
					env[field] = "/run/secrets/forbidden-demo-runtime"
				}
				_, err := LoadFrom(roleCase.role, mapLookup(env))
				assertConfigErrorField(t, err, field)
				if strings.Contains(err.Error(), env[field]) {
					t.Fatalf("%s leaked forbidden %s value", roleCase.name, field)
				}
			}
		})
	}
}

func TestGatewayMetricsListenerIsCanonicalLoopbackOrPrivateIPv4Only(t *testing.T) {
	t.Parallel()
	base := map[string]string{"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g')}
	valid := cloneEnvironment(base)
	valid["GATEWAY_METRICS_LISTEN_ADDR"] = "127.0.0.2:19090"
	config, err := LoadFrom(RoleGateway, mapLookup(valid))
	if err != nil {
		t.Fatal(err)
	}
	if config.Gateway.MetricsListenAddr != "127.0.0.2:19090" {
		t.Fatalf("metrics listener = %q", config.Gateway.MetricsListenAddr)
	}
	private := cloneEnvironment(base)
	private["GATEWAY_METRICS_LISTEN_ADDR"] = "172.29.0.2:9090"
	config, err = LoadFrom(RoleGateway, mapLookup(private))
	if err != nil || config.Gateway.MetricsListenAddr != "172.29.0.2:9090" {
		t.Fatalf("private metrics listener rejected: %+v %v", config.Gateway, err)
	}

	for _, value := range []string{
		":9090", "0.0.0.0:9090", "8.8.8.8:9090", "localhost:9090",
		"[::1]:9090", "127.0.0.1:0", "127.0.0.1:65536",
		"127.0.0.1:09090", " 127.0.0.1:9090", "127.0.0.1:9090 ",
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			environment := cloneEnvironment(base)
			environment["GATEWAY_METRICS_LISTEN_ADDR"] = value
			_, loadErr := LoadFrom(RoleGateway, mapLookup(environment))
			assertConfigErrorField(t, loadErr, "GATEWAY_METRICS_LISTEN_ADDR")
		})
	}
}

func TestLoadFromMissingRoleSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role     Role
		expected string
	}{
		{RoleGateway, "GATEWAY_EVENT_HMAC_KEY"},
		{RoleAPI, "DATABASE_API_URL"},
		{RoleDetector, "DATABASE_WORKER_URL"},
		{RoleWorker, "DATABASE_WORKER_URL"},
		{RoleValidationWorker, "DATABASE_WORKER_URL"},
		{RoleValidator, "NFT_BINARY_EXPECTED_SHA256"},
		{RoleDispatcher, "DATABASE_DISPATCHER_URL"},
		{RoleExecutor, "EXECUTOR_DISPATCH_PUBLIC_KEY_FILE"},
		{RoleSimulator, "AUTH_EVENT_HMAC_KEY"},
		{RoleDemoApp, "AUTH_EVENT_HMAC_KEY"},
		{RoleMigrator, "DATABASE_MIGRATION_URL"},
		{RoleReader, "DATABASE_READ_URL"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(string(tt.role), func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(tt.role, mapLookup(nil))
			assertConfigErrorField(t, err, tt.expected)
			if !strings.Contains(err.Error(), "required for service role") {
				t.Fatalf("error %q does not clearly report a required role secret", err)
			}
		})
	}
}

func TestDatabaseURLRequiresCanonicalTransportOnly(t *testing.T) {
	t.Parallel()
	for _, environment := range []string{"development", "test", "demo"} {
		for _, mode := range []string{"disable", "verify-full"} {
			_, err := LoadFrom(RoleMigrator, mapLookup(map[string]string{
				"SENTINELFLOW_ENV":       environment,
				"DATABASE_MIGRATION_URL": testDatabaseURLMode("migration-secret", mode),
			}))
			if err != nil {
				t.Fatalf("environment=%s mode=%s: %v", environment, mode, err)
			}
		}
	}
	if _, err := LoadFrom(RoleMigrator, mapLookup(map[string]string{
		"SENTINELFLOW_ENV":       "production",
		"DATABASE_MIGRATION_URL": testDatabaseURLMode("migration-secret", "verify-full"),
	})); err != nil {
		t.Fatalf("production verify-full rejected: %v", err)
	}
	if _, err := LoadFrom(RoleMigrator, mapLookup(map[string]string{
		"SENTINELFLOW_ENV":       "production",
		"DATABASE_MIGRATION_URL": testDatabaseURLMode("migration-secret", "disable"),
	})); err == nil {
		t.Fatal("production accepted sslmode=disable")
	} else {
		assertConfigErrorField(t, err, "DATABASE_MIGRATION_URL")
	}

	for _, value := range []string{
		"postgres://sentinelflow:migration-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow:migration-secret@postgres:5432/sentinelflow",
		"postgresql://sentinelflow:migration-secret@postgres:5432/sentinelflow?sslmode=prefer",
		"postgresql://sentinelflow:migration-secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dadmin",
		"postgresql://sentinelflow:migration-secret@postgres:5432/sentinelflow?sslmode=disable&application_name=override",
		"postgresql://sentinelflow:migration-secret@postgres:5432/sentinelflow?sslmode=disable#fragment",
		"postgresql://sentinelflow:migration-secret@postgres/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow:migration-secret@postgres:05432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow:migration-secret@postgres:5432/a/b?sslmode=disable",
		"postgresql://sentinelflow:migration-secret@postgres:5432/%73entinelflow?sslmode=disable",
	} {
		_, err := LoadFrom(RoleMigrator, mapLookup(map[string]string{"DATABASE_MIGRATION_URL": value}))
		assertConfigErrorField(t, err, "DATABASE_MIGRATION_URL")
		if strings.Contains(err.Error(), "migration-secret") {
			t.Fatal("database URL error leaked its password")
		}
	}
}

func TestLoadFromDetectorRejectsCredentialBearingEnvironment(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"DATABASE_WORKER_URL": testDatabaseURL("detector-password"),
	}
	for _, field := range []string{
		"DATABASE_MIGRATION_URL",
		"DATABASE_API_URL",
		"DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL",
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"OPENAI_API_KEY",
		"ADMIN_PASSWORD_ARGON2ID_HASH",
		"SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY",
		"AUTH_EVENT_HMAC_KEY",
		"AUTH_ACCOUNT_HASH_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"DISPATCHER_RESULT_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			env := cloneEnvironment(base)
			switch {
			case strings.HasPrefix(field, "DATABASE_"):
				env[field] = testDatabaseURL("must-not-enter-detector")
			case field == "ADMIN_PASSWORD_ARGON2ID_HASH":
				env[field] = testArgon2idPHC()
			case strings.HasSuffix(field, "HMAC_KEY") || field == "AUTH_ACCOUNT_HASH_KEY":
				env[field] = testBase64Key('x')
			default:
				env[field] = "/run/secrets/must-not-enter-detector"
			}
			_, err := LoadFrom(RoleDetector, mapLookup(env))
			assertConfigErrorField(t, err, field)
			if strings.Contains(err.Error(), env[field]) {
				t.Fatalf("detector configuration leaked forbidden value: %v", err)
			}
		})
	}
}

func TestLoadFromValidatorRejectsCredentialBearingEnvironment(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"NFT_BINARY_EXPECTED_SHA256": strings.Repeat("a", 64),
		"NFT_EXPECTED_VERSION":       "nftables v1.1.1",
	}
	for _, field := range []string{
		"DATABASE_MIGRATION_URL",
		"DATABASE_API_URL",
		"DATABASE_WORKER_URL",
		"DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL",
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"OPENAI_API_KEY",
		"ADMIN_PASSWORD_ARGON2ID_HASH",
		"SESSION_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY",
		"AUTH_EVENT_HMAC_KEY",
		"AUTH_ACCOUNT_HASH_KEY",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"DISPATCHER_RESULT_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			env := make(map[string]string, len(base)+1)
			for key, value := range base {
				env[key] = value
			}
			switch {
			case strings.HasPrefix(field, "DATABASE_"):
				env[field] = testDatabaseURL("must-not-enter-validator")
			case field == "ADMIN_PASSWORD_ARGON2ID_HASH":
				env[field] = testArgon2idPHC()
			case strings.HasSuffix(field, "HMAC_KEY") || field == "AUTH_ACCOUNT_HASH_KEY":
				env[field] = testBase64Key('x')
			default:
				env[field] = "/run/secrets/must-not-enter-validator"
			}
			_, err := LoadFrom(RoleValidator, mapLookup(env))
			assertConfigErrorField(t, err, field)
			if strings.Contains(err.Error(), env[field]) {
				t.Fatalf("validator configuration leaked forbidden value: %v", err)
			}
		})
	}
}

func TestDemoValidationWorkerAcceptsOnlyPublicHistoryProofInputs(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"SENTINELFLOW_ENV":                               "demo",
		"DATABASE_WORKER_URL":                            testWorkerDatabaseURL("worker-password"),
		"NFT_BINARY_EXPECTED_SHA256":                     strings.Repeat("a", 64),
		"NFT_EXPECTED_VERSION":                           "nftables v1.1.1",
		"PROTECTED_CURRENT_ADMIN_IPV4":                   "8.8.8.8",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE":              "/run/sentinelflow/demo-history-envelope.json",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL":                 base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32))),
		"DEMO_HISTORY_RUN_SCOPE":                         "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000901",
		"DEMO_HISTORY_IMPORT_ID":                         "019b0000-0000-7000-8000-000000000902",
		"DEMO_HISTORY_CLOCK_AT":                          "2026-07-18T02:00:00.000Z",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST":       "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE": DemoHistoryValidationActivationPath,
	}
	loaded, err := LoadFrom(RoleValidationWorker, mapLookup(base))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Demo.HistorySignedEnvelopeFile != base["DEMO_HISTORY_SIGNED_ENVELOPE_FILE"] ||
		loaded.Demo.HistoryPublicKeyB64URL != base["DEMO_HISTORY_PUBLIC_KEY_B64URL"] ||
		loaded.Demo.HistoryClockAt.Format("2006-01-02T15:04:05.000Z") != base["DEMO_HISTORY_CLOCK_AT"] {
		t.Fatalf("unexpected public demo proof config: %+v", loaded.Demo)
	}

	for _, field := range []string{
		"DEMO_HISTORY_FIXTURE_MANIFEST",
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE",
	} {
		env := cloneEnvironment(base)
		env[field] = "/run/secrets/private-or-legacy"
		_, rejectErr := LoadFrom(RoleValidationWorker, mapLookup(env))
		assertConfigErrorField(t, rejectErr, field)
		if strings.Contains(rejectErr.Error(), env[field]) {
			t.Fatalf("worker config leaked %s", field)
		}
	}

	for _, field := range []string{
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
	} {
		env := cloneEnvironment(base)
		delete(env, field)
		_, rejectErr := LoadFrom(RoleValidationWorker, mapLookup(env))
		assertConfigErrorField(t, rejectErr, field)
	}
}

func TestLoadFromValidatorRequiresCleanAbsoluteSocket(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"relative.sock", "/run/validator/../validator.sock"} {
		_, err := LoadFrom(RoleValidator, mapLookup(map[string]string{
			"NFT_BINARY_EXPECTED_SHA256": strings.Repeat("a", 64),
			"NFT_EXPECTED_VERSION":       "nftables v1.1.1",
			"NFT_VALIDATOR_SOCKET":       value,
		}))
		assertConfigErrorField(t, err, "NFT_VALIDATOR_SOCKET")
	}
}

func TestLoadFromRejectsInvalidTypedValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		value    string
		expected string
	}{
		{name: "duration", key: "GATEWAY_REQUEST_TIMEOUT", value: "forever", expected: "GATEWAY_REQUEST_TIMEOUT"},
		{name: "duration over limit", key: "GATEWAY_HEADER_READ_TIMEOUT", value: "6s", expected: "GATEWAY_HEADER_READ_TIMEOUT"},
		{name: "integer", key: "GATEWAY_EVENT_BATCH_SIZE", value: "1.5", expected: "GATEWAY_EVENT_BATCH_SIZE"},
		{name: "integer over limit", key: "OPENAI_MAX_EVIDENCE_REFS", value: "51", expected: "OPENAI_MAX_EVIDENCE_REFS"},
		{name: "boolean", key: "OPENAI_STORE", value: "TRUE", expected: "OPENAI_STORE"},
		{name: "private cidr", key: "GATEWAY_ORIGIN_CIDRS", value: "8.8.8.0/24", expected: "GATEWAY_ORIGIN_CIDRS"},
		{name: "broad private cidr", key: "GATEWAY_ORIGIN_CIDRS", value: "10.0.0.0/8", expected: "GATEWAY_ORIGIN_CIDRS"},
		{name: "noncanonical cidr", key: "GATEWAY_ORIGIN_CIDRS", value: "172.30.0.1/24", expected: "GATEWAY_ORIGIN_CIDRS"},
		{name: "upstream scheme", key: "GATEWAY_UPSTREAM_URL", value: "https://demo-app:8081", expected: "GATEWAY_UPSTREAM_URL"},
		{name: "upstream credentials", key: "GATEWAY_UPSTREAM_URL", value: "http://user:pass@demo-app:8081", expected: "GATEWAY_UPSTREAM_URL"},
		{name: "wrong ingest endpoint", key: "INTERNAL_GATEWAY_INGEST_URL", value: "http://api:8082/wrong", expected: "INTERNAL_GATEWAY_INGEST_URL"},
		{name: "public management bind", key: "API_MANAGEMENT_PUBLISHED_HOST", value: "0.0.0.0", expected: "API_MANAGEMENT_PUBLISHED_HOST"},
		{name: "tls pair", key: "GATEWAY_TLS_CERT_FILE", value: "/run/tls/cert.pem", expected: "GATEWAY_TLS_CERT_FILE"},
		{name: "unordered protected cidrs", key: "PROTECTED_CIDRS", value: "192.0.2.0/24,10.0.0.0/8", expected: "PROTECTED_CIDRS"},
		{name: "demo exception outside demo", key: "DEMO_ALLOW_RFC5737", value: "true", expected: "DEMO_ALLOW_RFC5737"},
		{name: "host enforcement", key: "HOST_ENFORCEMENT_ENABLED", value: "true", expected: "HOST_ENFORCEMENT_ENABLED"},
		{name: "alternate nft binary", key: "NFT_BINARY", value: "/bin/true", expected: "NFT_BINARY"},
		{name: "invalid nft binary digest", key: "NFT_BINARY_EXPECTED_SHA256", value: "SHA256:bad", expected: "NFT_BINARY_EXPECTED_SHA256"},
		{name: "invalid nft version", key: "NFT_EXPECTED_VERSION", value: "nftables 1.1.1", expected: "NFT_EXPECTED_VERSION"},
		{name: "bootstrap outside executor", key: "EXECUTOR_STARTUP_MODE", value: "bootstrap", expected: "EXECUTOR_STARTUP_MODE"},
		{name: "unordered protected runtime addresses", key: "PROTECTED_GATEWAY_IPV4", value: "10.0.0.2,10.0.0.1", expected: "PROTECTED_GATEWAY_IPV4"},
		{name: "duplicate protected runtime address", key: "PROTECTED_GATEWAY_IPV4", value: "10.0.0.1,10.0.0.1", expected: "PROTECTED_GATEWAY_IPV4"},
		{name: "noncanonical protected runtime address", key: "PROTECTED_GATEWAY_IPV4", value: "010.0.0.1", expected: "PROTECTED_GATEWAY_IPV4"},
		{name: "broad demo Gateway peer", key: "DEMO_GATEWAY_PEER_CIDRS", value: "172.30.0.0/16", expected: "DEMO_GATEWAY_PEER_CIDRS"},
		{name: "overlapping demo Gateway peers", key: "DEMO_GATEWAY_PEER_CIDRS", value: "172.30.0.0/24,172.30.0.2/32", expected: "DEMO_GATEWAY_PEER_CIDRS"},
		{name: "external plaintext admin origin", key: "ADMIN_ALLOWED_ORIGINS", value: "http://admin.example.test", expected: "ADMIN_ALLOWED_ORIGINS"},
		{name: "admin origin with path", key: "ADMIN_ALLOWED_ORIGINS", value: "https://admin.example.test/ui", expected: "ADMIN_ALLOWED_ORIGINS"},
		{name: "duplicate admin origin", key: "ADMIN_ALLOWED_ORIGINS", value: "https://admin.example.test,https://admin.example.test", expected: "ADMIN_ALLOWED_ORIGINS"},
		{name: "invalid admin cookie transport", key: "ADMIN_COOKIE_TRANSPORT", value: "insecure", expected: "ADMIN_COOKIE_TRANSPORT"},
		{name: "invalid admin cookie name", key: "ADMIN_SESSION_COOKIE_NAME", value: "bad cookie", expected: "ADMIN_SESSION_COOKIE_NAME"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{
				"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g'),
				tt.key:                   tt.value,
			}
			_, err := LoadFrom(RoleGateway, mapLookup(env))
			assertConfigErrorField(t, err, tt.expected)
		})
	}
}

func TestLoadFromProductionAPIRequiresTLSAdminBrowserBoundary(t *testing.T) {
	t.Parallel()
	base := withAPISourceIdentity(map[string]string{
		"SENTINELFLOW_ENV":             "production",
		"DATABASE_API_URL":             testDatabaseURLMode("api-password", "verify-full"),
		"GATEWAY_EVENT_HMAC_KEY":       testBase64Key('g'),
		"AUTH_EVENT_HMAC_KEY":          testBase64Key('a'),
		"ADMIN_PASSWORD_ARGON2ID_HASH": testArgon2idPHC(),
		"SESSION_HMAC_KEY":             testBase64Key('s'),
		"ADMIN_ALLOWED_ORIGINS":        "https://admin.example.test",
		"ADMIN_COOKIE_TRANSPORT":       "tls",
		"ADMIN_SESSION_COOKIE_NAME":    "__Host-sentinelflow",
	})
	if _, err := LoadFrom(RoleAPI, mapLookup(base)); err != nil {
		t.Fatalf("valid production administrator boundary rejected: %v", err)
	}

	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{name: "plaintext origin", field: "ADMIN_ALLOWED_ORIGINS", value: "http://localhost:5173"},
		{name: "local test cookie", field: "ADMIN_COOKIE_TRANSPORT", value: "explicit-local-test"},
		{name: "unprefixed cookie", field: "ADMIN_SESSION_COOKIE_NAME", value: "sentinelflow_admin"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			env := make(map[string]string, len(base))
			for key, value := range base {
				env[key] = value
			}
			env[test.field] = test.value
			_, err := LoadFrom(RoleAPI, mapLookup(env))
			assertConfigErrorField(t, err, test.field)
		})
	}
}

func TestLoadFromRejectsAdministratorContractDrift(t *testing.T) {
	t.Parallel()
	base := withAPISourceIdentity(map[string]string{
		"DATABASE_API_URL":             testDatabaseURL("api-password"),
		"GATEWAY_EVENT_HMAC_KEY":       testBase64Key('g'),
		"AUTH_EVENT_HMAC_KEY":          testBase64Key('a'),
		"ADMIN_PASSWORD_ARGON2ID_HASH": testArgon2idPHC(),
		"SESSION_HMAC_KEY":             testBase64Key('s'),
	})
	for _, test := range []struct {
		field string
		value string
	}{
		{field: "SESSION_TTL", value: "7h"},
		{field: "SESSION_IDLE_TIMEOUT", value: "29m"},
		{field: "HIL_REAUTH_AFTER", value: "14m"},
		{field: "HIL_DECISION_RATE_LIMIT_PER_MINUTE", value: "4"},
		{field: "ADMIN_LOGIN_RATE_LIMIT_PER_SOURCE_PER_MINUTE", value: "4"},
		{field: "ADMIN_LOGIN_RATE_LIMIT_GLOBAL_PER_MINUTE", value: "19"},
	} {
		test := test
		t.Run(test.field, func(t *testing.T) {
			env := make(map[string]string, len(base)+1)
			for key, value := range base {
				env[key] = value
			}
			env[test.field] = test.value
			_, err := LoadFrom(RoleAPI, mapLookup(env))
			assertConfigErrorField(t, err, test.field)
		})
	}
}

func TestLoadFromAPIRequiresExactExpectedSourceIdentity(t *testing.T) {
	t.Parallel()
	base := withAPISourceIdentity(map[string]string{
		"DATABASE_API_URL":             testDatabaseURL("api-password"),
		"GATEWAY_EVENT_HMAC_KEY":       testBase64Key('g'),
		"AUTH_EVENT_HMAC_KEY":          testBase64Key('a'),
		"ADMIN_PASSWORD_ARGON2ID_HASH": testArgon2idPHC(),
		"SESSION_HMAC_KEY":             testBase64Key('s'),
	})
	for _, field := range []string{
		"GATEWAY_EVENT_HMAC_KEY_ID",
		"AUTH_EVENT_HMAC_KEY_ID",
		"GATEWAY_EXPECTED_SOURCE_BINDING_ID",
		"AUTH_EXPECTED_SOURCE_BINDING_ID",
		"GATEWAY_SOURCE_CONFIG_SHA256",
		"AUTH_SOURCE_CONFIG_SHA256",
	} {
		field := field
		t.Run("missing "+field, func(t *testing.T) {
			env := cloneEnvironment(base)
			delete(env, field)
			_, err := LoadFrom(RoleAPI, mapLookup(env))
			assertConfigErrorField(t, err, field)
		})
	}
	for field, value := range map[string]string{
		"GATEWAY_EVENT_HMAC_KEY_ID":          "Gateway Key",
		"AUTH_EVENT_HMAC_KEY_ID":             "auth/key",
		"GATEWAY_EXPECTED_SOURCE_BINDING_ID": "11111111-1111-4111-8111-11111111111A",
		"AUTH_EXPECTED_SOURCE_BINDING_ID":    "not-a-uuid",
		"GATEWAY_SOURCE_CONFIG_SHA256":       strings.Repeat("A", 64),
		"AUTH_SOURCE_CONFIG_SHA256":          strings.Repeat("2", 63),
	} {
		field, value := field, value
		t.Run("invalid "+field, func(t *testing.T) {
			env := cloneEnvironment(base)
			env[field] = value
			_, err := LoadFrom(RoleAPI, mapLookup(env))
			assertConfigErrorField(t, err, field)
		})
	}
}

func TestLoadFromRejectsAnalysisContractLimitDrift(t *testing.T) {
	t.Parallel()
	for key, value := range map[string]string{
		"OPENAI_MAX_EVIDENCE_REFS": "49",
		"OPENAI_MAX_INPUT_BYTES":   "12000",
		"OPENAI_MAX_OUTPUT_TOKENS": "1024",
	} {
		key, value := key, value
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(RoleGateway, mapLookup(map[string]string{
				"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g'),
				key:                      value,
			}))
			assertConfigErrorField(t, err, key)
		})
	}
}

func TestLoadFromRejectsFrozenEnforcementContractDrift(t *testing.T) {
	t.Parallel()
	for key, value := range map[string]string{
		"NFT_BASE_CHAIN_EXPECTED_SHA256":      strings.Repeat("1", 64),
		"NFT_BASE_CHAIN_LIVE_EXPECTED_SHA256": strings.Repeat("2", 64),
		"PROTECTED_IPV4_EXPECTED_SHA256":      strings.Repeat("3", 64),
	} {
		key, value := key, value
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(RoleGateway, mapLookup(map[string]string{
				"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g'),
				key:                      value,
			}))
			assertConfigErrorField(t, err, key)
		})
	}
}

func TestLoadFromOrdersProtectedNetworksByNumericAddress(t *testing.T) {
	t.Parallel()
	cfg, err := LoadFrom(RoleGateway, mapLookup(map[string]string{
		"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g'),
		"PROTECTED_CIDRS":        "8.8.8.0/24,10.0.0.0/8",
		"PROTECTED_GATEWAY_IPV4": "8.8.8.8,10.0.0.1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Enforcement.ProtectedCIDRs) != 2 || len(cfg.Enforcement.ProtectedGatewayIPv4) != 2 ||
		cfg.Enforcement.ProtectedCIDRs[0].String() != "8.8.8.0/24" ||
		cfg.Enforcement.ProtectedGatewayIPv4[0].String() != "8.8.8.8" {
		t.Fatalf("unexpected ordering: %+v %+v", cfg.Enforcement.ProtectedCIDRs,
			cfg.Enforcement.ProtectedGatewayIPv4)
	}
}

func TestLoadFromAllowsBoundedDemoExceptionOnlyInDemo(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"SENTINELFLOW_ENV":                    "demo",
		"DEMO_ALLOW_RFC5737":                  "true",
		"DEMO_ENFORCEMENT_ISOLATION_VERIFIED": "true",
		"DEMO_HOST_RULESET_UNCHANGED":         "true",
		"GATEWAY_EVENT_HMAC_KEY":              testBase64Key('g'),
	}
	cfg, err := LoadFrom(RoleGateway, mapLookup(env))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if !cfg.Demo.AllowRFC5737 || cfg.Enforcement.HostEnforcementEnabled {
		t.Fatalf("unexpected enforcement/demo state: %+v %+v", cfg.Demo, cfg.Enforcement)
	}
}

func TestLoadFromWorkerRejectsValidationAuthority(t *testing.T) {
	t.Parallel()
	valid := map[string]string{
		"DATABASE_WORKER_URL":                   testDatabaseURL("worker-password"),
		"OPENAI_API_KEY":                        "sk-test-worker-secret",
		"OPENAI_RATE_CARD_VERSION":              "operator-2026-07-18",
		"OPENAI_INPUT_USD_PER_1M_TOKENS":        "1.25",
		"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS": "0.25",
		"OPENAI_OUTPUT_USD_PER_1M_TOKENS":       "5.00",
	}
	if _, err := LoadFrom(RoleWorker, mapLookup(valid)); err != nil {
		t.Fatalf("analysis-only worker rejected: %v", err)
	}
	for _, field := range []string{
		"NFT_BINARY_EXPECTED_SHA256",
		"NFT_EXPECTED_VERSION",
		"NFT_VALIDATOR_SOCKET",
		"PROTECTED_CURRENT_ADMIN_IPV4",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"EXECUTOR_SOCKET",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			env := cloneEnvironment(valid)
			env[field] = "must-not-enter-analysis-worker"
			_, err := LoadFrom(RoleWorker, mapLookup(env))
			assertConfigErrorField(t, err, field)
		})
	}
}

func TestDemoAnalysisWorkerAcceptsOnlyPublicHistoryProofInputs(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"SENTINELFLOW_ENV":                             "demo",
		"DATABASE_WORKER_URL":                          testDatabaseURL("worker-password"),
		"OPENAI_API_KEY":                               "sk-test-worker-secret",
		"OPENAI_RATE_CARD_VERSION":                     "operator-2026-07-18",
		"OPENAI_INPUT_USD_PER_1M_TOKENS":               "1.25",
		"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS":        "0.25",
		"OPENAI_OUTPUT_USD_PER_1M_TOKENS":              "5.00",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE":            "/run/sentinelflow-demo-history/signed-manifest.json",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL":               base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32))),
		"DEMO_HISTORY_RUN_SCOPE":                       "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000901",
		"DEMO_HISTORY_IMPORT_ID":                       "019b0000-0000-7000-8000-000000000902",
		"DEMO_HISTORY_CLOCK_AT":                        "2026-07-18T02:00:00.000Z",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST":     "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE": DemoHistoryAnalysisActivationPath,
	}
	loaded, err := LoadFrom(RoleWorker, mapLookup(base))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Environment != EnvironmentDemo ||
		loaded.Demo.HistorySignedEnvelopeFile != base["DEMO_HISTORY_SIGNED_ENVELOPE_FILE"] ||
		loaded.Demo.HistoryPublicKeyB64URL != base["DEMO_HISTORY_PUBLIC_KEY_B64URL"] ||
		loaded.Demo.HistoryRunScope != base["DEMO_HISTORY_RUN_SCOPE"] ||
		loaded.Demo.HistoryImportID != base["DEMO_HISTORY_IMPORT_ID"] ||
		loaded.Demo.HistoryClockAt.Format("2006-01-02T15:04:05.000Z") != base["DEMO_HISTORY_CLOCK_AT"] {
		t.Fatalf("unexpected demo analysis proof: %+v", loaded.Demo)
	}

	for _, field := range []string{
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE",
		"DEMO_HISTORY_IMPORT_ID",
		"DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
	} {
		env := cloneEnvironment(base)
		delete(env, field)
		_, rejectErr := LoadFrom(RoleWorker, mapLookup(env))
		assertConfigErrorField(t, rejectErr, field)
	}
	for _, field := range []string{
		"DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_VERIFIER_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_IMPORT_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_PRIVATE_KEY",
		"DEMO_HISTORY_SIGNING_PRIVATE_KEY_FILE",
	} {
		env := cloneEnvironment(base)
		env[field] = "/run/secrets/private"
		_, rejectErr := LoadFrom(RoleWorker, mapLookup(env))
		assertConfigErrorField(t, rejectErr, field)
	}
}

func TestLoadFromValidationWorkerRejectsUnrelatedAuthority(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"DATABASE_WORKER_URL":          testWorkerDatabaseURL("validation-password"),
		"NFT_BINARY_EXPECTED_SHA256":   strings.Repeat("a", 64),
		"NFT_EXPECTED_VERSION":         "nftables v1.1.1",
		"PROTECTED_CURRENT_ADMIN_IPV4": "8.8.8.8",
	}
	for _, field := range []string{
		"OPENAI_API_KEY",
		"OPENAI_OUTPUT_SCHEMA_FILE",
		"ADMIN_PASSWORD_ARGON2ID_HASH",
		"GATEWAY_EVENT_HMAC_KEY",
		"AUTH_EVENT_HMAC_KEY",
		"DATABASE_API_URL",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"EXECUTOR_SOCKET",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_SIGNING_PRIVATE_KEY_FILE",
		"DEMO_HISTORY_FIXTURE_DATASET",
		"PGOPTIONS",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			env := cloneEnvironment(base)
			env[field] = "must-not-enter-validation-worker"
			_, err := LoadFrom(RoleValidationWorker, mapLookup(env))
			assertConfigErrorField(t, err, field)
			if strings.Contains(err.Error(), env[field]) {
				t.Fatalf("validation worker configuration leaked %s", field)
			}
		})
	}
}

func TestLoadFromValidationWorkerRequiresCanonicalWorkerDatabaseRole(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"DATABASE_WORKER_URL":          testDatabaseURL("wrong-role-password"),
		"NFT_BINARY_EXPECTED_SHA256":   strings.Repeat("a", 64),
		"NFT_EXPECTED_VERSION":         "nftables v1.1.1",
		"PROTECTED_CURRENT_ADMIN_IPV4": "8.8.8.8",
	}
	_, err := LoadFrom(RoleValidationWorker, mapLookup(base))
	assertConfigErrorField(t, err, "DATABASE_WORKER_URL")
}

func TestLoadFromExecutorRequiresBinaryAttestationInputs(t *testing.T) {
	t.Parallel()
	valid := map[string]string{
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE": "/run/secrets/dispatcher-public",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE":  "/run/secrets/executor-result-private",
		"NFT_BINARY_EXPECTED_SHA256":        strings.Repeat("a", 64),
		"NFT_EXPECTED_VERSION":              "nftables v1.1.1",
	}
	for _, field := range []string{"NFT_BINARY_EXPECTED_SHA256", "NFT_EXPECTED_VERSION"} {
		field := field
		t.Run(field, func(t *testing.T) {
			env := make(map[string]string, len(valid))
			for key, value := range valid {
				env[key] = value
			}
			delete(env, field)
			_, err := LoadFrom(RoleExecutor, mapLookup(env))
			assertConfigErrorField(t, err, field)
		})
	}
}

func TestLoadFromAllowsExplicitExecutorBootstrapOnlyWithIsolationProof(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"SENTINELFLOW_ENV":                    "demo",
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE":   "/run/secrets/dispatcher-public",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE":    "/run/secrets/executor-result-private",
		"NFT_BINARY_EXPECTED_SHA256":          strings.Repeat("a", 64),
		"NFT_EXPECTED_VERSION":                "nftables v1.1.1",
		"EXECUTOR_STARTUP_MODE":               "bootstrap",
		"DEMO_ALLOW_RFC5737":                  "true",
		"DEMO_ENFORCEMENT_ISOLATION_VERIFIED": "true",
		"DEMO_HOST_RULESET_UNCHANGED":         "true",
	}
	cfg, err := LoadFrom(RoleExecutor, mapLookup(env))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Enforcement.ExecutorStartupMode != ExecutorStartupBootstrap {
		t.Fatalf("startup mode = %q", cfg.Enforcement.ExecutorStartupMode)
	}

	delete(env, "DEMO_HOST_RULESET_UNCHANGED")
	if _, err := LoadFrom(RoleExecutor, mapLookup(env)); err == nil {
		t.Fatal("bootstrap without host-ruleset proof was accepted")
	}
}

func TestLoadFromRejectsDemoProofWithoutExplicitException(t *testing.T) {
	t.Parallel()
	for _, field := range []string{
		"DEMO_ENFORCEMENT_ISOLATION_VERIFIED",
		"DEMO_HOST_RULESET_UNCHANGED",
	} {
		_, err := LoadFrom(RoleGateway, mapLookup(map[string]string{
			"GATEWAY_EVENT_HMAC_KEY": testBase64Key('g'),
			field:                    "true",
		}))
		assertConfigErrorField(t, err, field)
	}
}

func TestErrorsNeverLeakSecretValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		role   Role
		env    map[string]string
		secret string
		field  string
	}{
		{
			name:   "invalid hmac",
			role:   RoleGateway,
			env:    map[string]string{"GATEWAY_EVENT_HMAC_KEY": "hmac-super-secret-not-base64"},
			secret: "hmac-super-secret-not-base64",
			field:  "GATEWAY_EVENT_HMAC_KEY",
		},
		{
			name:   "invalid database password URL",
			role:   RoleMigrator,
			env:    map[string]string{"DATABASE_MIGRATION_URL": "postgres://admin:database-super-secret@%zz/db"},
			secret: "database-super-secret",
			field:  "DATABASE_MIGRATION_URL",
		},
		{
			name: "invalid argon hash",
			role: RoleAPI,
			env: map[string]string{
				"DATABASE_API_URL":             testDatabaseURL("api-password"),
				"GATEWAY_EVENT_HMAC_KEY":       testBase64Key('g'),
				"AUTH_EVENT_HMAC_KEY":          testBase64Key('a'),
				"ADMIN_PASSWORD_ARGON2ID_HASH": "$argon2id$admin-super-secret",
				"SESSION_HMAC_KEY":             testBase64Key('s'),
			},
			secret: "admin-super-secret",
			field:  "ADMIN_PASSWORD_ARGON2ID_HASH",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(tt.role, mapLookup(tt.env))
			assertConfigErrorField(t, err, tt.field)
			if strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("error leaked secret %q: %q", tt.secret, err)
			}
		})
	}
}

func TestArgon2idConfigurationRejectsResourceExhaustionAndAmbiguity(t *testing.T) {
	t.Parallel()
	valid := testArgon2idPHC()
	for name, value := range map[string]string{
		"excessive memory":      strings.Replace(valid, "m=65536", "m=262145", 1),
		"excessive time":        strings.Replace(valid, "t=3", "t=11", 1),
		"excessive parallelism": strings.Replace(valid, "p=2", "p=17", 1),
		"wrong order":           strings.Replace(valid, "m=65536,t=3,p=2", "t=3,m=65536,p=2", 1),
		"leading zero":          strings.Replace(valid, "m=65536", "m=065536", 1),
		"padded hash":           valid + "=",
	} {
		t.Run(name, func(t *testing.T) {
			if validateArgon2idPHC(value) {
				t.Fatalf("unsafe PHC accepted: %s", name)
			}
		})
	}
	if !validateArgon2idPHC(valid) {
		t.Fatal("valid bounded PHC rejected")
	}
}

func TestSecretFormattingAndMarshalingAreRedacted(t *testing.T) {
	t.Parallel()
	const raw = "sk-test-do-not-print"
	secret := makeSecret(raw)

	for _, formatted := range []string{
		secret.String(),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%#v", secret),
	} {
		if strings.Contains(formatted, raw) || formatted != redacted {
			t.Fatalf("unsafe formatted secret: %q", formatted)
		}
	}

	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), raw) || string(encoded) != `"[REDACTED]"` {
		t.Fatalf("unsafe JSON secret: %s", encoded)
	}
	text, err := secret.MarshalText()
	if err != nil || string(text) != redacted {
		t.Fatalf("unsafe text secret: %q, %v", text, err)
	}
	if got := secret.Reveal(); got != raw {
		t.Fatalf("Reveal() = %q, want explicit raw value", got)
	}
}

func TestRedactValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, value, want string
	}{
		{"OPENAI_API_KEY", "secret", redacted},
		{"DATABASE_API_URL", "postgres://secret", redacted},
		{"ADMIN_PASSWORD_ARGON2ID_HASH", "secret", redacted},
		{"DISPATCHER_SIGNING_PRIVATE_KEY_FILE", "/run/key", redacted},
		{"GATEWAY_PUBLIC_HOST", "localhost:8080", "localhost:8080"},
		{"OPENAI_API_KEY", "", ""},
	}
	for _, tt := range tests {
		if got := RedactValue(tt.name, tt.value); got != tt.want {
			t.Errorf("RedactValue(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestInvalidRoleAndLookup(t *testing.T) {
	t.Parallel()
	_, err := LoadFrom(Role("root"), mapLookup(nil))
	assertConfigErrorField(t, err, "ROLE")
	_, err = LoadFrom(RoleGateway, nil)
	assertConfigErrorField(t, err, "ENVIRONMENT")
}

func assertConfigErrorField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("LoadFrom() error = nil, want field %s", field)
	}
	var configErr *Error
	if !errors.As(err, &configErr) {
		t.Fatalf("error type = %T, want *Error: %v", err, err)
	}
	if configErr.Field != field {
		t.Fatalf("error field = %q, want %q: %v", configErr.Field, field, err)
	}
}

func mapLookup(values map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func withAPISourceIdentity(values map[string]string) map[string]string {
	values["GATEWAY_EVENT_HMAC_KEY_ID"] = "gateway-key-v1"
	values["AUTH_EVENT_HMAC_KEY_ID"] = "auth-key-v1"
	values["GATEWAY_EXPECTED_SOURCE_BINDING_ID"] = "11111111-1111-4111-8111-111111111111"
	values["AUTH_EXPECTED_SOURCE_BINDING_ID"] = "22222222-2222-4222-8222-222222222222"
	values["GATEWAY_SOURCE_CONFIG_SHA256"] = strings.Repeat("1", 64)
	values["AUTH_SOURCE_CONFIG_SHA256"] = strings.Repeat("2", 64)
	return values
}

func cloneEnvironment(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func testBase64Key(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(fill), 32)))
}

func testArgon2idPHC() string {
	salt := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("s", 16)))
	hash := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("h", 32)))
	return "$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$" + hash
}

func testDatabaseURL(password string) string {
	return testDatabaseURLMode(password, "disable")
}

func testWorkerDatabaseURL(password string) string {
	return "postgresql://sentinelflow_worker:" + password + "@postgres:5432/sentinelflow?sslmode=disable"
}

func testDatabaseURLMode(password, sslmode string) string {
	return "postgresql://sentinelflow:" + password + "@postgres:5432/sentinelflow?sslmode=" + sslmode
}
