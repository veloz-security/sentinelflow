package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var composeServiceHeaderPattern = regexp.MustCompile(`(?m)^  [a-z0-9][a-z0-9-]*:\s*$`)

func TestComposeHistoryImporterHasOnlyPublicImportAuthority(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	service := serviceBlock(t, compose, "history-importer")
	for _, expected := range []string{
		`<<: [*backend, *read-only-service]`,
		`command: ["/usr/local/bin/historyimporter"]`,
		`restart: "no"`,
		`migrate:`,
		`condition: service_completed_successfully`,
		`SENTINELFLOW_ENV: demo`,
		`DATABASE_DEMO_IMPORTER_URL: ${DATABASE_DEMO_IMPORTER_URL}`,
		`DEMO_HISTORY_FIXTURE_DATASET: ${DEMO_HISTORY_FIXTURE_DATASET}`,
		`DEMO_HISTORY_SIGNED_ENVELOPE_FILE: ${DEMO_HISTORY_SIGNED_ENVELOPE_FILE}`,
		`DEMO_HISTORY_PUBLIC_KEY_B64URL: ${DEMO_HISTORY_PUBLIC_KEY_B64URL}`,
		`DEMO_HISTORY_RUN_SCOPE: ${DEMO_HISTORY_RUN_SCOPE}`,
		`DEMO_HISTORY_IMPORT_ID: ${DEMO_HISTORY_IMPORT_ID}`,
		`DEMO_HISTORY_CLOCK_AT: ${DEMO_HISTORY_CLOCK_AT}`,
		`DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST: ${DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST}`,
		`${DEMO_HISTORY_SOURCE:-../data/demo-history}:/run/sentinelflow-demo-history:ro`,
		`ipv4_address: 172.32.0.8`,
	} {
		if !strings.Contains(service, expected) {
			t.Errorf("history importer service missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"profiles:", "ports:", "ai-egress:", "management:", "ingest:",
		"OPENAI_", "ADMIN_", "SESSION_", "EVENT_HMAC", "ACCOUNT_HASH",
		"DATABASE_WORKER_URL", "DATABASE_DEMO_ACTIVATOR_URL", "DATABASE_API_URL", "DATABASE_READ_URL", "DATABASE_DISPATCHER_URL", "DATABASE_MIGRATION_URL",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE", "DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
		"DISPATCHER_", "EXECUTOR_", "NFT_", "PRIVATE_KEY", "PUBLIC_KEY_FILE", "/run/secrets",
	} {
		if strings.Contains(service, forbidden) {
			t.Errorf("history importer contains forbidden authority %q", forbidden)
		}
	}
	anchor := compose[:strings.Index(compose, "services:")]
	for _, expected := range []string{"read_only: true", "cap_drop:", "- ALL", "no-new-privileges:true"} {
		if !strings.Contains(anchor, expected) {
			t.Errorf("read-only service anchor missing %q", expected)
		}
	}
}

func TestComposeGatesControlPlaneButNotGatewayOnHistoryImport(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	for _, serviceName := range []string{"detector", "validator"} {
		service := serviceBlock(t, compose, serviceName)
		if !strings.Contains(service, "history-importer:") ||
			!strings.Contains(service, "condition: service_completed_successfully") {
			t.Errorf("%s is not gated on successful history import", serviceName)
		}
	}
	handoff := serviceBlock(t, compose, "demo-activation-handoff")
	if !strings.Contains(handoff, "history-importer:") ||
		!strings.Contains(handoff, "condition: service_completed_successfully") {
		t.Fatal("demo activation handoff is not gated on successful history import")
	}
	activator := serviceBlock(t, compose, "demo-activator")
	if !strings.Contains(activator, "demo-activation-handoff:") ||
		!strings.Contains(activator, "condition: service_completed_successfully") {
		t.Fatal("demo activator is not gated on successful authority handoff")
	}
	for _, serviceName := range []string{"validationworker", "stubworker", "worker"} {
		service := serviceBlock(t, compose, serviceName)
		if !strings.Contains(service, "demo-activator:") ||
			!strings.Contains(service, "condition: service_completed_successfully") {
			t.Errorf("%s is not gated on atomic demo activation", serviceName)
		}
	}
	for _, serviceName := range []string{"gateway", "api"} {
		if strings.Contains(serviceBlock(t, compose, serviceName), "history-importer") {
			t.Errorf("%s data plane/control API was incorrectly blocked on demo import", serviceName)
		}
	}
}

func TestComposeStagesDemoHistoryCapabilityAndDatabaseAuthority(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")

	secretInit := serviceBlock(t, compose, "secret-init")
	for _, expected := range []string{
		`${DEMO_SECRETS_SOURCE:-../secrets/demo}:/source:ro`,
		`demo-history-capability-receipts:/volumes/demo-history-capability-receipts`,
		`demo-history-analysis-activation:/volumes/demo-history-analysis-activation`,
		`demo-history-validation-activation:/volumes/demo-history-validation-activation`,
		`find /volumes/demo-history-capability-receipts -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +`,
		`printf 'sha256:%s\n' "$$analysis_digest" >/volumes/demo-history-capability-receipts/analysis.sha256`,
		`printf 'sha256:%s\n' "$$validation_digest" >/volumes/demo-history-capability-receipts/validation.sha256`,
		`test "$$(find /volumes/demo-history-capability-receipts -mindepth 1 -maxdepth 1 | wc -l)" -eq 2`,
	} {
		if !strings.Contains(secretInit, expected) {
			t.Errorf("secret-init missing staged capability handoff %q", expected)
		}
	}

	migrate := serviceBlock(t, compose, "migrate")
	for _, expected := range []string{
		`DATABASE_DEMO_IMPORTER_PASSWORD: ${DATABASE_DEMO_IMPORTER_PASSWORD}`,
		`demo-history-capability-receipts:/run/sentinelflow-demo-history-capability-receipts:ro`,
	} {
		if !strings.Contains(migrate, expected) {
			t.Errorf("migrate missing staged importer authority %q", expected)
		}
	}
	for _, forbidden := range []string{
		"DATABASE_DEMO_ACTIVATOR_PASSWORD",
		"demo-history-analysis-activation:",
		"demo-history-validation-activation:",
		"activation-capability",
	} {
		if strings.Contains(migrate, forbidden) {
			t.Errorf("migrate contains forbidden activator or raw capability authority %q", forbidden)
		}
	}

	handoff := serviceBlock(t, compose, "demo-activation-handoff")
	for _, expected := range []string{
		`history-importer:`,
		`condition: service_completed_successfully`,
		`DATABASE_DEMO_ACTIVATOR_PASSWORD: ${DATABASE_DEMO_ACTIVATOR_PASSWORD}`,
		`command: ["/opt/sentinelflow/demo-activation-handoff.sh"]`,
		`./postgres/demo-activation-handoff.sh:/opt/sentinelflow/demo-activation-handoff.sh:ro`,
		`demo-history-capability-receipts:/run/sentinelflow-demo-history-capability-receipts:ro`,
	} {
		if !strings.Contains(handoff, expected) {
			t.Errorf("demo activation handoff missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"DATABASE_DEMO_IMPORTER_PASSWORD",
		"DATABASE_DEMO_IMPORTER_URL",
		"DATABASE_DEMO_ACTIVATOR_URL",
		"demo-history-analysis-activation:",
		"demo-history-validation-activation:",
		"activation-capability",
	} {
		if strings.Contains(handoff, forbidden) {
			t.Errorf("demo activation handoff contains forbidden importer or raw capability authority %q", forbidden)
		}
	}

	activator := serviceBlock(t, compose, "demo-activator")
	if !strings.Contains(activator, "demo-activation-handoff:") ||
		!strings.Contains(activator, "condition: service_completed_successfully") {
		t.Fatal("demo activator does not consume the completed staged authority handoff")
	}
}

func TestComposeSelectsOneLeastPrivilegeAnalysisConsumer(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	stub := serviceBlock(t, compose, "stubworker")
	for _, expected := range []string{
		`<<: [*backend, *read-only-service]`, `profiles: ["stub-ai"]`,
		`command: ["/usr/local/bin/stubworker"]`, `DATABASE_WORKER_URL: ${DATABASE_WORKER_URL}`,
		`STUB_WORKER_LEASE_DURATION: 30s`, `STUB_WORKER_POLL_INTERVAL: 250ms`,
		`STUB_WORKER_MAX_CONCURRENCY: "2"`, `postgres:`, `condition: service_healthy`,
		`migrate:`, `demo-activator:`, `condition: service_completed_successfully`,
		`DEMO_HISTORY_SIGNED_ENVELOPE_FILE: ${DEMO_HISTORY_SIGNED_ENVELOPE_FILE}`,
		`DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: ${DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE}`,
		`demo-history-analysis-activation:/run/secrets/sentinelflow-demo-history-analysis:ro`,
		`pidof stubworker >/dev/null`, `control:`, `ipv4_address: 172.32.0.9`,
	} {
		if !strings.Contains(stub, expected) {
			t.Errorf("stubworker service missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"OPENAI_", "RATE_CARD", "BUDGET", "ADMIN_", "SESSION_", "HMAC", "NFT_",
		"DISPATCHER_", "EXECUTOR_", "VALIDATOR_", "DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
		"DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL", "ai-egress:", "management:", "ingest:", "ports:",
	} {
		if strings.Contains(stub, forbidden) {
			t.Errorf("stubworker contains forbidden authority %q", forbidden)
		}
	}
	live := serviceBlock(t, compose, "worker")
	if !strings.Contains(live, `profiles: ["live-ai"]`) || strings.Contains(live, `profiles: ["stub-ai"]`) {
		t.Fatal("OpenAI worker is not isolated behind the live-ai profile")
	}
	for _, expected := range []string{
		`demo-activator:`, `DEMO_HISTORY_SIGNED_ENVELOPE_FILE: ${DEMO_HISTORY_SIGNED_ENVELOPE_FILE}`,
		`DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: ${DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE}`,
		`demo-history-analysis-activation:/run/secrets/sentinelflow-demo-history-analysis:ro`,
	} {
		if !strings.Contains(live, expected) {
			t.Errorf("OpenAI worker missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"NFT_", "PROTECTED_", "DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE", "DEMO_ALLOW_RFC5737",
		"DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL", "validator:", "validator-socket", "management:", "ingest:", "ports:",
	} {
		if strings.Contains(live, forbidden) {
			t.Errorf("OpenAI worker contains non-analysis authority %q", forbidden)
		}
	}
	environment := readRepositoryFile(t, ".env.example")
	if !strings.Contains(environment, "COMPOSE_PROFILES=stub-ai") ||
		!strings.Contains(environment, "do not combine profiles") {
		t.Fatal("example environment does not require an explicit single analysis consumer")
	}
	dockerfile := readRepositoryFile(t, "deployments", "Dockerfile.backend")
	if !strings.Contains(dockerfile, "demoactivator demoapp detector") ||
		!strings.Contains(dockerfile, "validator worker stubworker validationworker") {
		t.Fatal("backend image does not build the isolated validation and analysis workers")
	}
}

func TestComposeRunsExactlyOneProviderIndependentValidationConsumer(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	service := serviceBlock(t, compose, "validationworker")
	for _, expected := range []string{
		`<<: [*backend, *read-only-service]`,
		`command: ["/usr/local/bin/validationworker"]`,
		`restart: unless-stopped`,
		`demo-activator:`, `condition: service_completed_successfully`,
		`validator:`, `condition: service_healthy`,
		`DATABASE_WORKER_URL: ${DATABASE_WORKER_URL}`,
		`NFT_BINARY_EXPECTED_SHA256: ${NFT_BINARY_EXPECTED_SHA256}`,
		`NFT_EXPECTED_VERSION: ${NFT_EXPECTED_VERSION}`,
		`NFT_VALIDATOR_SOCKET: /run/sentinelflow-validator/validator.sock`,
		`DEMO_HISTORY_SIGNED_ENVELOPE_FILE: ${DEMO_HISTORY_SIGNED_ENVELOPE_FILE}`,
		`DEMO_HISTORY_PUBLIC_KEY_B64URL: ${DEMO_HISTORY_PUBLIC_KEY_B64URL}`,
		`DEMO_HISTORY_RUN_SCOPE: ${DEMO_HISTORY_RUN_SCOPE}`,
		`DEMO_HISTORY_IMPORT_ID: ${DEMO_HISTORY_IMPORT_ID}`,
		`DEMO_HISTORY_CLOCK_AT: ${DEMO_HISTORY_CLOCK_AT}`,
		`DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST: ${DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST}`,
		`DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE: ${DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE}`,
		`validator-socket:/run/sentinelflow-validator:ro`,
		`${DEMO_HISTORY_SOURCE:-../data/demo-history}:/run/sentinelflow-demo-history:ro`,
		`demo-history-validation-activation:/run/secrets/sentinelflow-demo-history-validation:ro`,
		`control:`, `ipv4_address: 172.32.0.6`,
	} {
		if !strings.Contains(service, expected) {
			t.Errorf("validationworker service missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"profiles:", "OPENAI_", "ADMIN_PASSWORD", "ADMIN_USERNAME", "SESSION_", "EVENT_HMAC", "ACCOUNT_HASH",
		"DATABASE_API_URL", "DATABASE_READ_URL", "DATABASE_DISPATCHER_URL", "DATABASE_MIGRATION_URL",
		"DISPATCHER_", "EXECUTOR_", "PRIVATE_KEY", "DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DATABASE_DEMO_IMPORTER_URL", "DATABASE_DEMO_ACTIVATOR_URL", "ai-egress:",
		"management:", "ingest:", "ports:",
	} {
		if strings.Contains(service, forbidden) {
			t.Errorf("validationworker contains forbidden authority %q", forbidden)
		}
	}
	if strings.Count(compose, `command: ["/usr/local/bin/validationworker"]`) != 1 {
		t.Fatal("Compose must have exactly one policy validation consumer")
	}
	for _, analysisService := range []string{"stubworker", "worker"} {
		block := serviceBlock(t, compose, analysisService)
		if strings.Contains(block, "validationworker") || strings.Contains(block, "NFT_VALIDATOR_SOCKET") {
			t.Errorf("%s embeds policy validation authority", analysisService)
		}
	}
}

func TestHistoryImporterImageAndPreparationExcludePrivateKeyMaterial(t *testing.T) {
	t.Parallel()
	dockerfile := readRepositoryFile(t, "deployments", "Dockerfile.backend")
	for _, expected := range []string{"-o /out/historyimporter", "./cmd/historyimporter", "COPY --chown=0:0 contracts ./contracts"} {
		if !strings.Contains(dockerfile, expected) {
			t.Errorf("backend image missing %q", expected)
		}
	}
	for _, forbidden := range []string{"COPY data", "COPY secrets", "COPY .env", "demo-history-private"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Errorf("backend image includes private/runtime material %q", forbidden)
		}
	}
	dockerignore := readRepositoryFile(t, ".dockerignore")
	for _, ignored := range []string{".env.*", "data", "secrets", "*.pem", "*.key"} {
		if !strings.Contains(dockerignore, ignored) {
			t.Errorf(".dockerignore missing %q", ignored)
		}
	}
	prepare := readRepositoryFile(t, "scripts", "prepare-demo.sh")
	for _, expected := range []string{
		`history_directory="$repo_root/data/demo-history"`,
		`-e "$history_directory"`, `-L "$history_directory"`,
		`--history-dir "$history_directory"`,
	} {
		if !strings.Contains(prepare, expected) {
			t.Errorf("prepare-demo missing fail-closed history behavior %q", expected)
		}
	}
}

func TestExampleEnvironmentUsesOnlyPublicHistoryHandoff(t *testing.T) {
	t.Parallel()
	environment := readRepositoryFile(t, ".env.example")
	for _, expected := range []string{
		"DEMO_HISTORY_FIXTURE_DATASET=/app/contracts/fixtures/demo_history_dataset_v1.json",
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE=/run/sentinelflow-demo-history/signed-manifest.json",
		"DEMO_HISTORY_PUBLIC_KEY_B64URL=", "DEMO_HISTORY_RUN_SCOPE=", "DEMO_HISTORY_IMPORT_ID=",
		"DEMO_HISTORY_CLOCK_AT=", "DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST=",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE=/run/secrets/sentinelflow-demo-history-analysis/activation-capability",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE=/run/secrets/sentinelflow-demo-history-validation/activation-capability",
		"DATABASE_DEMO_IMPORTER_URL=", "DATABASE_DEMO_ACTIVATOR_URL=",
		"canonical `postgresql` URLs", "`sslmode=disable`",
	} {
		if !strings.Contains(environment, expected) {
			t.Errorf("example environment missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"DEMO_HISTORY_FIXTURE_MANIFEST", "DEMO_HISTORY_PUBLIC_KEY_FILE",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE", "DEMO_HISTORY_PRIVATE_KEY",
	} {
		if strings.Contains(environment, forbidden) {
			t.Errorf("example environment contains obsolete/private history field %q", forbidden)
		}
	}
}

func readRepositoryFile(t testing.TB, elements ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, elements...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func serviceBlock(t testing.TB, compose, service string) string {
	t.Helper()
	headerPattern := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(service) + `:\s*$`)
	headerMatch := headerPattern.FindStringIndex(compose)
	if headerMatch == nil {
		t.Fatalf("compose service %q not found", service)
	}
	start := headerMatch[0]
	after := compose[headerMatch[1]:]
	match := composeServiceHeaderPattern.FindStringIndex(after)
	end := len(compose)
	if match != nil {
		end = headerMatch[1] + match[0]
	}
	if marker := strings.Index(after, "\nvolumes:\n"); marker >= 0 && headerMatch[1]+marker < end {
		end = headerMatch[1] + marker
	}
	return compose[start:end]
}
