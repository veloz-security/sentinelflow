package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var serviceHeaderPattern = regexp.MustCompile(`(?m)^  [a-z0-9][a-z0-9-]*:\s*$`)

func TestComposeRunsIsolatedDetectorInCoreProfile(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	detector := composeServiceBlock(t, compose, "detector")
	for _, expected := range []string{
		`<<: [*backend, *read-only-service]`,
		`command: ["/usr/local/bin/detector"]`,
		`DATABASE_WORKER_URL: ${DATABASE_WORKER_URL}`,
		`PATH_CATALOG_VERSION: path-catalog-v1`,
		`AUTH_ROUTE_LABEL: login`,
		`DETECT_PATH_SCAN_UNIQUE_PATHS: "8"`,
		`DETECT_REQUEST_BURST_COUNT: "120"`,
		`DETECT_BRUTE_FORCE_FAILURES: "10"`,
		`DETECT_CREDENTIAL_STUFFING_FAILURES: "20"`,
		`DETECT_CREDENTIAL_STUFFING_UNIQUE_ACCOUNTS: "8"`,
		`control:`,
		`ipv4_address: 172.32.0.7`,
	} {
		if !strings.Contains(detector, expected) {
			t.Errorf("detector service missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"profiles:", "ports:", "volumes:", "ai-egress:", "management:",
		"OPENAI_", "ADMIN_", "SESSION_HMAC_KEY", "EVENT_HMAC_KEY", "ACCOUNT_HASH_KEY",
		"DATABASE_API_URL", "DATABASE_READ_URL", "DATABASE_DISPATCHER_URL", "DATABASE_MIGRATION_URL",
		"NFT_", "VALIDATOR_SOCKET", "EXECUTOR_", "DISPATCHER_", "HISTORY_",
	} {
		if strings.Contains(detector, forbidden) {
			t.Errorf("detector service contains forbidden authority %q", forbidden)
		}
	}

	dockerfile := readRepositoryFile(t, "deployments", "Dockerfile.backend")
	commandLoop := regexp.MustCompile(`(?m)^[ \t]*for command in ([a-z0-9]+(?: [a-z0-9]+)*); do[ \t]*\\[ \t]*$`).FindStringSubmatch(dockerfile)
	if len(commandLoop) != 2 {
		t.Fatal("backend image command build loop is missing or malformed")
	}
	built := make(map[string]bool)
	for _, command := range strings.Fields(commandLoop[1]) {
		built[command] = true
	}
	if !built["detector"] {
		t.Fatal("backend image does not build the detector binary")
	}
}

func TestComposeGatewayWaitsForBootstrapButDoesNotDependOnExecutorAfterStart(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	gateway := composeServiceBlock(t, compose, "gateway")
	for _, expected := range []string{
		"fresh_executor() {",
		"until fresh_executor; do",
		"test \"$$attempts\" -lt 300 || exit 1",
		"exec /usr/local/bin/gateway",
		"GATEWAY_LISTEN_ADDR: 203.0.113.10:8080",
		"GATEWAY_METRICS_LISTEN_ADDR: 172.29.0.2:9090",
		"http://203.0.113.10:8080/health/ready",
		"http://172.29.0.2:9090/metrics",
		"127.0.0.1:${GATEWAY_PUBLISHED_PORT:-8080}:8080",
		"edge:",
		"ipv4_address: 203.0.113.10",
		"observability:",
		"ipv4_address: 172.29.0.2",
	} {
		if !strings.Contains(gateway, expected) {
			t.Errorf("Gateway bootstrap gate missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"/usr/local/bin/gateway &",
		"while kill -0 \"$$child\"",
		"if ! fresh_executor",
		"9090:9090",
		"http://127.0.0.1:8080/health/ready",
	} {
		if strings.Contains(gateway, forbidden) {
			t.Errorf("Gateway forwarding still depends on executor after startup: %q", forbidden)
		}
	}
}

func TestComposeObservabilityCannotReachGatewayDataListener(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	gateway := composeServiceBlock(t, compose, "gateway")
	prometheus := composeServiceBlock(t, compose, "prometheus")
	exporter := composeServiceBlock(t, compose, "controlmetricsexporter")
	observability := composeTopLevelBlock(t, compose, "observability")
	prometheusConfig := readRepositoryFile(t, "deployments", "observability", "prometheus.yml")

	for _, expected := range []string{
		"GATEWAY_LISTEN_ADDR: 203.0.113.10:8080",
		"GATEWAY_METRICS_LISTEN_ADDR: 172.29.0.2:9090",
		"edge:", "ipv4_address: 203.0.113.10",
		"observability:", "ipv4_address: 172.29.0.2",
	} {
		if !strings.Contains(gateway, expected) {
			t.Errorf("Gateway interface isolation missing %q", expected)
		}
	}
	for _, expected := range []string{
		`user: "65532:65532"`, `cpus: "0.50"`, "mem_limit: 256m",
		"observability:", "ipv4_address: 172.29.0.4",
	} {
		if !strings.Contains(prometheus, expected) {
			t.Errorf("Prometheus hardening missing %q", expected)
		}
	}
	for _, forbidden := range []string{"ports:", "edge:", "origin:", "ingest:", "control:", "management:"} {
		if strings.Contains(prometheus, forbidden) {
			t.Errorf("Prometheus gained forbidden network/publication %q", forbidden)
		}
	}
	if !strings.Contains(exporter, "control:") || !strings.Contains(exporter, "observability:") ||
		strings.Contains(exporter, "edge:") || strings.Contains(exporter, "ports:") {
		t.Fatalf("control metrics exporter network boundary drifted:\n%s", exporter)
	}
	if !strings.Contains(observability, "internal: true") ||
		!strings.Contains(observability, "subnet: 172.29.0.0/24") {
		t.Fatalf("observability network is not isolated:\n%s", observability)
	}
	if !strings.Contains(prometheusConfig, "172.29.0.2:9090") ||
		strings.Contains(prometheusConfig, "172.29.0.2:8080") ||
		strings.Contains(prometheusConfig, "203.0.113.10:8080") {
		t.Fatalf("Prometheus targets escaped metrics-only interfaces:\n%s", prometheusConfig)
	}
}

func TestComposeSimulatorUsesOneSupportedScenario(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	simulator := composeServiceBlock(t, compose, "simulator")
	for _, expected := range []string{
		"- -gateway-host",
		"- localhost:8080",
		"- ${SIMULATOR_SCENARIO:-normal}",
	} {
		if !strings.Contains(simulator, expected) {
			t.Errorf("simulator service missing %q", expected)
		}
	}
	if strings.Contains(simulator, "- mixed") {
		t.Fatal("simulator service still invokes unsupported mixed scenario")
	}
	environment := readRepositoryFile(t, ".env.example")
	if !strings.Contains(environment, "SIMULATOR_SCENARIO=normal") {
		t.Fatal("non-secret simulator scenario setting is missing")
	}
}

func TestComposeSeparatesManagementFromDatabaseControlNetwork(t *testing.T) {
	t.Parallel()
	compose := readRepositoryFile(t, "deployments", "compose.yaml")
	api := composeServiceBlock(t, compose, "api")
	web := composeServiceBlock(t, compose, "web")
	postgres := composeServiceBlock(t, compose, "postgres")
	validationWorker := composeServiceBlock(t, compose, "validationworker")

	for _, expected := range []string{
		`API_MANAGEMENT_LISTEN_ADDR: 172.34.0.10:8083`,
		`http://172.34.0.10:8083/health/ready`,
		"ingest:", "control:", "management:", "ipv4_address: 172.34.0.10",
	} {
		if !strings.Contains(api, expected) {
			t.Errorf("API service missing management boundary %q", expected)
		}
	}
	if !strings.Contains(web, "management:") || !strings.Contains(web, "ipv4_address: 172.34.0.6") ||
		strings.Contains(web, "control:") {
		t.Fatalf("web must use only the management network:\n%s", web)
	}
	if !strings.Contains(postgres, "control:") || strings.Contains(postgres, "management:") {
		t.Fatalf("PostgreSQL escaped the internal control network:\n%s", postgres)
	}
	for _, expected := range []string{
		"hba_file=/etc/postgresql/sentinelflow-pg_hba.conf",
		"listen_addresses=172.32.0.2",
		"pg_isready -q -h 172.32.0.2",
		"source: ./postgres/pg_hba.conf",
		"target: /etc/postgresql/sentinelflow-pg_hba.conf",
		"read_only: true",
		"create_host_path: false",
	} {
		if !strings.Contains(postgres, expected) {
			t.Errorf("PostgreSQL service missing HBA boundary %q", expected)
		}
	}
	for _, expected := range []string{
		"PROTECTED_MANAGEMENT_IPV4: 172.34.0.10",
		"PROTECTED_CURRENT_ADMIN_IPV4: 172.34.0.6",
	} {
		if !strings.Contains(validationWorker, expected) {
			t.Errorf("validation worker missing management protection %q", expected)
		}
	}

	management := composeTopLevelBlock(t, compose, "management")
	if strings.Contains(management, "internal: true") || !strings.Contains(management, "subnet: 172.34.0.0/24") {
		t.Fatalf("management network must be publishable and dedicated:\n%s", management)
	}

	hba := readRepositoryFile(t, "deployments", "postgres", "pg_hba.conf")
	for _, expected := range []string{
		"local   all   all                         scram-sha-256",
		"host    all   all   172.32.0.1/32         reject",
		"host    all   all   172.32.0.0/24         scram-sha-256",
		"host    all   all   0.0.0.0/0             reject",
		"host    all   all   ::0/0                 reject",
	} {
		if !strings.Contains(hba, expected) {
			t.Errorf("PostgreSQL HBA missing %q", expected)
		}
	}
}

func readRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, elements...)...)
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(value)
}

func composeServiceBlock(t *testing.T, compose, service string) string {
	t.Helper()
	header := "  " + service + ":"
	start := strings.Index(compose, header)
	if start < 0 {
		t.Fatalf("compose service %q not found", service)
	}
	after := compose[start+len(header):]
	match := serviceHeaderPattern.FindStringIndex(after)
	end := len(compose)
	if match != nil {
		end = start + len(header) + match[0]
	}
	if marker := strings.Index(after, "\nvolumes:\n"); marker >= 0 && start+len(header)+marker < end {
		end = start + len(header) + marker
	}
	return compose[start:end]
}

func composeTopLevelBlock(t *testing.T, compose, name string) string {
	t.Helper()
	networks := strings.Index(compose, "\nnetworks:\n")
	if networks < 0 {
		t.Fatal("top-level networks map not found")
	}
	return composeServiceBlock(t, compose[networks+len("\nnetworks:\n"):], name)
}
