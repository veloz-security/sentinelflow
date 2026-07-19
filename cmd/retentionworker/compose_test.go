package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var retentionServiceHeaderPattern = regexp.MustCompile(`(?m)^  [a-z0-9][a-z0-9-]*:\s*$`)

func TestComposeRetentionWorkerHasOnlyRetentionFunctionAuthority(t *testing.T) {
	t.Parallel()
	compose := retentionReadRepositoryFile(t, "deployments", "compose.yaml")
	service := retentionComposeServiceBlock(t, compose, "retentionworker")
	for _, expected := range []string{
		`<<: [*backend, *read-only-service]`,
		`command: ["/usr/local/bin/retentionworker"]`,
		`restart: unless-stopped`,
		`history-importer:`,
		`condition: service_completed_successfully`,
		`SENTINELFLOW_ENV: development`,
		`DATABASE_RETENTION_URL: ${DATABASE_RETENTION_URL}`,
		`RETENTION_INTERVAL: ${RETENTION_INTERVAL:-1h}`,
		`RETENTION_RUN_TIMEOUT: ${RETENTION_RUN_TIMEOUT:-5m}`,
		`RETENTION_MAX_ROWS: ${RETENTION_MAX_ROWS:-1000}`,
		`pidof retentionworker >/dev/null`,
		`control:`,
		`ipv4_address: 172.32.0.11`,
	} {
		if !strings.Contains(service, expected) {
			t.Errorf("retention worker service missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"profiles:", "ports:", "volumes:", "ai-egress:", "management:", "ingest:",
		"OPENAI_", "ADMIN_", "SESSION_", "HMAC", "ACCOUNT_HASH", "PRIVATE_KEY",
		"DATABASE_API_URL", "DATABASE_WORKER_URL", "DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL", "DATABASE_MIGRATION_URL", "POSTGRES_PASSWORD",
		"DISPATCHER_", "EXECUTOR_", "NFT_", "VALIDATOR_", "PROTECTED_", "HIL_",
		"DEMO_HISTORY_", "/run/secrets", "cap_add:", "privileged:",
	} {
		if strings.Contains(service, forbidden) {
			t.Errorf("retention worker service contains forbidden authority %q", forbidden)
		}
	}

	anchor := compose[:strings.Index(compose, "services:")]
	for _, expected := range []string{"read_only: true", "cap_drop:", "- ALL", "no-new-privileges:true"} {
		if !strings.Contains(anchor, expected) {
			t.Errorf("read-only service anchor missing %q", expected)
		}
	}
	dockerfile := retentionReadRepositoryFile(t, "deployments", "Dockerfile.backend")
	if !strings.Contains(dockerfile, "gateway retentionworker simulator") {
		t.Fatal("backend image does not build the retention worker binary")
	}
	environment := retentionReadRepositoryFile(t, ".env.example")
	for _, expected := range []string{
		"DATABASE_RETENTION_URL=", "RETENTION_INTERVAL=1h",
		"RETENTION_RUN_TIMEOUT=5m", "RETENTION_MAX_ROWS=1000",
	} {
		if !strings.Contains(environment, expected) {
			t.Errorf("example environment missing %q", expected)
		}
	}
}

func retentionReadRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, elements...)...)
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(value)
}

func retentionComposeServiceBlock(t *testing.T, compose, service string) string {
	t.Helper()
	header := "  " + service + ":"
	start := strings.Index(compose, header)
	if start < 0 {
		t.Fatalf("compose service %q not found", service)
	}
	after := compose[start+len(header):]
	match := retentionServiceHeaderPattern.FindStringIndex(after)
	end := len(compose)
	if match != nil {
		end = start + len(header) + match[0]
	}
	if marker := strings.Index(after, "\nvolumes:\n"); marker >= 0 && start+len(header)+marker < end {
		end = start + len(header) + marker
	}
	return compose[start:end]
}
