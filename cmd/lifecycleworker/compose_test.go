package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var lifecycleServiceHeaderPattern = regexp.MustCompile(`(?m)^  [a-z0-9][a-z0-9-]*:\s*$`)

func TestComposeLifecycleWorkerHasOnlyLifecycleFunctionAuthority(t *testing.T) {
	t.Parallel()
	compose := lifecycleReadRepositoryFile(t, "deployments", "compose.yaml")
	service := lifecycleComposeServiceBlock(t, compose, "lifecycleworker")
	for _, expected := range []string{
		`<<: [*backend, *read-only-service]`,
		`command: ["/usr/local/bin/lifecycleworker"]`,
		`restart: unless-stopped`,
		`migrate:`,
		`condition: service_completed_successfully`,
		`SENTINELFLOW_ENV: development`,
		`DATABASE_LIFECYCLE_URL: ${DATABASE_LIFECYCLE_URL}`,
		`LIFECYCLE_SCHEDULER_ID: ${LIFECYCLE_SCHEDULER_ID:-lifecycle-scheduler-v1}`,
		`LIFECYCLE_LEASE_OWNER: ${LIFECYCLE_LEASE_OWNER:-lifecycleworker-01}`,
		`LIFECYCLE_LEASE_DURATION: ${LIFECYCLE_LEASE_DURATION:-10s}`,
		`LIFECYCLE_RETRY_BACKOFF: ${LIFECYCLE_RETRY_BACKOFF:-1s}`,
		`LIFECYCLE_POLL_INTERVAL: ${LIFECYCLE_POLL_INTERVAL:-250ms}`,
		`LIFECYCLE_CLEANUP_TIMEOUT: ${LIFECYCLE_CLEANUP_TIMEOUT:-1s}`,
		`pidof lifecycleworker >/dev/null`,
		`control:`,
		`ipv4_address: 172.32.0.13`,
	} {
		if !strings.Contains(service, expected) {
			t.Errorf("lifecycle worker service missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"profiles:", "ports:", "volumes:", "ai-egress:", "management:", "ingest:",
		"OPENAI_", "ADMIN_", "SESSION_", "HMAC", "ACCOUNT_HASH", "PRIVATE_KEY",
		"DATABASE_API_URL", "DATABASE_WORKER_URL", "DATABASE_READ_URL",
		"DATABASE_DISPATCHER_URL", "DATABASE_RETENTION_URL", "DATABASE_METRICS_URL",
		"DATABASE_MIGRATION_URL", "POSTGRES_PASSWORD", "DISPATCHER_", "EXECUTOR_",
		"NFT_", "VALIDATOR_", "PROTECTED_", "HIL_", "DEMO_HISTORY_", "/run/secrets",
		"cap_add:", "privileged:", "executor-socket", "validator-socket", "secret-init:",
	} {
		if strings.Contains(service, forbidden) {
			t.Errorf("lifecycle worker service contains forbidden authority %q", forbidden)
		}
	}
	environmentBlock := lifecycleDelimitedBlock(
		t, service, "    environment:\n", "    healthcheck:\n",
	)
	allowedEnvironment := map[string]bool{
		"SENTINELFLOW_ENV": true, "DATABASE_LIFECYCLE_URL": true,
		"LIFECYCLE_SCHEDULER_ID": true, "LIFECYCLE_LEASE_OWNER": true,
		"LIFECYCLE_LEASE_DURATION": true, "LIFECYCLE_RETRY_BACKOFF": true,
		"LIFECYCLE_POLL_INTERVAL": true, "LIFECYCLE_CLEANUP_TIMEOUT": true,
	}
	seenEnvironment := make(map[string]bool, len(allowedEnvironment))
	for _, line := range strings.Split(environmentBlock, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok || !allowedEnvironment[name] || seenEnvironment[name] {
			t.Fatalf("lifecycle worker has unapproved or duplicate environment key %q", name)
		}
		seenEnvironment[name] = true
	}
	if len(seenEnvironment) != len(allowedEnvironment) {
		t.Fatalf("lifecycle worker environment key count=%d want=%d", len(seenEnvironment), len(allowedEnvironment))
	}
	networkMarker := "    networks:\n"
	networkStart := strings.Index(service, networkMarker)
	if networkStart < 0 || strings.TrimSpace(service[networkStart+len(networkMarker):]) !=
		"control:\n        ipv4_address: 172.32.0.13" {
		t.Fatal("lifecycle worker network scope is not exactly the internal control network")
	}

	anchor := compose[:strings.Index(compose, "services:")]
	for _, expected := range []string{"read_only: true", "cap_drop:", "- ALL", "no-new-privileges:true"} {
		if !strings.Contains(anchor, expected) {
			t.Errorf("read-only service anchor missing %q", expected)
		}
	}
	if strings.Count(compose, "ipv4_address: 172.32.0.13") != 1 {
		t.Fatal("lifecycle worker control address is not unique")
	}
	dockerfile := lifecycleReadRepositoryFile(t, "deployments", "Dockerfile.backend")
	if !strings.Contains(dockerfile, "validationworker lifecycleworker") {
		t.Fatal("backend image does not build the lifecycle worker binary")
	}
	environment := lifecycleReadRepositoryFile(t, ".env.example")
	for _, expected := range []string{
		"DATABASE_LIFECYCLE_URL=", "LIFECYCLE_SCHEDULER_ID=lifecycle-scheduler-v1",
		"LIFECYCLE_LEASE_OWNER=lifecycleworker-01", "LIFECYCLE_LEASE_DURATION=10s",
		"LIFECYCLE_RETRY_BACKOFF=1s", "LIFECYCLE_POLL_INTERVAL=250ms",
		"LIFECYCLE_CLEANUP_TIMEOUT=1s",
	} {
		if !strings.Contains(environment, expected) {
			t.Errorf("example environment missing %q", expected)
		}
	}
	initScript := lifecycleReadRepositoryFile(t, "deployments", "postgres", "init.sh")
	for _, expected := range []string{
		"DATABASE_LIFECYCLE_PASSWORD is required", "\\getenv lifecycle_password DATABASE_LIFECYCLE_PASSWORD",
		"'sentinelflow_lifecycle', :'lifecycle_password'", "ALTER ROLE sentinelflow_lifecycle LOGIN NOINHERIT",
		"NOBYPASSRLS CONNECTION LIMIT 4",
	} {
		if !strings.Contains(initScript, expected) {
			t.Errorf("database initialization missing %q", expected)
		}
	}
	if strings.Contains(initScript, "\nGRANT ") || strings.Contains(initScript, "\nREVOKE ") {
		t.Fatal("database initialization script owns privileges instead of migrations")
	}
	migrate := lifecycleComposeServiceBlock(t, compose, "migrate")
	if !strings.Contains(migrate, "DATABASE_LIFECYCLE_PASSWORD: ${DATABASE_LIFECYCLE_PASSWORD}") {
		t.Fatal("migration service does not receive the lifecycle role password")
	}
}

func lifecycleReadRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, elements...)...)
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(value)
}

func lifecycleComposeServiceBlock(t *testing.T, compose, service string) string {
	t.Helper()
	header := "  " + service + ":"
	start := strings.Index(compose, header)
	if start < 0 {
		t.Fatalf("compose service %q not found", service)
	}
	after := compose[start+len(header):]
	match := lifecycleServiceHeaderPattern.FindStringIndex(after)
	end := len(compose)
	if match != nil {
		end = start + len(header) + match[0]
	}
	if marker := strings.Index(after, "\nvolumes:\n"); marker >= 0 && start+len(header)+marker < end {
		end = start + len(header) + marker
	}
	return compose[start:end]
}

func lifecycleDelimitedBlock(t *testing.T, value, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(value, startMarker)
	if start < 0 {
		t.Fatalf("block marker %q not found", startMarker)
	}
	remainder := value[start+len(startMarker):]
	end := strings.Index(remainder, endMarker)
	if end < 0 {
		t.Fatalf("block marker %q not found", endMarker)
	}
	return remainder[:end]
}
