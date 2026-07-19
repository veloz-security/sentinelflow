package postgres_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDemoActivationHandoffShellSyntax(t *testing.T) {
	t.Parallel()
	handoff := repositoryPostgresFile(t, "demo-activation-handoff.sh")
	info, err := os.Stat(handoff)
	if err != nil {
		t.Fatalf("stat demo activation handoff: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("demo activation handoff is not executable")
	}
	if output, err := exec.Command("sh", "-n", handoff).CombinedOutput(); err != nil {
		t.Fatalf("demo activation handoff shell syntax: %v\n%s", err, output)
	}
}

func TestMigrationRunnerStagesOnlyImporterCredentialAndDigestReceipts(t *testing.T) {
	t.Parallel()
	runner := mustReadPostgresFile(t, "init.sh")
	for _, expected := range []string{
		`DATABASE_DEMO_IMPORTER_PASSWORD is required in demo mode`,
		`/run/sentinelflow-demo-history-capability-receipts`,
		`analysis.sha256`,
		`validation.sha256`,
		`pin_demo_history_runtime_capability_expectation_000030`,
		`'sentinelflow_demo_importer', :'demo_importer_password'`,
		`SELECT COALESCE(`,
		`expectation.importer_lease_expires_at > clock_timestamp()`,
		`clock_timestamp() + interval '5 minutes'`,
		`role.rolname = 'sentinelflow_demo_activator'`,
		`AND NOT role.rolcanlogin`,
		`AND role.rolpassword IS NULL`,
		`VALID UNTIL '1970-01-01 00:00:00+00'`,
		`make_demo_roles_inert_after_failure()`,
		`pg_catalog.pg_terminate_backend(target_pid, 5000)`,
	} {
		if !strings.Contains(runner, expected) {
			t.Errorf("migration runner missing staged importer contract %q", expected)
		}
	}
	for _, forbidden := range []string{
		"DATABASE_DEMO_ACTIVATOR_PASSWORD",
		"demo-history-analysis-activation.capability",
		"demo-history-validation-activation.capability",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
	} {
		if strings.Contains(runner, forbidden) {
			t.Errorf("migration runner contains activator credential or raw capability %q", forbidden)
		}
	}
}

func TestSuperuserHandoffRequiresCompletedImporterFenceAndEnablesOnlyActivator(t *testing.T) {
	t.Parallel()
	handoff := mustReadPostgresFile(t, "demo-activation-handoff.sh")
	for _, expected := range []string{
		`DATABASE_DEMO_ACTIVATOR_PASSWORD is required`,
		`role.rolname = SESSION_USER`,
		`AND role.rolsuper`,
		`demo_history_runtime_capability_expectation`,
		`pin.importer_lease_expires_at > clock_timestamp()`,
		`role.rolname = 'sentinelflow_demo_importer'`,
		`AND NOT role.rolcanlogin`,
		`AND role.rolpassword IS NULL`,
		`role.rolname = 'sentinelflow_demo_activator'`,
		`'ALTER ROLE %I LOGIN PASSWORD %L VALID UNTIL %L'`,
		`VALUES (clock_timestamp() + interval '5 minutes')`,
		`cardinality(setting.setconfig) = 5`,
		`make_bootstrap_roles_inert()`,
		`pg_catalog.pg_terminate_backend(activity.pid, 5000)`,
	} {
		if !strings.Contains(handoff, expected) {
			t.Errorf("demo activation handoff missing exact authority contract %q", expected)
		}
	}
	for _, forbidden := range []string{
		"DATABASE_DEMO_IMPORTER_PASSWORD",
		"DATABASE_DEMO_IMPORTER_URL",
		"DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE",
		"DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE",
		"activation-capability",
	} {
		if strings.Contains(handoff, forbidden) {
			t.Errorf("demo activation handoff contains importer credential or raw capability %q", forbidden)
		}
	}
}

func repositoryPostgresFile(t testing.TB, name string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate demo activation handoff tests")
	}
	return filepath.Join(filepath.Dir(source), name)
}

func mustReadPostgresFile(t testing.TB, name string) string {
	t.Helper()
	path := repositoryPostgresFile(t, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
