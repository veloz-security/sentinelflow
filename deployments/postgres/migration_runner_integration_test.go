//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	postgres17Image  = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
	postgresPassword = "sentinelflow-migration-runner-postgres-only"
)

var resourceSequence atomic.Uint64

type postgresFixture struct {
	t           *testing.T
	container   string
	initScript  string
	repository  string
	cleanupOnce sync.Once
}

func TestMigrationRunnerSyntheticPostgreSQL17(t *testing.T) {
	fixture := startPostgres17(t)

	t.Run("applies_all_noops_on_restart_and_applies_next_once", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)

		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		initial := fixture.snapshot(t, database)
		if !strings.Contains(initial, "1:bootstrap_roles") ||
			!strings.Contains(initial, "2:second") ||
			!strings.Contains(initial, "bootstrap:1") ||
			!strings.Contains(initial, "second:1") {
			t.Fatalf("initial migration evidence is incomplete:\n%s", initial)
		}

		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		if restarted := fixture.snapshot(t, database); restarted != initial {
			t.Fatalf("same-volume restart changed durable evidence\nbefore:\n%s\nafter:\n%s", initial, restarted)
		}

		writeMigration(t, migrations, "000003_next.up.sql", syntheticStepMigration(3, "next", "next", ""))
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		withNext := fixture.snapshot(t, database)
		if !strings.Contains(withNext, "3:next") || !strings.Contains(withNext, "next:1") {
			t.Fatalf("controlled next migration was not applied: %s", withNext)
		}
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		if replayed := fixture.snapshot(t, database); replayed != withNext {
			t.Fatalf("controlled next migration was applied more than once\nbefore:\n%s\nafter:\n%s", withNext, replayed)
		}
	})

	t.Run("rejects_version_name_conflict_without_role_or_data_mutation", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)
		fixture.mustRunRunner(t, database, migrations, "role-password-a")

		before := fixture.snapshotWithRole(t, database)
		if err := os.Rename(
			filepath.Join(migrations, "000002_second.up.sql"),
			filepath.Join(migrations, "000002_conflicting_name.up.sql"),
		); err != nil {
			t.Fatalf("rename migration: %v", err)
		}
		output, err := fixture.runRunner(t, database, migrations, "role-password-b", 2*time.Minute)
		assertRunnerFailure(t, output, err, "version/name identity conflict")
		if after := fixture.snapshotWithRole(t, database); after != before {
			t.Fatalf("identity conflict changed database or role state\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})

	t.Run("rejects_missing_applied_file_without_mutation", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		before := fixture.snapshotWithRole(t, database)

		if err := os.Remove(filepath.Join(migrations, "000002_second.up.sql")); err != nil {
			t.Fatalf("remove applied migration: %v", err)
		}
		output, err := fixture.runRunner(t, database, migrations, "role-password-b", 2*time.Minute)
		assertRunnerFailure(t, output, err, "unknown future or missing-file version")
		if after := fixture.snapshotWithRole(t, database); after != before {
			t.Fatalf("missing migration file changed database or role state\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})

	t.Run("rejects_ledger_gap_without_applying_pending_suffix", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		writeMigration(t, migrations, "000003_third.up.sql", syntheticStepMigration(3, "third", "third", ""))
		fixture.execSQL(t, database, "DELETE FROM sentinelflow.schema_migrations WHERE version = 2; INSERT INTO sentinelflow.schema_migrations(version, name) VALUES (3, 'third')")
		before := fixture.snapshotWithRole(t, database)

		output, err := fixture.runRunner(t, database, migrations, "role-password-b", 2*time.Minute)
		assertRunnerFailure(t, output, err, "not a contiguous prefix")
		if after := fixture.snapshotWithRole(t, database); after != before {
			t.Fatalf("ledger gap changed database or role state\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})

	t.Run("rejects_unknown_future_ledger_without_mutation", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		fixture.execSQL(t, database, "INSERT INTO sentinelflow.schema_migrations(version, name) VALUES (3, 'future')")
		before := fixture.snapshotWithRole(t, database)

		output, err := fixture.runRunner(t, database, migrations, "role-password-b", 2*time.Minute)
		assertRunnerFailure(t, output, err, "unknown future or missing-file version")
		if after := fixture.snapshotWithRole(t, database); after != before {
			t.Fatalf("future ledger row changed database or role state\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})

	t.Run("fences_surviving_demo_role_when_a_late_role_is_missing", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		fixture.execSQL(t, database, "DROP ROLE sentinelflow_demo_activator")

		output, err := fixture.runRunner(t, database, migrations, "role-password-b", 2*time.Minute)
		assertRunnerFailure(t, output, err, `role "sentinelflow_demo_activator" does not exist`)
		if state := fixture.demoRoleIsolationState(t, database); state != "0:1:0" {
			t.Fatalf("surviving demo role after failed role preflight = %s, want 0:1:0", state)
		}

		// Roles are cluster-global in this shared test fixture. Restore the exact
		// late role name so later isolated-database cases can bootstrap normally.
		fixture.execSQL(t, database, "CREATE ROLE sentinelflow_demo_activator NOLOGIN")
	})

	t.Run("non_demo_mode_clears_demo_login_authority", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, false)
		fixture.mustRunRunner(t, database, migrations, "role-password-a")
		if state := fixture.demoRoleIsolationState(t, database); state != "1:1:0" {
			t.Fatalf("demo role state after demo migration = %s, want 1:1:0", state)
		}

		output, err := fixture.runRunnerWithDemoEnvironment(
			t, database, migrations, "role-password-a", 2*time.Minute,
			[]string{"SENTINELFLOW_ENV=production"},
		)
		if err != nil {
			t.Fatalf("run production migration runner: %v\n%s", err, output)
		}
		if state := fixture.demoRoleIsolationState(t, database); state != "0:2:0" {
			t.Fatalf("demo role state after production transition = %s, want 0:2:0", state)
		}
	})

	for _, testCase := range []struct {
		name         string
		environment  []string
		wantFragment string
	}{
		{
			name:         "demo importer password missing",
			environment:  []string{"SENTINELFLOW_ENV=demo"},
			wantFragment: "DATABASE_DEMO_IMPORTER_PASSWORD is required in demo mode",
		},
		{
			name: "demo password outside demo mode",
			environment: []string{
				"SENTINELFLOW_ENV=production",
				"DATABASE_DEMO_IMPORTER_PASSWORD=forbidden-demo-password",
			},
			wantFragment: "DATABASE_DEMO_IMPORTER_PASSWORD is forbidden outside demo mode",
		},
		{
			name:         "unknown environment",
			environment:  []string{"SENTINELFLOW_ENV=staging"},
			wantFragment: "SENTINELFLOW_ENV must be demo, development, or production",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			database := fixture.createDatabase(t)
			migrations := writeSyntheticMigrations(t, false)
			output, err := fixture.runRunnerWithDemoEnvironment(
				t, database, migrations, "role-password-a", 2*time.Minute, testCase.environment,
			)
			assertRunnerFailure(t, output, err, testCase.wantFragment)
			if relation := fixture.query(t, database, "SELECT COALESCE(to_regclass('sentinelflow.schema_migrations')::text, '')"); relation != "" {
				t.Fatalf("demo environment rejection opened or mutated the database: %q", relation)
			}
		})
	}

	for _, testCase := range []struct {
		name         string
		files        map[string]string
		wantFragment string
	}{
		{
			name: "malformed filename",
			files: map[string]string{
				"000001_bootstrap_roles.up.sql": syntheticBootstrapMigration(),
				"bad-name.up.sql":               syntheticStepMigration(2, "bad", "bad", ""),
			},
			wantFragment: "invalid migration filename",
		},
		{
			name: "duplicate version",
			files: map[string]string{
				"000001_bootstrap_roles.up.sql": syntheticBootstrapMigration(),
				"000001_duplicate.up.sql":       syntheticBootstrapMigration(),
			},
			wantFragment: "expected version 000002 but found 000001",
		},
		{
			name: "gap or out of order chain",
			files: map[string]string{
				"000001_bootstrap_roles.up.sql": syntheticBootstrapMigration(),
				"000003_third.up.sql":           syntheticStepMigration(3, "third", "third", ""),
			},
			wantFragment: "expected version 000002 but found 000003",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			database := fixture.createDatabase(t)
			migrations := t.TempDir()
			if err := os.Chmod(migrations, 0o755); err != nil {
				t.Fatalf("make migration directory readable: %v", err)
			}
			for name, body := range testCase.files {
				writeMigration(t, migrations, name, body)
			}

			output, err := fixture.runRunner(t, database, migrations, "role-password-a", 2*time.Minute)
			assertRunnerFailure(t, output, err, testCase.wantFragment)
			if relation := fixture.query(t, database, "SELECT COALESCE(to_regclass('sentinelflow.schema_migrations')::text, '')"); relation != "" {
				t.Fatalf("file-chain rejection opened or mutated the database: %q", relation)
			}
		})
	}

	t.Run("rejects_migration_symlink_before_database_access", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := t.TempDir()
		if err := os.Chmod(migrations, 0o755); err != nil {
			t.Fatalf("make migration directory readable: %v", err)
		}
		writeMigration(t, migrations, "000001_bootstrap_roles.up.sql", syntheticBootstrapMigration())
		writeMigration(t, migrations, "second.sql", syntheticStepMigration(2, "second", "second", ""))
		if err := os.Symlink("second.sql", filepath.Join(migrations, "000002_second.up.sql")); err != nil {
			t.Fatalf("create migration symlink: %v", err)
		}

		output, err := fixture.runRunner(t, database, migrations, "role-password-a", 2*time.Minute)
		assertRunnerFailure(t, output, err, "migration symlinks are not allowed")
		if relation := fixture.query(t, database, "SELECT COALESCE(to_regclass('sentinelflow.schema_migrations')::text, '')"); relation != "" {
			t.Fatalf("symlink rejection opened or mutated the database: %q", relation)
		}
	})

	t.Run("two_concurrent_runners_serialize_and_apply_once", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := writeSyntheticMigrations(t, true)

		type result struct {
			output string
			err    error
		}
		start := make(chan struct{})
		results := make(chan result, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				output, err := fixture.runRunner(t, database, migrations, "role-password-a", 3*time.Minute)
				results <- result{output: output, err: err}
			}()
		}
		close(start)
		for i := 0; i < 2; i++ {
			got := <-results
			if got.err != nil {
				t.Fatalf("concurrent migration runner failed: %v\n%s", got.err, got.output)
			}
		}

		if count := fixture.query(t, database, "SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 2 AND name = 'second'"); count != "1" {
			t.Fatalf("migration 2 ledger count = %s, want 1", count)
		}
		if count := fixture.query(t, database, "SELECT applied_count FROM sentinelflow.migration_runner_evidence WHERE label = 'second'"); count != "1" {
			t.Fatalf("migration 2 application count = %s, want 1", count)
		}
	})
}

// TestMigrationRunnerCanonicalPostgreSQL17 is deliberately separate from the
// synthetic fault matrix. It proves the checked-in migration set can bootstrap,
// restart against retained data, and accept exactly one new suffix migration.
func TestMigrationRunnerCanonicalPostgreSQL17(t *testing.T) {
	fixture := startPostgres17(t)
	database := fixture.createDatabase(t)
	migrations := copyCanonicalMigrations(t, filepath.Join(fixture.repository, "db", "migrations"))

	fixture.mustRunRunner(t, database, migrations, "canonical-role-password")
	fixture.execSQL(t, database, "CREATE TABLE public.migration_runner_restart_evidence (id bigint PRIMARY KEY, value text NOT NULL); INSERT INTO public.migration_runner_restart_evidence VALUES (1, 'retained')")
	initial := fixture.canonicalSnapshot(t, database)

	fixture.mustRunRunner(t, database, migrations, "canonical-role-password")
	if restarted := fixture.canonicalSnapshot(t, database); restarted != initial {
		t.Fatalf("canonical same-volume restart changed ledger or evidence\nbefore:\n%s\nafter:\n%s", initial, restarted)
	}

	versions := migrationVersions(t, migrations)
	next := versions[len(versions)-1] + 1
	filename := fmt.Sprintf("%06d_migration_runner_probe.up.sql", next)
	body := fmt.Sprintf(`BEGIN;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;
CREATE TABLE migration_runner_canonical_probe (
    id bigint PRIMARY KEY,
    applied_count bigint NOT NULL
);
INSERT INTO migration_runner_canonical_probe VALUES (1, 1);
INSERT INTO schema_migrations(version, name) VALUES (%d, 'migration_runner_probe');
COMMIT;
`, next)
	writeMigration(t, migrations, filename, body)

	fixture.mustRunRunner(t, database, migrations, "canonical-role-password")
	withNext := fixture.canonicalSnapshot(t, database)
	if !strings.Contains(withNext, fmt.Sprintf("%d:migration_runner_probe", next)) ||
		!strings.Contains(withNext, "probe=1") {
		t.Fatalf("canonical suffix migration evidence missing: %s", withNext)
	}
	fixture.mustRunRunner(t, database, migrations, "canonical-role-password")
	if replayed := fixture.canonicalSnapshot(t, database); replayed != withNext {
		t.Fatalf("canonical suffix migration was applied more than once\nbefore:\n%s\nafter:\n%s", withNext, replayed)
	}
}

func TestMigrationRunnerCanonicalDemoPinRestartFailClosedPostgreSQL17(t *testing.T) {
	fixture := startPostgres17(t)

	t.Run("different_capability_receipt", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := copyCanonicalMigrations(t, filepath.Join(fixture.repository, "db", "migrations"))
		fixture.mustRunRunner(t, database, migrations, "pin-drift-role-password")

		output, err := fixture.runRunnerWithDemoEnvironmentAndReceipts(
			t, database, migrations, "pin-drift-role-password", 2*time.Minute,
			[]string{
				"SENTINELFLOW_ENV=demo",
				"DATABASE_DEMO_IMPORTER_PASSWORD=pin-drift-role-password-demo-importer",
			},
			"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			demoValidationReceipt,
		)
		assertRunnerFailure(t, output, err, "sentinelflow_demo_capability_pin_result_pinned_check")
		if state := fixture.demoRoleIsolationState(t, database); state != "0:2:0" {
			t.Fatalf("demo roles after capability receipt drift = %s, want 0:2:0", state)
		}
	})

	t.Run("stale_immutable_pin", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := copyCanonicalMigrations(t, filepath.Join(fixture.repository, "db", "migrations"))
		fixture.mustRunRunner(t, database, migrations, "pin-stale-role-password")
		fixture.execSQL(t, database, `
ALTER TABLE sentinelflow.demo_history_runtime_capability_expectation
    DISABLE TRIGGER demo_history_runtime_capability_expectation_append_only;
UPDATE sentinelflow.demo_history_runtime_capability_expectation AS expectation
SET pinned_at = stale.clock_at - interval '6 minutes',
    importer_lease_expires_at = stale.clock_at - interval '1 minute'
FROM (SELECT clock_timestamp() AS clock_at) AS stale
WHERE expectation.bootstrap_id = 1;
ALTER TABLE sentinelflow.demo_history_runtime_capability_expectation
    ENABLE TRIGGER demo_history_runtime_capability_expectation_append_only;
`)
		output, err := fixture.runRunner(t, database, migrations, "pin-stale-role-password", 2*time.Minute)
		assertRunnerFailure(t, output, err, "sentinelflow_demo_capability_pin_result_pinned_check")
		if state := fixture.demoRoleIsolationState(t, database); state != "0:2:0" {
			t.Fatalf("demo roles after stale capability pin = %s, want 0:2:0", state)
		}
	})

	t.Run("import_state_already_started", func(t *testing.T) {
		database := fixture.createDatabase(t)
		migrations := copyCanonicalMigrations(t, filepath.Join(fixture.repository, "db", "migrations"))
		fixture.mustRunRunner(t, database, migrations, "pin-active-role-password")
		fixture.execSQL(t, database, `
WITH fixture_clock AS (
    SELECT date_trunc('milliseconds', clock_timestamp()) AS clock_at
)
INSERT INTO sentinelflow.demo_history_imports (
    import_id, schema_version, manifest_id, profile, dataset_id,
    dataset_schema_version, dataset_locator, raw_file_byte_sha256,
    manifest_dataset_jcs_digest, imported_rows_jcs_digest,
    imported_record_count, source_health_jcs_digest, manifest_digest,
    run_scope_digest, public_key_digest, signature_verification_digest,
    path_catalog_version, clock_at, issued_at, coverage_start, coverage_end,
    status, attempt_count, started_at
)
SELECT
    '019b0000-0000-7000-8000-000000000301',
    'demo-history-import-v1',
    '019b0000-0000-7000-8000-000000000302',
    'isolated-demo',
    '019b0000-0000-7000-8000-000000000100',
    'demo-history-dataset-v1',
    'contracts/fixtures/demo_history_dataset_v1.json',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00',
    'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807',
    4,
    'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    'path-catalog-v1', clock_at, clock_at, clock_at - interval '24 hours',
    clock_at, 'importing', 1, clock_at
FROM fixture_clock;
`)
		output, err := fixture.runRunner(t, database, migrations, "pin-active-role-password", 2*time.Minute)
		assertRunnerFailure(t, output, err, "sentinelflow_demo_capability_pin_result_pinned_check")
		if state := fixture.demoRoleIsolationState(t, database); state != "0:2:0" {
			t.Fatalf("demo roles after existing import state = %s, want 0:2:0", state)
		}
	})
}

func startPostgres17(t *testing.T) *postgresFixture {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for the PostgreSQL 17 migration-runner integration tests")
	}

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate migration runner integration test")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	fixture := &postgresFixture{
		t:          t,
		container:  uniqueResource("sf-migration-runner-pg"),
		initScript: filepath.Join(repository, "deployments", "postgres", "init.sh"),
		repository: repository,
	}
	t.Cleanup(fixture.cleanup)

	output, err := runCommand(2*time.Minute, "docker", "run", "--detach", "--rm",
		"--name", fixture.container,
		"--env", "POSTGRES_USER=postgres",
		"--env", "POSTGRES_DB=postgres",
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		postgres17Image,
	)
	if err != nil {
		t.Fatalf("start PostgreSQL 17 container: %v\n%s", err, output)
	}

	deadline := time.Now().Add(45 * time.Second)
	stableStart := ""
	stableChecks := 0
	for time.Now().Before(deadline) {
		output, err := runCommand(5*time.Second, "docker", "exec", fixture.container,
			"psql", "--no-psqlrc", "--tuples-only", "--no-align", "--username", "postgres",
			"--dbname", "postgres", "--command", "SELECT pg_postmaster_start_time()::text")
		if err == nil {
			startedAt := strings.TrimSpace(output)
			if startedAt == stableStart {
				stableChecks++
			} else {
				stableStart = startedAt
				stableChecks = 1
			}
			// The official image briefly exposes its initialization postmaster.
			// Require one unchanged postmaster for over a second before testing.
			if stableChecks >= 5 {
				return fixture
			}
		} else {
			stableStart = ""
			stableChecks = 0
		}
		time.Sleep(250 * time.Millisecond)
	}
	logs, _ := runCommand(10*time.Second, "docker", "logs", fixture.container)
	t.Fatalf("PostgreSQL 17 did not become ready:\n%s", logs)
	return nil
}

func (f *postgresFixture) cleanup() {
	f.cleanupOnce.Do(func() {
		_, _ = runCommand(30*time.Second, "docker", "rm", "--force", f.container)
	})
}

func (f *postgresFixture) createDatabase(t *testing.T) string {
	t.Helper()
	database := strings.ReplaceAll(uniqueResource("sf_migration_runner_db"), "-", "_")
	output, err := runCommand(30*time.Second, "docker", "exec", f.container,
		"createdb", "-U", "postgres", database)
	if err != nil {
		t.Fatalf("create database %s: %v\n%s", database, err, output)
	}
	return database
}

func (f *postgresFixture) mustRunRunner(t *testing.T, database, migrations, rolePassword string) {
	t.Helper()
	output, err := f.runRunner(t, database, migrations, rolePassword, 5*time.Minute)
	if err != nil {
		t.Fatalf("run migration runner: %v\n%s", err, output)
	}
}

func (f *postgresFixture) runRunner(t *testing.T, database, migrations, rolePassword string, timeout time.Duration) (string, error) {
	return f.runRunnerWithDemoEnvironment(t, database, migrations, rolePassword, timeout, []string{
		"SENTINELFLOW_ENV=demo",
		"DATABASE_DEMO_IMPORTER_PASSWORD=" + rolePassword + "-demo-importer",
	})
}

func (f *postgresFixture) runRunnerWithDemoEnvironment(
	t *testing.T,
	database string,
	migrations string,
	rolePassword string,
	timeout time.Duration,
	demoEnvironment []string,
) (string, error) {
	return f.runRunnerWithDemoEnvironmentAndReceipts(
		t, database, migrations, rolePassword, timeout, demoEnvironment,
		demoAnalysisReceipt, demoValidationReceipt,
	)
}

func (f *postgresFixture) runRunnerWithDemoEnvironmentAndReceipts(
	t *testing.T,
	database string,
	migrations string,
	rolePassword string,
	timeout time.Duration,
	demoEnvironment []string,
	analysisReceipt string,
	validationReceipt string,
) (string, error) {
	t.Helper()
	runner := uniqueResource("sf-migration-runner-client")
	t.Cleanup(func() {
		_, _ = runCommand(30*time.Second, "docker", "rm", "--force", runner)
	})
	arguments := []string{"run", "--rm",
		"--name", runner,
		"--network", "container:" + f.container,
		"--user", "70:70",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
		"--env", "PGHOST=127.0.0.1",
		"--env", "PGPORT=5432",
		"--env", "PGPASSWORD=" + postgresPassword,
		"--env", "POSTGRES_USER=postgres",
		"--env", "POSTGRES_DB=" + database,
		"--env", "DATABASE_API_PASSWORD=" + rolePassword,
		"--env", "DATABASE_WORKER_PASSWORD=" + rolePassword,
		"--env", "DATABASE_READ_PASSWORD=" + rolePassword,
		"--env", "DATABASE_DISPATCHER_PASSWORD=" + rolePassword,
		"--env", "DATABASE_RETENTION_PASSWORD=" + rolePassword,
		"--env", "DATABASE_LIFECYCLE_PASSWORD=" + rolePassword,
		"--env", "DATABASE_METRICS_PASSWORD=" + rolePassword,
	}
	for _, entry := range demoEnvironment {
		arguments = append(arguments, "--env", entry)
	}
	for _, entry := range demoEnvironment {
		if entry == "SENTINELFLOW_ENV=demo" {
			receipts := createDemoCapabilityReceiptVolume(
				t,
				analysisReceipt,
				validationReceipt,
			)
			arguments = append(
				arguments,
				"--volume",
				receipts+":/run/sentinelflow-demo-history-capability-receipts:ro",
			)
			break
		}
	}
	arguments = append(arguments,
		"--volume", f.initScript+":/opt/sentinelflow/init.sh:ro",
		"--volume", migrations+":/migrations:ro",
		postgres17Image,
		"/opt/sentinelflow/init.sh",
	)
	return runCommand(timeout, "docker", arguments...)
}

func (f *postgresFixture) query(t *testing.T, database, query string) string {
	t.Helper()
	output, err := runCommand(30*time.Second, "docker", "exec", f.container,
		"psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--tuples-only", "--no-align",
		"--username", "postgres", "--dbname", database, "--command", query)
	if err != nil {
		t.Fatalf("query database %s: %v\n%s", database, err, output)
	}
	return strings.TrimSpace(output)
}

func (f *postgresFixture) execSQL(t *testing.T, database, query string) {
	t.Helper()
	_ = f.query(t, database, query)
}

func (f *postgresFixture) snapshot(t *testing.T, database string) string {
	t.Helper()
	return f.query(t, database, `
SELECT string_agg(version::text || ':' || name || ':' || applied_at::text, ',' ORDER BY version)
FROM sentinelflow.schema_migrations;
SELECT string_agg(label || ':' || applied_count::text, ',' ORDER BY label)
FROM sentinelflow.migration_runner_evidence;
`)
}

func (f *postgresFixture) snapshotWithRole(t *testing.T, database string) string {
	t.Helper()
	return f.snapshot(t, database) + "\nrole=" + f.query(t, database,
		"SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = 'sentinelflow_api'")
}

func (f *postgresFixture) roleSnapshot(t *testing.T, database string) string {
	t.Helper()
	return f.query(t, database, `
SELECT string_agg(
    rolname || ':' || COALESCE(rolpassword, '') || ':' ||
    rolcanlogin::text || ':' || rolsuper::text || ':' || rolcreatedb::text || ':' ||
    rolcreaterole::text || ':' || rolreplication::text || ':' || rolbypassrls::text || ':' ||
    rolinherit::text || ':' || rolconnlimit::text,
    E'\n' ORDER BY rolname
)
FROM pg_catalog.pg_authid
WHERE rolname = ANY (ARRAY[
    'sentinelflow_api', 'sentinelflow_worker', 'sentinelflow_read',
	    'sentinelflow_dispatcher', 'sentinelflow_retention',
	    'sentinelflow_lifecycle', 'sentinelflow_metrics',
	    'sentinelflow_demo_importer', 'sentinelflow_demo_activator'
]);
`)
}

func (f *postgresFixture) demoRoleIsolationState(t *testing.T, database string) string {
	t.Helper()
	return f.query(t, database, `
WITH demo_roles AS (
    SELECT oid, rolcanlogin, rolpassword, rolsuper, rolinherit, rolcreaterole,
           rolcreatedb, rolreplication, rolbypassrls, rolconnlimit
    FROM pg_catalog.pg_authid
    WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
)
SELECT
    count(*) FILTER (WHERE rolcanlogin AND
        rolpassword ~ '^SCRAM-SHA-256[$][1-9][0-9]*:[A-Za-z0-9+/]+={0,2}[$][A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$' AND
        NOT rolsuper AND NOT rolinherit AND NOT rolcreaterole AND NOT rolcreatedb AND
        NOT rolreplication AND NOT rolbypassrls AND rolconnlimit = 2)::text || ':' ||
    count(*) FILTER (WHERE NOT rolcanlogin AND rolpassword IS NULL AND
        NOT rolsuper AND NOT rolinherit AND NOT rolcreaterole AND NOT rolcreatedb AND
        NOT rolreplication AND NOT rolbypassrls AND rolconnlimit = 2)::text || ':' ||
    (SELECT count(*) FROM pg_catalog.pg_auth_members membership
     WHERE membership.roleid IN (SELECT oid FROM demo_roles)
        OR membership.member IN (SELECT oid FROM demo_roles))::text
FROM demo_roles;
`)
}

func (f *postgresFixture) canonicalSnapshot(t *testing.T, database string) string {
	t.Helper()
	snapshot := f.query(t, database, `
SELECT string_agg(version::text || ':' || name || ':' || applied_at::text, ',' ORDER BY version)
FROM sentinelflow.schema_migrations;
SELECT 'restart=' || value FROM public.migration_runner_restart_evidence WHERE id = 1;
`)
	if relation := f.query(t, database, "SELECT COALESCE(to_regclass('sentinelflow.migration_runner_canonical_probe')::text, '')"); relation == "" {
		return snapshot + "\nprobe=absent"
	}
	return snapshot + "\nprobe=" + f.query(t, database,
		"SELECT applied_count FROM sentinelflow.migration_runner_canonical_probe WHERE id = 1")
}

func writeSyntheticMigrations(t *testing.T, slowSecond bool) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("make migration directory readable: %v", err)
	}
	delay := ""
	if slowSecond {
		delay = "SELECT pg_catalog.pg_sleep(2);"
	}
	writeMigration(t, directory, "000001_bootstrap_roles.up.sql", syntheticBootstrapMigration())
	writeMigration(t, directory, "000002_second.up.sql", syntheticStepMigration(2, "second", "second", delay))
	return directory
}

func writeMigration(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write migration %s: %v", name, err)
	}
}

func syntheticBootstrapMigration() string {
	return `BEGIN;
DO $roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'sentinelflow_migration',
        'sentinelflow_api',
        'sentinelflow_worker',
        'sentinelflow_read',
        'sentinelflow_dispatcher',
        'sentinelflow_retention',
	        'sentinelflow_lifecycle',
	        'sentinelflow_metrics',
	        'sentinelflow_demo_importer',
	        'sentinelflow_demo_activator'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = role_name) THEN
            EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', role_name);
        ELSE
            EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN', role_name);
        END IF;
    END LOOP;
END
$roles$;
CREATE SCHEMA sentinelflow AUTHORIZATION sentinelflow_migration;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;
CREATE TABLE schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL UNIQUE,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE migration_runner_evidence (
    label text PRIMARY KEY,
    applied_count bigint NOT NULL
);
CREATE TABLE demo_history_runtime_capability_expectation (
    bootstrap_id smallint PRIMARY KEY CHECK (bootstrap_id = 1),
    analysis_secret_digest text NOT NULL,
    validation_secret_digest text NOT NULL,
    pinned_at timestamptz NOT NULL,
    importer_lease_expires_at timestamptz NOT NULL
);
RESET ROLE;
CREATE FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
    p_analysis_secret_digest text,
    p_validation_secret_digest text,
    p_importer_lease_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
BEGIN
    IF p_analysis_secret_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_validation_secret_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_analysis_secret_digest = p_validation_secret_digest OR
       p_importer_lease_expires_at <= server_now OR
       p_importer_lease_expires_at > server_now + interval '5 minutes' THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT 1 FROM sentinelflow.demo_history_runtime_capability_expectation) THEN
        RETURN EXISTS (
            SELECT 1
            FROM sentinelflow.demo_history_runtime_capability_expectation AS expectation
            WHERE expectation.bootstrap_id = 1
              AND expectation.analysis_secret_digest = p_analysis_secret_digest
              AND expectation.validation_secret_digest = p_validation_secret_digest
              AND expectation.importer_lease_expires_at = p_importer_lease_expires_at
              AND expectation.importer_lease_expires_at > server_now
        );
    END IF;
    INSERT INTO sentinelflow.demo_history_runtime_capability_expectation (
        bootstrap_id, analysis_secret_digest, validation_secret_digest,
        pinned_at, importer_lease_expires_at
    ) VALUES (
        1, p_analysis_secret_digest, p_validation_secret_digest,
        server_now, p_importer_lease_expires_at
    );
    RETURN true;
END
$function$;
REVOKE ALL ON FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
    text, text, timestamptz
) FROM PUBLIC, sentinelflow_migration, sentinelflow_api, sentinelflow_worker,
sentinelflow_read, sentinelflow_dispatcher, sentinelflow_retention,
sentinelflow_lifecycle, sentinelflow_metrics, sentinelflow_demo_importer,
sentinelflow_demo_activator;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;
INSERT INTO migration_runner_evidence VALUES ('bootstrap', 1);
INSERT INTO schema_migrations(version, name) VALUES (1, 'bootstrap_roles');
COMMIT;
`
}

func syntheticStepMigration(version int, name, evidence, prelude string) string {
	return fmt.Sprintf(`BEGIN;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;
%s
INSERT INTO migration_runner_evidence(label, applied_count) VALUES ('%s', 1);
INSERT INTO schema_migrations(version, name) VALUES (%d, '%s');
COMMIT;
`, prelude, evidence, version, name)
}

func copyCanonicalMigrations(t *testing.T, source string) string {
	t.Helper()
	destination := t.TempDir()
	if err := os.Chmod(destination, 0o755); err != nil {
		t.Fatalf("make canonical migration directory readable: %v", err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("read canonical migrations: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatalf("read canonical migration %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(destination, entry.Name()), body, 0o644); err != nil {
			t.Fatalf("copy canonical migration %s: %v", entry.Name(), err)
		}
	}
	return destination
}

func migrationVersions(t *testing.T, directory string) []int {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var versions []int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		value, err := strconv.Atoi(strings.SplitN(entry.Name(), "_", 2)[0])
		if err != nil {
			t.Fatalf("parse migration version %s: %v", entry.Name(), err)
		}
		versions = append(versions, value)
	}
	sort.Ints(versions)
	if len(versions) == 0 {
		t.Fatal("canonical migrations are empty")
	}
	return versions
}

func assertRunnerFailure(t *testing.T, output string, err error, wantFragment string) {
	t.Helper()
	if err == nil {
		t.Fatalf("migration runner unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(output, wantFragment) {
		t.Fatalf("migration runner failure does not contain %q: %v\n%s", wantFragment, err, output)
	}
}

func uniqueResource(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), resourceSequence.Add(1))
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("%s timed out after %s: %w", name, timeout, ctx.Err())
	}
	return string(output), err
}
