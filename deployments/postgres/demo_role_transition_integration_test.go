//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	demoAnalysisReceipt   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	demoValidationReceipt = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestMigrationRunnerTerminatesRetainedDemoAuthoritySessionsPostgreSQL17(t *testing.T) {
	fixture := startPostgres17(t)
	database := fixture.createDatabase(t)
	migrations := copyCanonicalMigrations(
		t,
		filepath.Join(fixture.repository, "db", "migrations"),
	)
	receipts := createDemoCapabilityReceiptVolume(t, demoAnalysisReceipt, demoValidationReceipt)
	const rolePassword = "session-fence-role-password"

	fixture.mustRunStagedRunner(t, database, migrations, rolePassword, receipts)
	if state := fixture.demoRoleValidityState(t, database); state != "1:1" {
		t.Fatalf("demo role validity after staged demo migration = %s, want 1:1", state)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sessionOutput bytes.Buffer
	session := exec.CommandContext(
		ctx,
		"docker", "exec",
		"--env", "PGPASSWORD="+rolePassword+"-demo-importer",
		fixture.container,
		"psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1",
		"--host", "127.0.0.1", "--username", "sentinelflow_demo_importer",
		"--dbname", database,
		"--command", "SELECT pg_backend_pid(); SELECT pg_sleep(300);",
	)
	session.Stdout = &sessionOutput
	session.Stderr = &sessionOutput
	if err := session.Start(); err != nil {
		t.Fatalf("start retained demo importer session: %v", err)
	}
	sessionDone := make(chan error, 1)
	go func() { sessionDone <- session.Wait() }()
	reaped := false
	t.Cleanup(func() {
		cancel()
		if !reaped {
			select {
			case <-sessionDone:
			case <-time.After(10 * time.Second):
				if session.Process != nil {
					_ = session.Process.Kill()
				}
			}
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for {
		if fixture.activeDemoRoleSessionCount(t, database) == "1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("demo importer session did not become active: %s", sessionOutput.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	output, err := fixture.runRunnerWithDemoEnvironment(
		t, database, migrations, rolePassword, 2*time.Minute,
		[]string{"SENTINELFLOW_ENV=production"},
	)
	if err != nil {
		t.Fatalf(
			"run production migration runner: %v (role_state=%s active_sessions=%s)\n%s",
			err,
			fixture.demoRoleIsolationState(t, database),
			fixture.activeDemoRoleSessionCount(t, database),
			output,
		)
	}

	select {
	case sessionErr := <-sessionDone:
		reaped = true
		if sessionErr == nil {
			t.Fatal("retained demo importer session completed instead of being terminated")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("retained demo importer session survived the production transition")
	}

	if count := fixture.activeDemoRoleSessionCount(t, database); count != "0" {
		t.Fatalf("active demo authority sessions after production transition = %s, want 0", count)
	}
	if state := fixture.demoRoleIsolationState(t, database); state != "0:2:0" {
		t.Fatalf("demo role state after production transition = %s, want 0:2:0", state)
	}
	if state := fixture.demoRoleValidityState(t, database); state != "0:2" {
		t.Fatalf("demo role validity after production transition = %s, want 0:2", state)
	}
	for role, password := range map[string]string{
		"sentinelflow_demo_importer":  rolePassword + "-demo-importer",
		"sentinelflow_demo_activator": rolePassword + "-demo-activator",
	} {
		connectionOutput, connectionErr := runCommand(
			10*time.Second,
			"docker", "exec", "--env", "PGPASSWORD="+password,
			fixture.container,
			"psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1",
			"--host", "127.0.0.1", "--username", role,
			"--dbname", database, "--command", "SELECT 1;",
		)
		if connectionErr == nil {
			t.Fatalf("disabled demo authority role %s authenticated", role)
		}
		if strings.Contains(connectionOutput, password) {
			t.Fatalf("disabled demo authority role %s leaked its credential", role)
		}
	}
}

func TestMigrationRunnerCanonicalMultiDatabaseRoleFencePostgreSQL17(t *testing.T) {
	fixture := startPostgres17(t)
	migrations := copyCanonicalMigrations(
		t,
		filepath.Join(fixture.repository, "db", "migrations"),
	)

	firstDatabase := fixture.createDatabase(t)
	firstReceipts := createDemoCapabilityReceiptVolume(t, demoAnalysisReceipt, demoValidationReceipt)
	fixture.mustRunStagedRunner(t, firstDatabase, migrations, "multi-db-first-password", firstReceipts)
	if state := fixture.demoRoleIsolationState(t, firstDatabase); state != "1:1:0" {
		t.Fatalf("first database demo role state = %s, want 1:1:0", state)
	}

	secondDatabase := fixture.createDatabase(t)
	secondReceipts := createDemoCapabilityReceiptVolume(t, demoAnalysisReceipt, demoValidationReceipt)
	fixture.mustRunStagedRunner(t, secondDatabase, migrations, "multi-db-second-password", secondReceipts)
	if state := fixture.demoRoleIsolationState(t, secondDatabase); state != "1:1:0" {
		t.Fatalf("second database demo role state = %s, want 1:1:0", state)
	}

	for _, database := range []string{firstDatabase, secondDatabase} {
		ledger := fixture.query(t, database, `
SELECT version::text || ':' || name
FROM sentinelflow.schema_migrations
WHERE version = 30;
`)
		if strings.TrimSpace(ledger) != "30:demo_history_runtime_activation" {
			t.Fatalf("database %s version-30 ledger = %q", database, ledger)
		}
	}
}

func TestDemoActivationHandoffStagesExclusiveRoleAuthorityPostgreSQL17(t *testing.T) {
	fixture := startPostgres17(t)
	migrations := copyCanonicalMigrations(
		t,
		filepath.Join(fixture.repository, "db", "migrations"),
	)
	receipts := createDemoCapabilityReceiptVolume(t, demoAnalysisReceipt, demoValidationReceipt)
	const (
		importerPassword  = "staged-importer-password"
		activatorPassword = "staged-activator-password"
	)

	t.Run("successful handoff enables only activator", func(t *testing.T) {
		database := fixture.createDatabase(t)
		fixture.mustRunStagedRunner(t, database, migrations, importerPassword, receipts)
		if state := fixture.stagedDemoRoleState(t, database); state != "importer-login:activator-inert" {
			t.Fatalf("post-migration staged role state = %s", state)
		}
		fixture.fenceImporterAsImporter(t, database, importerPassword)
		if state := fixture.stagedDemoRoleState(t, database); state != "both-inert" {
			t.Fatalf("post-import staged role state = %s", state)
		}

		output, err := fixture.runDemoActivationHandoff(
			t, database, activatorPassword, receipts, nil,
		)
		if err != nil {
			t.Fatalf("run successful demo activation handoff: %v\n%s", err, output)
		}
		if strings.Contains(output, activatorPassword) {
			t.Fatal("successful handoff output leaked the activator credential")
		}
		if state := fixture.stagedDemoRoleState(t, database); state != "importer-inert:activator-login" {
			t.Fatalf("post-handoff staged role state = %s", state)
		}
		if count := fixture.activeDemoRoleSessionCount(t, database); count != "0" {
			t.Fatalf("post-handoff active demo sessions = %s, want 0", count)
		}
		fixture.assertDemoCapabilityPinAndTimeouts(t, database)
		fixture.assertRoleAuthentication(t, database, "sentinelflow_demo_importer", importerPassword, false)
		fixture.assertRoleAuthentication(t, database, "sentinelflow_demo_activator", activatorPassword, true)
	})

	t.Run("missing activator credential fences both roles", func(t *testing.T) {
		database := fixture.createDatabase(t)
		fixture.mustRunStagedRunner(t, database, migrations, importerPassword, receipts)
		fixture.fenceImporterAsImporter(t, database, importerPassword)

		output, err := fixture.runDemoActivationHandoff(
			t, database, activatorPassword, receipts,
			[]string{"DATABASE_DEMO_ACTIVATOR_PASSWORD="},
		)
		if err == nil {
			t.Fatalf("handoff without activator credential succeeded:\n%s", output)
		}
		if strings.Contains(output, activatorPassword) {
			t.Fatal("failed handoff output leaked the activator credential")
		}
		if state := fixture.stagedDemoRoleState(t, database); state != "both-inert" {
			t.Fatalf("failed handoff role state = %s, want both-inert", state)
		}
		if count := fixture.activeDemoRoleSessionCount(t, database); count != "0" {
			t.Fatalf("failed handoff active demo sessions = %s, want 0", count)
		}
		fixture.assertRoleAuthentication(t, database, "sentinelflow_demo_importer", importerPassword, false)
		fixture.assertRoleAuthentication(t, database, "sentinelflow_demo_activator", activatorPassword, false)
	})
}

func (f *postgresFixture) activeDemoRoleSessionCount(t *testing.T, database string) string {
	t.Helper()
	return f.query(t, database, `
SELECT count(*)
FROM pg_catalog.pg_stat_activity
WHERE usename IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator');
`)
}

func (f *postgresFixture) demoRoleValidityState(t *testing.T, database string) string {
	t.Helper()
	return f.query(t, database, `
SELECT
    count(*) FILTER (
        WHERE rolcanlogin
          AND rolvaliduntil > clock_timestamp()
          AND rolvaliduntil <= clock_timestamp() + interval '5 minutes'
    )::text || ':' ||
    count(*) FILTER (
        WHERE NOT rolcanlogin
          AND rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
    )::text
FROM pg_catalog.pg_authid
WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator');
`)
}

func createDemoCapabilityReceiptVolume(t *testing.T, analysisDigest, validationDigest string) string {
	t.Helper()
	volume := uniqueResource("sf-demo-capability-receipts")
	if output, err := runCommand(
		30*time.Second,
		"docker", "volume", "create",
		"--label", "com.sentinelflow.test=demo-capability-handoff",
		volume,
	); err != nil {
		t.Fatalf("create demo capability receipt volume: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		_, _ = runCommand(30*time.Second, "docker", "volume", "rm", "--force", volume)
	})
	initializer := uniqueResource("sf-demo-capability-receipt-init")
	output, err := runCommand(
		30*time.Second,
		"docker", "run", "--rm",
		"--name", initializer,
		"--network", "none",
		"--user", "0:0",
		"--read-only",
		"--cap-drop", "ALL",
		"--cap-add", "CHOWN",
		"--security-opt", "no-new-privileges:true",
		"--env", "ANALYSIS_DIGEST="+analysisDigest,
		"--env", "VALIDATION_DIGEST="+validationDigest,
		"--volume", volume+":/receipts",
		postgres17Image,
		"/bin/sh", "-eu", "-c", `
test "$ANALYSIS_DIGEST" != "$VALIDATION_DIGEST"
printf '%s\n' "$ANALYSIS_DIGEST" >/receipts/analysis.sha256
printf '%s\n' "$VALIDATION_DIGEST" >/receipts/validation.sha256
chown 0:70 /receipts /receipts/analysis.sha256 /receipts/validation.sha256
chmod 0750 /receipts
chmod 0440 /receipts/analysis.sha256 /receipts/validation.sha256
test "$(stat -c '%u:%g:%a:%s' /receipts/analysis.sha256)" = '0:70:440:72'
test "$(stat -c '%u:%g:%a:%s' /receipts/validation.sha256)" = '0:70:440:72'
`,
	)
	if err != nil {
		t.Fatalf("initialize demo capability receipt volume: %v\n%s", err, output)
	}
	return volume
}

func (f *postgresFixture) mustRunStagedRunner(
	t *testing.T,
	database string,
	migrations string,
	importerPassword string,
	receiptVolume string,
) {
	t.Helper()
	output, err := f.runStagedRunner(
		t, database, migrations, importerPassword, receiptVolume, 5*time.Minute,
	)
	if err != nil {
		t.Fatalf("run staged migration runner: %v\n%s", err, output)
	}
}

func (f *postgresFixture) runStagedRunner(
	t *testing.T,
	database string,
	migrations string,
	importerPassword string,
	receiptVolume string,
	timeout time.Duration,
) (string, error) {
	t.Helper()
	runner := uniqueResource("sf-staged-migration-runner-client")
	t.Cleanup(func() {
		_, _ = runCommand(30*time.Second, "docker", "rm", "--force", runner)
	})
	arguments := []string{
		"run", "--rm",
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
		"--env", "SENTINELFLOW_ENV=demo",
		"--env", "DATABASE_API_PASSWORD=staged-api-password",
		"--env", "DATABASE_WORKER_PASSWORD=staged-worker-password",
		"--env", "DATABASE_READ_PASSWORD=staged-read-password",
		"--env", "DATABASE_DISPATCHER_PASSWORD=staged-dispatcher-password",
		"--env", "DATABASE_RETENTION_PASSWORD=staged-retention-password",
		"--env", "DATABASE_LIFECYCLE_PASSWORD=staged-lifecycle-password",
		"--env", "DATABASE_METRICS_PASSWORD=staged-metrics-password",
		"--env", "DATABASE_DEMO_IMPORTER_PASSWORD=" + importerPassword,
		"--volume", f.initScript + ":/opt/sentinelflow/init.sh:ro",
		"--volume", migrations + ":/migrations:ro",
		"--volume", receiptVolume + ":/run/sentinelflow-demo-history-capability-receipts:ro",
		postgres17Image,
		"/opt/sentinelflow/init.sh",
	}
	return runCommand(timeout, "docker", arguments...)
}

func (f *postgresFixture) fenceImporterAsImporter(
	t *testing.T,
	database string,
	password string,
) {
	t.Helper()
	output, err := runCommand(
		30*time.Second,
		"docker", "exec",
		"--env", "PGPASSWORD="+password,
		f.container,
		"psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1",
		"--host", "127.0.0.1",
		"--username", "sentinelflow_demo_importer",
		"--dbname", database,
		"--command", "SELECT sentinelflow.fence_demo_history_importer_role_000030();",
		"--command", "SELECT sentinelflow.finalize_demo_history_importer_role_fence_000030();",
	)
	if err != nil {
		t.Fatalf("fence importer authority: %v\n%s", err, output)
	}
	if strings.Contains(output, password) {
		t.Fatal("importer fence output leaked the credential")
	}
}

func (f *postgresFixture) runDemoActivationHandoff(
	t *testing.T,
	database string,
	activatorPassword string,
	receiptVolume string,
	extraEnvironment []string,
) (string, error) {
	t.Helper()
	runner := uniqueResource("sf-demo-activation-handoff-client")
	t.Cleanup(func() {
		_, _ = runCommand(30*time.Second, "docker", "rm", "--force", runner)
	})
	script := filepath.Join(f.repository, "deployments", "postgres", "demo-activation-handoff.sh")
	arguments := []string{
		"run", "--rm",
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
		"--env", "SENTINELFLOW_ENV=demo",
		"--env", "DATABASE_DEMO_ACTIVATOR_PASSWORD=" + activatorPassword,
	}
	for _, entry := range extraEnvironment {
		arguments = append(arguments, "--env", entry)
	}
	arguments = append(
		arguments,
		"--volume", script+":/opt/sentinelflow/demo-activation-handoff.sh:ro",
		"--volume", receiptVolume+":/run/sentinelflow-demo-history-capability-receipts:ro",
		postgres17Image,
		"/opt/sentinelflow/demo-activation-handoff.sh",
	)
	return runCommand(2*time.Minute, "docker", arguments...)
}

func (f *postgresFixture) stagedDemoRoleState(t *testing.T, database string) string {
	t.Helper()
	state := f.query(t, database, `
WITH role_states AS (
    SELECT role.rolname,
           CASE
             WHEN role.rolcanlogin
              AND role.rolpassword IS NOT NULL
              AND role.rolvaliduntil > clock_timestamp()
              AND role.rolvaliduntil <= clock_timestamp() + interval '5 minutes'
              AND NOT role.rolsuper AND NOT role.rolinherit
              AND NOT role.rolcreatedb AND NOT role.rolcreaterole
              AND NOT role.rolreplication AND NOT role.rolbypassrls
              AND role.rolconnlimit = 2 THEN 'login'
             WHEN NOT role.rolcanlogin
              AND role.rolpassword IS NULL
              AND role.rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
              AND NOT role.rolsuper AND NOT role.rolinherit
              AND NOT role.rolcreatedb AND NOT role.rolcreaterole
              AND NOT role.rolreplication AND NOT role.rolbypassrls
              AND role.rolconnlimit = 2 THEN 'inert'
             ELSE 'invalid'
           END AS state
    FROM pg_catalog.pg_authid AS role
    WHERE role.rolname IN (
        'sentinelflow_demo_importer', 'sentinelflow_demo_activator'
    )
), membership_count AS (
    SELECT count(*) AS count
    FROM pg_catalog.pg_auth_members AS membership
    WHERE membership.roleid IN (
              pg_catalog.to_regrole('sentinelflow_demo_importer'),
              pg_catalog.to_regrole('sentinelflow_demo_activator')
          )
       OR membership.member IN (
              pg_catalog.to_regrole('sentinelflow_demo_importer'),
              pg_catalog.to_regrole('sentinelflow_demo_activator')
          )
)
SELECT string_agg(rolname || ':' || state, ',' ORDER BY rolname) ||
       ',memberships:' || (SELECT count::text FROM membership_count)
FROM role_states;
`)
	switch state {
	case "sentinelflow_demo_activator:inert,sentinelflow_demo_importer:login,memberships:0":
		return "importer-login:activator-inert"
	case "sentinelflow_demo_activator:inert,sentinelflow_demo_importer:inert,memberships:0":
		return "both-inert"
	case "sentinelflow_demo_activator:login,sentinelflow_demo_importer:inert,memberships:0":
		return "importer-inert:activator-login"
	default:
		return "invalid(" + state + ")"
	}
}

func (f *postgresFixture) assertDemoCapabilityPinAndTimeouts(t *testing.T, database string) {
	t.Helper()
	state := f.query(t, database, fmt.Sprintf(`
SELECT
    (SELECT count(*)
     FROM sentinelflow.demo_history_runtime_capability_expectation AS pin
     WHERE pin.bootstrap_id = 1
       AND pin.analysis_secret_digest::text = %s
       AND pin.validation_secret_digest::text = %s
       AND pin.pinned_at <= clock_timestamp()
       AND pin.importer_lease_expires_at > clock_timestamp()
       AND pin.importer_lease_expires_at <= pin.pinned_at + interval '5 minutes')::text
    || ':' ||
    (SELECT count(*)
     FROM pg_catalog.pg_db_role_setting AS setting
     JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole
     JOIN pg_catalog.pg_database AS database ON database.oid = setting.setdatabase
     WHERE database.datname = current_database()
       AND role.rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
       AND cardinality(setting.setconfig) = 5)::text;
`, quoteSQLLiteral(demoAnalysisReceipt), quoteSQLLiteral(demoValidationReceipt)))
	if state != "1:2" {
		t.Fatalf("demo capability pin/timeout state = %s, want 1:2", state)
	}
}

func (f *postgresFixture) assertRoleAuthentication(
	t *testing.T,
	database string,
	role string,
	password string,
	wantSuccess bool,
) {
	t.Helper()
	output, err := runCommand(
		10*time.Second,
		"docker", "exec",
		"--env", "PGPASSWORD="+password,
		f.container,
		"psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1",
		"--host", "127.0.0.1", "--username", role,
		"--dbname", database, "--command", "SELECT 1;",
	)
	if (err == nil) != wantSuccess {
		t.Fatalf("role %s authentication success=%t, want %t: %v\n%s", role, err == nil, wantSuccess, err, output)
	}
	if strings.Contains(output, password) {
		t.Fatalf("role %s authentication output leaked its credential", role)
	}
}

func quoteSQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
