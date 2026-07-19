//go:build integration

package controlmetrics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	lifecycleMetricsPostgresImage = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
	lifecycleMetricsAdminPassword = "sentinelflow-observability-test-only"
	lifecycleMetricsRolePassword  = "sentinelflow-metrics-test-only"
)

func TestLifecycleObservabilityAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 lifecycle observability coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-lifecycle-observability-%d", time.Now().UnixNano())
	lifecycleMetricsDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD="+lifecycleMetricsAdminPassword,
		"--publish", "127.0.0.1::5432", lifecycleMetricsPostgresImage)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForLifecycleMetricsPostgres(t, ctx, container)
	port := lifecycleMetricsDockerPort(t, ctx, container)

	adminURL := fmt.Sprintf("postgresql://postgres:%s@127.0.0.1:%s/postgres?sslmode=disable",
		lifecycleMetricsAdminPassword, port)
	admin := connectLifecycleMetricsPostgres(t, ctx, adminURL)
	if _, err := admin.Exec(ctx, `CREATE DATABASE sentinelflow`); err != nil {
		t.Fatal(err)
	}
	_ = admin.Close(context.Background())

	ownerURL := fmt.Sprintf("postgresql://postgres:%s@127.0.0.1:%s/sentinelflow?sslmode=disable",
		lifecycleMetricsAdminPassword, port)
	owner := connectLifecycleMetricsPostgres(t, ctx, ownerURL)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyLifecycleMetricsMigrationsThrough(t, ctx, owner, 28)
	assertLifecycleMetricsMigrationLedger(t, ctx, owner, 28)

	// Empty down/up proves that rollback restores exactly the 000024 exporter
	// boundary and the new migration is safely repeatable on the current chain.
	applyLifecycleMetricsMigration(t, ctx, owner, "000028_lifecycle_observability.down.sql")
	assertPreLifecycleMetricsACL(t, ctx, owner)
	applyLifecycleMetricsMigration(t, ctx, owner, "000028_lifecycle_observability.up.sql")
	assertLifecycleMetricsMigrationLedger(t, ctx, owner, 28)

	if _, err := owner.Exec(ctx,
		`ALTER ROLE sentinelflow_metrics LOGIN PASSWORD '`+lifecycleMetricsRolePassword+`'`); err != nil {
		t.Fatal(err)
	}
	metricsURL := fmt.Sprintf(
		"postgresql://sentinelflow_metrics:%s@127.0.0.1:%s/sentinelflow?sslmode=disable",
		lifecycleMetricsRolePassword, port,
	)
	metrics := connectLifecycleMetricsPostgres(t, ctx, metricsURL)
	t.Cleanup(func() { _ = metrics.Close(context.Background()) })

	if err := ValidateDatabaseIdentity(ctx, metrics); err != nil {
		t.Fatalf("runtime database identity attestation: %v", err)
	}
	assertLifecycleMetricsACL(t, ctx, owner, metrics)
	assertLifecycleMetricsIdentityRejectsAuthorityDrift(t, ctx, owner)
	store, err := NewStore(metrics)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := store.Collect(ctx)
	if err != nil || len(empty) != 362 {
		t.Fatalf("empty aggregate samples=%d err=%v", len(empty), err)
	}
	assertEmptyLifecycleSamples(t, empty)

	seedLifecycleMetricMatrix(t, ctx, owner)
	seeded, err := store.Collect(ctx)
	if err != nil || len(seeded) != 362 {
		t.Fatalf("seeded aggregate samples=%d err=%v", len(seeded), err)
	}
	assertSeededLifecycleSamples(t, seeded)
	assertLifecycleMetricsACL(t, ctx, owner, metrics)
}

func assertLifecycleMetricsIdentityRejectsAuthorityDrift(
	t *testing.T, ctx context.Context, owner *pgx.Conn,
) {
	t.Helper()
	for _, test := range []struct {
		name  string
		grant string
	}{
		{
			name: "alternate function",
			grant: `GRANT EXECUTE ON FUNCTION
                sentinelflow.control_observability_samples_000024()
                TO sentinelflow_metrics`,
		},
		{
			name: "direct lifecycle column",
			grant: `GRANT SELECT (purpose) ON
                sentinelflow.lifecycle_inspection_schedules_000026
                TO sentinelflow_metrics`,
		},
		{
			name:  "schema create",
			grant: `GRANT CREATE ON SCHEMA sentinelflow TO sentinelflow_metrics`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, test.grant); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE sentinelflow_metrics`); err != nil {
				t.Fatal(err)
			}
			if err := ValidateDatabaseIdentity(ctx, tx); err != ErrDatabaseIdentity {
				t.Fatalf("authority drift disposition=%v", err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertPreLifecycleMetricsACL(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	var newMissing, oldMetrics, oldPublic bool
	var metricsFunctions int
	if err := owner.QueryRow(ctx, `
SELECT to_regprocedure('sentinelflow.control_observability_samples_000028()') IS NULL,
       has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.control_observability_samples_000024()', 'EXECUTE'
       ),
       EXISTS (
           SELECT 1
           FROM pg_proc function
           CROSS JOIN LATERAL aclexplode(
               COALESCE(function.proacl, acldefault('f', function.proowner))
           ) privilege
           WHERE function.oid =
                 'sentinelflow.control_observability_samples_000024()'::regprocedure
             AND privilege.grantee = 0
             AND privilege.privilege_type = 'EXECUTE'
       ),
       (
           SELECT count(*)::integer
           FROM pg_proc function
           JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND has_function_privilege('sentinelflow_metrics', function.oid, 'EXECUTE')
       )`).Scan(&newMissing, &oldMetrics, &oldPublic, &metricsFunctions); err != nil {
		t.Fatal(err)
	}
	if !newMissing || !oldMetrics || oldPublic || metricsFunctions != 1 {
		t.Fatalf("000028 down ACL mismatch: missing=%t old=%t public=%t functions=%d",
			newMissing, oldMetrics, oldPublic, metricsFunctions)
	}
}

func assertLifecycleMetricsACL(
	t *testing.T, ctx context.Context, owner, metrics *pgx.Conn,
) {
	t.Helper()
	var newMetrics, oldMetrics, newPublic, oldPublic bool
	var tableRead, tableWrite, claimExecute, finishExecute, lifecyclePublic bool
	var metricsFunctions int
	if err := owner.QueryRow(ctx, `
SELECT has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
       ),
       has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.control_observability_samples_000024()', 'EXECUTE'
       ),
       EXISTS (
           SELECT 1 FROM pg_proc function
           CROSS JOIN LATERAL aclexplode(
               COALESCE(function.proacl, acldefault('f', function.proowner))
           ) privilege
           WHERE function.oid =
                 'sentinelflow.control_observability_samples_000028()'::regprocedure
             AND privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
       ),
       EXISTS (
           SELECT 1 FROM pg_proc function
           CROSS JOIN LATERAL aclexplode(
               COALESCE(function.proacl, acldefault('f', function.proowner))
           ) privilege
           WHERE function.oid =
                 'sentinelflow.control_observability_samples_000024()'::regprocedure
             AND privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
       ),
       has_table_privilege(
           'sentinelflow_metrics',
           'sentinelflow.lifecycle_inspection_schedules_000026', 'SELECT'
       ),
       has_table_privilege(
           'sentinelflow_metrics',
           'sentinelflow.lifecycle_inspection_schedules_000026', 'UPDATE'
       ),
       has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.claim_lifecycle_inspection_schedule_000026(sentinelflow.ascii_id,sentinelflow.ascii_id,integer)',
           'EXECUTE'
       ),
       has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.finish_lifecycle_inspection_failure_000026(uuid,uuid,integer,sentinelflow.ascii_id,sentinelflow.sha256_digest,integer)',
           'EXECUTE'
       ),
       EXISTS (
           SELECT 1
           FROM pg_proc function
           JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
           CROSS JOIN LATERAL aclexplode(
               COALESCE(function.proacl, acldefault('f', function.proowner))
           ) privilege
           WHERE namespace.nspname = 'sentinelflow'
             AND function.proname IN (
                 'lifecycle_inspect_jcs_000026',
                 'lifecycle_schedule_idempotency_000026',
                 'lifecycle_inspection_authorization_jcs_000026',
                 'enforce_action_transition_000026',
                 'claim_lifecycle_inspection_schedule_000026',
                 'commit_lifecycle_inspection_000026',
                 'finish_lifecycle_inspection_failure_000026'
             )
             AND privilege.grantee = 0
             AND privilege.privilege_type = 'EXECUTE'
       ),
       (
           SELECT count(*)::integer
           FROM pg_proc function
           JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND has_function_privilege('sentinelflow_metrics', function.oid, 'EXECUTE')
	)`).Scan(
		&newMetrics, &oldMetrics, &newPublic, &oldPublic, &tableRead, &tableWrite,
		&claimExecute, &finishExecute, &lifecyclePublic, &metricsFunctions,
	); err != nil {
		t.Fatal(err)
	}
	if !newMetrics || oldMetrics || newPublic || oldPublic || tableRead || tableWrite ||
		claimExecute || finishExecute || lifecyclePublic || metricsFunctions != 1 {
		t.Fatalf("000028 ACL mismatch: new=%t old=%t public=%t/%t lifecycle_public=%t table=%t/%t claim=%t finish=%t functions=%d",
			newMetrics, oldMetrics, newPublic, oldPublic, lifecyclePublic,
			tableRead, tableWrite, claimExecute, finishExecute, metricsFunctions)
	}

	if err := metrics.QueryRow(ctx,
		`SELECT count(*) FROM sentinelflow.control_observability_samples_000024()`).Scan(new(int)); lifecycleMetricsPGCode(err) != "42501" {
		t.Fatalf("old aggregate remained executable: %v", err)
	}
	if err := metrics.QueryRow(ctx,
		`SELECT count(*) FROM sentinelflow.lifecycle_inspection_schedules_000026`).Scan(new(int)); lifecycleMetricsPGCode(err) != "42501" {
		t.Fatalf("lifecycle table became readable: %v", err)
	}
	if err := metrics.QueryRow(ctx, `
SELECT count(*) FROM sentinelflow.claim_lifecycle_inspection_schedule_000026(
    'metrics-probe', 'metrics-probe', 30
)`).Scan(new(int)); lifecycleMetricsPGCode(err) != "42501" {
		t.Fatalf("lifecycle claim became executable: %v", err)
	}
	if err := metrics.QueryRow(ctx, `
SELECT sentinelflow.finish_lifecycle_inspection_failure_000026(
    '019f0000-0000-7000-8000-000000002801',
    '019f0000-0000-4000-8000-000000002802', 1, 'context_cancelled',
    'sha256:0000000000000000000000000000000000000000000000000000000000000000', 1
)`).Scan(new(string)); lifecycleMetricsPGCode(err) != "42501" {
		t.Fatalf("lifecycle finish became executable: %v", err)
	}
}

func assertEmptyLifecycleSamples(t *testing.T, samples []Sample) {
	t.Helper()
	for _, sample := range samples {
		if strings.HasPrefix(sample.Name, "sentinelflow_control_lifecycle_") && sample.Value != 0 {
			t.Fatalf("empty lifecycle sample is nonzero: %+v", sample)
		}
	}
}

func seedLifecycleMetricMatrix(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	if _, err := owner.Exec(ctx, `
BEGIN;
SET LOCAL session_replication_role = replica;
WITH
clock AS MATERIALIZED (
    SELECT clock_timestamp() AS observed_at
),
purposes(purpose, due_age_seconds, lease_lag_seconds) AS (
    VALUES
        ('reconciliation', 120, 45),
        ('expiry_confirmation', 90, 35),
        ('operator_status', 30, -15)
),
states(state) AS (
    VALUES ('pending'), ('leased'), ('retry'), ('dispatched'), ('completed'), ('dead')
),
fixture AS (
    SELECT purpose.purpose, purpose.due_age_seconds, purpose.lease_lag_seconds,
           state.state, clock.observed_at,
           CASE
               WHEN state.state = 'leased' THEN
                   clock.observed_at - make_interval(
                       secs => CASE purpose.purpose
                           WHEN 'reconciliation' THEN 60
                           WHEN 'expiry_confirmation' THEN 50
                           ELSE 15
                       END
                   )
               ELSE clock.observed_at - interval '180 seconds'
           END AS lease_start
    FROM purposes purpose CROSS JOIN states state CROSS JOIN clock
)
INSERT INTO sentinelflow.lifecycle_inspection_schedules_000026 (
    schedule_id, authorization_id, dispatch_job_id, source_result_id,
    source_result_digest, action_id, action_version, policy_id, policy_version,
    target_ipv4, original_add_digest, original_authorization_digest,
    evidence_snapshot_digest, validation_snapshot_id, validation_snapshot_digest,
    owned_schema_digest, purpose, due_at, state, attempts, max_attempts,
    scheduler_id, lease_owner, lease_token, leased_at, lease_expires_at,
    authorization_requested_at, authorization_valid_until, last_error_code,
    last_error_digest, dispatch_authorization_digest, created_at, updated_at
)
SELECT gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
       ('sha256:' || repeat('1', 64))::sentinelflow.sha256_digest,
       gen_random_uuid(), 1, gen_random_uuid(), 1, '203.0.113.254',
       ('sha256:' || repeat('2', 64))::sentinelflow.sha256_digest,
       ('sha256:' || repeat('3', 64))::sentinelflow.sha256_digest,
       ('sha256:' || repeat('4', 64))::sentinelflow.sha256_digest,
       gen_random_uuid(),
       ('sha256:' || repeat('5', 64))::sentinelflow.sha256_digest,
       ('sha256:' || repeat('6', 64))::sentinelflow.sha256_digest,
       fixture.purpose,
       CASE
           WHEN fixture.state = 'pending' THEN
               fixture.observed_at - make_interval(secs => fixture.due_age_seconds)
           WHEN fixture.state = 'retry' THEN fixture.observed_at + interval '60 seconds'
           ELSE fixture.observed_at + interval '300 seconds'
       END,
       fixture.state,
       CASE WHEN fixture.state = 'dead' THEN 8
            WHEN fixture.state = 'pending' THEN 0 ELSE 1 END,
       8,
       CASE WHEN fixture.state IN ('pending', 'dead') THEN NULL
            ELSE 'lifecycle-metrics-test'::sentinelflow.ascii_id END,
       CASE WHEN fixture.state IN ('pending', 'dead') THEN NULL
            ELSE 'lifecycle-metrics-test'::sentinelflow.ascii_id END,
       CASE WHEN fixture.state IN ('pending', 'dead') THEN NULL ELSE gen_random_uuid() END,
       CASE WHEN fixture.state IN ('pending', 'dead') THEN NULL ELSE fixture.lease_start END,
       CASE
           WHEN fixture.state IN ('pending', 'dead') THEN NULL
           WHEN fixture.state = 'leased' THEN
               fixture.observed_at - make_interval(secs => fixture.lease_lag_seconds)
           ELSE fixture.lease_start + interval '30 seconds'
       END,
       CASE WHEN fixture.state IN ('pending', 'dead') THEN NULL ELSE fixture.lease_start END,
       CASE WHEN fixture.state IN ('pending', 'dead') THEN NULL
            ELSE fixture.lease_start + interval '5 minutes' END,
       CASE WHEN fixture.state IN ('retry', 'dead')
            THEN 'contract_rejected'::sentinelflow.ascii_id ELSE NULL END,
       CASE WHEN fixture.state IN ('retry', 'dead')
            THEN ('sha256:' || repeat('7', 64))::sentinelflow.sha256_digest ELSE NULL END,
       CASE WHEN fixture.state IN ('dispatched', 'completed')
            THEN ('sha256:' || repeat('8', 64))::sentinelflow.sha256_digest ELSE NULL END,
       fixture.observed_at - interval '180 seconds',
       fixture.observed_at - interval '180 seconds'
FROM fixture;
COMMIT;`); err != nil {
		t.Fatalf("seed lifecycle metric matrix: %v", err)
	}
}

func assertSeededLifecycleSamples(t *testing.T, samples []Sample) {
	t.Helper()
	index := make(map[string]Sample, len(samples))
	for _, sample := range samples {
		index[sampleKey(sample)] = sample
	}
	purposes := []string{"reconciliation", "expiry_confirmation", "operator_status"}
	states := []string{"pending", "leased", "retry", "dispatched", "completed", "dead"}
	for _, purpose := range purposes {
		for _, state := range states {
			sample := Sample{
				Name:       "sentinelflow_control_lifecycle_schedules",
				Label1Name: "purpose", Label1Value: purpose,
				Label2Name: "state", Label2Value: state,
			}
			if got, ok := index[sampleKey(sample)]; !ok || got.Value != 1 {
				t.Fatalf("lifecycle matrix purpose=%s state=%s sample=%+v present=%t",
					purpose, state, got, ok)
			}
		}
	}

	assertLifecycleAge(t, index,
		"sentinelflow_control_lifecycle_oldest_due_age_seconds", "reconciliation", 120)
	assertLifecycleAge(t, index,
		"sentinelflow_control_lifecycle_oldest_due_age_seconds", "expiry_confirmation", 90)
	assertLifecycleAge(t, index,
		"sentinelflow_control_lifecycle_oldest_due_age_seconds", "operator_status", 30)
	assertLifecycleAge(t, index,
		"sentinelflow_control_lifecycle_lease_expiry_lag_seconds", "reconciliation", 45)
	assertLifecycleAge(t, index,
		"sentinelflow_control_lifecycle_lease_expiry_lag_seconds", "expiry_confirmation", 35)
	assertLifecycleAge(t, index,
		"sentinelflow_control_lifecycle_lease_expiry_lag_seconds", "operator_status", 0)
}

func assertLifecycleAge(
	t *testing.T, index map[string]Sample, name, purpose string, minimum float64,
) {
	t.Helper()
	key := sampleKey(Sample{Name: name, Label1Name: "purpose", Label1Value: purpose})
	sample, ok := index[key]
	if !ok {
		t.Fatalf("lifecycle age sample missing: %s/%s", name, purpose)
	}
	if minimum == 0 {
		if sample.Value != 0 {
			t.Fatalf("lifecycle age %s/%s=%f want=0", name, purpose, sample.Value)
		}
		return
	}
	if sample.Value < minimum || sample.Value > minimum+15 {
		t.Fatalf("lifecycle age %s/%s=%f want=[%f,%f]",
			name, purpose, sample.Value, minimum, minimum+15)
	}
}

func assertLifecycleMetricsMigrationLedger(
	t *testing.T, ctx context.Context, connection *pgx.Conn, version int,
) {
	t.Helper()
	var serverVersion, latest int
	var name string
	if err := connection.QueryRow(ctx, `
SELECT current_setting('server_version_num')::integer / 10000,
       migration.version, migration.name
FROM sentinelflow.schema_migrations migration
ORDER BY migration.version DESC LIMIT 1`).Scan(&serverVersion, &latest, &name); err != nil {
		t.Fatal(err)
	}
	if serverVersion != 17 || latest != version || name != "lifecycle_observability" {
		t.Fatalf("migration ledger server=%d latest=%d/%s", serverVersion, latest, name)
	}
}

func applyLifecycleMetricsMigrationsThrough(
	t *testing.T, ctx context.Context, connection *pgx.Conn, maximum int,
) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(lifecycleMetricsRepositoryRoot(t),
		"db", "migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		var version int
		if _, err := fmt.Sscanf(filepath.Base(path), "%06d_", &version); err != nil || version > maximum {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, string(contents)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), err)
		}
	}
}

func applyLifecycleMetricsMigration(
	t *testing.T, ctx context.Context, connection *pgx.Conn, name string,
) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(
		lifecycleMetricsRepositoryRoot(t), "db", "migrations", name,
	))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, string(contents)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

func lifecycleMetricsRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate lifecycle observability integration test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func waitForLifecycleMetricsPostgres(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func lifecycleMetricsDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := lifecycleMetricsDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func lifecycleMetricsDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func connectLifecycleMetricsPostgres(
	t *testing.T, ctx context.Context, connectionString string,
) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("connect to disposable PostgreSQL 17")
	return nil
}

func lifecycleMetricsPGCode(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}
