//go:build integration

package detectionworker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

func TestDelayedCrossSourceCoverageRecoversAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-cross-source-%d", time.Now().UnixNano())
	detectionDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only", "--publish", "127.0.0.1::5432",
		detectionPostgres17Image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitDetectionPostgres(t, ctx, container)
	port := detectionDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port)
	connection := connectDetectionPostgres(t, ctx, connectionString)
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	applyDetectionMigrations(t, ctx, connection)
	verifyCrossSourceMigrationLifecycle(t, ctx, connection)

	var serverNow time.Time
	if err := connection.QueryRow(ctx,
		`SELECT date_trunc('milliseconds', clock_timestamp())`).Scan(&serverNow); err != nil {
		t.Fatal(err)
	}
	evaluatedAt := serverNow.Add(-2 * time.Minute)
	jobID := seedDelayedCrossSourceFixture(t, ctx, connection, evaluatedAt)
	secondConnection := connectDetectionPostgres(t, ctx, connectionString)
	t.Cleanup(func() { _ = secondConnection.Close(context.Background()) })
	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := secondConnection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	firstStore, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := NewPostgreSQLStore(secondConnection)
	if err != nil {
		t.Fatal(err)
	}
	firstRuntime := newCrossSourceRuntime(t, firstStore, "cross-source-one",
		"019f0000-0000-4000-8000-000000000181")
	secondRuntime := newCrossSourceRuntime(t, secondStore, "cross-source-two",
		"019f0000-0000-4000-8000-000000000182")

	results := runCrossSourceConcurrent(ctx, firstRuntime, secondRuntime)
	retried, empty := 0, 0
	for _, value := range results {
		if value.err != nil {
			t.Fatal(value.err)
		}
		switch value.result.Outcome {
		case worker.OutcomeRetryScheduled:
			retried++
			if value.result.JobID != jobID || value.result.RunOutcome != RunIncomplete ||
				value.result.FailureCode != "detection_source_coverage_incomplete" ||
				value.result.RetryAt == nil {
				t.Fatalf("initial recovery result=%+v", value.result)
			}
		case worker.OutcomeNoJob:
			empty++
		default:
			t.Fatalf("unexpected initial recovery result=%+v", value.result)
		}
	}
	if retried != 1 || empty != 1 {
		t.Fatalf("initial concurrent retried=%d empty=%d", retried, empty)
	}

	if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err = secondConnection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	assertDetectionRetryHasNoArtifacts(t, ctx, connection, jobID)
	appendCrossSourceCoverage(t, ctx, connection, evaluatedAt)
	if _, err = connection.Exec(ctx, `
WITH timing AS MATERIALIZED (SELECT clock_timestamp() AS now)
UPDATE sentinelflow.outbox_jobs
SET available_at = timing.now, updated_at = timing.now
FROM timing
WHERE job_id = $1::uuid AND state = 'retry'`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err = secondConnection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}

	results = runCrossSourceConcurrent(ctx, firstRuntime, secondRuntime)
	completed, empty := 0, 0
	for _, value := range results {
		if value.err != nil {
			t.Fatal(value.err)
		}
		switch value.result.Outcome {
		case worker.OutcomeCompleted:
			completed++
			if value.result.JobID != jobID || value.result.RunOutcome != RunComplete ||
				value.result.SignalCount != 2 || value.result.IncidentMutations != 2 {
				t.Fatalf("recovered result=%+v", value.result)
			}
		case worker.OutcomeNoJob:
			empty++
		default:
			t.Fatalf("unexpected recovered result=%+v", value.result)
		}
	}
	if completed != 1 || empty != 1 {
		t.Fatalf("recovered concurrent completed=%d empty=%d", completed, empty)
	}
	assertRecoveredCrossSourceArtifacts(t, ctx, connection, jobID, evaluatedAt)

	// A completed exact job is replay-safe: neither another lease nor another
	// signal/incident mutation can be produced.
	replay, err := firstRuntime.RunOnce(ctx)
	if err != nil || replay.Outcome != worker.OutcomeNoJob {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	assertRecoveredCrossSourceArtifacts(t, ctx, connection, jobID, evaluatedAt)

	// A different incomplete job persists its terminal fail-closed run only at
	// the configured maximum attempt.
	if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	maxJob := seedIncompleteDetectionJob(t, ctx, connection, 2, serverNow)
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.outbox_jobs SET max_attempts = 1
WHERE job_id = $1::uuid AND state = 'pending'`, maxJob); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	terminal, err := firstRuntime.RunOnce(ctx)
	if err != nil || terminal.Outcome != worker.OutcomeCompleted ||
		terminal.JobID != maxJob || terminal.RunOutcome != RunIncomplete ||
		terminal.SignalCount != 0 || terminal.IncidentMutations != 0 {
		t.Fatalf("terminal max-attempt result=%+v err=%v", terminal, err)
	}
	var terminalRuns int
	if err = connection.QueryRow(ctx, `
SELECT count(*) FROM sentinelflow.detector_runs
WHERE job_id = $1::uuid AND outcome = 'incomplete'
  AND signal_count = 0 AND incident_mutation_count = 0`, maxJob).Scan(&terminalRuns); err != nil || terminalRuns != 1 {
		t.Fatalf("terminal incomplete runs=%d err=%v", terminalRuns, err)
	}
	if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	assertCrossSourceDownPreservesLiveEvidence(t, ctx, connection)
}

type crossSourceRunResult struct {
	result Result
	err    error
}

func runCrossSourceConcurrent(ctx context.Context, runtimes ...*Runtime) []crossSourceRunResult {
	start := make(chan struct{})
	values := make(chan crossSourceRunResult, len(runtimes))
	for _, runtimeValue := range runtimes {
		runtimeValue := runtimeValue
		go func() {
			<-start
			result, err := runtimeValue.RunOnce(ctx)
			values <- crossSourceRunResult{result: result, err: err}
		}()
	}
	close(start)
	results := make([]crossSourceRunResult, 0, len(runtimes))
	for range runtimes {
		results = append(results, <-values)
	}
	return results
}

func newCrossSourceRuntime(
	t *testing.T,
	store Store,
	owner, leaseToken string,
) *Runtime {
	t.Helper()
	config := DefaultConfig(owner)
	config.LeaseDuration = 30 * time.Second
	config.Backoff = worker.BackoffPolicy{BaseDelay: 20 * time.Millisecond, MaxDelay: 20 * time.Millisecond}
	value, err := New(store, detection.NewDefault(), config, Dependencies{
		Tokens: fixedTokens{value: leaseToken}, Jitter: fixedJitter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func seedDelayedCrossSourceFixture(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	evaluatedAt time.Time,
) string {
	t.Helper()
	evaluatedAt = time.UnixMilli(evaluatedAt.UnixMilli()).UTC()
	gatewayBatch := integrationUUID(0x18100)
	authBatch := integrationUUID(0x18200)
	gatewayRawDigest := digestBytes([]byte("cross-source-gateway-batch"))
	authRawDigest := digestBytes([]byte("cross-source-auth-batch"))
	effectiveAt := evaluatedAt.Add(-time.Hour)
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.expected_source_bindings (
    binding_id, sender_id, endpoint_kind, endpoint_path, service_label,
    key_id, config_digest, binding_digest, effective_at
) VALUES
(
    '019f1000-0000-8000-8000-000000000001', 'gateway-main', 'gateway',
    '/internal/v1/gateway-events', 'demo-app', 'gateway-key',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222', $1
),
(
    '019f1000-0000-8000-8000-000000000018', 'auth-main', 'auth',
    '/internal/v1/auth-events', 'demo-app', 'auth-key',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444', $1
);`, effectiveAt)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES
	('gateway-main', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0, NULL, false, false, $1),
	('auth-main', 'auth', 'BBBBBBBBBBBBBBBBBBBBBB', 0, NULL, false, false, $1);`,
		evaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES
	('gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA', $1::uuid, 1, 'gateway', 'event-batch-v1',
	 $2, 2000, 20, $3, $3, 'gateway-key'),
	('auth-main', 'BBBBBBBBBBBBBBBBBBBBBB', $4::uuid, 1, 'auth', 'event-batch-v1',
	 $5, 2000, 20, $3, $3, 'auth-key')`,
		gatewayBatch, gatewayRawDigest, evaluatedAt, authBatch, authRawDigest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest = CASE endpoint_kind
        WHEN 'gateway' THEN $1 ELSE $2 END,
    updated_at = $3
WHERE sender_id IN ('gateway-main', 'auth-main')`,
		gatewayRawDigest, authRawDigest, evaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	for index := 0; index < detection.CredentialStuffingEventThreshold; index++ {
		gatewayEventID := integrationUUID(0x18300 + index)
		authEventID := integrationUUID(0x18400 + index)
		requestID := integrationUUID(0x18500 + index)
		traceID := integrationUUID(0x18600 + index)
		gatewayAt := evaluatedAt.Add(-time.Duration(19-index) * time.Second)
		authAt := evaluatedAt.Add(-time.Duration(200-index*10) * time.Second)
		bindingState, bindingReason := "verified", "verified"
		var boundGateway any = gatewayEventID
		var bindingResolved any = evaluatedAt
		if index == detection.CredentialStuffingEventThreshold-1 {
			bindingState, bindingReason = "pending", "awaiting_gateway_event"
			boundGateway = nil
			bindingResolved = nil
		}
		_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, received_at,
    trust_state, trust_reason
) VALUES (
    $1::uuid, 'gateway-http-v1', 'gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA', $2::uuid, $3,
    $4::uuid, $5::uuid, $6::timestamptz - interval '1 millisecond', $6,
    '203.0.113.18', 'POST', 'HTTP/1.1', 'login', 'path-catalog-v1', 'none',
	'demo.test', 'demo-app', 401, 0, 0, 1, $7, 'trusted', 'none'
)`, gatewayEventID, gatewayBatch, digestBytes([]byte("gateway-"+gatewayEventID)),
			requestID, traceID, gatewayAt, evaluatedAt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.auth_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    gateway_request_id, trace_id, occurred_at, source_ip, service_label, route_label,
    account_hash, outcome, received_at, trust_state, trust_reason, binding_state,
    binding_deadline, binding_reason, bound_gateway_event_id, binding_resolved_at
) VALUES (
	$1::uuid, 'auth-event-v1', 'auth-main', 'BBBBBBBBBBBBBBBBBBBBBB', $2::uuid, $3,
	$4::uuid, $5::uuid, $6, '203.0.113.18', 'demo-app', 'login', $8, 'failed',
	$7, 'trusted', 'none', $9, $7::timestamptz + interval '5 minutes', $10,
	$11::uuid, $12
)`, authEventID, authBatch, digestBytes([]byte("auth-"+authEventID)),
			requestID, traceID, authAt, evaluatedAt,
			fmt.Sprintf("hmac-sha256:%064x", index%8+1), bindingState, bindingReason,
			boundGateway, bindingResolved)
		if err != nil {
			t.Fatal(err)
		}
	}

	finalAuthID := integrationUUID(0x18400 + detection.CredentialStuffingEventThreshold - 1)
	finalGatewayID := integrationUUID(0x18300 + detection.CredentialStuffingEventThreshold - 1)
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.auth_events
SET binding_state = 'verified', binding_reason = 'verified',
    bound_gateway_event_id = $1::uuid
WHERE event_id = $2::uuid AND binding_state = 'pending'`, finalGatewayID, finalAuthID); err != nil {
		t.Fatal(err)
	}
	var jobID string
	if err = connection.QueryRow(ctx, `
SELECT job_id::text FROM sentinelflow.outbox_jobs
WHERE kind = 'detect' AND aggregate_type = 'auth_binding'
  AND aggregate_id = $1::uuid`, finalAuthID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	return jobID
}

func appendCrossSourceCoverage(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	evaluatedAt time.Time,
) {
	t.Helper()
	evaluatedAt = time.UnixMilli(evaluatedAt.UnixMilli()).UTC()
	gatewayBatch := integrationUUID(0x18100)
	authBatch := integrationUUID(0x18200)
	gatewayCoverageID := integrationUUID(0x18701)
	authCoverageID := integrationUUID(0x18702)
	gatewayRawDigest := digestBytes([]byte("cross-source-gateway-batch"))
	authRawDigest := digestBytes([]byte("cross-source-auth-batch"))
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.source_coverage_attestations (
    coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
    sender_epoch, segment_id, previous_coverage_digest, coverage_start, coverage_end,
    covered_through_batch_id, covered_through_sequence, coverage_digest, binding_id,
    raw_body_digest, received_at, trust_state, trust_reason
) VALUES
(
    $1::uuid, 'source-coverage-v1', $2, 'gateway-main', 'gateway',
    'AAAAAAAAAAAAAAAAAAAAAA', $3::uuid, NULL, $4::timestamptz - interval '5 minutes', $4,
	$5::uuid, 1, $6, '019f1000-0000-8000-8000-000000000001',
    $7, $4, 'trusted', 'none'
),
(
    $8::uuid, 'source-coverage-v1', $9, 'auth-main', 'auth',
    'BBBBBBBBBBBBBBBBBBBBBB', $10::uuid, NULL, $4::timestamptz - interval '5 minutes', $4,
	$11::uuid, 1, $12, '019f1000-0000-8000-8000-000000000018',
    $13, $4, 'trusted', 'none'
)`, gatewayCoverageID, digestBytes([]byte("gateway-coverage-idempotency")),
		integrationUUID(0x18801), evaluatedAt, gatewayBatch,
		digestBytes([]byte("gateway-coverage")), gatewayRawDigest,
		authCoverageID, digestBytes([]byte("auth-coverage-idempotency")),
		integrationUUID(0x18802), authBatch, digestBytes([]byte("auth-coverage")), authRawDigest)
	if err != nil {
		t.Fatal(err)
	}
}

func assertDetectionRetryHasNoArtifacts(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	jobID string,
) {
	t.Helper()
	var state, failureCode string
	var attempts, runs, signals, incidents int
	err := connection.QueryRow(ctx, `
SELECT job.state, job.attempts, job.last_error_code,
       (SELECT count(*) FROM sentinelflow.detector_runs WHERE job_id = job.job_id),
       (SELECT count(*) FROM sentinelflow.signals),
       (SELECT count(*) FROM sentinelflow.incidents)
FROM sentinelflow.outbox_jobs job WHERE job.job_id = $1::uuid`, jobID).Scan(
		&state, &attempts, &failureCode, &runs, &signals, &incidents)
	if err != nil || state != "retry" || attempts != 1 ||
		failureCode != "detection_source_coverage_incomplete" ||
		runs != 0 || signals != 0 || incidents != 0 {
		t.Fatalf("retry state=%s attempts=%d failure=%s runs=%d signals=%d incidents=%d err=%v",
			state, attempts, failureCode, runs, signals, incidents, err)
	}
}

func assertRecoveredCrossSourceArtifacts(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	jobID string,
	evaluatedAt time.Time,
) {
	t.Helper()
	var outcome string
	var storedEvaluation, jobCreatedAt time.Time
	var attempts, signalCount, runSignals, incidentCount int
	err := connection.QueryRow(ctx, `
SELECT run.outcome, run.evaluated_at, job.created_at, job.attempts, run.signal_count,
       (SELECT count(*) FROM sentinelflow.detector_run_signals WHERE job_id = run.job_id),
       (SELECT count(*) FROM sentinelflow.incidents)
FROM sentinelflow.detector_runs run
JOIN sentinelflow.outbox_jobs job USING (job_id)
WHERE run.job_id = $1::uuid`, jobID).Scan(
		&outcome, &storedEvaluation, &jobCreatedAt, &attempts, &signalCount,
		&runSignals, &incidentCount)
	if err != nil || outcome != "complete" || !storedEvaluation.Equal(evaluatedAt) ||
		storedEvaluation.Equal(jobCreatedAt) || attempts != 2 || signalCount != 2 ||
		runSignals != 2 || incidentCount != 1 {
		t.Fatalf("run outcome=%s evaluated=%s want=%s created=%s attempts=%d signals=%d links=%d incidents=%d err=%v",
			outcome, storedEvaluation, evaluatedAt, jobCreatedAt, attempts,
			signalCount, runSignals, incidentCount, err)
	}
	var bruteForce, credentialStuffing int
	if err = connection.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE kind = 'brute_force'),
       count(*) FILTER (WHERE kind = 'credential_stuffing')
FROM sentinelflow.signals`).Scan(&bruteForce, &credentialStuffing); err != nil ||
		bruteForce != 1 || credentialStuffing != 1 {
		t.Fatalf("brute_force=%d credential_stuffing=%d err=%v",
			bruteForce, credentialStuffing, err)
	}
}

func verifyCrossSourceMigrationLifecycle(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
) {
	t.Helper()
	down := crossSourceMigrationContents(t, "000018_cross_source_detection_recovery.down.sql")
	up := crossSourceMigrationContents(t, "000018_cross_source_detection_recovery.up.sql")
	if _, err := connection.Exec(ctx, string(down)); err != nil {
		t.Fatalf("clean 000018 down: %v", err)
	}
	var migrationCount int
	var preservedOldSource bool
	var restoredExecute bool
	if err := connection.QueryRow(ctx, `
SELECT (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 18),
       position(
           'evaluation_time := date_trunc(''milliseconds'', job.created_at);'
           IN pg_get_functiondef(
               'sentinelflow.prepare_detection_job(uuid,uuid)'::regprocedure
		   )
	   ) > 0,
	   has_function_privilege(
		   'sentinelflow_worker',
		   'sentinelflow.prepare_detection_job(uuid,uuid)',
		   'EXECUTE'
	   )`).Scan(&migrationCount, &preservedOldSource, &restoredExecute); err != nil ||
		migrationCount != 0 || !preservedOldSource || !restoredExecute {
		t.Fatalf("clean down migration=%d preserved_old=%t worker_execute=%t err=%v",
			migrationCount, preservedOldSource, restoredExecute, err)
	}
	if _, err := connection.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000018 reapply: %v", err)
	}
	if _, err := connection.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000018 idempotent reapply: %v", err)
	}
	var recoveredSource bool
	var activeExecute, preservedExecute bool
	if err := connection.QueryRow(ctx, `
SELECT (SELECT count(*) FROM sentinelflow.schema_migrations
        WHERE version = 18 AND name = 'cross_source_detection_recovery'),
       position(
           'cross-source-evaluation-time-v2'
           IN pg_get_functiondef(
               'sentinelflow.prepare_detection_job(uuid,uuid)'::regprocedure
		   )
	   ) > 0,
	   has_function_privilege(
		   'sentinelflow_worker',
		   'sentinelflow.prepare_detection_job(uuid,uuid)',
		   'EXECUTE'
	   ),
	   has_function_privilege(
		   'sentinelflow_worker',
		   'sentinelflow.prepare_detection_job_pre_000018(uuid,uuid)',
		   'EXECUTE'
	   )`).Scan(&migrationCount, &recoveredSource, &activeExecute, &preservedExecute); err != nil ||
		migrationCount != 1 || !recoveredSource || !activeExecute || preservedExecute {
		t.Fatalf("reapplied migration=%d recovered_source=%t active_execute=%t preserved_execute=%t err=%v",
			migrationCount, recoveredSource, activeExecute, preservedExecute, err)
	}
}

func assertCrossSourceDownPreservesLiveEvidence(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
) {
	t.Helper()
	down := crossSourceMigrationContents(t, "000018_cross_source_detection_recovery.down.sql")
	if _, err := connection.Exec(ctx, string(down)); err == nil {
		t.Fatal("000018 down discarded live cross-source detection evidence")
	}
	if _, err := connection.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	var migrationCount int
	var recoveredSource bool
	if err := connection.QueryRow(ctx, `
SELECT (SELECT count(*) FROM sentinelflow.schema_migrations
        WHERE version = 18 AND name = 'cross_source_detection_recovery'),
       position(
           'cross-source-evaluation-time-v2'
           IN pg_get_functiondef(
               'sentinelflow.prepare_detection_job(uuid,uuid)'::regprocedure
           )
       ) > 0`).Scan(&migrationCount, &recoveredSource); err != nil ||
		migrationCount != 1 || !recoveredSource {
		t.Fatalf("fail-stop migration=%d recovered_source=%t err=%v",
			migrationCount, recoveredSource, err)
	}
}

func crossSourceMigrationContents(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("cannot locate cross-source integration test")
	}
	contents, err := os.ReadFile(filepath.Join(
		filepath.Dir(file), "..", "..", "db", "migrations", name,
	))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
