//go:build integration

package detectionworker

import (
	"context"
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

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const detectionPostgres17Image = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"

func TestDurableDetectionCorrelationLifecycleAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-detection-%d", time.Now().UnixNano())
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

	var serverNow time.Time
	if err := connection.QueryRow(ctx,
		`SELECT date_trunc('milliseconds', clock_timestamp())`).Scan(&serverNow); err != nil {
		t.Fatal(err)
	}
	firstEvaluation := serverNow.Add(-20 * time.Minute)
	seedExpectedGatewaySource(t, ctx, connection, firstEvaluation.Add(-time.Hour))
	firstJob := seedBurstDetectionJob(t, ctx, connection, 1, firstEvaluation, true)

	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	runtimeOne := newPostgreSQLRuntime(t, store, "detection-pg-one")
	first, err := runtimeOne.RunOnce(ctx)
	if err != nil || first.Outcome != worker.OutcomeCompleted ||
		first.RunOutcome != RunComplete || first.SignalCount != 1 || first.IncidentMutations != 1 {
		t.Fatalf("first run=%+v err=%v", first, err)
	}
	if first.JobID != firstJob {
		t.Fatalf("first job=%s want=%s", first.JobID, firstJob)
	}
	assertIncidentVersion(t, ctx, connection, 1, "open", "created", 1)
	assertDetectionArtifacts(t, ctx, connection, 1, 1, 1)

	closed, err := store.CloseIdle(ctx, 10)
	if err != nil || closed != 1 {
		t.Fatalf("CloseIdle()=%d err=%v", closed, err)
	}
	assertIncidentVersion(t, ctx, connection, 2, "closed", "closed", 1)

	if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	secondEvaluation := serverNow.Add(-4 * time.Minute)
	secondJob := seedBurstDetectionJob(t, ctx, connection, 3, secondEvaluation, true)
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	second, err := runtimeOne.RunOnce(ctx)
	if err != nil || second.JobID != secondJob || second.RunOutcome != RunComplete ||
		second.SignalCount != 1 || second.IncidentMutations != 1 {
		t.Fatalf("second run=%+v err=%v", second, err)
	}
	assertIncidentVersion(t, ctx, connection, 3, "open", "reopened", 2)
	assertDetectionArtifacts(t, ctx, connection, 2, 2, 2)

	// Exact completed-job replay has no lease and cannot refresh evidence or
	// increment the incident. This is the restart-safe idempotency boundary.
	replay, err := runtimeOne.RunOnce(ctx)
	if err != nil || replay.Outcome != worker.OutcomeNoJob {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	assertIncidentVersion(t, ctx, connection, 3, "open", "reopened", 2)

	if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	thirdJob := seedIncompleteDetectionJob(t, ctx, connection, 5, serverNow)
	secondConnection := connectDetectionPostgres(t, ctx, connectionString)
	t.Cleanup(func() { _ = secondConnection.Close(context.Background()) })
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err = secondConnection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	secondStore, err := NewPostgreSQLStore(secondConnection)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTwo := newPostgreSQLRuntime(t, secondStore, "detection-pg-two")
	type runResult struct {
		result Result
		err    error
	}
	results := make(chan runResult, 2)
	start := make(chan struct{})
	for _, target := range []*Runtime{runtimeOne, runtimeTwo} {
		target := target
		go func() {
			<-start
			value, runErr := target.RunOnce(ctx)
			results <- runResult{value, runErr}
		}()
	}
	close(start)
	retried, empty := 0, 0
	for range 2 {
		value := <-results
		if value.err != nil {
			t.Fatal(value.err)
		}
		switch value.result.Outcome {
		case worker.OutcomeRetryScheduled:
			retried++
			if value.result.JobID != thirdJob || value.result.RunOutcome != RunIncomplete ||
				value.result.SignalCount != 0 || value.result.IncidentMutations != 0 ||
				value.result.FailureCode != "detection_source_coverage_incomplete" ||
				value.result.RetryAt == nil {
				t.Fatalf("incomplete retry=%+v", value.result)
			}
		case worker.OutcomeNoJob:
			empty++
		default:
			t.Fatalf("unexpected concurrent result=%+v", value.result)
		}
	}
	if retried != 1 || empty != 1 {
		t.Fatalf("concurrent retried=%d empty=%d", retried, empty)
	}
	assertIncidentVersion(t, ctx, connection, 3, "open", "reopened", 2)
	var prematureRuns int
	if err = connection.QueryRow(ctx, `
SELECT count(*) FROM sentinelflow.detector_runs WHERE job_id = $1::uuid`,
		thirdJob).Scan(&prematureRuns); err != nil || prematureRuns != 0 {
		t.Fatalf("premature detector runs=%d err=%v", prematureRuns, err)
	}

	// Exhaust the same durable job under the migration role. Only its final
	// bounded attempt may persist an incomplete detector run.
	if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err = secondConnection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, `
WITH timing AS MATERIALIZED (SELECT clock_timestamp() AS now)
UPDATE sentinelflow.outbox_jobs
SET attempts = max_attempts - 1, available_at = timing.now, updated_at = timing.now
FROM timing
WHERE job_id = $1::uuid AND state = 'retry'`, thirdJob); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err = secondConnection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	results = make(chan runResult, 2)
	start = make(chan struct{})
	for _, target := range []*Runtime{runtimeOne, runtimeTwo} {
		target := target
		go func() {
			<-start
			value, runErr := target.RunOnce(ctx)
			results <- runResult{value, runErr}
		}()
	}
	close(start)
	completed, empty := 0, 0
	for range 2 {
		value := <-results
		if value.err != nil {
			t.Fatal(value.err)
		}
		switch value.result.Outcome {
		case worker.OutcomeCompleted:
			completed++
			if value.result.JobID != thirdJob || value.result.RunOutcome != RunIncomplete ||
				value.result.SignalCount != 0 || value.result.IncidentMutations != 0 {
				t.Fatalf("terminal incomplete run=%+v", value.result)
			}
		case worker.OutcomeNoJob:
			empty++
		default:
			t.Fatalf("unexpected terminal concurrent result=%+v", value.result)
		}
	}
	if completed != 1 || empty != 1 {
		t.Fatalf("terminal concurrent completed=%d empty=%d", completed, empty)
	}
	var incompleteRuns int
	if err = connection.QueryRow(ctx, `
SELECT count(*) FROM sentinelflow.detector_runs
WHERE outcome = 'incomplete' AND signal_count = 0 AND incident_mutation_count = 0`).Scan(&incompleteRuns); err != nil || incompleteRuns != 1 {
		t.Fatalf("incomplete detector runs=%d err=%v", incompleteRuns, err)
	}

	// Append-only evidence/version history cannot be rewritten even by the
	// operational worker role.
	if _, err = connection.Exec(ctx, `
UPDATE sentinelflow.incident_version_history SET kind = 'unknown'`); err == nil {
		t.Fatal("worker rewrote immutable incident version history")
	}
}

func newPostgreSQLRuntime(t *testing.T, store Store, owner string) *Runtime {
	t.Helper()
	config := DefaultConfig(owner)
	config.LeaseDuration = 30 * time.Second
	value, err := New(store, detection.NewDefault(), config, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func seedExpectedGatewaySource(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	effectiveAt time.Time,
) {
	t.Helper()
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.expected_source_bindings (
    binding_id, sender_id, endpoint_kind, endpoint_path, service_label,
    key_id, config_digest, binding_digest, effective_at
) VALUES (
    '019f1000-0000-8000-8000-000000000001', 'gateway-main', 'gateway',
    '/internal/v1/gateway-events', 'demo-app', 'gateway-key',
	'sha256:1111111111111111111111111111111111111111111111111111111111111111',
	'sha256:2222222222222222222222222222222222222222222222222222222222222222', $1
)`, effectiveAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES (
    'gateway-main', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
    NULL, false, false, $1
)`, effectiveAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
}

func seedBurstDetectionJob(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	firstSequence int,
	evaluatedAt time.Time,
	coverage bool,
) string {
	t.Helper()
	evaluatedAt = databaseTime(evaluatedAt)
	firstBatch := integrationUUID(0x1000 + firstSequence)
	secondBatch := integrationUUID(0x1000 + firstSequence + 1)
	firstDigest := digestBytes([]byte("batch-" + firstBatch))
	secondDigest := digestBytes([]byte("batch-" + secondBatch))
	seedBurstBatch(t, ctx, connection, firstBatch, firstSequence, firstDigest,
		evaluatedAt, 0, 100, false)
	return seedBurstBatch(t, ctx, connection, secondBatch, firstSequence+1,
		secondDigest, evaluatedAt, 100, 20, coverage)
}

func seedBurstBatch(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	batchID string,
	sequence int,
	rawDigest string,
	evaluatedAt time.Time,
	startIndex, count int,
	coverage bool,
) string {
	t.Helper()
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	receivedAt := evaluatedAt
	if startIndex == 0 {
		receivedAt = evaluatedAt.Add(-2 * time.Second)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA', $1::uuid, $2, 'gateway', 'event-batch-v1',
    $3, 1000, $4, $5, $5, 'gateway-key'
)`, batchID, sequence, rawDigest, count, receivedAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
	firstSequence := sequence
	if startIndex >= 100 {
		firstSequence--
	}
	for index := startIndex; index < startIndex+count; index++ {
		completedAt := evaluatedAt.Add(-2 * time.Second).Add(time.Duration(index%100) * time.Millisecond)
		if index >= 100 {
			completedAt = evaluatedAt.Add(-time.Duration(index-100) * time.Millisecond)
		}
		eventID := integrationUUID(firstSequence*1000 + index + 1)
		requestID := integrationUUID(firstSequence*1000 + index + 201)
		traceID := integrationUUID(firstSequence*1000 + index + 401)
		_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, received_at,
    trust_state, trust_reason
) VALUES (
    $1::uuid, 'gateway-http-v1', 'gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA', $2::uuid, $3,
    $4::uuid, $5::uuid, $6::timestamptz - interval '1 millisecond', $6, '203.0.113.9', 'GET',
    'HTTP/1.1', 'public', 'path-catalog-v1', 'none', 'demo.test', 'demo-app',
    200, 0, 0, 1, $6, 'trusted', 'none'
)`, eventID, batchID, digestBytes([]byte("event-"+eventID)), requestID, traceID, completedAt.UTC())
		if err != nil {
			t.Fatal(err)
		}
	}
	if coverage {
		coverageID := integrationUUID(0x3000 + firstSequence)
		segmentID := "019f1000-0000-8000-8000-000000000002"
		_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.source_coverage_attestations (
    coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
    sender_epoch, segment_id, previous_coverage_digest, coverage_start, coverage_end,
    covered_through_batch_id, covered_through_sequence, coverage_digest, binding_id,
    raw_body_digest, received_at, trust_state, trust_reason
) VALUES (
    $1::uuid, 'source-coverage-v1', $2, 'gateway-main', 'gateway',
    'AAAAAAAAAAAAAAAAAAAAAA', $3::uuid, NULL, $4::timestamptz - interval '5 minutes', $4,
    $5::uuid, $6, $7, '019f1000-0000-8000-8000-000000000001',
    $8, $4, 'trusted', 'none'
)`, coverageID, digestBytes([]byte("coverage-idempotency-"+coverageID)), segmentID,
			evaluatedAt.UTC(), batchID, sequence,
			digestBytes([]byte("coverage-"+coverageID)), rawDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = $1,
    last_acknowledged_body_digest = $2,
    updated_at = GREATEST(updated_at, $3::timestamptz)
WHERE sender_id = 'gateway-main' AND endpoint_kind = 'gateway'`,
		sequence, rawDigest, receivedAt.UTC()); err != nil {
		t.Fatal(err)
	}
	jobID := ""
	if coverage {
		jobID = appendExactDetectionOutbox(t, ctx, tx, batchID, rawDigest)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return jobID
}

func seedIncompleteDetectionJob(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	sequence int,
	evaluatedAt time.Time,
) string {
	t.Helper()
	evaluatedAt = databaseTime(evaluatedAt)
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	batchID := integrationUUID(0x5000 + sequence)
	rawDigest := digestBytes([]byte("incomplete-batch-" + batchID))
	eventID := integrationUUID(0x6000 + sequence)
	_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA', $1::uuid, $2, 'gateway', 'event-batch-v1',
    $3, 100, 1, $4, $4, 'gateway-key'
)
`, batchID, sequence, rawDigest, evaluatedAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, received_at,
    trust_state, trust_reason
) VALUES (
    $3::uuid, 'gateway-http-v1', 'gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA', $1::uuid, $4,
    $5::uuid, $6::uuid, $2::timestamptz - interval '1 millisecond', $2, '203.0.113.9', 'GET',
    'HTTP/1.1', 'public', 'path-catalog-v1', 'none', 'demo.test', 'demo-app',
    200, 0, 0, 1, $2, 'trusted', 'none'
)`, batchID, evaluatedAt.UTC(), eventID,
		digestBytes([]byte("event-"+eventID)), integrationUUID(0x7000+sequence),
		integrationUUID(0x8000+sequence))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = $1,
    last_acknowledged_body_digest = $2,
    updated_at = GREATEST(updated_at, $3::timestamptz)
WHERE sender_id = 'gateway-main' AND endpoint_kind = 'gateway'`,
		sequence, rawDigest, evaluatedAt.UTC()); err != nil {
		t.Fatal(err)
	}
	jobID := appendExactDetectionOutbox(t, ctx, tx, batchID, rawDigest)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return jobID
}

type detectionSQLer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func appendExactDetectionOutbox(
	t *testing.T,
	ctx context.Context,
	connection detectionSQLer,
	batchID, rawDigest string,
) string {
	t.Helper()
	var jobID, idempotency string
	err := connection.QueryRow(ctx, `
WITH identity AS (
    SELECT convert_to(
        'sentinelflow ingest detect outbox v1' || chr(10) ||
        batch.sender_id || chr(10) || batch.sender_epoch || chr(10) ||
        batch.batch_id::text || chr(10), 'UTF8') AS canonical
    FROM sentinelflow.ingest_batches batch
    WHERE batch.sender_id = 'gateway-main' AND batch.batch_id = $1::uuid
      AND batch.raw_body_digest = $2
)
SELECT sentinelflow.detection_uuid_v8(canonical)::text,
       sentinelflow.detection_sha256(canonical)::text
FROM identity`, batchID, rawDigest).Scan(&jobID, &idempotency)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, `
SELECT sentinelflow.append_ingest_detect_outbox(
    'gateway-main', $1::uuid, $2, $3::uuid, $4
)`, batchID, rawDigest, jobID, idempotency); err != nil {
		t.Fatal(err)
	}
	return jobID
}

func assertIncidentVersion(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	version int,
	state, mutation string,
	signalCount int,
) {
	t.Helper()
	var currentVersion, evidenceVersion, historyCount, versionSignals int
	var currentState, mutationKind, score string
	err := connection.QueryRow(ctx, `
SELECT incident.version, incident.evidence_version, incident.state,
       incident.deterministic_score::text,
       history.mutation_kind,
       (SELECT count(*) FROM sentinelflow.incident_version_history
        WHERE incident_id = incident.incident_id),
       (SELECT count(*) FROM sentinelflow.incident_version_signals
        WHERE incident_id = incident.incident_id AND incident_version = incident.version)
FROM sentinelflow.incidents incident
JOIN sentinelflow.incident_version_history history
  ON history.incident_id = incident.incident_id
 AND history.incident_version = incident.version`,
	).Scan(&currentVersion, &evidenceVersion, &currentState, &score,
		&mutationKind, &historyCount, &versionSignals)
	wantEvidenceVersion := version
	if mutation == "closed" {
		wantEvidenceVersion = version - 1
	}
	if err != nil || currentVersion != version || evidenceVersion != wantEvidenceVersion ||
		currentState != state || score != "1.00000" ||
		mutationKind != mutation || historyCount != version || versionSignals != signalCount {
		t.Fatalf("incident version=%d evidence_version=%d state=%s score=%s mutation=%s history=%d signals=%d err=%v",
			currentVersion, evidenceVersion, currentState, score, mutationKind,
			historyCount, versionSignals, err)
	}
}

func assertDetectionArtifacts(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	signals, snapshots, analysisJobs int,
) {
	t.Helper()
	var signalCount, snapshotCount, analysisCount int
	err := connection.QueryRow(ctx, `
SELECT (SELECT count(*) FROM sentinelflow.signals),
       (SELECT count(*) FROM sentinelflow.evidence_snapshots),
       (SELECT count(*) FROM sentinelflow.outbox_jobs WHERE kind = 'analyze')`).Scan(
		&signalCount, &snapshotCount, &analysisCount)
	if err != nil || signalCount != signals || snapshotCount != snapshots || analysisCount != analysisJobs {
		t.Fatalf("signals=%d snapshots=%d analysis=%d err=%v", signalCount, snapshotCount, analysisCount, err)
	}
}

func integrationUUID(value int) string {
	return fmt.Sprintf("019f2000-0000-8000-8000-%012x", value)
}

func applyDetectionMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, execErr := connection.Exec(ctx, string(contents)); execErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), execErr)
		}
	}
}

func connectDetectionPostgres(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("connect PostgreSQL 17")
	return nil
}

func waitDetectionPostgres(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func detectionDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := detectionDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 {
		t.Fatalf("unexpected port output %q", output)
	}
	return parts[len(parts)-1]
}

func detectionDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
