//go:build integration

package analysisstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

func TestAnalysisLifecycleVersionAlignmentAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-analysis-lifecycle-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	admin, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	applyIntegrationMigrations(t, ctx, admin)
	installAnalysisProducerHistory(t, ctx, admin)

	workerOne := connectAnalysisWorker(t, ctx, connectionString)
	t.Cleanup(func() { _ = workerOne.Close(context.Background()) })
	storeOne, err := NewPostgreSQLStore(workerOne)
	if err != nil {
		t.Fatal(err)
	}

	// A claim that started under the pre-000017 projection is upgraded without
	// rewriting D, then finishes through the new A->T fence.
	legacyFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x080, 1, true)
	down, up := analysisLifecycleMigrationFiles(t)
	if _, err = admin.Exec(ctx, string(down)); err != nil {
		t.Fatalf("prepare populated 000017 upgrade: %v", err)
	}
	legacyJob := leaseLifecycleJob(t, ctx, storeOne, legacyFixture, 0x081, "analysis-legacy")
	legacySnapshot := prepareLifecycleJob(t, ctx, storeOne, legacyJob)
	if _, err = admin.Exec(ctx, string(up)); err != nil {
		t.Fatalf("populated 000017 upgrade: %v", err)
	}
	if _, err = admin.Exec(ctx, string(up)); err != nil {
		t.Fatalf("populated 000017 idempotent re-up: %v", err)
	}
	assertAnalysisLifecycle(t, ctx, admin, legacyFixture.IncidentID,
		legacySnapshot.AnalysisID, 2, 1, "analyzing", 1, 2, 0, 2)
	legacyFinished, legacyErr := storeOne.Finalize(ctx, lifecycleSuccessFinalize(legacyJob, legacySnapshot))
	if legacyErr != nil || !legacyFinished {
		t.Fatalf("upgraded analysis finalize finished=%v err=%v", legacyFinished, legacyErr)
	}
	assertAnalysisLifecycle(t, ctx, admin, legacyFixture.IncidentID,
		legacySnapshot.AnalysisID, 3, 1, "review_ready", 1, 2, 3, 3)

	// D=1 is the immutable evidence version, A=2 is analyzing, and T=3 is
	// review_ready. Replays cannot append a fourth lifecycle row.
	successFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x100, 1, true)
	successJob := leaseLifecycleJob(t, ctx, storeOne, successFixture, 0x101, "analysis-success")
	successSnapshot := prepareLifecycleJob(t, ctx, storeOne, successJob)
	assertAnalysisLifecycle(t, ctx, admin, successFixture.IncidentID,
		successSnapshot.AnalysisID, 2, 1, "analyzing", 1, 2, 0, 2)
	successRequest := lifecycleSuccessFinalize(successJob, successSnapshot)
	finished, err := storeOne.Finalize(ctx, successRequest)
	if err != nil || !finished {
		t.Fatalf("success finalize finished=%v err=%v", finished, err)
	}
	assertAnalysisLifecycle(t, ctx, admin, successFixture.IncidentID,
		successSnapshot.AnalysisID, 3, 1, "review_ready", 1, 2, 3, 3)
	assertAnalysisPublicationVersion(t, ctx, admin, successFixture.IncidentID,
		successSnapshot.AnalysisID, 1, true)
	if replayed, replayErr := storeOne.Finalize(ctx, successRequest); replayErr != nil || replayed {
		t.Fatalf("terminal replay finished=%v err=%v", replayed, replayErr)
	}
	if _, replayed, replayErr := storeOne.Prepare(ctx, analysisworker.PrepareRequest{
		Job: successJob.Job, LeaseToken: successJob.LeaseToken,
	}); replayErr != nil || replayed {
		t.Fatalf("terminal prepare replay prepared=%v err=%v", replayed, replayErr)
	}
	assertAnalysisLifecycle(t, ctx, admin, successFixture.IncidentID,
		successSnapshot.AnalysisID, 3, 1, "review_ready", 1, 2, 3, 3)

	// A later deterministic signal advances both aggregate and evidence version.
	// The completed analysis remains bound to D instead of being rewritten.
	appendNewEvidenceVersion(t, ctx, admin, successFixture, 4)
	assertCurrentEvidenceAndAnalysisVersion(t, ctx, admin,
		successFixture.IncidentID, successSnapshot.AnalysisID, 4, 4, 1)

	// A typed provider failure still follows D->A->T and creates no validation.
	failureFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x200, 1, true)
	failureJob := leaseLifecycleJob(t, ctx, storeOne, failureFixture, 0x201, "analysis-failure")
	failureSnapshot := prepareLifecycleJob(t, ctx, storeOne, failureJob)
	failureRequest := lifecycleFailureFinalize(failureJob, failureSnapshot)
	finished, err = storeOne.Finalize(ctx, failureRequest)
	if err != nil || !finished {
		t.Fatalf("failure finalize finished=%v err=%v", finished, err)
	}
	assertAnalysisLifecycle(t, ctx, admin, failureFixture.IncidentID,
		failureSnapshot.AnalysisID, 3, 1, "analysis_failed", 1, 2, 3, 3)
	assertAnalysisPublicationVersion(t, ctx, admin, failureFixture.IncidentID,
		failureSnapshot.AnalysisID, 1, false)

	// Operational retry before Prepare has no domain effect. The later Prepare
	// advances exactly once to A.
	retryFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x300, 1, true)
	retryJob := leaseLifecycleJob(t, ctx, storeOne, retryFixture, 0x301, "analysis-retry-one")
	retryNow := time.Now().UTC()
	retryAt := retryNow.Add(time.Millisecond)
	finished, err = storeOne.Finalize(ctx, analysisworker.FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishRetry, Now: retryNow, RetryAt: &retryAt,
			JobID: retryJob.JobID, LeaseToken: retryJob.LeaseToken,
			ErrorCode: "snapshot_unavailable", ErrorDigest: lifecycleDigest(0x301),
		},
	})
	if err != nil || !finished {
		t.Fatalf("operational retry finished=%v err=%v", finished, err)
	}
	assertIncidentProjection(t, ctx, admin, retryFixture.IncidentID, 1, 1, "open", 1)
	time.Sleep(3 * time.Millisecond)
	retryJob = leaseLifecycleJob(t, ctx, storeOne, retryFixture, 0x302, "analysis-retry-two")
	retrySnapshot := prepareLifecycleJob(t, ctx, storeOne, retryJob)
	assertAnalysisLifecycle(t, ctx, admin, retryFixture.IncidentID,
		retrySnapshot.AnalysisID, 2, 1, "analyzing", 1, 2, 0, 2)

	// Recovery of a started claim can never cross the provider boundary again.
	interruptedFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x400, 1, true)
	interruptedJob := leaseLifecycleJob(t, ctx, storeOne, interruptedFixture, 0x401, "analysis-interrupt-one")
	interruptedSnapshot := prepareLifecycleJob(t, ctx, storeOne, interruptedJob)
	expireLifecycleLease(t, ctx, admin, interruptedJob.JobID)
	interruptedJob = leaseLifecycleJob(t, ctx, storeOne, interruptedFixture, 0x402, "analysis-interrupt-two")
	if _, prepared, prepareErr := storeOne.Prepare(ctx, analysisworker.PrepareRequest{
		Job: interruptedJob.Job, LeaseToken: interruptedJob.LeaseToken,
	}); prepareErr != nil || prepared {
		t.Fatalf("interrupted recovery prepared=%v err=%v", prepared, prepareErr)
	}
	assertAnalysisLifecycle(t, ctx, admin, interruptedFixture.IncidentID,
		interruptedSnapshot.AnalysisID, 3, 1, "analysis_failed", 1, 2, 3, 3)
	assertInterruptedAttempt(t, ctx, admin, interruptedSnapshot.AnalysisID)

	// The hard fifty-reference boundary prepares all fifty without sampling.
	fiftyFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x500, 50, true)
	fiftyJob := leaseLifecycleJob(t, ctx, storeOne, fiftyFixture, 0x501, "analysis-fifty")
	fiftySnapshot := prepareLifecycleJob(t, ctx, storeOne, fiftyJob)
	if len(fiftySnapshot.Signals) != 50 {
		t.Fatalf("fifty-reference snapshot was truncated to %d", len(fiftySnapshot.Signals))
	}
	assertAnalysisLifecycle(t, ctx, admin, fiftyFixture.IncidentID,
		fiftySnapshot.AnalysisID, 2, 1, "analyzing", 50, 2, 0, 2)

	// Fifty-one is rejected in Prepare as a typed no-call; no snapshot or model
	// claim is manufactured and there is no analyzing lifecycle revision.
	fiftyOneFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x600, 51, false)
	fiftyOneJob := leaseLifecycleJob(t, ctx, storeOne, fiftyOneFixture, 0x601, "analysis-fifty-one")
	if _, prepared, prepareErr := storeOne.Prepare(ctx, analysisworker.PrepareRequest{
		Job: fiftyOneJob.Job, LeaseToken: fiftyOneJob.LeaseToken,
	}); prepareErr != nil || prepared {
		t.Fatalf("fifty-one prepared=%v err=%v", prepared, prepareErr)
	}
	assertFiftyOneNoCall(t, ctx, admin, fiftyOneFixture.IncidentID)

	// Two sessions may submit the same terminal result, but the lease fence and
	// lifecycle CAS allow exactly one D->A->T publication.
	concurrentFixture := insertAnalysisLifecycleFixture(t, ctx, admin, 0x700, 1, true)
	concurrentJob := leaseLifecycleJob(t, ctx, storeOne, concurrentFixture, 0x701, "analysis-concurrent")
	concurrentSnapshot := prepareLifecycleJob(t, ctx, storeOne, concurrentJob)
	workerTwo := connectAnalysisWorker(t, ctx, connectionString)
	t.Cleanup(func() { _ = workerTwo.Close(context.Background()) })
	storeTwo, storeErr := NewPostgreSQLStore(workerTwo)
	if storeErr != nil {
		t.Fatal(storeErr)
	}
	concurrentRequest := lifecycleSuccessFinalize(concurrentJob, concurrentSnapshot)
	type finalizeResult struct {
		finished bool
		err      error
	}
	results := make(chan finalizeResult, 2)
	start := make(chan struct{})
	for _, target := range []*PostgreSQLStore{storeOne, storeTwo} {
		go func() {
			<-start
			value, finalizeErr := target.Finalize(ctx, concurrentRequest)
			results <- finalizeResult{value, finalizeErr}
		}()
	}
	close(start)
	committed := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.finished {
			committed++
		}
	}
	if committed != 1 {
		t.Fatalf("concurrent finalization committed %d times", committed)
	}
	assertAnalysisLifecycle(t, ctx, admin, concurrentFixture.IncidentID,
		concurrentSnapshot.AnalysisID, 3, 1, "review_ready", 1, 2, 3, 3)
	assertPopulatedLifecycleRollbackFails(t, ctx, admin)
}

type lifecycleFixture struct {
	IncidentID string
	SnapshotID string
	JobID      string
	SourceIP   string
	SignalIDs  []string
}

func connectAnalysisWorker(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	connection, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		_ = connection.Close(context.Background())
		t.Fatal(err)
	}
	return connection
}

func installAnalysisProducerHistory(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	_, err := admin.Exec(ctx, `
BEGIN;
SET LOCAL ROLE sentinelflow_migration;
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES
    ('gateway.lifecycle', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
     NULL, false, false, clock_timestamp() - interval '26 hours'),
    ('auth.lifecycle', 'auth', 'BBBBBBBBBBBBBBBBBBBBBB', 0,
     NULL, false, false, clock_timestamp() - interval '26 hours');
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:0101010101010101010101010101010101010101010101010101010101010101',
    updated_at = clock_timestamp() - interval '25 hours'
WHERE sender_id = 'gateway.lifecycle' AND endpoint_kind = 'gateway';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway.lifecycle', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-00000000a001', 1, 'gateway', 'event-batch-v1',
    'sha256:0101010101010101010101010101010101010101010101010101010101010101',
    128, 1, clock_timestamp() - interval '25 hours',
    clock_timestamp() - interval '25 hours'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 2,
    last_acknowledged_body_digest =
        'sha256:0202020202020202020202020202020202020202020202020202020202020202',
    updated_at = clock_timestamp() - interval '1 minute'
WHERE sender_id = 'gateway.lifecycle' AND endpoint_kind = 'gateway';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway.lifecycle', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-00000000a002', 2, 'gateway', 'event-batch-v1',
    'sha256:0202020202020202020202020202020202020202020202020202020202020202',
    128, 1, clock_timestamp() - interval '1 minute',
    clock_timestamp() - interval '1 minute'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:0303030303030303030303030303030303030303030303030303030303030303',
    updated_at = clock_timestamp() - interval '25 hours'
WHERE sender_id = 'auth.lifecycle' AND endpoint_kind = 'auth';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'auth.lifecycle', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019b0000-0000-7000-8000-00000000a003', 1, 'auth', 'event-batch-v1',
    'sha256:0303030303030303030303030303030303030303030303030303030303030303',
    128, 1, clock_timestamp() - interval '25 hours',
    clock_timestamp() - interval '25 hours'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 2,
    last_acknowledged_body_digest =
        'sha256:0404040404040404040404040404040404040404040404040404040404040404',
    updated_at = clock_timestamp() - interval '1 minute'
WHERE sender_id = 'auth.lifecycle' AND endpoint_kind = 'auth';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'auth.lifecycle', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019b0000-0000-7000-8000-00000000a004', 2, 'auth', 'event-batch-v1',
    'sha256:0404040404040404040404040404040404040404040404040404040404040404',
    128, 1, clock_timestamp() - interval '1 minute',
    clock_timestamp() - interval '1 minute'
);
COMMIT;`)
	if err != nil {
		t.Fatalf("install producer history: %v", err)
	}
}

func insertAnalysisLifecycleFixture(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	seed, signalCount int,
	withSnapshot bool,
) lifecycleFixture {
	t.Helper()
	fixture := lifecycleFixture{
		IncidentID: lifecycleUUID(seed + 1), SnapshotID: lifecycleUUID(seed + 2),
		JobID: lifecycleUUID(seed + 3), SourceIP: fmt.Sprintf("198.51.100.%d", seed/0x100+20),
		SignalIDs: make([]string, signalCount),
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE sentinelflow_migration"); err != nil {
		t.Fatal(err)
	}
	eventTime := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, evidence_version, created_at, updated_at
) VALUES ($1::uuid, 'path_scan', 'open', $2::inet, 'demo', $3, $3,
          1.00000, 1, 1, $3, $3)`, fixture.IncidentID, fixture.SourceIP, eventTime); err != nil {
		t.Fatal(err)
	}
	for index := range signalCount {
		signalID := lifecycleUUID(seed + 100 + index)
		eventID := lifecycleUUID(seed + 300 + index)
		fixture.SignalIDs[index] = signalID
		evidenceDigest := lifecycleDigest(seed + 100 + index)
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, request_id, trace_id, started_at, completed_at,
    source_ip, method, protocol, route_label, path_catalog_version,
    suspicious_path_id, host, service_label, status_code,
    request_bytes, response_bytes, latency_ms, received_at,
    trust_state, trust_reason
) VALUES (
    $1::uuid, 'gateway-http-v1', 'gateway.lifecycle',
    'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-00000000a002', $2,
    gen_random_uuid(), gen_random_uuid(), $3, $3, $4::inet, 'GET',
    'HTTP/1.1', 'home', 'path-catalog-v1', 'admin_console',
    'demo.example', 'demo', 404, 0, 0, 1, $3, 'trusted', 'none'
)`, eventID, lifecycleDigest(seed+300+index), eventTime, fixture.SourceIP); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip,
    service_label, window_start, window_end, observed_count, distinct_count,
    threshold_count, threshold_distinct, source_health_status,
    evidence_digest, created_at
) VALUES (
    $1::uuid, 'signal-v1', 'path_scan.v1', 1, 'path_scan', $2::inet,
    'demo', $3, $3, 1, 1, 1, 1, 'complete', $4, $3
)`, signalID, fixture.SourceIP, eventTime, evidenceDigest); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.signal_evidence (
    evidence_link_id, signal_id, event_kind, gateway_event_id,
    event_time, relation_reason, created_at
) VALUES (gen_random_uuid(), $1::uuid, 'gateway', $2::uuid,
          $3, 'threshold_member', $3);
INSERT INTO sentinelflow.incident_signals (
    incident_id, signal_id, incident_version, relation_reason, linked_at
) VALUES ($4::uuid, $1::uuid, 1, 'same_source_overlap', $3);
INSERT INTO sentinelflow.incident_events (
    incident_event_id, incident_id, incident_version, event_kind,
    gateway_event_id, relation_reason, linked_at
) VALUES (gen_random_uuid(), $4::uuid, 1, 'gateway', $2::uuid,
          'threshold_member', $3)`, pgx.QueryExecModeSimpleProtocol,
			signalID, eventID, eventTime, fixture.IncidentID); err != nil {
			t.Fatal(err)
		}
	}
	historyDigest := lifecycleDigest(seed + 700)
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind,
    mutation_digest, evidence_digest, signal_count, recorded_at
) VALUES (
    $1::uuid, 1, 'open', 'path_scan', $2::inet, 'demo', $3, $3,
    1.00000, 'created', $4, $5, $6, $3
)`, fixture.IncidentID, fixture.SourceIP, eventTime,
		lifecycleDigest(seed+701), historyDigest, signalCount); err != nil {
		t.Fatal(err)
	}
	for index, signalID := range fixture.SignalIDs {
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_version_signals (
    incident_id, incident_version, signal_id, ordinal
) VALUES ($1::uuid, 1, $2::uuid, $3)`, fixture.IncidentID, signalID, index+1); err != nil {
			t.Fatal(err)
		}
	}
	if withSnapshot {
		canonical := []byte(fmt.Sprintf(`{"fixture":"%s"}`, fixture.SnapshotID))
		snapshotDigest := sha256Digest(canonical)
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.evidence_snapshots (
    evidence_snapshot_id, schema_version, incident_id, incident_version,
    source_ip, service_label, window_start, window_end, source_health_status,
    signal_count, expanded_event_count, snapshot_digest, created_at, expires_at
) VALUES (
    $1::uuid, 'evidence-snapshot-v1', $2::uuid, 1, $3::inet, 'demo',
    $4, $4, 'complete', $5, $5, $6, $4,
    clock_timestamp() + interval '30 minutes'
);
INSERT INTO sentinelflow.evidence_snapshot_artifacts (
    evidence_snapshot_id, schema_version, source_health_digest,
    canonical_bytes, canonical_digest, created_at
) VALUES ($1::uuid, 'evidence-snapshot-v1', $7, $8, $6, $4)`,
			pgx.QueryExecModeSimpleProtocol, fixture.SnapshotID,
			fixture.IncidentID, fixture.SourceIP, eventTime,
			signalCount, snapshotDigest, lifecycleDigest(seed+702), canonical); err != nil {
			t.Fatal(err)
		}
		for index, signalID := range fixture.SignalIDs {
			eventID := lifecycleUUID(seed + 300 + index)
			if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.evidence_snapshot_signals (
    evidence_snapshot_id, ordinal, signal_id, evidence_id,
    evidence_digest, expanded_event_count
) VALUES ($1::uuid, $2, $3::uuid, $3, $4, 1);
INSERT INTO sentinelflow.evidence_snapshot_events (
    evidence_snapshot_event_id, evidence_snapshot_id, signal_id,
    event_kind, gateway_event_id, event_time
) VALUES (gen_random_uuid(), $1::uuid, $3::uuid, 'gateway', $5::uuid, $6)`,
				pgx.QueryExecModeSimpleProtocol, fixture.SnapshotID, index+1, signalID,
				lifecycleDigest(seed+100+index), eventID, eventTime); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    idempotency_key, state, available_at, max_attempts, created_at, updated_at
) VALUES ($1::uuid, 'analyze', 'incident', $2::uuid, 1, $3,
          'pending', clock_timestamp(), 8, clock_timestamp(), clock_timestamp())`,
		fixture.JobID, fixture.IncidentID, lifecycleDigest(seed+703)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func leaseLifecycleJob(
	t *testing.T,
	ctx context.Context,
	store *PostgreSQLStore,
	fixture lifecycleFixture,
	tokenSeed int,
	owner string,
) worker.LeasedJob {
	t.Helper()
	now := time.Now().UTC()
	job, found, err := store.Lease(ctx, worker.LeaseRequest{
		Now: now, LeaseToken: lifecycleToken(tokenSeed), LeaseOwner: owner,
		LeaseExpiresAt: now.Add(30 * time.Second),
	})
	if err != nil || !found || job.JobID != fixture.JobID {
		t.Fatalf("lease %s job=%+v found=%v err=%v", fixture.JobID, job, found, err)
	}
	return job
}

func prepareLifecycleJob(
	t *testing.T,
	ctx context.Context,
	store *PostgreSQLStore,
	job worker.LeasedJob,
) analysisworker.Snapshot {
	t.Helper()
	snapshot, prepared, err := store.Prepare(ctx, analysisworker.PrepareRequest{
		Job: job.Job, LeaseToken: job.LeaseToken,
	})
	if err != nil || !prepared {
		t.Fatalf("prepare job=%s prepared=%v err=%v", job.JobID, prepared, err)
	}
	return snapshot
}

func lifecycleSuccessFinalize(
	job worker.LeasedJob,
	snapshot analysisworker.Snapshot,
) analysisworker.FinalizeRequest {
	evidenceIDs := make([]string, len(snapshot.Signals))
	for index, signal := range snapshot.Signals {
		evidenceIDs[index] = signal.SignalID
	}
	command := fmt.Sprintf(
		"add element inet sentinelflow blacklist_ipv4 { %s timeout 30m }", snapshot.SourceIP,
	)
	policyDocument := map[string]any{
		"schema_version": "response-policy-v1", "action": "block_ip",
		"target_ip": snapshot.SourceIP, "ttl_seconds": 1800,
		"evidence_ids": evidenceIDs, "rationale": "Deterministic evidence warrants review.",
	}
	candidateDocument := map[string]any{
		"schema_version": "nft-blacklist-v1", "target_ip": snapshot.SourceIP,
		"timeout": "30m", "evidence_ids": evidenceIDs, "command": command,
	}
	analysisDocument := map[string]any{
		"schema_version":   "sentinelflow_analysis_v1",
		"incident_summary": "Deterministic path scan evidence was observed.",
		"classification":   "path_scan", "confidence": 0.9, "uncertainty": "",
		"false_positive_factors": []string{"Authorized scanner"},
		"evidence_ids":           evidenceIDs, "policy": policyDocument,
		"nftables_command_candidate": candidateDocument,
	}
	policyJSON, _ := json.Marshal(policyDocument)
	candidateJSON, _ := json.Marshal(candidateDocument)
	analysisJSON, _ := json.Marshal(analysisDocument)
	return analysisworker.FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishCompleted, Now: time.Now().UTC(),
			JobID: job.JobID, LeaseToken: job.LeaseToken,
		},
		Mutation: &analysisworker.Mutation{
			IncidentID: snapshot.IncidentID, IncidentVersion: snapshot.IncidentVersion,
			AnalysisID: snapshot.AnalysisID, EvidenceSnapshotID: snapshot.EvidenceSnapshotID,
			EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest,
			State:                  analysisworker.StateReviewReady, AuditAction: "analysis_succeeded",
			ValidationRequested: true,
			Success: &analysisworker.Success{
				ProviderKind: string(ai.ProviderOpenAIResponses),
				AdapterID:    ai.OpenAIResponsesAdapterID,
				Model:        ai.Model, ReasoningEffort: ai.ReasoningEffort,
				RateCardVersion: "operator-v1", ResponseID: "resp_lifecycle", Attempts: 1,
				InputBytes: 512, InputDigest: lifecycleDigest(0xb01),
				InputSchemaDigest: lifecycleDigest(0xb02), PromptDigest: lifecycleDigest(0xb03),
				OutputSchemaDigest: lifecycleDigest(0xb04), OutputDigest: sha256Digest(analysisJSON),
				AnalysisJSON: analysisJSON, PolicyJSON: policyJSON,
				CommandCandidateJSON:   candidateJSON,
				GeneratedCommandDigest: sha256Digest([]byte(command)), EvidenceIDs: evidenceIDs,
				Usage: ai.Usage{InputTokens: 120, CachedInputTokens: 20, OutputTokens: 80, Trusted: true},
			},
		},
	}
}

func lifecycleFailureFinalize(
	job worker.LeasedJob,
	snapshot analysisworker.Snapshot,
) analysisworker.FinalizeRequest {
	return analysisworker.FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishCompleted, Now: time.Now().UTC(),
			JobID: job.JobID, LeaseToken: job.LeaseToken,
		},
		Mutation: &analysisworker.Mutation{
			IncidentID: snapshot.IncidentID, IncidentVersion: snapshot.IncidentVersion,
			AnalysisID: snapshot.AnalysisID, EvidenceSnapshotID: snapshot.EvidenceSnapshotID,
			EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest,
			State:                  analysisworker.StateAnalysisFailed, AuditAction: "analysis_failed",
			Failure: &analysisworker.Failure{
				Reason: ai.FailureTimeout, Attempts: 2, RetryEligible: true,
				InputBytes: 512, InputDigest: lifecycleDigest(0xb05),
			},
		},
	}
}

func assertAnalysisLifecycle(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	incidentID, analysisID string,
	wantVersion, wantEvidenceVersion int,
	wantState string,
	wantSignalCount, wantAnalyzing, wantTerminal, wantHistory int,
) {
	t.Helper()
	var version, evidenceVersion, analyzing, terminal, historyCount int
	var state string
	err := admin.QueryRow(ctx, `
SELECT incident.version, incident.evidence_version, incident.state,
       COALESCE(claim.analyzing_incident_version, 0),
       COALESCE(claim.terminal_incident_version, 0),
       (SELECT count(*) FROM sentinelflow.incident_version_history history
        WHERE history.incident_id = incident.incident_id)
FROM sentinelflow.incidents incident
JOIN sentinelflow.analysis_attempt_claims claim
  ON claim.incident_id = incident.incident_id AND claim.analysis_id = $2::uuid
WHERE incident.incident_id = $1::uuid`, incidentID, analysisID).Scan(
		&version, &evidenceVersion, &state, &analyzing, &terminal, &historyCount,
	)
	if err != nil || version != wantVersion || evidenceVersion != wantEvidenceVersion ||
		state != wantState || analyzing != wantAnalyzing || terminal != wantTerminal ||
		historyCount != wantHistory {
		t.Fatalf("lifecycle incident=%s version=%d evidence=%d state=%s A=%d T=%d history=%d err=%v",
			incidentID, version, evidenceVersion, state, analyzing, terminal, historyCount, err)
	}
	var distinctEvidence, badSignalVersions int
	err = admin.QueryRow(ctx, `
SELECT count(DISTINCT history.evidence_digest),
       count(*) FILTER (WHERE version_signal_count <> $2)
FROM (
    SELECT history.incident_version, history.evidence_digest,
           (SELECT count(*) FROM sentinelflow.incident_version_signals link
            WHERE link.incident_id = history.incident_id
              AND link.incident_version = history.incident_version) AS version_signal_count
    FROM sentinelflow.incident_version_history history
    WHERE history.incident_id = $1::uuid
) history`, incidentID, wantSignalCount).Scan(&distinctEvidence, &badSignalVersions)
	if err != nil || distinctEvidence != 1 || badSignalVersions != 0 {
		t.Fatalf("immutable history incident=%s evidence_digests=%d bad_signal_versions=%d err=%v",
			incidentID, distinctEvidence, badSignalVersions, err)
	}
}

func assertIncidentProjection(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	incidentID string,
	wantVersion, wantEvidenceVersion int,
	wantState string,
	wantHistory int,
) {
	t.Helper()
	var version, evidenceVersion, history int
	var state string
	err := admin.QueryRow(ctx, `
SELECT version, evidence_version, state,
       (SELECT count(*) FROM sentinelflow.incident_version_history history
        WHERE history.incident_id = incidents.incident_id)
FROM sentinelflow.incidents
WHERE incident_id = $1::uuid`, incidentID).Scan(&version, &evidenceVersion, &state, &history)
	if err != nil || version != wantVersion || evidenceVersion != wantEvidenceVersion ||
		state != wantState || history != wantHistory {
		t.Fatalf("projection version=%d evidence=%d state=%s history=%d err=%v",
			version, evidenceVersion, state, history, err)
	}
}

func assertAnalysisPublicationVersion(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	incidentID, analysisID string,
	wantEvidenceVersion int,
	wantValidation bool,
) {
	t.Helper()
	var analysisVersion, validationCount int
	err := admin.QueryRow(ctx, `
SELECT COALESCE((
           SELECT incident_version FROM sentinelflow.ai_analyses
           WHERE analysis_id = $2::uuid
       ), 0),
       (SELECT count(*) FROM sentinelflow.outbox_jobs
        WHERE kind = 'validate' AND aggregate_id = $2::uuid)
FROM sentinelflow.incidents WHERE incident_id = $1::uuid`, incidentID, analysisID).Scan(
		&analysisVersion, &validationCount,
	)
	wantValidationCount := 0
	if wantValidation {
		wantValidationCount = 1
	}
	if err != nil || analysisVersion != map[bool]int{true: wantEvidenceVersion, false: 0}[wantValidation] ||
		validationCount != wantValidationCount {
		t.Fatalf("publication analysis_version=%d validation=%d err=%v",
			analysisVersion, validationCount, err)
	}
}

func expireLifecycleLease(t *testing.T, ctx context.Context, admin *pgx.Conn, jobID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE sentinelflow_migration"); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
UPDATE sentinelflow.outbox_jobs
SET updated_at = created_at,
    lease_expires_at = created_at + interval '1 microsecond'
WHERE job_id = $1::uuid AND state = 'leased'`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertPopulatedLifecycleRollbackFails(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	down, _ := analysisLifecycleMigrationFiles(t)
	_, err := admin.Exec(ctx, string(down))
	if err == nil || !strings.Contains(err.Error(), "cannot discard durable analysis lifecycle evidence") {
		t.Fatalf("populated 000017 down migration err=%v", err)
	}
	if _, rollbackErr := admin.Exec(ctx, "ROLLBACK"); rollbackErr != nil {
		t.Fatalf("rollback failed down migration: %v", rollbackErr)
	}
	var versionPresent, evidenceColumnPresent, lifecycleColumnPresent bool
	err = admin.QueryRow(ctx, `
SELECT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 17
       ), EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'sentinelflow' AND table_name = 'incidents'
             AND column_name = 'evidence_version'
       ), EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'sentinelflow'
             AND table_name = 'analysis_attempt_claims'
             AND column_name = 'terminal_incident_version'
       )`).Scan(&versionPresent, &evidenceColumnPresent, &lifecycleColumnPresent)
	if err != nil || !versionPresent || !evidenceColumnPresent || !lifecycleColumnPresent {
		t.Fatalf("populated rollback changed durable schema version=%v evidence_column=%v lifecycle_column=%v err=%v",
			versionPresent, evidenceColumnPresent, lifecycleColumnPresent, err)
	}
}

func assertInterruptedAttempt(t *testing.T, ctx context.Context, admin *pgx.Conn, analysisID string) {
	t.Helper()
	var claimState, resultState, jobState, reason string
	err := admin.QueryRow(ctx, `
SELECT claim.state, result.result_state, result.failure_reason, job.state
FROM sentinelflow.analysis_attempt_claims claim
JOIN sentinelflow.analysis_attempt_results result USING (analysis_id)
JOIN sentinelflow.outbox_jobs job USING (job_id)
WHERE claim.analysis_id = $1::uuid`, analysisID).Scan(
		&claimState, &resultState, &reason, &jobState,
	)
	if err != nil || claimState != "interrupted" || resultState != "interrupted" ||
		reason != "analysis_interrupted" || jobState != "dead" {
		t.Fatalf("interrupted claim=%s result=%s reason=%s job=%s err=%v",
			claimState, resultState, reason, jobState, err)
	}
}

func assertFiftyOneNoCall(t *testing.T, ctx context.Context, admin *pgx.Conn, incidentID string) {
	t.Helper()
	var version, evidenceVersion, analyzing, terminal, historyCount int
	var incidentState, claimState, reason string
	err := admin.QueryRow(ctx, `
SELECT incident.version, incident.evidence_version, incident.state,
       claim.state, result.failure_reason,
       COALESCE(claim.analyzing_incident_version, 0),
       COALESCE(claim.terminal_incident_version, 0),
       (SELECT count(*) FROM sentinelflow.incident_version_history history
        WHERE history.incident_id = incident.incident_id)
FROM sentinelflow.incidents incident
JOIN sentinelflow.analysis_attempt_claims claim USING (incident_id)
JOIN sentinelflow.analysis_attempt_results result USING (analysis_id)
WHERE incident.incident_id = $1::uuid`, incidentID).Scan(
		&version, &evidenceVersion, &incidentState, &claimState, &reason,
		&analyzing, &terminal, &historyCount,
	)
	if err != nil || version != 2 || evidenceVersion != 1 ||
		incidentState != "analysis_failed" || claimState != "no_call" ||
		reason != "input_too_large" || analyzing != 0 || terminal != 2 || historyCount != 2 {
		t.Fatalf("51 no-call version=%d evidence=%d incident=%s claim=%s reason=%s A=%d T=%d history=%d err=%v",
			version, evidenceVersion, incidentState, claimState, reason,
			analyzing, terminal, historyCount, err)
	}
}

func appendNewEvidenceVersion(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	fixture lifecycleFixture,
	version int,
) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE sentinelflow_migration"); err != nil {
		t.Fatal(err)
	}
	signalID := lifecycleUUID(0xc01)
	eventID := lifecycleUUID(0xc02)
	eventTime := time.Now().UTC().Truncate(time.Millisecond)
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, request_id, trace_id, started_at, completed_at,
    source_ip, method, protocol, route_label, path_catalog_version,
    suspicious_path_id, host, service_label, status_code,
    request_bytes, response_bytes, latency_ms, received_at,
    trust_state, trust_reason
) VALUES (
    $1::uuid, 'gateway-http-v1', 'gateway.lifecycle', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-00000000a002', $2, gen_random_uuid(),
    gen_random_uuid(), $3, $3, $4::inet, 'GET', 'HTTP/1.1', 'home',
    'path-catalog-v1', 'env_file', 'demo.example', 'demo', 404,
    0, 0, 1, $3, 'trusted', 'none'
);
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip,
    service_label, window_start, window_end, observed_count, distinct_count,
    threshold_count, threshold_distinct, source_health_status,
    evidence_digest, created_at
) VALUES (
    $5::uuid, 'signal-v1', 'path_scan.v1', 1, 'path_scan', $4::inet,
    'demo', $3, $3, 1, 1, 1, 1, 'complete', $6, $3
);
INSERT INTO sentinelflow.signal_evidence (
    evidence_link_id, signal_id, event_kind, gateway_event_id,
    event_time, relation_reason, created_at
) VALUES (gen_random_uuid(), $5::uuid, 'gateway', $1::uuid,
          $3, 'threshold_member', $3)`, pgx.QueryExecModeSimpleProtocol,
		eventID, lifecycleDigest(0xc02),
		eventTime, fixture.SourceIP, signalID, lifecycleDigest(0xc01)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
UPDATE sentinelflow.incidents
SET state = 'open', version = $2, evidence_version = $2,
    last_seen = GREATEST(last_seen, $3), analysis_failure_reason = NULL,
    updated_at = $3
WHERE incident_id = $1::uuid AND version = $2 - 1;
UPDATE sentinelflow.incident_signals SET incident_version = $2
WHERE incident_id = $1::uuid;
UPDATE sentinelflow.incident_events SET incident_version = $2
WHERE incident_id = $1::uuid;
INSERT INTO sentinelflow.incident_signals (
    incident_id, signal_id, incident_version, relation_reason, linked_at
) VALUES ($1::uuid, $4::uuid, $2, 'same_source_overlap', $3);
INSERT INTO sentinelflow.incident_events (
    incident_event_id, incident_id, incident_version, event_kind,
    gateway_event_id, relation_reason, linked_at
) VALUES (gen_random_uuid(), $1::uuid, $2, 'gateway', $5::uuid,
          'threshold_member', $3);
INSERT INTO sentinelflow.incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind,
    mutation_digest, evidence_digest, signal_count, recorded_at
)
SELECT incident_id, version, state, kind, source_ip, service_label,
       first_seen, last_seen, deterministic_score, 'signal_added',
       $6, $7, 2, $3
FROM sentinelflow.incidents WHERE incident_id = $1::uuid AND version = $2`,
		pgx.QueryExecModeSimpleProtocol, fixture.IncidentID, version,
		eventTime, signalID, eventID,
		lifecycleDigest(0xc03), lifecycleDigest(0xc04)); err != nil {
		t.Fatal(err)
	}
	signalIDs := append(append([]string(nil), fixture.SignalIDs...), signalID)
	for index, value := range signalIDs {
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_version_signals (
    incident_id, incident_version, signal_id, ordinal
) VALUES ($1::uuid, $2, $3::uuid, $4)`,
			fixture.IncidentID, version, value, index+1); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertCurrentEvidenceAndAnalysisVersion(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	incidentID, analysisID string,
	wantAggregate, wantEvidence, wantAnalysis int,
) {
	t.Helper()
	var aggregate, evidence, analysis int
	err := admin.QueryRow(ctx, `
SELECT incident.version, incident.evidence_version, analysis.incident_version
FROM sentinelflow.incidents incident
JOIN sentinelflow.ai_analyses analysis
  ON analysis.incident_id = incident.incident_id
WHERE incident.incident_id = $1::uuid AND analysis.analysis_id = $2::uuid`,
		incidentID, analysisID).Scan(&aggregate, &evidence, &analysis)
	if err != nil || aggregate != wantAggregate || evidence != wantEvidence || analysis != wantAnalysis {
		t.Fatalf("version mapping aggregate=%d evidence=%d analysis=%d err=%v",
			aggregate, evidence, analysis, err)
	}
}

func lifecycleUUID(seed int) string {
	return fmt.Sprintf("019b%04x-0000-7000-8000-%012x", seed&0xffff, seed)
}

func lifecycleToken(seed int) string {
	return fmt.Sprintf("019b%04x-0000-4000-8000-%012x", seed&0xffff, seed)
}

func lifecycleDigest(seed int) string {
	return fmt.Sprintf("sha256:%064x", seed)
}
