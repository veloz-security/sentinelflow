//go:build integration

package detectionworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisstore"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

func TestDetectionAnalysisEvidenceRaceAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	for _, order := range []string{"evidence_first", "finalize_first"} {
		order := order
		t.Run(order, func(t *testing.T) {
			runDetectionAnalysisRace(t, order)
		})
	}
}

func runDetectionAnalysisRace(t *testing.T, order string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-detection-analysis-race-%s-%d", order, time.Now().UnixNano())
	detectionDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only", "--publish", "127.0.0.1::5432",
		detectionPostgres17Image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitDetectionPostgres(t, ctx, container)
	port := detectionDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port)
	admin := connectDetectionPostgres(t, ctx, connectionString)
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	applyDetectionMigrations(t, ctx, admin)

	var serverNow time.Time
	if err := admin.QueryRow(ctx,
		`SELECT date_trunc('milliseconds', clock_timestamp())`).Scan(&serverNow); err != nil {
		t.Fatal(err)
	}
	evaluatedAt := serverNow.Add(-time.Minute)
	seedExpectedGatewaySource(t, ctx, admin, evaluatedAt.Add(-time.Hour))
	seedBurstDetectionJob(t, ctx, admin, 1, evaluatedAt, true)
	if _, err := admin.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	detectionStore, err := NewPostgreSQLStore(admin)
	if err != nil {
		t.Fatal(err)
	}
	detectionResult, err := newPostgreSQLRuntime(t, detectionStore, "race-bootstrap").RunOnce(ctx)
	if err != nil || detectionResult.Outcome != worker.OutcomeCompleted ||
		detectionResult.SignalCount != 1 || detectionResult.IncidentMutations != 1 {
		t.Fatalf("bootstrap detection result=%+v err=%v", detectionResult, err)
	}
	if _, err = admin.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	seedAnalysisRaceProducerHistory(t, ctx, admin)

	analysisConnection := connectDetectionPostgres(t, ctx, connectionString)
	t.Cleanup(func() { _ = analysisConnection.Close(context.Background()) })
	var analysisPID int32
	if err = analysisConnection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&analysisPID); err != nil {
		t.Fatal(err)
	}
	if _, err = analysisConnection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	analysisStore, err := analysisstore.NewPostgreSQLStore(analysisConnection)
	if err != nil {
		t.Fatal(err)
	}
	leaseNow := time.Now().UTC()
	leaseToken := map[string]string{
		"evidence_first": "019f3000-0000-4000-8000-000000000101",
		"finalize_first": "019f3000-0000-4000-8000-000000000102",
	}[order]
	analysisJob, found, err := analysisStore.Lease(ctx, worker.LeaseRequest{
		Now: leaseNow, LeaseToken: leaseToken, LeaseOwner: "analysis-race-" + order,
		LeaseExpiresAt: leaseNow.Add(30 * time.Second),
	})
	if err != nil || !found {
		t.Fatalf("lease analysis found=%v err=%v", found, err)
	}
	snapshot, prepared, err := analysisStore.Prepare(ctx, analysisworker.PrepareRequest{
		Job: analysisJob.Job, LeaseToken: analysisJob.LeaseToken,
	})
	if err != nil || !prepared {
		t.Fatalf("prepare analysis prepared=%v err=%v", prepared, err)
	}
	if snapshot.IncidentVersion != 1 {
		t.Fatalf("analysis evidence version=%d", snapshot.IncidentVersion)
	}

	evidenceConnection := connectDetectionPostgres(t, ctx, connectionString)
	t.Cleanup(func() { _ = evidenceConnection.Close(context.Background()) })
	var evidencePID int32
	if err = evidenceConnection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&evidencePID); err != nil {
		t.Fatal(err)
	}
	raceSignal := newAnalysisRaceSignal(snapshot, order, evaluatedAt.Add(time.Second))
	finalize := analysisRaceSuccessFinalize(analysisJob, snapshot, order)

	switch order {
	case "evidence_first":
		evidenceTx, incidentID, version, routeErr := beginAnalysisRaceSignal(
			ctx, evidenceConnection, raceSignal, integrationUUID(0xa101))
		if routeErr != nil || incidentID != snapshot.IncidentID || version != 4 {
			t.Fatalf("evidence-first route incident=%s version=%d err=%v", incidentID, version, routeErr)
		}
		type finalizeResult struct {
			finished bool
			err      error
		}
		finalized := make(chan finalizeResult, 1)
		go func() {
			value, finalizeErr := analysisStore.Finalize(ctx, finalize)
			finalized <- finalizeResult{value, finalizeErr}
		}()
		waitForPostgreSQLLock(t, ctx, admin, analysisPID)
		if err = evidenceTx.Commit(ctx); err != nil {
			t.Fatalf("commit evidence-first signal: %v", err)
		}
		result := <-finalized
		if result.err != nil || result.finished {
			t.Fatalf("stale finalizer finished=%v err=%v", result.finished, result.err)
		}
		assertAnalysisRaceOutcome(t, ctx, admin, snapshot, "interrupted", "dead", 0)

	case "finalize_first":
		if _, err = analysisConnection.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		analysisTx, txErr := analysisConnection.BeginTx(ctx, pgx.TxOptions{})
		if txErr != nil {
			t.Fatal(txErr)
		}
		defer func() { _ = analysisTx.Rollback(context.Background()) }()
		lockAnalysisRaceRows(t, ctx, analysisTx, analysisJob.JobID, snapshot.AnalysisID, snapshot.IncidentID)
		txStore, txErr := analysisstore.NewPostgreSQLStore(analysisTx)
		if txErr != nil {
			t.Fatal(txErr)
		}
		type routeResult struct {
			incidentID string
			version    int32
			err        error
		}
		routed := make(chan routeResult, 1)
		go func() {
			tx, incidentID, version, routeErr := beginAnalysisRaceSignal(
				ctx, evidenceConnection, raceSignal, integrationUUID(0xa102))
			if routeErr == nil {
				routeErr = tx.Commit(ctx)
			}
			routed <- routeResult{incidentID, version, routeErr}
		}()
		waitForPostgreSQLLock(t, ctx, admin, evidencePID)
		finished, finalizeErr := txStore.Finalize(ctx, finalize)
		if finalizeErr != nil || !finished {
			t.Fatalf("winning finalizer finished=%v err=%v", finished, finalizeErr)
		}
		if err = analysisTx.Commit(ctx); err != nil {
			t.Fatalf("commit winning finalizer: %v", err)
		}
		lost := <-routed
		var pgError *pgconn.PgError
		if !errors.As(lost.err, &pgError) || pgError.Code != "40001" {
			t.Fatalf("losing detector incident=%s version=%d err=%v", lost.incidentID, lost.version, lost.err)
		}
		if classified := classifyPersistenceError(lost.err); !errors.Is(classified, ErrRetryablePersistence) {
			t.Fatalf("losing detector conflict classified=%v", classified)
		}
		assertRaceSignalAbsent(t, ctx, admin, raceSignal.SignalID)

		retryTx, incidentID, version, retryErr := beginAnalysisRaceSignal(
			ctx, evidenceConnection, raceSignal, integrationUUID(0xa103))
		if retryErr != nil || incidentID != snapshot.IncidentID || version != 4 {
			t.Fatalf("detector retry incident=%s version=%d err=%v", incidentID, version, retryErr)
		}
		if err = retryTx.Commit(ctx); err != nil {
			t.Fatalf("commit detector retry: %v", err)
		}
		assertAnalysisRaceOutcome(t, ctx, admin, snapshot, "succeeded", "completed", 1)
	default:
		t.Fatalf("unknown race order %q", order)
	}
	assertIncidentVersion(t, ctx, admin, 4, "open", "signal_added", 2)
}

func seedAnalysisRaceProducerHistory(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) {
	t.Helper()
	_, err := admin.Exec(ctx, `
BEGIN;
SET LOCAL ROLE sentinelflow_migration;

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'gateway-main', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f3000-0000-4000-8000-000000000201', 3, 'gateway', 'event-batch-v1',
    'sha256:2121212121212121212121212121212121212121212121212121212121212121',
    128, 1, clock_timestamp() - interval '25 hours',
    clock_timestamp() - interval '25 hours', 'gateway-key'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 3,
    last_acknowledged_body_digest =
        'sha256:2121212121212121212121212121212121212121212121212121212121212121',
    updated_at = GREATEST(updated_at, clock_timestamp() - interval '1 minute')
WHERE sender_id = 'gateway-main' AND endpoint_kind = 'gateway';

INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES (
    'auth.race', 'auth', 'BBBBBBBBBBBBBBBBBBBBBB', 0,
    NULL, false, false, clock_timestamp() - interval '26 hours'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    updated_at = clock_timestamp() - interval '25 hours'
WHERE sender_id = 'auth.race' AND endpoint_kind = 'auth';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'auth.race', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019f3000-0000-4000-8000-000000000202', 1, 'auth', 'event-batch-v1',
    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    128, 1, clock_timestamp() - interval '25 hours',
    clock_timestamp() - interval '25 hours', 'auth-key'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 2,
    last_acknowledged_body_digest =
        'sha256:2323232323232323232323232323232323232323232323232323232323232323',
    updated_at = clock_timestamp() - interval '1 minute'
WHERE sender_id = 'auth.race' AND endpoint_kind = 'auth';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'auth.race', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019f3000-0000-4000-8000-000000000203', 2, 'auth', 'event-batch-v1',
    'sha256:2323232323232323232323232323232323232323232323232323232323232323',
    128, 1, clock_timestamp() - interval '1 minute',
    clock_timestamp() - interval '1 minute', 'auth-key'
);

COMMIT;`)
	if err != nil {
		t.Fatalf("seed analysis race producer history: %v", err)
	}
}

func beginAnalysisRaceSignal(
	ctx context.Context,
	connection *pgx.Conn,
	signal detection.Signal,
	jobID string,
) (pgx.Tx, string, int32, error) {
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, "", 0, err
	}
	rollback := func(value error) (pgx.Tx, string, int32, error) {
		_ = tx.Rollback(context.Background())
		return nil, "", 0, value
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE sentinelflow_worker"); err != nil {
		return rollback(err)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip,
    service_label, window_start, window_end, observed_count, distinct_count,
    threshold_count, threshold_distinct, source_health_status,
    evidence_digest, created_at, configuration_version,
    configuration_digest, signal_digest
) VALUES (
    $1::uuid, 'signal-v1', $2, 1, $3, $4::inet, $5, $6, $7,
    $8, NULL, 120, NULL, 'complete', $9, $7, $10, $11, $12
)`, signal.SignalID, string(signal.RuleID), string(signal.Classification),
		signal.SourceIP, signal.ServiceLabel, signal.WindowStart.UTC(), signal.WindowEnd.UTC(),
		signal.Metrics.EventCount, signal.EvidenceDigest, signal.ConfigurationVersion,
		signal.ConfigurationDigest, signal.Digest); err != nil {
		return rollback(err)
	}
	incidentID, version, err := routeSignal(ctx, tx, signal, signal.WindowEnd, jobID)
	if err != nil {
		return rollback(err)
	}
	return tx, incidentID, version, nil
}

func newAnalysisRaceSignal(
	snapshot analysisworker.Snapshot,
	order string,
	windowEnd time.Time,
) detection.Signal {
	seed := 0xb101
	if order == "finalize_first" {
		seed = 0xb102
	}
	digest := digestBytes([]byte("analysis-race-signal-" + order))
	return detection.Signal{
		SignalID: integrationUUID(seed), RuleID: detection.RuleRequestBurst,
		Classification:       detection.ClassificationRequestBurst,
		ConfigurationVersion: detection.DefaultConfigurationVersion,
		ConfigurationDigest:  digestBytes([]byte("analysis-race-config")),
		SourceIP:             snapshot.SourceIP, ServiceLabel: snapshot.ServiceLabel,
		WindowStart: windowEnd.Add(-10 * time.Second), WindowEnd: windowEnd,
		Metrics: detection.Metrics{EventCount: 120}, EvidenceIDs: []string{},
		EvidenceDigest: digest, Digest: digest,
		SourceHealthStatus: detection.SourceHealthStatusComplete,
	}
}

func analysisRaceSuccessFinalize(
	job worker.LeasedJob,
	snapshot analysisworker.Snapshot,
	order string,
) analysisworker.FinalizeRequest {
	evidenceIDs := make([]string, len(snapshot.Signals))
	for index, signal := range snapshot.Signals {
		evidenceIDs[index] = signal.SignalID
	}
	command := fmt.Sprintf(
		"add element inet sentinelflow blacklist_ipv4 { %s timeout 30m }", snapshot.SourceIP)
	policy := map[string]any{
		"schema_version": "response-policy-v1", "action": "block_ip",
		"target_ip": snapshot.SourceIP, "ttl_seconds": 1800,
		"evidence_ids": evidenceIDs, "rationale": "Deterministic evidence warrants review.",
	}
	candidate := map[string]any{
		"schema_version": "nft-blacklist-v1", "target_ip": snapshot.SourceIP,
		"timeout": "30m", "evidence_ids": evidenceIDs, "command": command,
	}
	analysis := map[string]any{
		"schema_version": "sentinelflow_analysis_v1", "incident_summary": "Request burst observed.",
		"classification": "request_burst", "confidence": 0.9, "uncertainty": "",
		"false_positive_factors": []string{"Authorized load test"}, "evidence_ids": evidenceIDs,
		"policy": policy, "nftables_command_candidate": candidate,
	}
	policyJSON, _ := json.Marshal(policy)
	candidateJSON, _ := json.Marshal(candidate)
	analysisJSON, _ := json.Marshal(analysis)
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
				ProviderKind: string(ai.ProviderOpenAIResponses), AdapterID: ai.OpenAIResponsesAdapterID,
				Model: ai.Model, ReasoningEffort: ai.ReasoningEffort,
				RateCardVersion: "operator-v1", ResponseID: "resp_race_" + order, Attempts: 1,
				InputBytes: 512, InputDigest: digestBytes([]byte("race-input-" + order)),
				InputSchemaDigest:  digestBytes([]byte("race-input-schema")),
				PromptDigest:       digestBytes([]byte("race-prompt")),
				OutputSchemaDigest: digestBytes([]byte("race-output-schema")),
				OutputDigest:       digestBytes(analysisJSON), AnalysisJSON: analysisJSON,
				PolicyJSON: policyJSON, CommandCandidateJSON: candidateJSON,
				GeneratedCommandDigest: digestBytes([]byte(command)), EvidenceIDs: evidenceIDs,
				Usage: ai.Usage{InputTokens: 120, CachedInputTokens: 20, OutputTokens: 80, Trusted: true},
			},
		},
	}
}

func lockAnalysisRaceRows(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	jobID, analysisID, incidentID string,
) {
	t.Helper()
	for _, query := range []struct {
		statement string
		value     string
	}{
		{`SELECT job_id FROM sentinelflow.outbox_jobs WHERE job_id = $1::uuid FOR UPDATE`, jobID},
		{`SELECT analysis_id FROM sentinelflow.analysis_attempt_claims WHERE analysis_id = $1::uuid FOR UPDATE`, analysisID},
		{`SELECT incident_id FROM sentinelflow.incidents WHERE incident_id = $1::uuid FOR UPDATE`, incidentID},
	} {
		var ignored string
		if err := tx.QueryRow(ctx, query.statement, query.value).Scan(&ignored); err != nil {
			t.Fatal(err)
		}
	}
}

func waitForPostgreSQLLock(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	backendPID int32,
) {
	t.Helper()
	for range 200 {
		var waiting bool
		err := admin.QueryRow(ctx, `
SELECT COALESCE(wait_event_type = 'Lock', false)
FROM pg_stat_activity WHERE pid = $1`, backendPID).Scan(&waiting)
		if err == nil && waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for backend %d lock: %v", backendPID, ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("backend %d did not block on the expected lock", backendPID)
}

func assertRaceSignalAbsent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	signalID string,
) {
	t.Helper()
	var present bool
	if err := admin.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM sentinelflow.signals WHERE signal_id = $1::uuid)`,
		signalID).Scan(&present); err != nil || present {
		t.Fatalf("rolled-back signal present=%v err=%v", present, err)
	}
}

func assertAnalysisRaceOutcome(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	snapshot analysisworker.Snapshot,
	wantClaimState, wantJobState string,
	wantPublished int,
) {
	t.Helper()
	var claimState, jobState string
	var analyzingVersion, terminalVersion int
	var analyses, stagedOutputs, policies, validations, analysisVersion int
	err := admin.QueryRow(ctx, `
SELECT claim.state, job.state, claim.analyzing_incident_version,
       claim.terminal_incident_version,
       (SELECT count(*) FROM sentinelflow.ai_analyses analysis
        WHERE analysis.incident_id = claim.incident_id),
       (SELECT count(*) FROM sentinelflow.analysis_output_staging staging
        WHERE staging.analysis_id = claim.analysis_id),
       (SELECT count(*) FROM sentinelflow.policy_proposals policy
        WHERE policy.incident_id = claim.incident_id),
       (SELECT count(*) FROM sentinelflow.outbox_jobs validation
        WHERE validation.kind = 'validate'
          AND validation.aggregate_type = 'analysis_staging'
          AND validation.aggregate_id = claim.analysis_id),
       COALESCE((SELECT analysis.incident_version
                 FROM sentinelflow.ai_analyses analysis
                 WHERE analysis.incident_id = claim.incident_id), 0)
FROM sentinelflow.analysis_attempt_claims claim
JOIN sentinelflow.outbox_jobs job USING (job_id)
	WHERE claim.analysis_id = $1::uuid`, snapshot.AnalysisID).Scan(
		&claimState, &jobState, &analyzingVersion, &terminalVersion,
		&analyses, &stagedOutputs, &policies, &validations, &analysisVersion,
	)
	if err != nil || claimState != wantClaimState || jobState != wantJobState ||
		analyzingVersion != 2 || terminalVersion != 3 || analyses != wantPublished ||
		stagedOutputs != wantPublished || policies != 0 || validations != wantPublished ||
		analysisVersion != map[int]int{0: 0, 1: 1}[wantPublished] {
		t.Fatalf("race outcome claim=%s job=%s A=%d T=%d analyses=%d staged=%d policies=%d validations=%d analysis_version=%d err=%v",
			claimState, jobState, analyzingVersion, terminalVersion,
			analyses, stagedOutputs, policies, validations, analysisVersion, err)
	}
}
