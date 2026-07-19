//go:build integration

package validationstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hilartifactstore"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const testAnalysisJobID = "019b0000-0000-7000-8000-000000009101"

func TestValidationStoreLifecycleAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-validationstore-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432",
		"postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	connection := connectWithRetry(t, ctx, connectionString)
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	applyMigrations(t, ctx, connection)
	insertValidationFixture(t, ctx, connection)
	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatalf("set worker role: %v", err)
	}
	store, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}

	lease := leaseRequest()
	lease.Now = time.Now().UTC()
	lease.LeaseExpiresAt = lease.Now.Add(30 * time.Second)
	job, found, err := store.Lease(ctx, lease)
	if err != nil || !found || job.JobID != testJobID {
		t.Fatalf("lease=%+v found=%v err=%v", job, found, err)
	}
	snapshot, prepared, err := store.Prepare(ctx, validationworker.PrepareRequest{
		Job: job.Job, LeaseToken: job.LeaseToken,
	})
	if err != nil || !prepared || snapshot.AnalysisID != testAnalysisID ||
		snapshot.ValidationAttemptID == "" || snapshot.History.CoverageComplete {
		t.Fatalf("snapshot=%+v prepared=%v err=%v", snapshot, prepared, err)
	}

	request := exactValidFinalize(t, snapshot)
	request.Finish.Now = time.Now().UTC()
	request.Finish.LeaseToken = job.LeaseToken
	request.Mutation.ValidationAttemptID = snapshot.ValidationAttemptID
	finished, err := store.Finalize(ctx, request)
	if err != nil || !finished {
		t.Fatalf("finalize finished=%v err=%v", finished, err)
	}
	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	var jobState, claimState string
	var failureCode *string
	var gateCount int
	err = connection.QueryRow(ctx, `
SELECT job.state, claim.state, claim.failure_code, count(gate.gate_order)
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.validation_attempt_claims claim ON claim.job_id = job.job_id
JOIN sentinelflow.validation_attempt_gates gate
  ON gate.validation_attempt_id = claim.validation_attempt_id
WHERE job.job_id = $1
GROUP BY job.state, claim.state, claim.failure_code`, testJobID).
		Scan(&jobState, &claimState, &failureCode, &gateCount)
	if err != nil || jobState != "completed" || claimState != "valid" ||
		failureCode != nil || gateCount != 6 {
		t.Fatalf("terminal state job=%q claim=%q code=%v gates=%d err=%v",
			jobState, claimState, failureCode, gateCount, err)
	}
	var exactCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.hil_exact_artifacts
WHERE policy_id = $1 AND policy_version = 1`, snapshot.PolicyID).Scan(&exactCount); err != nil || exactCount != 1 {
		t.Fatalf("exact artifact count=%d err=%v", exactCount, err)
	}
	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT * FROM sentinelflow.finalize_validation_attempt(
$1::uuid, $2::uuid, 'completed', NULL, clock_timestamp(), NULL, NULL, NULL::json)`,
		job.JobID, job.LeaseToken); err == nil {
		t.Fatal("worker retained raw validation finalizer authority")
	}
	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_api"); err != nil {
		t.Fatal(err)
	}
	loader, err := hilartifactstore.NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := loader.Load(ctx, snapshot.PolicyID, 1, request.Mutation.Validation.CreatedAt.Add(time.Second))
	if err != nil || exact.PolicyID() != snapshot.PolicyID ||
		exact.EvidenceSnapshotDigest() != snapshot.EvidenceSnapshotDigest {
		t.Fatalf("loaded exact=%+v err=%v", exact, err)
	}
}

func TestValidationStoreEvidenceStalenessAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-validation-stale-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432",
		"postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	base := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/", port,
	)

	t.Run("stale_after_prepare", func(t *testing.T) {
		connection := connectWithRetry(t, ctx, base+"postgres?sslmode=disable")
		defer connection.Close(context.Background())
		applyMigrations(t, ctx, connection)
		insertValidationFixture(t, ctx, connection)
		if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
			t.Fatal(err)
		}
		store, err := NewPostgreSQLStore(connection)
		if err != nil {
			t.Fatal(err)
		}
		lease := leaseRequest()
		lease.Now = time.Now().UTC()
		lease.LeaseExpiresAt = lease.Now.Add(30 * time.Second)
		job, found, err := store.Lease(ctx, lease)
		if err != nil || !found {
			t.Fatalf("lease found=%v err=%v", found, err)
		}
		snapshot, prepared, err := store.Prepare(ctx, validationworker.PrepareRequest{
			Job: job.Job, LeaseToken: job.LeaseToken,
		})
		if err != nil || !prepared {
			t.Fatalf("prepare prepared=%v err=%v", prepared, err)
		}
		if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		if _, err = connection.Exec(ctx, `UPDATE sentinelflow.incidents
SET evidence_version = 2 WHERE incident_id = $1::uuid`, testIncidentID); err != nil {
			t.Fatalf("advance evidence: %v", err)
		}
		if _, err = connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
			t.Fatal(err)
		}
		request := exactValidFinalize(t, snapshot)
		request.Finish.Now = time.Now().UTC()
		request.Finish.LeaseToken = job.LeaseToken
		request.Mutation.ValidationAttemptID = snapshot.ValidationAttemptID
		if finished, finalizeErr := store.Finalize(ctx, request); finished || !errors.Is(finalizeErr, ErrEvidenceStale) {
			t.Fatalf("stale finalize finished=%v err=%v", finished, finalizeErr)
		}
		if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		assertStaleValidationTerminal(t, ctx, connection, true)
	})

	if admin := connectWithRetry(t, ctx, base+"postgres?sslmode=disable"); admin != nil {
		if _, err := admin.Exec(ctx, `CREATE DATABASE sentinelflow_stale_before`); err != nil {
			t.Fatalf("create stale-before database: %v", err)
		}
		_ = admin.Close(context.Background())
	}
	t.Run("stale_before_prepare", func(t *testing.T) {
		connection := connectWithRetry(t, ctx, base+"sentinelflow_stale_before?sslmode=disable")
		defer connection.Close(context.Background())
		applyMigrations(t, ctx, connection)
		insertValidationFixture(t, ctx, connection)
		if _, err := connection.Exec(ctx, `UPDATE sentinelflow.incidents
SET evidence_version = 2 WHERE incident_id = $1::uuid`, testIncidentID); err != nil {
			t.Fatalf("advance evidence: %v", err)
		}
		if _, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker"); err != nil {
			t.Fatal(err)
		}
		store, err := NewPostgreSQLStore(connection)
		if err != nil {
			t.Fatal(err)
		}
		lease := leaseRequest()
		lease.Now = time.Now().UTC()
		lease.LeaseExpiresAt = lease.Now.Add(30 * time.Second)
		job, found, err := store.Lease(ctx, lease)
		if err != nil || !found {
			t.Fatalf("lease found=%v err=%v", found, err)
		}
		_, prepared, err := store.Prepare(ctx, validationworker.PrepareRequest{
			Job: job.Job, LeaseToken: job.LeaseToken,
		})
		if err != nil || prepared {
			t.Fatalf("stale prepare prepared=%v err=%v", prepared, err)
		}
		if _, err = connection.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		assertStaleValidationTerminal(t, ctx, connection, false)
	})
}

func assertStaleValidationTerminal(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	wantClaim bool,
) {
	t.Helper()
	var jobState, failureCode string
	var claimCount, policyCount, artifactCount int
	if err := connection.QueryRow(ctx, `
SELECT job.state, job.last_error_code,
       (SELECT count(*)::integer FROM sentinelflow.validation_attempt_claims
         WHERE job_id = job.job_id),
       (SELECT count(*)::integer FROM sentinelflow.policy_proposals),
       (SELECT count(*)::integer FROM sentinelflow.hil_exact_artifacts)
FROM sentinelflow.outbox_jobs job WHERE job.job_id = $1::uuid`, testJobID).Scan(
		&jobState, &failureCode, &claimCount, &policyCount, &artifactCount,
	); err != nil {
		t.Fatal(err)
	}
	wantClaimCount := 0
	if wantClaim {
		wantClaimCount = 1
	}
	if jobState != "dead" || failureCode != "evidence_version_stale" ||
		claimCount != wantClaimCount || policyCount != 0 || artifactCount != 0 {
		t.Fatalf("stale terminal job=%s code=%s claims=%d policy=%d artifacts=%d",
			jobState, failureCode, claimCount, policyCount, artifactCount)
	}
	if wantClaim {
		var claimState, claimFailure string
		if err := connection.QueryRow(ctx, `SELECT state, failure_code
FROM sentinelflow.validation_attempt_claims WHERE job_id = $1::uuid`, testJobID).Scan(
			&claimState, &claimFailure,
		); err != nil || claimState != "interrupted" || claimFailure != "evidence_version_stale" {
			t.Fatalf("stale claim state=%s code=%s err=%v", claimState, claimFailure, err)
		}
	}
}

func exactValidFinalize(t *testing.T, snapshot validationworker.Snapshot) validationworker.FinalizeRequest {
	return exactValidFinalizeForSignal(t, snapshot, testSignalID)
}

func exactValidFinalizeForSignal(
	t *testing.T,
	snapshot validationworker.Snapshot,
	signalID string,
) validationworker.FinalizeRequest {
	t.Helper()
	generated := []byte("add element inet sentinelflow blacklist_ipv4 { 8.8.8.8 timeout 30m }")
	command, err := nftvalidate.Canonicalize(generated, 1800)
	if err != nil {
		t.Fatal(err)
	}
	rationale := "Synthetic evidence supports a temporary block."
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion: policy.PolicySchemaVersion, PolicyID: snapshot.PolicyID, PolicyVersion: 1,
		IncidentID: snapshot.IncidentID, AnalysisID: snapshot.AnalysisID,
		Action: policy.ActionBlockIP, TargetIPv4: "8.8.8.8", TTLSeconds: 1800,
		EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest,
		EvidenceIDs:            []string{signalID}, RationaleDigest: policy.Digest([]byte(rationale)),
		CreatedAt: snapshot.GeneratedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkIDs := []validation.ValidationCheckID{
		validation.CheckStructuredOutput, validation.CheckCommandGrammar,
		validation.CheckPolicyEvidenceCommandConsistency, validation.CheckProtectedNetwork,
		validation.CheckOwnedSchemaSyntax, validation.CheckHistoricalImpact,
	}
	checks := make([]validation.ValidationCheck, len(checkIDs))
	gates := make([]validationworker.GateRecord, len(checkIDs))
	for index, checkID := range checkIDs {
		checks[index] = validation.ValidationCheck{
			CheckID: checkID, Result: "pass", ReasonCode: "ok", InputDigest: testDigest,
		}
		gates[index] = validationworker.GateRecord{
			Order: uint8(index + 1), Name: checkID, Passed: true, ResultCode: "ok",
			InputDigest: testDigest, ResultDigest: testDigest,
		}
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion: validation.ValidationSnapshotSchemaVersion,
		ValidationID:  snapshot.ValidationID, PolicyDigest: checkedPolicy.Digest(),
		EvidenceSnapshotDigest:     snapshot.EvidenceSnapshotDigest,
		AnalysisInputDigest:        snapshot.AnalysisInputDigest,
		AnalysisOutputSchemaDigest: snapshot.OutputSchemaDigest, PromptDigest: snapshot.PromptDigest,
		GeneratedCandidateDigest: command.GeneratedDigest(), CanonicalArtifactDigest: command.CanonicalDigest(),
		GrammarVersion: nftvalidate.GrammarVersion, ParserVersion: nftvalidate.ParserVersion,
		ValidatorVersion:                   nftvalidate.ValidatorVersion,
		BaseChainContractRawDigest:         nftvalidate.PinnedBaseChainRawDigest,
		LiveOwnedSchemaDigest:              nftvalidate.PinnedLiveSchemaDigest,
		ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: testDigest, NFTBinaryDigest: testDigest,
		NFTVersion: "1.0.9", HistoricalImpactDigest: testDigest, Checks: checks,
		CreatedAt:  snapshot.GeneratedAt,
		ValidUntil: snapshot.GeneratedAt.Add(validation.ValidationSnapshotLifetime),
	})
	if err != nil {
		t.Fatal(err)
	}
	return validationworker.FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishCompleted, Now: time.Now().UTC(),
			JobID: testJobID, LeaseToken: testLeaseToken,
		},
		Mutation: &validationworker.Mutation{
			ValidationAttemptID: snapshot.ValidationAttemptID, AnalysisID: snapshot.AnalysisID,
			IncidentID: snapshot.IncidentID, IncidentVersion: snapshot.IncidentVersion,
			State: validationworker.StateValid, FailureCode: validationworker.ValidationFailureNone,
			AuditAction:            validationworker.ValidationAuditSucceeded,
			EvidenceCanonicalBytes: snapshot.EvidenceCanonicalBytes, Gates: gates,
			Candidate: &validationworker.CandidateRecord{
				SchemaVersion: policy.CandidateSchemaVersion, TargetIPv4: "8.8.8.8",
				TimeoutToken: "30m", TTLSeconds: 1800,
				GeneratedBytes: command.GeneratedBytes(), GeneratedDigest: command.GeneratedDigest(),
				CanonicalBytes: command.CanonicalBytes(), CanonicalDigest: command.CanonicalDigest(),
			},
			Policy: &validationworker.PolicyRecord{
				SchemaVersion: policy.PolicySchemaVersion, PolicyID: snapshot.PolicyID, PolicyVersion: 1,
				CanonicalBytes: checkedPolicy.CanonicalBytes(), PolicyDigest: checkedPolicy.Digest(),
				TargetIPv4: "8.8.8.8", TTLSeconds: 1800, Rationale: rationale,
			},
			Validation: &validationworker.ValidationRecord{
				CanonicalBytes: checkedValidation.CanonicalBytes(), SnapshotDigest: checkedValidation.Digest(),
				PolicyDigest: checkedPolicy.Digest(), EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest,
				AnalysisInputDigest:        snapshot.AnalysisInputDigest,
				AnalysisOutputSchemaDigest: snapshot.OutputSchemaDigest, PromptDigest: snapshot.PromptDigest,
				GeneratedCandidateDigest: command.GeneratedDigest(),
				CanonicalArtifactDigest:  command.CanonicalDigest(), GrammarVersion: nftvalidate.GrammarVersion,
				ParserVersion: nftvalidate.ParserVersion, ValidatorVersion: nftvalidate.ValidatorVersion,
				BaseChainContractRawDigest:         nftvalidate.PinnedBaseChainRawDigest,
				LiveOwnedSchemaDigest:              nftvalidate.PinnedLiveSchemaDigest,
				ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
				ProtectedIPv4EffectiveConfigDigest: testDigest, NFTBinaryDigest: testDigest,
				NFTVersion: "1.0.9", HistoricalImpactDigest: testDigest,
				TargetIPv4: "8.8.8.8", TTLSeconds: 1800,
				SourceHealthStatus: validation.SourceHealthComplete,
				CreatedAt:          snapshot.GeneratedAt,
				ValidUntil:         snapshot.GeneratedAt.Add(validation.ValidationSnapshotLifetime),
			},
		},
	}
}

func insertValidationFixture(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	insertValidationFixtureAt(t, ctx, connection, "8.8.8.8", time.Now().UTC().Truncate(time.Microsecond))
}

func insertValidationFixtureAt(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	sourceIPv4 string,
	fixtureAt time.Time,
) {
	t.Helper()
	commandText := "add element inet sentinelflow blacklist_ipv4 { " + sourceIPv4 + " timeout 30m }"
	policyValue := map[string]any{
		"schema_version": policy.PolicySchemaVersion, "action": policy.ActionBlockIP,
		"target_ip": sourceIPv4, "ttl_seconds": 1800,
		"evidence_ids": []string{testSignalID},
		"rationale":    "Complete deterministic evidence supports a temporary block.",
	}
	candidateValue := map[string]any{
		"schema_version": policy.CandidateSchemaVersion, "target_ip": sourceIPv4,
		"timeout": "30m", "evidence_ids": []string{testSignalID}, "command": commandText,
	}
	policyJSON, err := json.Marshal(policyValue)
	if err != nil {
		t.Fatal(err)
	}
	candidateJSON, err := json.Marshal(candidateValue)
	if err != nil {
		t.Fatal(err)
	}
	structuredOutput, err := json.Marshal(map[string]any{
		"schema_version":   "sentinelflow_analysis_v1",
		"incident_summary": "Synthetic test incident.", "classification": "path_scan",
		"confidence": 0.9, "uncertainty": "", "false_positive_factors": []string{},
		"evidence_ids": []string{testSignalID}, "policy": policyValue,
		"nftables_command_candidate": candidateValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	outputDigest := digest(structuredOutput)
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    testEvidenceID, IncidentID: testIncidentID, IncidentVersion: 1,
		SourceIPv4: sourceIPv4, ServiceLabel: "gateway",
		WindowStart: fixtureAt.Add(-time.Minute), WindowEnd: fixtureAt,
		SourceHealthDigest: testDigest, EventIDs: []string{testGatewayID},
		SignalIDs: []string{testSignalID}, CreatedAt: fixtureAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	command, err := nftvalidate.Canonicalize(
		[]byte("add element inet sentinelflow blacklist_ipv4 { "+sourceIPv4+" timeout 30m }"), 1800,
	)
	if err != nil {
		t.Fatal(err)
	}
	signalDigest := digest([]byte("validation-fixture-signal-v1"))
	historyEvidenceDigest := validationIncidentEvidenceDigest(
		testIncidentID, 1, testSignalID, signalDigest,
	)
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version, idempotency_key,
    state, available_at, attempts, max_attempts, created_at, updated_at
) VALUES
    ($1, 'analyze', 'incident', $2, 1,
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        'completed', clock_timestamp(), 1, 2, clock_timestamp(), clock_timestamp()),
    ($3, 'validate', 'analysis_staging', $4, 1,
        'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        'pending', clock_timestamp(), 0, 3, clock_timestamp(), clock_timestamp());
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, evidence_version
) VALUES ($2, 'path_scan', 'review_ready', $15::inet, 'gateway',
    $10::timestamptz - interval '1 minute', $10::timestamptz, 0.9, 3, 1);
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES ('gateway-test', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
    NULL, false, false, clock_timestamp());
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    updated_at = clock_timestamp()
WHERE sender_id = 'gateway-test' AND endpoint_kind = 'gateway';
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES ('gateway-test', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-000000009102', 1, 'gateway', 'event-batch-v1',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    100, 1, clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute');
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, trust_state, trust_reason
) VALUES ($5, 'gateway-http-v1', 'gateway-test', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-000000009102',
    'sha256:9999999999999999999999999999999999999999999999999999999999999999',
    '019b0000-0000-7000-8000-000000009103',
    '019b0000-0000-7000-8000-000000009104',
    clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute',
    $15::inet, 'GET', 'HTTP/1.1', 'public', 'path-catalog-v1', 'admin_console',
    'example.test', 'gateway', 404, 0, 0, 1, 'trusted', 'none');
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip, service_label,
    window_start, window_end, observed_count, distinct_count, threshold_count,
    threshold_distinct, source_health_status, evidence_digest,
    configuration_version, configuration_digest, signal_digest
) VALUES ($6, 'signal-v1', 'path_scan.v1', 1, 'path_scan', $15::inet, 'gateway',
    $10::timestamptz - interval '1 minute', $10::timestamptz, 8, 8, 8, 8,
    'complete', 'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'detector-v1', $8, $14);
INSERT INTO sentinelflow.incident_signals (
    incident_id, signal_id, incident_version, relation_reason, linked_at
) VALUES ($2, $6, 3, 'same_source_overlap', $10::timestamptz);
INSERT INTO sentinelflow.incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind,
    mutation_digest, evidence_digest, signal_count, recorded_at
) VALUES ($2, 1, 'open', 'path_scan', $15::inet, 'gateway',
    $10::timestamptz - interval '1 minute', $10::timestamptz, 0.9,
    'created',
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    $13, 1, $10::timestamptz);
INSERT INTO sentinelflow.incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind,
    mutation_digest, evidence_digest, signal_count, recorded_at
) VALUES
    ($2, 2, 'analyzing', 'path_scan', $15::inet, 'gateway',
     $10::timestamptz - interval '1 minute', $10::timestamptz, 0.9,
     'state_changed',
     'sha256:7777777777777777777777777777777777777777777777777777777777777777',
     $13, 1, $10::timestamptz),
    ($2, 3, 'review_ready', 'path_scan', $15::inet, 'gateway',
     $10::timestamptz - interval '1 minute', $10::timestamptz, 0.9,
     'state_changed',
     'sha256:8888888888888888888888888888888888888888888888888888888888888888',
     $13, 1, $10::timestamptz);
INSERT INTO sentinelflow.incident_version_signals (
    incident_id, incident_version, signal_id, ordinal
) VALUES ($2, 1, $6, 1), ($2, 2, $6, 1), ($2, 3, $6, 1);
INSERT INTO sentinelflow.evidence_snapshots (
    evidence_snapshot_id, schema_version, incident_id, incident_version,
    source_ip, service_label, window_start, window_end, source_health_status,
    signal_count, expanded_event_count, snapshot_digest, created_at, expires_at
) VALUES ($7, 'evidence-snapshot-v1', $2, 1, $15::inet, 'gateway',
    $10::timestamptz - interval '1 minute', $10::timestamptz, 'complete', 1, 1,
    $8, $10::timestamptz, $10::timestamptz + interval '1 day');
INSERT INTO sentinelflow.evidence_snapshot_artifacts (
    evidence_snapshot_id, schema_version, source_health_digest,
    canonical_bytes, canonical_digest, created_at
) VALUES ($7, 'evidence-snapshot-v1',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    $12::bytea, $8, $10::timestamptz);
INSERT INTO sentinelflow.evidence_snapshot_signals (
    evidence_snapshot_id, ordinal, signal_id, evidence_id, evidence_digest,
    expanded_event_count
) VALUES ($7, 1, $6, $6::text,
    'sha256:5555555555555555555555555555555555555555555555555555555555555555', 1);
INSERT INTO sentinelflow.evidence_snapshot_events (
    evidence_snapshot_event_id, evidence_snapshot_id, signal_id, event_kind,
    gateway_event_id, event_time
) VALUES ('019b0000-0000-7000-8000-000000009105', $7, $6, 'gateway', $5,
    $10::timestamptz);
INSERT INTO sentinelflow.analysis_attempt_claims (
    analysis_id, job_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, outbox_attempt, state, generated_at, terminal_at,
    analyzing_incident_version, terminal_incident_version
) VALUES ($4, $1, $2, 1, $7, $8, 1, 'succeeded', clock_timestamp(),
    clock_timestamp(), 2, 3);
INSERT INTO sentinelflow.ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, attempt, model, reasoning_effort, store_enabled,
    input_schema_digest, prompt_digest, output_schema_digest, input_digest,
    input_bytes, result_state, output_digest, incident_summary, classification,
    confidence, uncertainty, input_tokens, cached_input_tokens, output_tokens,
    started_at, completed_at
) VALUES ($4, $2, 1, $7, $8, 1, 'gpt-5.6-sol', 'medium', false,
    $8, $19, $19, $8, 2, 'succeeded', $9, 'Synthetic incident', 'path_scan',
    0.9, '', 1, 0, 1, clock_timestamp(), clock_timestamp());
INSERT INTO sentinelflow.analysis_attempt_results (
    analysis_id, result_state, provider_attempts, provider_response_id, model,
    reasoning_effort, rate_card_version, input_bytes, input_digest,
    input_schema_digest, prompt_digest, output_schema_digest, output_digest,
    generated_command_digest, input_tokens, cached_input_tokens, output_tokens,
    completed_at
) VALUES ($4, 'succeeded', 1, 'resp_validation_fixture', 'gpt-5.6-sol', 'medium',
    'operator-v1', 2, $8, $8, $19, $19, $9, $11, 1, 0, 1, clock_timestamp());
INSERT INTO sentinelflow.analysis_evidence (
    analysis_id, ordinal, evidence_snapshot_id, signal_id, evidence_id
) VALUES ($4, 1, $7, $6, $6::text);
INSERT INTO sentinelflow.analysis_output_staging (
    analysis_id, structured_output, policy_output, command_candidate_output,
    output_digest, generated_command_digest, created_at
) VALUES ($4, $16::bytea, $17::bytea, $18::bytea, $9, $11, clock_timestamp());`,
		pgx.QueryExecModeSimpleProtocol,
		testAnalysisJobID, testIncidentID, testJobID, testAnalysisID, testGatewayID,
		testSignalID, testEvidenceID, evidence.Digest(), outputDigest, fixtureAt,
		command.GeneratedDigest(), evidence.CanonicalBytes(), historyEvidenceDigest,
		signalDigest, sourceIPv4, structuredOutput, policyJSON, candidateJSON, testDigest)
	if err != nil {
		t.Fatalf("insert validation fixture: %v", err)
	}
}

func validationIncidentEvidenceDigest(
	incidentID string,
	version int,
	signalID string,
	signalDigest string,
) string {
	values := []string{
		"incident-evidence-v1", incidentID, fmt.Sprintf("%d", version),
		signalID, signalDigest,
	}
	hash := sha256.New()
	for _, value := range values {
		_, _ = fmt.Fprintf(hash, "%d:%s\n", len(value), value)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func applyMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(matches)
	for _, migration := range matches {
		contents, readErr := os.ReadFile(migration)
		if readErr != nil {
			t.Fatalf("read %s: %v", filepath.Base(migration), readErr)
		}
		if _, execErr := connection.Exec(ctx, string(contents)); execErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(migration), execErr)
		}
	}
}

func connectWithRetry(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		select {
		case <-ctx.Done():
			t.Fatalf("connect PostgreSQL 17: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("connect PostgreSQL 17")
	return nil
}

func waitForPostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL 17 readiness: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func dockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
