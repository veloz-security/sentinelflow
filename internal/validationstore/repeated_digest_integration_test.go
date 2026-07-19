//go:build integration

package validationstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationworker"
)

const (
	repeatedAnalysisJobID = "019b0000-0000-7000-8000-000000009201"
	repeatedJobID         = "019b0000-0000-7000-8000-000000009202"
	repeatedAnalysisID    = "019b0000-0000-7000-8000-000000009203"
	repeatedIncidentID    = "019b0000-0000-7000-8000-000000009204"
	repeatedEvidenceID    = "019b0000-0000-7000-8000-000000009205"
	repeatedSnapshotEvent = "019b0000-0000-7000-8000-000000009206"
	repeatedSignalID      = "019b0000-0000-7000-8000-000000009207"
)

func TestValidationStoreAllowsRepeatedArtifactDigestAcrossEvidenceBindings(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-validation-repeat-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432",
		"postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	connection := connectWithRetry(t, ctx, fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	))
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	applyMigrations(t, ctx, connection)

	fixtureAt := time.Now().UTC().Truncate(time.Microsecond)
	insertValidationFixtureAt(t, ctx, connection, "8.8.8.8", fixtureAt)
	first := finalizeNextValidation(t, ctx, connection, testJobID, testSignalID)

	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	insertRepeatedDigestFixture(t, ctx, connection, fixtureAt.Add(time.Second))
	second := finalizeNextValidation(t, ctx, connection, repeatedJobID, repeatedSignalID)
	if first.PolicyID == second.PolicyID || first.AnalysisID == second.AnalysisID ||
		first.EvidenceSnapshotDigest == second.EvidenceSnapshotDigest {
		t.Fatalf("bindings were not distinct: first=%+v second=%+v", first, second)
	}

	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	var candidates, policies, exactArtifacts, generatedDigests, canonicalDigests int
	err := connection.QueryRow(ctx, `
SELECT
  count(*)::integer,
  count(DISTINCT candidate.generated_artifact_digest)::integer,
  count(DISTINCT candidate.canonical_artifact_digest)::integer,
  count(DISTINCT policy.policy_id)::integer,
  count(DISTINCT exact.policy_id)::integer
FROM sentinelflow.command_candidates candidate
JOIN sentinelflow.policy_proposals policy
  ON policy.command_candidate_id = candidate.command_candidate_id
JOIN sentinelflow.hil_exact_artifacts exact
  ON exact.policy_id = policy.policy_id
 AND exact.policy_version = policy.version
 AND exact.command_candidate_id = candidate.command_candidate_id
WHERE candidate.analysis_id = ANY($1::uuid[])`,
		[]string{testAnalysisID, repeatedAnalysisID}).Scan(
		&candidates, &generatedDigests, &canonicalDigests, &policies, &exactArtifacts,
	)
	if err != nil || candidates != 2 || policies != 2 || exactArtifacts != 2 ||
		generatedDigests != 1 || canonicalDigests != 1 {
		t.Fatalf("candidate/HIL identity rows=%d policies=%d exact=%d generated_digests=%d canonical_digests=%d err=%v",
			candidates, policies, exactArtifacts, generatedDigests, canonicalDigests, err)
	}

	var completedJobs, validClaims, distinctCandidates, distinctValidations int
	if err := connection.QueryRow(ctx, `
SELECT
  count(*) FILTER (WHERE job.state = 'completed')::integer,
  count(*) FILTER (WHERE claim.state = 'valid')::integer,
  count(DISTINCT policy.command_candidate_id)::integer,
  count(DISTINCT exact.validation_snapshot_id)::integer
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.validation_attempt_claims claim ON claim.job_id = job.job_id
JOIN sentinelflow.policy_proposals policy ON policy.analysis_id = claim.analysis_id
JOIN sentinelflow.hil_exact_artifacts exact
  ON exact.policy_id = policy.policy_id AND exact.policy_version = policy.version
WHERE job.job_id = ANY($1::uuid[])`, []string{testJobID, repeatedJobID}).Scan(
		&completedJobs, &validClaims, &distinctCandidates, &distinctValidations,
	); err != nil || completedJobs != 2 || validClaims != 2 ||
		distinctCandidates != 2 || distinctValidations != 2 {
		t.Fatalf("terminal/HIL bindings completed=%d valid=%d candidates=%d validations=%d err=%v",
			completedJobs, validClaims, distinctCandidates, distinctValidations, err)
	}
}

func finalizeNextValidation(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	wantJobID string,
	signalID string,
) validationworker.Snapshot {
	t.Helper()
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
	if err != nil || !found || job.JobID != wantJobID {
		t.Fatalf("lease job=%s want=%s found=%v err=%v", job.JobID, wantJobID, found, err)
	}
	snapshot, prepared, err := store.Prepare(ctx, validationworker.PrepareRequest{
		Job: job.Job, LeaseToken: job.LeaseToken,
	})
	if err != nil || !prepared {
		t.Fatalf("prepare prepared=%v err=%v", prepared, err)
	}
	request := exactValidFinalizeForSignal(t, snapshot, signalID)
	request.Finish.JobID = job.JobID
	request.Finish.LeaseToken = job.LeaseToken
	request.Finish.Now = time.Now().UTC()
	request.Mutation.ValidationAttemptID = snapshot.ValidationAttemptID
	request.Mutation.AnalysisID = snapshot.AnalysisID
	request.Mutation.IncidentID = snapshot.IncidentID
	request.Mutation.IncidentVersion = snapshot.IncidentVersion
	if finished, finalizeErr := store.Finalize(ctx, request); finalizeErr != nil || !finished {
		t.Fatalf("finalize job=%s finished=%v err=%v", job.JobID, finished, finalizeErr)
	}
	return snapshot
}

func insertRepeatedDigestFixture(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	fixtureAt time.Time,
) {
	t.Helper()
	commandText := "add element inet sentinelflow blacklist_ipv4 { 8.8.8.8 timeout 30m }"
	policyValue := map[string]any{
		"schema_version": policy.PolicySchemaVersion, "action": policy.ActionBlockIP,
		"target_ip": "8.8.8.8", "ttl_seconds": 1800,
		"evidence_ids": []string{repeatedSignalID},
		"rationale":    "Complete deterministic evidence supports a temporary block.",
	}
	candidateValue := map[string]any{
		"schema_version": policy.CandidateSchemaVersion, "target_ip": "8.8.8.8",
		"timeout": "30m", "evidence_ids": []string{repeatedSignalID}, "command": commandText,
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
		"evidence_ids": []string{repeatedSignalID}, "policy": policyValue,
		"nftables_command_candidate": candidateValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    repeatedEvidenceID, IncidentID: repeatedIncidentID, IncidentVersion: 1,
		SourceIPv4: "8.8.8.8", ServiceLabel: "gateway",
		WindowStart: fixtureAt.Add(-time.Minute), WindowEnd: fixtureAt,
		SourceHealthDigest: testDigest, EventIDs: []string{testGatewayID},
		SignalIDs: []string{repeatedSignalID}, CreatedAt: fixtureAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	command, err := nftvalidate.Canonicalize([]byte(commandText), 1800)
	if err != nil {
		t.Fatal(err)
	}
	outputDigest := digest(structuredOutput)
	historyEvidenceDigest := validationIncidentEvidenceDigest(
		repeatedIncidentID, 1, repeatedSignalID, digest([]byte("validation-fixture-repeat-signal-v1")),
	)
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version, idempotency_key,
    state, available_at, attempts, max_attempts, created_at, updated_at
) VALUES
    ($1, 'analyze', 'incident', $2, 1, $13, 'completed', clock_timestamp(), 1, 2,
        clock_timestamp(), clock_timestamp()),
    ($3, 'validate', 'analysis_staging', $4, 1, $14, 'pending', clock_timestamp(), 0, 3,
        clock_timestamp(), clock_timestamp());
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, evidence_version
) VALUES ($2, 'path_scan', 'review_ready', '8.8.8.8'::inet, 'gateway',
    $9::timestamptz - interval '1 minute', $9, 0.9, 3, 1);
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip, service_label,
    window_start, window_end, observed_count, distinct_count, threshold_count,
    threshold_distinct, source_health_status, evidence_digest, configuration_version,
    configuration_digest, signal_digest
) SELECT $5, schema_version, rule_id, rule_version, kind, source_ip, service_label,
    window_start + interval '1 second', window_end + interval '1 second', observed_count,
    distinct_count, threshold_count, threshold_distinct, source_health_status,
    evidence_digest, configuration_version, configuration_digest, $24
  FROM sentinelflow.signals WHERE signal_id = $25;
INSERT INTO sentinelflow.incident_signals (
    incident_id, signal_id, incident_version, relation_reason, linked_at
) VALUES ($2, $5, 3, 'same_source_overlap', $9);
INSERT INTO sentinelflow.incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, deterministic_score, mutation_kind, mutation_digest,
    evidence_digest, signal_count, recorded_at
) VALUES
    ($2, 1, 'open', 'path_scan', '8.8.8.8'::inet, 'gateway', $9::timestamptz - interval '1 minute',
     $9, 0.9, 'created', $15, $12, 1, $9),
    ($2, 2, 'analyzing', 'path_scan', '8.8.8.8'::inet, 'gateway', $9::timestamptz - interval '1 minute',
     $9, 0.9, 'state_changed', $16, $12, 1, $9),
    ($2, 3, 'review_ready', 'path_scan', '8.8.8.8'::inet, 'gateway', $9::timestamptz - interval '1 minute',
     $9, 0.9, 'state_changed', $17, $12, 1, $9);
INSERT INTO sentinelflow.incident_version_signals (
    incident_id, incident_version, signal_id, ordinal
) VALUES ($2, 1, $5, 1), ($2, 2, $5, 1), ($2, 3, $5, 1);
INSERT INTO sentinelflow.evidence_snapshots (
    evidence_snapshot_id, schema_version, incident_id, incident_version, source_ip,
    service_label, window_start, window_end, source_health_status, signal_count,
    expanded_event_count, snapshot_digest, created_at, expires_at
) VALUES ($6, 'evidence-snapshot-v1', $2, 1, '8.8.8.8'::inet, 'gateway',
    $9::timestamptz - interval '1 minute', $9, 'complete', 1, 1, $7, $9,
    $9::timestamptz + interval '1 day');
INSERT INTO sentinelflow.evidence_snapshot_artifacts (
    evidence_snapshot_id, schema_version, source_health_digest, canonical_bytes,
    canonical_digest, created_at
) VALUES ($6, 'evidence-snapshot-v1', $18, $11::bytea, $7, $9);
INSERT INTO sentinelflow.evidence_snapshot_signals (
    evidence_snapshot_id, ordinal, signal_id, evidence_id, evidence_digest, expanded_event_count
) SELECT $6, 1, signal_id, signal_id::text, evidence_digest, 1
    FROM sentinelflow.signals WHERE signal_id = $5;
INSERT INTO sentinelflow.evidence_snapshot_events (
    evidence_snapshot_event_id, evidence_snapshot_id, signal_id, event_kind,
    gateway_event_id, event_time
) VALUES ($19, $6, $5, 'gateway', $20, $9);
INSERT INTO sentinelflow.analysis_attempt_claims (
    analysis_id, job_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, outbox_attempt, state, generated_at, terminal_at,
    analyzing_incident_version, terminal_incident_version
) VALUES ($4, $1, $2, 1, $6, $7, 1, 'succeeded', clock_timestamp(),
    clock_timestamp(), 2, 3);
INSERT INTO sentinelflow.ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, attempt, model, reasoning_effort, store_enabled,
    input_schema_digest, prompt_digest, output_schema_digest, input_digest,
    input_bytes, result_state, output_digest, incident_summary, classification,
    confidence, uncertainty, input_tokens, cached_input_tokens, output_tokens,
    started_at, completed_at
) VALUES ($4, $2, 1, $6, $7, 1, 'gpt-5.6-sol', 'medium', false,
    $18, $18, $18, $18, 2, 'succeeded', $8, 'Synthetic incident', 'path_scan',
    0.9, '', 1, 0, 1, clock_timestamp(), clock_timestamp());
INSERT INTO sentinelflow.analysis_attempt_results (
    analysis_id, result_state, provider_attempts, provider_response_id, model,
    reasoning_effort, rate_card_version, input_bytes, input_digest,
    input_schema_digest, prompt_digest, output_schema_digest, output_digest,
    generated_command_digest, input_tokens, cached_input_tokens, output_tokens,
    completed_at
) VALUES ($4, 'succeeded', 1, 'resp_validation_repeat_fixture', 'gpt-5.6-sol',
    'medium', 'operator-v1', 2, $18, $18, $18, $18, $8, $10, 1, 0, 1,
    clock_timestamp());
INSERT INTO sentinelflow.analysis_evidence (
    analysis_id, ordinal, evidence_snapshot_id, signal_id, evidence_id
) VALUES ($4, 1, $6, $5, $5::text);
INSERT INTO sentinelflow.analysis_output_staging (
    analysis_id, structured_output, policy_output, command_candidate_output,
    output_digest, generated_command_digest, created_at
) VALUES ($4, $21::bytea, $22::bytea, $23::bytea, $8, $10, clock_timestamp());`,
		pgx.QueryExecModeSimpleProtocol,
		repeatedAnalysisJobID, repeatedIncidentID, repeatedJobID, repeatedAnalysisID,
		repeatedSignalID, repeatedEvidenceID, evidence.Digest(), outputDigest, fixtureAt,
		command.GeneratedDigest(), evidence.CanonicalBytes(), historyEvidenceDigest,
		digest([]byte("repeat-analyze-job")), digest([]byte("repeat-validate-job")),
		digest([]byte("repeat-incident-created")), digest([]byte("repeat-incident-analyzing")),
		digest([]byte("repeat-incident-ready")), testDigest, repeatedSnapshotEvent,
		testGatewayID, structuredOutput, policyJSON, candidateJSON,
		digest([]byte("validation-fixture-repeat-signal-v1")), testSignalID,
	)
	if err != nil {
		t.Fatalf("insert repeated digest fixture: %v", err)
	}
}
