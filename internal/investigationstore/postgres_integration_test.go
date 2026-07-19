//go:build integration

package investigationstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const investigationPostgreSQL17Image = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"

// TestInvestigationReadsAgainstPostgreSQL17 proves that the adapter works as
// sentinelflow_api and that the same role cannot mutate investigation state or
// read the executor capability/signature table.
func TestInvestigationReadsAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-investigation-%d", time.Now().UnixNano())
	runInvestigationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", investigationPostgreSQL17Image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForInvestigationPostgreSQL(t, ctx, container)
	port := investigationDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	owner, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatalf("connect owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyInvestigationMigrations(t, ctx, owner)
	seedInvestigationFixture(t, ctx, owner)

	var versionText string
	if err = owner.QueryRow(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil {
		t.Fatal("query PostgreSQL version")
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version/10000 != 17 {
		t.Fatalf("expected PostgreSQL 17, got %q", versionText)
	}

	api, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatalf("connect api role: %v", err)
	}
	t.Cleanup(func() { _ = api.Close(context.Background()) })
	if _, err = api.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatalf("set API role: %v", err)
	}
	store, err := NewPostgreSQLStore(api)
	if err != nil {
		t.Fatal(err)
	}
	incidents, err := store.ListIncidents(ctx, IncidentQuery{State: "open", Limit: 10})
	if err != nil || len(incidents.Items) != 1 || incidents.Items[0].IncidentID != testIncidentID {
		t.Fatalf("API role incidents=%+v err=%v", incidents, err)
	}
	detail, err := store.GetIncident(ctx, testIncidentID)
	if err != nil || detail.Incident.IncidentID != testIncidentID || len(detail.Signals) != 0 ||
		detail.Incident.Version != 11 ||
		detail.Analysis == nil ||
		detail.Analysis.ProviderKind != "deterministic_stub" ||
		detail.Analysis.AdapterID != "sentinelflow-deterministic-ai-stub-v1" ||
		detail.Analysis.IncidentVersion != 10 ||
		detail.Analysis.Model != nil || detail.Analysis.ReasoningEffort != nil ||
		detail.Analysis.RateCardVersion != nil || len(detail.Policies) != 3 {
		t.Fatalf("API role detail=%+v err=%v", detail, err)
	}
	expectedPolicies := []struct {
		id              string
		incidentVersion int32
	}{
		{"019b0000-0000-7000-8000-000000009211", 10},
		{"019b0000-0000-7000-8000-000000009231", 6},
		{testPolicyID, 2},
	}
	analysisIDs := make(map[string]struct{}, len(expectedPolicies))
	candidateIDs := make(map[string]struct{}, len(expectedPolicies))
	policyIDs := make(map[string]struct{}, len(expectedPolicies))
	const generatedDigest = "sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303"
	const canonicalDigest = "sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6"
	for index, summary := range detail.Policies {
		expected := expectedPolicies[index]
		if summary.PolicyID != expected.id || summary.IncidentVersion != expected.incidentVersion ||
			summary.State != "valid" || summary.TargetIPv4 != "203.0.113.20" {
			t.Fatalf("API role policy[%d]=%+v expected=%+v", index, summary, expected)
		}
		policy, policyErr := store.GetPolicy(ctx, summary.PolicyID)
		if policyErr != nil || policy.PolicyID != expected.id ||
			policy.IncidentVersion != expected.incidentVersion || policy.State != "valid" ||
			policy.TargetIPv4 != "203.0.113.20" || policy.GeneratedDigest != generatedDigest ||
			policy.CanonicalDigest != canonicalDigest || policy.Validation == nil ||
			policy.Validation.State != "valid" || len(policy.Validation.Gates) != 6 {
			t.Fatalf("API role policy detail[%d]=%+v err=%v", index, policy, policyErr)
		}
		if calculated := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(policy.GeneratedCommand))); calculated != generatedDigest {
			t.Fatalf("generated artifact digest mismatch: calculated=%s stored=%s", calculated, generatedDigest)
		}
		if calculated := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(policy.CanonicalCommand))); calculated != canonicalDigest {
			t.Fatalf("canonical artifact digest mismatch: calculated=%s stored=%s", calculated, canonicalDigest)
		}
		policyIDs[policy.PolicyID] = struct{}{}
		analysisIDs[policy.AnalysisID] = struct{}{}
		candidateIDs[policy.CommandCandidateID] = struct{}{}
	}
	if len(policyIDs) != 3 || len(analysisIDs) != 3 || len(candidateIDs) != 3 {
		t.Fatalf("repeated content lost distinct bindings: policies=%v analyses=%v candidates=%v",
			policyIDs, analysisIDs, candidateIDs)
	}
	if _, err = owner.Exec(ctx, `UPDATE sentinelflow.incidents
SET version = 12, evidence_version = 11, updated_at = $2
WHERE incident_id = $1`, testIncidentID, testNow.Add(time.Second)); err != nil {
		t.Fatalf("advance current evidence without analysis: %v", err)
	}
	detail, err = store.GetIncident(ctx, testIncidentID)
	if err != nil || detail.Incident.Version != 12 || detail.Analysis != nil {
		t.Fatalf("current evidence without analysis must omit latest_analysis: detail=%+v err=%v", detail, err)
	}
	const currentAttemptOne = "019b0000-0000-4000-8000-0000000092ff"
	const currentAttemptTwo = "019b0000-0000-4000-8000-000000009201"
	if _, err = owner.Exec(ctx, `
INSERT INTO sentinelflow.ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_digest,
    attempt, provider_kind, adapter_id, model, reasoning_effort,
    rate_card_version, store_enabled, input_schema_digest, prompt_digest,
    output_schema_digest, input_digest, input_bytes, result_state,
    output_digest, incident_summary, classification, confidence, uncertainty,
    started_at, completed_at
)
SELECT seed.analysis_id::uuid, source.incident_id, 11,
       source.evidence_snapshot_digest, seed.attempt,
       source.provider_kind, source.adapter_id, source.model,
       source.reasoning_effort, source.rate_card_version,
       source.store_enabled, source.input_schema_digest, source.prompt_digest,
       source.output_schema_digest, source.input_digest, source.input_bytes,
       source.result_state, source.output_digest, seed.summary,
       source.classification, source.confidence, source.uncertainty,
       $1::timestamptz + (seed.attempt || ' seconds')::interval,
       $1::timestamptz + (seed.attempt || ' seconds')::interval
FROM sentinelflow.ai_analyses source
CROSS JOIN (VALUES
    ($2, 1, 'Synthetic current analysis attempt one.'),
    ($3, 2, 'Synthetic current analysis attempt two.')
) AS seed(analysis_id, attempt, summary)
WHERE source.analysis_id = '019b0000-0000-4000-8000-000000009222'::uuid`,
		testNow, currentAttemptOne, currentAttemptTwo); err != nil {
		t.Fatalf("seed current evidence analysis attempts: %v", err)
	}
	detail, err = store.GetIncident(ctx, testIncidentID)
	if err != nil || detail.Analysis == nil || detail.Analysis.IncidentVersion != 11 ||
		detail.Analysis.AnalysisID != currentAttemptTwo || detail.Analysis.Summary == nil ||
		*detail.Analysis.Summary != "Synthetic current analysis attempt two." {
		t.Fatalf("current analysis attempt ordering: detail=%+v err=%v", detail, err)
	}
	driftDB := &mutationAfterIncidentReadQueryer{
		connection: api,
		afterScan: func() error {
			_, updateErr := owner.Exec(ctx, `UPDATE sentinelflow.incidents
SET version = 13, evidence_version = 12, updated_at = $2
WHERE incident_id = $1`, testIncidentID, testNow.Add(2*time.Second))
			return updateErr
		},
	}
	driftStore, err := NewPostgreSQLStore(driftDB)
	if err != nil {
		t.Fatal(err)
	}
	driftDetail, err := driftStore.GetIncident(ctx, testIncidentID)
	if err != nil || !driftDB.fired || driftDetail.Incident.Version != 12 ||
		driftDetail.Analysis == nil || driftDetail.Analysis.IncidentVersion != 11 ||
		driftDetail.Analysis.AnalysisID != currentAttemptTwo {
		t.Fatalf("cross-statement evidence binding: fired=%v detail=%+v err=%v", driftDB.fired, driftDetail, err)
	}
	var aggregateVersion int32
	var evidenceVersion int32
	if err = owner.QueryRow(ctx, `SELECT version, evidence_version
FROM sentinelflow.incidents WHERE incident_id = $1`, testIncidentID).
		Scan(&aggregateVersion, &evidenceVersion); err != nil || aggregateVersion != 13 || evidenceVersion != 12 {
		t.Fatalf("concurrent evidence advance not observed: aggregate=%d evidence=%d err=%v",
			aggregateVersion, evidenceVersion, err)
	}
	const invalidPolicyID = "019b0000-0000-7000-8000-00000000b020"
	const invalidAnalysisID = "019b0000-0000-4000-8000-00000000b021"
	seedInvalidValidationAttempt(t, ctx, owner, invalidPolicyID, invalidAnalysisID)
	invalidPolicy, err := store.GetPolicy(ctx, invalidPolicyID)
	if err != nil || invalidPolicy.State != "invalid" || invalidPolicy.StateRevision != 3 ||
		invalidPolicy.Validation != nil || invalidPolicy.ValidationAttempt == nil {
		t.Fatalf("API role invalid policy=%+v err=%v", invalidPolicy, err)
	}
	attempt := invalidPolicy.ValidationAttempt
	if attempt.ValidationAttemptID != "019b0000-0000-7000-8000-00000000b001" ||
		attempt.PolicyID != invalidPolicyID || attempt.AnalysisID != invalidAnalysisID ||
		attempt.IncidentID != testIncidentID || attempt.IncidentVersion != 12 ||
		attempt.State != "invalid" || attempt.FailureCode == nil ||
		*attempt.FailureCode != "history_demo_binding_mismatch" || attempt.FailedGate == nil ||
		*attempt.FailedGate != "historical_impact" || attempt.TerminalMutationDigest == nil ||
		attempt.PreparedSnapshotDigest != "sha256:"+strings.Repeat("b4", 32) ||
		*attempt.TerminalMutationDigest != "sha256:"+strings.Repeat("b6", 32) ||
		len(attempt.Gates) != 6 {
		t.Fatalf("API role validation attempt=%+v", attempt)
	}
	expectedGateNames := []string{
		"structured_output", "command_grammar", "policy_evidence_command_consistency",
		"protected_network", "owned_schema_syntax", "historical_impact",
	}
	for index, gate := range attempt.Gates {
		expectedState, expectedCode := "passed", "ok"
		if index == 5 {
			expectedState, expectedCode = "failed", "history_demo_binding_mismatch"
		}
		expectedDigest := fmt.Sprintf("sha256:%s", strings.Repeat(strconv.Itoa(index+1), 64))
		if gate.Order != int16(index+1) || gate.Name != expectedGateNames[index] ||
			gate.State != expectedState || gate.ResultCode != expectedCode ||
			gate.ArtifactDigest != expectedDigest {
			t.Fatalf("API role validation gate[%d]=%+v", index, gate)
		}
	}
	if _, err = owner.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatalf("disable triggers for contradictory policy fixture: %v", err)
	}
	if _, err = owner.Exec(ctx, `UPDATE sentinelflow.policy_proposals
SET state = 'valid'
WHERE policy_id = $1`, invalidPolicyID); err != nil {
		t.Fatalf("seed contradictory policy state: %v", err)
	}
	if _, err = owner.Exec(ctx, `SET session_replication_role = origin`); err != nil {
		t.Fatalf("restore triggers after contradictory policy fixture: %v", err)
	}
	if _, err = store.GetPolicy(ctx, invalidPolicyID); !errors.Is(err, ErrInvalidRow) {
		t.Fatalf("API accepted valid policy with invalid terminal attempt: %v", err)
	}
	if _, err = owner.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatalf("disable triggers to restore policy fixture: %v", err)
	}
	if _, err = owner.Exec(ctx, `UPDATE sentinelflow.policy_proposals
SET state = 'invalid'
WHERE policy_id = $1`, invalidPolicyID); err != nil {
		t.Fatalf("restore invalid policy state: %v", err)
	}
	if _, err = owner.Exec(ctx, `SET session_replication_role = origin`); err != nil {
		t.Fatalf("restore triggers after policy fixture repair: %v", err)
	}
	var rawJSON []byte
	if err = api.QueryRow(ctx, `SELECT prepared_snapshot::text::bytea
FROM sentinelflow.validation_attempt_claims LIMIT 1`).Scan(&rawJSON); err == nil || err == pgx.ErrNoRows {
		t.Fatalf("sentinelflow_api unexpectedly read raw prepared snapshot: %v", err)
	}
	if err = api.QueryRow(ctx, `SELECT terminal_mutation::text::bytea
FROM sentinelflow.validation_attempt_results LIMIT 1`).Scan(&rawJSON); err == nil || err == pgx.ErrNoRows {
		t.Fatalf("sentinelflow_api unexpectedly read raw terminal mutation: %v", err)
	}
	events, err := store.ListIncidentEvents(ctx, IncidentEventQuery{IncidentID: testIncidentID, Limit: 10})
	if err != nil || len(events.Items) != 0 {
		t.Fatalf("API role incident events=%+v err=%v", events, err)
	}
	audit, err := store.ListAuditEvents(ctx, AuditQuery{IncidentID: testIncidentID, Limit: 10})
	if err != nil || len(audit.Items) != 1 || audit.Items[0].Action != "incident_created" {
		t.Fatalf("API role audit=%+v err=%v", audit, err)
	}

	if _, err = api.Exec(ctx, `UPDATE sentinelflow.incidents SET state = 'closed' WHERE incident_id = $1`, testIncidentID); err == nil {
		t.Fatal("sentinelflow_api unexpectedly mutated incidents")
	}
	if _, err = api.Exec(ctx, `INSERT INTO sentinelflow.audit_events (
		event_id, actor_type, actor_id, action, object_type, outcome, occurred_at
	) VALUES (gen_random_uuid(), 'system', 'api', 'forbidden', 'incident', 'failed', clock_timestamp())`); err == nil {
		t.Fatal("sentinelflow_api unexpectedly inserted audit event directly")
	}
	var signature []byte
	if err = api.QueryRow(ctx, `SELECT capability_signature FROM sentinelflow.execution_capabilities LIMIT 1`).Scan(&signature); err == nil || err == pgx.ErrNoRows {
		t.Fatalf("sentinelflow_api unexpectedly read execution capability signature: %v", err)
	}
}

func seedInvalidValidationAttempt(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	policyID string,
	analysisID string,
) {
	t.Helper()
	const candidateID = "019b0000-0000-7000-8000-00000000b022"
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_digest,
    attempt, provider_kind, adapter_id, model, reasoning_effort,
    rate_card_version, store_enabled, input_schema_digest, prompt_digest,
    output_schema_digest, input_digest, input_bytes, result_state,
    output_digest, incident_summary, classification, confidence, uncertainty,
    started_at, completed_at
) VALUES (
    $4, $3, 12,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    1, 'deterministic_stub', 'sentinelflow-deterministic-ai-stub-v1',
    NULL, NULL, NULL, false,
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    128, 'succeeded',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'Synthetic deterministic stub analysis.', 'request_burst', 0.75, '', $2, $2
);

INSERT INTO sentinelflow.command_candidates (
    command_candidate_id, schema_version, analysis_id,
    evidence_snapshot_digest, target_ipv4, timeout_token, ttl_seconds,
    generated_command, generated_artifact_digest, parse_state,
    canonical_artifact, canonical_artifact_digest, created_at, updated_at
) VALUES (
    $5, 'nft-blacklist-v1', $4,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '203.0.113.20', '30m', 1800,
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'valid',
    convert_to('add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }' || chr(10), 'UTF8'),
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    $2, $2
);

INSERT INTO sentinelflow.policy_proposals (
    policy_id, version, schema_version, incident_id, incident_version,
    analysis_id, command_candidate_id, evidence_snapshot_digest,
    policy_digest, generated_artifact_digest, canonical_artifact_digest,
    target_ipv4, action, ttl_seconds, rationale, state, state_revision,
    created_at, updated_at
) VALUES (
    $1, 1, 'response-policy-v1', $3, 12, $4, $5,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    '203.0.113.20', 'block_ip', 1800, 'Synthetic fail-closed review.',
    'draft', 1, $2, $2
);
UPDATE sentinelflow.policy_proposals
SET state = 'validating', state_revision = 2, updated_at = $2
WHERE policy_id = $1;

INSERT INTO sentinelflow.evidence_snapshots (
    evidence_snapshot_id, schema_version, incident_id, incident_version,
    source_ip, service_label, window_start, window_end, source_health_status,
    signal_count, expanded_event_count, snapshot_digest, created_at, expires_at
) VALUES (
    '019b0000-0000-7000-8000-00000000b010', 'evidence-snapshot-v1', $3, 12,
    '203.0.113.20', 'demo', $2::timestamptz - interval '1 minute', $2, 'complete',
    1, 1, 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    $2, $2::timestamptz + interval '7 days'
);

INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    idempotency_key, state, attempts, max_attempts, created_at, updated_at
) VALUES
(
    '019b0000-0000-7000-8000-00000000b011', 'analyze', 'incident', $3, 12,
    'sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1',
    'completed', 1, 8, $2, $2
),
(
    '019b0000-0000-7000-8000-00000000b012', 'validate', 'analysis_staging', $4, 1,
    'sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2',
    'completed', 1, 8, $2, $2
);

INSERT INTO sentinelflow.analysis_attempt_claims (
    analysis_id, job_id, incident_id, incident_version, evidence_snapshot_id,
    evidence_snapshot_digest, outbox_attempt, state, generated_at, terminal_at,
    analyzing_incident_version, terminal_incident_version
) VALUES (
    $4, '019b0000-0000-7000-8000-00000000b011', $3, 12,
    '019b0000-0000-7000-8000-00000000b010',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    1, 'succeeded', $2, $2, 13, 14
);

INSERT INTO sentinelflow.analysis_output_staging (
    analysis_id, structured_output, policy_output, command_candidate_output,
    output_digest, generated_command_digest, created_at
) VALUES (
    $4, convert_to('{}', 'UTF8'), convert_to('{}', 'UTF8'), convert_to('{}', 'UTF8'),
    'sha256:b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303', $2
);

INSERT INTO sentinelflow.analysis_attempt_results (
    analysis_id, result_state, retry_eligible, provider_attempts,
    provider_response_id, model, reasoning_effort, rate_card_version,
    input_bytes, input_digest, input_schema_digest, prompt_digest,
    output_schema_digest, output_digest, generated_command_digest,
    input_tokens, cached_input_tokens, output_tokens, completed_at
) VALUES (
    $4, 'succeeded', false, 1, 'deterministic-test-response', 'gpt-5.6-sol',
    'medium', 'test-rate-v1', 2,
    'sha256:b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    2, 0, 1, $2
);

INSERT INTO sentinelflow.validation_attempt_claims (
    validation_attempt_id, job_id, analysis_id, incident_id, incident_version,
    evidence_snapshot_id, evidence_snapshot_digest, policy_id,
    command_candidate_id, validation_snapshot_id, outbox_attempt, state,
    failure_code, prepared_snapshot, prepared_snapshot_digest, generated_at, terminal_at
) VALUES (
    '019b0000-0000-7000-8000-00000000b001',
    '019b0000-0000-7000-8000-00000000b012', $4, $3, 12,
    '019b0000-0000-7000-8000-00000000b010',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    $1, $5, '019b0000-0000-7000-8000-00000000b013', 1, 'invalid',
    'history_demo_binding_mismatch', '{}'::jsonb,
    'sha256:b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4',
    $2, $2
);

INSERT INTO sentinelflow.validation_attempt_gates (
    validation_attempt_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
)
SELECT '019b0000-0000-7000-8000-00000000b001', gate_order, gate_name,
       gate_order < 6,
       CASE WHEN gate_order < 6 THEN 'ok' ELSE 'history_demo_binding_mismatch' END,
       'sha256:b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5',
       ('sha256:' || repeat(to_hex(gate_order), 64))::sentinelflow.sha256_digest, $2
FROM (VALUES
    (1, 'structured_output'),
    (2, 'command_grammar'),
    (3, 'policy_evidence_command_consistency'),
    (4, 'protected_network'),
    (5, 'owned_schema_syntax'),
    (6, 'historical_impact')
) AS gate(gate_order, gate_name);

INSERT INTO sentinelflow.validation_attempt_results (
    validation_attempt_id, result_state, failure_code, failed_gate,
    prepared_snapshot_digest, terminal_mutation, terminal_mutation_digest, completed_at
) VALUES (
    '019b0000-0000-7000-8000-00000000b001', 'invalid',
    'history_demo_binding_mismatch', 'historical_impact',
    'sha256:b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4',
    '{"schema_version":"validation-terminal-v1"}'::jsonb,
    'sha256:b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6',
		$2
);

UPDATE sentinelflow.command_candidates
SET parse_state = 'canonical', updated_at = $2
WHERE command_candidate_id = $5;

UPDATE sentinelflow.policy_proposals
SET state = 'invalid', state_revision = 3, updated_at = $2
WHERE policy_id = $1 AND state = 'validating';`,
		pgx.QueryExecModeSimpleProtocol,
		policyID,
		testNow.Add(time.Second),
		testIncidentID,
		analysisID,
		candidateID,
	)
	if err != nil {
		t.Fatalf("seed invalid validation attempt: %v", err)
	}
}

func seedInvestigationFixture(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, evidence_version, created_at, updated_at
) VALUES (
	$1, 'request_burst', 'open', '203.0.113.20', 'demo', $2, $2,
	0.9, 11, 10, $2, $2
);`, testIncidentID, testNow)
	if err != nil {
		t.Fatalf("seed incident fixture: %v", err)
	}
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_digest,
    attempt, provider_kind, adapter_id, model, reasoning_effort,
    rate_card_version, store_enabled, input_schema_digest, prompt_digest,
    output_schema_digest, input_digest, input_bytes, result_state,
    output_digest, incident_summary, classification, confidence, uncertainty,
    started_at, completed_at
) VALUES (
    $3, $1, 2,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    1, 'deterministic_stub', 'sentinelflow-deterministic-ai-stub-v1',
    NULL, NULL, NULL, false,
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    128, 'succeeded',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'Synthetic deterministic stub analysis.', 'request_burst', 0.75, '', $2, $2
);`, testIncidentID, testNow, testAnalysisID)
	if err != nil {
		t.Fatalf("seed analysis fixture: %v", err)
	}
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.ai_analyses (
    analysis_id, incident_id, incident_version, evidence_snapshot_digest,
    attempt, provider_kind, adapter_id, model, reasoning_effort,
    rate_card_version, store_enabled, input_schema_digest, prompt_digest,
    output_schema_digest, input_digest, input_bytes, result_state,
    output_digest, incident_summary, classification, confidence, uncertainty,
    started_at, completed_at
) VALUES
(
    '019b0000-0000-4000-8000-000000009212', $1, 6,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    1, 'deterministic_stub', 'sentinelflow-deterministic-ai-stub-v1',
    NULL, NULL, NULL, false,
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    128, 'succeeded',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'Synthetic deterministic stub analysis.', 'request_burst', 0.75, '', $2, $2
),
(
    '019b0000-0000-4000-8000-000000009222', $1, 10,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    1, 'deterministic_stub', 'sentinelflow-deterministic-ai-stub-v1',
    NULL, NULL, NULL, false,
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    128, 'succeeded',
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'Synthetic deterministic stub analysis.', 'request_burst', 0.75, '', $2, $2
);`, testIncidentID, testNow)
	if err != nil {
		t.Fatalf("seed repeated analysis fixtures: %v", err)
	}
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.command_candidates (
    command_candidate_id, schema_version, analysis_id,
    evidence_snapshot_digest, target_ipv4, timeout_token, ttl_seconds,
    generated_command, generated_artifact_digest, parse_state,
    canonical_artifact, canonical_artifact_digest, created_at, updated_at
) VALUES
(
    $1, 'nft-blacklist-v1', $2,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '203.0.113.20', '30m', 1800,
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'valid',
    convert_to('add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }' || chr(10), 'UTF8'),
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    $3, $3
),
(
    '019b0000-0000-7000-8000-000000009213', 'nft-blacklist-v1',
    '019b0000-0000-4000-8000-000000009212',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '203.0.113.20', '30m', 1800,
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'valid',
    convert_to('add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }' || chr(10), 'UTF8'),
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    $3, $3
),
(
    '019b0000-0000-7000-8000-000000009223', 'nft-blacklist-v1',
    '019b0000-0000-4000-8000-000000009222',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '203.0.113.20', '30m', 1800,
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'valid',
    convert_to('add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }' || chr(10), 'UTF8'),
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    $3, $3
);`, testCandidateID, testAnalysisID, testNow)
	if err != nil {
		t.Fatalf("seed repeated command candidate fixtures: %v", err)
	}
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.policy_proposals (
    policy_id, version, schema_version, incident_id, incident_version,
    analysis_id, command_candidate_id, evidence_snapshot_digest,
    policy_digest, generated_artifact_digest, canonical_artifact_digest,
    target_ipv4, action, ttl_seconds, rationale, state, state_revision,
    created_at, updated_at
) VALUES
(
    $1, 1, 'response-policy-v1', $2, 2, $3, $4,
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    '203.0.113.20', 'block_ip', 1800, 'Synthetic evidence-bound review.',
    'draft', 1, $5, $5
),
(
    '019b0000-0000-7000-8000-000000009231', 1, 'response-policy-v1', $2, 6,
    '019b0000-0000-4000-8000-000000009212',
    '019b0000-0000-7000-8000-000000009213',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    '203.0.113.20', 'block_ip', 1800, 'Synthetic evidence-bound review.',
    'draft', 1, $5, $5
),
(
    '019b0000-0000-7000-8000-000000009211', 1, 'response-policy-v1', $2, 10,
    '019b0000-0000-4000-8000-000000009222',
    '019b0000-0000-7000-8000-000000009223',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:5555555555555555555555555555555555555555555555555555555555555555',
    'sha256:cdf58824141aa6d280b4a5c32c5b2ecc50db68e334b104e4861e6a6421de3303',
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
    '203.0.113.20', 'block_ip', 1800, 'Synthetic evidence-bound review.',
    'draft', 1, $5, $5
);`, testPolicyID, testIncidentID, testAnalysisID, testCandidateID, testNow)
	if err != nil {
		t.Fatalf("seed repeated policy fixtures: %v", err)
	}
	_, err = connection.Exec(ctx, `
UPDATE sentinelflow.policy_proposals
SET state = 'validating', state_revision = 2
WHERE incident_id = $1;

INSERT INTO sentinelflow.validation_snapshots (
    validation_snapshot_id, schema_version, policy_id, policy_version,
    command_candidate_id, snapshot_digest, policy_digest,
    evidence_snapshot_digest, analysis_input_digest,
    analysis_output_schema_digest, prompt_digest, generated_candidate_digest,
    canonical_artifact_digest, grammar_version, parser_version,
    validator_version, base_chain_contract_raw_digest, live_owned_schema_digest,
    protected_ipv4_static_digest, protected_ipv4_effective_config_digest,
    nft_binary_digest, nft_version, historical_impact_digest, target_ipv4,
    ttl_seconds, historical_impact_lookback_seconds, state,
    source_health_status, created_at, valid_until
)
SELECT
    seed.validation_snapshot_id::uuid, 'validation-snapshot-v1',
    policy.policy_id, policy.version, policy.command_candidate_id,
    seed.snapshot_digest::sentinelflow.sha256_digest, policy.policy_digest,
    policy.evidence_snapshot_digest,
    'sha256:6666666666666666666666666666666666666666666666666666666666666666',
    'sha256:7777777777777777777777777777777777777777777777777777777777777777',
    'sha256:8888888888888888888888888888888888888888888888888888888888888888',
    policy.generated_artifact_digest, policy.canonical_artifact_digest,
    'nft-blacklist-v1', 'parser-v1', 'validator-v1',
    'sha256:9999999999999999999999999999999999999999999999999999999999999999',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    '1.0.0',
    'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    policy.target_ipv4, policy.ttl_seconds, 86400, 'draft', 'complete',
    $2, $2::timestamptz + interval '5 minutes'
FROM sentinelflow.policy_proposals policy
JOIN (VALUES
    ($3, '019b0000-0000-7000-8000-000000009214',
        'sha256:1212121212121212121212121212121212121212121212121212121212121212'),
    ('019b0000-0000-7000-8000-000000009231',
        '019b0000-0000-7000-8000-000000009215',
        'sha256:1313131313131313131313131313131313131313131313131313131313131313'),
    ('019b0000-0000-7000-8000-000000009211',
        '019b0000-0000-7000-8000-000000009225',
        'sha256:1414141414141414141414141414141414141414141414141414141414141414')
) AS seed(policy_id, validation_snapshot_id, snapshot_digest)
  ON policy.policy_id = seed.policy_id::uuid
WHERE policy.incident_id = $1;

INSERT INTO sentinelflow.validation_gates (
    validation_snapshot_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
)
SELECT validation.validation_snapshot_id, gate.gate_order, gate.gate_name,
       true, 'ok',
       'sha256:1515151515151515151515151515151515151515151515151515151515151515',
       'sha256:1616161616161616161616161616161616161616161616161616161616161616',
       $2
FROM sentinelflow.validation_snapshots validation
CROSS JOIN (VALUES
    (1, 'structured_output'),
    (2, 'command_grammar'),
    (3, 'policy_evidence_command_consistency'),
    (4, 'protected_network'),
    (5, 'owned_schema_syntax'),
    (6, 'historical_impact')
) AS gate(gate_order, gate_name)
WHERE validation.policy_id IN (
    $3, '019b0000-0000-7000-8000-000000009231',
    '019b0000-0000-7000-8000-000000009211'
);

UPDATE sentinelflow.validation_snapshots
SET state = 'valid'
WHERE policy_id IN (
    $3, '019b0000-0000-7000-8000-000000009231',
    '019b0000-0000-7000-8000-000000009211'
);

UPDATE sentinelflow.policy_proposals
SET state = 'valid', state_revision = 3
WHERE incident_id = $1;`, pgx.QueryExecModeSimpleProtocol, testIncidentID, testNow, testPolicyID)
	if err != nil {
		t.Fatalf("validate repeated policy fixtures: %v", err)
	}
	_, err = connection.Exec(ctx, `
INSERT INTO sentinelflow.audit_events (
	event_id, actor_type, actor_id, action, object_type, object_id,
	incident_id, outcome, occurred_at, recorded_at
) VALUES (
	$3, 'system', 'correlator', 'incident_created', 'incident', $1,
	$1, 'succeeded', $2, $2
);`, testIncidentID, testNow, testEventID)
	if err != nil {
		t.Fatalf("seed investigation fixture: %v", err)
	}
}

func applyInvestigationMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", filepath.Base(path), readErr)
		}
		if _, applyErr := connection.Exec(ctx, string(contents)); applyErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), applyErr)
		}
	}
}

func waitForInvestigationPostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	consecutive := 0
	for range 120 {
		if exec.CommandContext(
			ctx, "docker", "exec", container, "pg_isready", "--host", "127.0.0.1",
			"--username", "postgres", "--dbname", "postgres",
		).Run() == nil {
			consecutive++
			if consecutive == 2 {
				return
			}
		} else {
			consecutive = 0
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL readiness: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func investigationDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runInvestigationDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runInvestigationDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

type mutationAfterIncidentReadQueryer struct {
	connection *pgx.Conn
	afterScan  func() error
	fired      bool
}

func (queryer *mutationAfterIncidentReadQueryer) Query(
	ctx context.Context,
	query string,
	args ...any,
) (pgx.Rows, error) {
	return queryer.connection.Query(ctx, query, args...)
}

func (queryer *mutationAfterIncidentReadQueryer) QueryRow(
	ctx context.Context,
	query string,
	args ...any,
) pgx.Row {
	row := queryer.connection.QueryRow(ctx, query, args...)
	if query != getIncidentSQL || queryer.fired {
		return row
	}
	queryer.fired = true
	return mutationAfterScanRow{Row: row, afterScan: queryer.afterScan}
}

type mutationAfterScanRow struct {
	pgx.Row
	afterScan func() error
}

func (row mutationAfterScanRow) Scan(dest ...any) error {
	if err := row.Row.Scan(dest...); err != nil {
		return err
	}
	return row.afterScan()
}
