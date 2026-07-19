-- name: GetIncidentForUpdate :one
SELECT incident_id, kind, state, source_ip, service_label, first_seen,
    last_seen, closed_at, reopen_until, deterministic_score, version,
    analysis_failure_reason, created_at, updated_at
FROM sentinelflow.incidents
WHERE incident_id = $1
FOR UPDATE;

-- name: ListIncidentEvidence :many
SELECT
    event_kind,
    gateway_event_id,
    auth_event_id,
    source_health_event_id,
    relation_reason,
    linked_at
FROM sentinelflow.incident_events
WHERE incident_id = $1
  AND incident_version = $2
ORDER BY linked_at, incident_event_id;

-- name: GetPolicyVersion :one
SELECT policy_id, version, incident_id, incident_version, analysis_id,
    command_candidate_id, evidence_snapshot_id, evidence_snapshot_digest, policy_digest,
    generated_artifact_digest, canonical_artifact_digest, target_ipv4, action,
    ttl_seconds, rationale, state, state_revision, created_at, updated_at
FROM sentinelflow.policy_proposals
WHERE policy_id = $1
  AND version = $2;

-- name: TransitionPolicyState :one
UPDATE sentinelflow.policy_proposals
SET state = $1,
    state_revision = state_revision + 1,
    updated_at = $2
WHERE policy_id = $3
  AND version = $4
  AND state = $5
  AND state_revision = $6
RETURNING policy_id, version, state, state_revision, updated_at;

-- name: GetValidationSnapshot :one
SELECT validation_snapshot_id, schema_version, policy_id, policy_version,
    command_candidate_id, evidence_snapshot_id, snapshot_digest, policy_digest,
    evidence_snapshot_digest, analysis_input_digest, analysis_output_schema_digest,
    prompt_digest, generated_candidate_digest, canonical_artifact_digest,
    grammar_version, parser_version, validator_version,
    base_chain_contract_raw_digest, live_owned_schema_digest,
    protected_ipv4_static_digest, protected_ipv4_effective_config_digest,
    nft_binary_digest, nft_version, historical_impact_digest,
    history_dataset_digest, history_manifest_digest, target_ipv4, ttl_seconds,
    historical_impact_lookback_seconds, state, failure_code,
    source_health_status, created_at, valid_until
FROM sentinelflow.validation_snapshots
WHERE validation_snapshot_id = $1;

-- name: ListValidationGates :many
SELECT validation_snapshot_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
FROM sentinelflow.validation_gates
WHERE validation_snapshot_id = $1
ORDER BY gate_order;

-- name: GetDecisionChallengeForUpdate :one
SELECT challenge_id, schema_version, nonce_digest, session_id,
    session_digest, actor_id, operation, resource_type, resource_id,
    resource_version, policy_id, policy_version, action_id, target_ipv4, policy_digest,
    evidence_snapshot_digest, generated_artifact_digest,
    canonical_artifact_digest, original_add_digest, validation_snapshot_digest,
    validation_valid_until, idempotency_key_digest, authenticated_at,
    reauth_required_after_seconds, issued_at, expires_at, consumed_at,
    consumed_decision_id
FROM sentinelflow.decision_challenges
WHERE challenge_id = $1
FOR UPDATE;

-- name: ConsumeDecisionChallenge :one
UPDATE sentinelflow.decision_challenges
SET consumed_at = $1,
    consumed_decision_id = $2
WHERE challenge_id = $3
  AND consumed_at IS NULL
  AND expires_at >= $1
RETURNING challenge_id, consumed_at, consumed_decision_id;

-- name: AppendAuditEvent :one
SELECT sentinelflow.append_audit_event(
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10,
    $11,
    $12,
    $13,
    $14,
    $15
);

-- name: ListAuditEventsAfter :many
SELECT sequence, event_id, actor_type, actor_id, action, object_type,
    object_id, incident_id, policy_id, policy_version, enforcement_action_id,
    trace_id, primary_digest, secondary_digest, outcome, occurred_at, recorded_at
FROM sentinelflow.audit_events
WHERE sequence > $1
ORDER BY sequence
LIMIT $2;
