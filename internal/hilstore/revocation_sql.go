package hilstore

const issueRevocationChallengeSQL = `
SELECT *
FROM sentinelflow.issue_hil_revocation_challenge_000027(
    $1::uuid, $2, $3::uuid, $4, $5, $6, $7::timestamptz,
    $8::timestamptz, $9, $10::uuid, $11, $12, $13
)`

const commitRevocationSQL = `
SELECT
    committed_decision_id, committed_revocation_id,
    committed_authorization_id, committed_authorization_digest,
    committed_outbox_job_id, replayed, session_rotated
FROM sentinelflow.commit_hil_revocation_with_session_rotation_000027(
    $1::uuid, $2, $3, $4, $5::timestamptz, $6::timestamptz,
    $7::uuid, $8, $9, $10, $11, $12::uuid, $13, $14::uuid, $15,
    $16, $17, $18::uuid, $19, $20, $21, $22, $23::uuid,
    $24::timestamptz, $25::timestamptz, $26, $27, $28::uuid,
    $29, $30, $31::uuid, $32::uuid, $33::uuid, $34::timestamptz,
    $35::timestamptz, $36::uuid, $37::timestamptz, $38::uuid,
    $39, $40, $41, $42::timestamptz, $43::timestamptz,
    $44::timestamptz, $45::timestamptz, $46::uuid
)`

const lookupRevocationSQL = `
SELECT
    decision.schema_version,
    decision.decision_id::text,
    decision.challenge_id::text,
    decision.session_digest::text,
    decision.operation,
    decision.decision,
    decision.resource_type,
    decision.resource_id::text,
    decision.resource_version,
    host(decision.target_ipv4),
    decision.policy_digest::text,
    decision.generated_artifact_digest::text,
    decision.canonical_artifact_digest::text,
    decision.original_add_digest::text,
    decision.evidence_snapshot_digest::text,
    decision.validation_snapshot_digest::text,
    decision.validation_snapshot_id::text,
    validation.live_owned_schema_digest::text,
    decision.actor_id::text,
    decision.reason_digest::text,
    decision.challenge_nonce_digest::text,
    decision.idempotency_key_digest::text,
    decision.decided_at,
    decision.decision_valid_until,
    decision.decision_jcs,
    decision.decision_digest::text,
    challenge.challenge_jcs,
    challenge.challenge_digest::text,
    challenge.consumed_at,
    challenge.consumed_decision_id::text,
    reason.reason_id::text,
    reason.actor_id::text,
    reason.operation,
    reason.reason_code,
    reason.normalized_reason,
    reason.reason_jcs,
    reason.reason_digest::text,
    authz.authorization_id::text,
    authz.authorization_jcs,
    authz.authorization_digest::text,
    authz.decided_at,
    authz.valid_until,
    revoke.revocation_id::text,
    revoke.action_version,
    revoke.artifact,
    revoke.artifact_digest::text,
    revoke.original_add_digest::text,
    revoke.state,
    job.job_id::text,
    job.aggregate_version,
    job.kind,
    job.operation,
    job.idempotency_key::text,
    operation.artifact,
    operation.artifact_digest::text,
    operation.original_add_digest::text,
    operation.authorization_digest::text,
    operation.enforcement_authorization_id::text,
    operation.inspection_authorization_id::text,
    operation.policy_id::text,
    operation.policy_version,
    host(operation.target_ipv4),
    operation.evidence_snapshot_digest::text,
    operation.validation_snapshot_id::text,
    operation.validation_snapshot_digest::text,
    operation.actor_id::text,
    operation.reason_digest::text,
    operation.owned_schema_digest::text,
    operation.not_before,
    operation.valid_until,
    audit.event_id,
    audit.match_count
FROM sentinelflow.approval_decisions decision
JOIN sentinelflow.decision_challenges challenge
  ON challenge.challenge_id = decision.challenge_id
JOIN sentinelflow.hil_reasons reason ON reason.reason_id = decision.reason_id
JOIN sentinelflow.enforcement_authorizations authz
  ON authz.approval_decision_id = decision.decision_id
 AND authz.authorization_kind = 'revoke'
 AND authz.action_id = decision.action_id
 AND authz.policy_id = decision.policy_id
 AND authz.policy_version = decision.policy_version
 AND authz.decision = 'revoke'
 AND authz.target_ipv4 = decision.target_ipv4
 AND authz.policy_digest = decision.policy_digest
 AND authz.generated_artifact_digest = decision.generated_artifact_digest
 AND authz.canonical_artifact_digest = decision.canonical_artifact_digest
 AND authz.original_add_digest = decision.original_add_digest
 AND authz.evidence_snapshot_digest = decision.evidence_snapshot_digest
 AND authz.validation_snapshot_digest = decision.validation_snapshot_digest
 AND authz.actor_id = decision.actor_id
 AND authz.hil_reason_digest = decision.reason_digest
 AND authz.decision_nonce_digest = decision.challenge_nonce_digest
 AND authz.idempotency_key_digest = decision.idempotency_key_digest
 AND authz.decided_at = decision.decided_at
 AND authz.valid_until = decision.decision_valid_until
JOIN sentinelflow.revocation_operations revoke
  ON revoke.approval_decision_id = decision.decision_id
 AND revoke.authorization_id = authz.authorization_id
 AND revoke.action_id = decision.action_id
 AND revoke.action_version = decision.resource_version
 AND revoke.actor_id = decision.actor_id
 AND revoke.reason_id = decision.reason_id
 AND revoke.reason_digest = decision.reason_digest
 AND revoke.target_ipv4 = decision.target_ipv4
 AND revoke.original_add_digest = decision.original_add_digest
 AND revoke.artifact_digest = decision.canonical_artifact_digest
JOIN sentinelflow.enforcement_actions action
  ON action.action_id = revoke.action_id
 AND action.policy_id = decision.policy_id
 AND action.policy_version = decision.policy_version
 AND action.validation_snapshot_id = decision.validation_snapshot_id
 AND action.target_ipv4 = decision.target_ipv4
 AND action.canonical_artifact_digest = decision.original_add_digest
 AND action.evidence_snapshot_digest = decision.evidence_snapshot_digest
JOIN sentinelflow.validation_snapshots validation
  ON validation.validation_snapshot_id = decision.validation_snapshot_id
 AND validation.snapshot_digest = decision.validation_snapshot_digest
JOIN sentinelflow.outbox_jobs job
  ON job.kind = 'dispatch_revoke'
 AND job.operation = 'revoke'
 AND job.aggregate_id = revoke.action_id
 AND job.aggregate_version = revoke.action_version
 AND job.idempotency_key = authz.authorization_digest
JOIN sentinelflow.dispatch_operations operation
  ON operation.job_id = job.job_id
 AND operation.operation = 'revoke'
 AND operation.action_id = revoke.action_id
 AND operation.policy_id = authz.policy_id
 AND operation.policy_version = authz.policy_version
 AND operation.target_ipv4 = authz.target_ipv4
 AND operation.artifact = revoke.artifact
 AND operation.artifact_digest = revoke.artifact_digest
 AND operation.original_add_digest = revoke.original_add_digest
 AND operation.evidence_snapshot_digest = authz.evidence_snapshot_digest
 AND operation.validation_snapshot_id = decision.validation_snapshot_id
 AND operation.validation_snapshot_digest = authz.validation_snapshot_digest
 AND operation.enforcement_authorization_id = authz.authorization_id
 AND operation.inspection_authorization_id IS NULL
 AND operation.authorization_digest = authz.authorization_digest
 AND operation.actor_id = decision.actor_id
 AND operation.reason_digest = decision.reason_digest
 AND operation.owned_schema_digest = validation.live_owned_schema_digest
 AND operation.not_before = authz.decided_at
 AND operation.valid_until = authz.valid_until
CROSS JOIN LATERAL (
    SELECT min(candidate.event_id::text) AS event_id, count(*)::integer AS match_count
    FROM sentinelflow.audit_events candidate
    WHERE candidate.object_id = revoke.revocation_id
      AND candidate.action = 'enforcement_revoke_authorized'
      AND candidate.actor_type = 'administrator'
      AND candidate.actor_id = decision.actor_id
      AND candidate.object_type = 'revocation'
      AND candidate.primary_digest = decision.decision_digest
      AND candidate.secondary_digest = authz.authorization_digest
      AND candidate.policy_id = decision.policy_id
      AND candidate.policy_version = decision.policy_version
      AND candidate.enforcement_action_id = revoke.action_id
      AND candidate.outcome = 'accepted'
) audit
WHERE decision.idempotency_key_digest = $1
LIMIT 1`
