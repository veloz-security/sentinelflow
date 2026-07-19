package hilstore

const issueChallengeSQL = `
SELECT * FROM sentinelflow.issue_hil_policy_challenge(
    $1::uuid, $2, $3::uuid, $4, $5, $6, $7::timestamptz,
    $8::timestamptz, $9, $10::uuid, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21::timestamptz,
    $22::timestamptz, $23
)`

const classifyIssueFailureSQL = `
WITH db_now AS MATERIALIZED (
    SELECT clock_timestamp() AS value
), session_state AS (
    SELECT
        session.authenticated_at,
        session.expires_at,
        session.last_seen_at
    FROM sentinelflow.admin_sessions AS session, db_now
    WHERE session.session_id = $1::uuid
      AND session.actor_id = $2
      AND session.token_digest = $3
      AND session.csrf_digest = $4
      AND session.authenticated_at = $5::timestamptz
      AND session.expires_at = $6::timestamptz
      AND session.revoked_at IS NULL
      AND session.expires_at > db_now.value
      AND session.last_seen_at + interval '30 minutes' > db_now.value
), validation_state AS (
    SELECT validation.valid_until
    FROM sentinelflow.policy_proposals AS policy
    JOIN sentinelflow.command_candidates AS candidate
      ON candidate.command_candidate_id = policy.command_candidate_id
    JOIN sentinelflow.validation_snapshots AS validation
      ON validation.policy_id = policy.policy_id
     AND validation.policy_version = policy.version
     AND validation.command_candidate_id = candidate.command_candidate_id
    WHERE policy.policy_id = $7::uuid
      AND policy.version = $8
      AND policy.target_ipv4 = $9
      AND policy.policy_digest = $10
      AND policy.evidence_snapshot_digest = $11
      AND policy.generated_artifact_digest = $12
      AND policy.canonical_artifact_digest = $13
      AND policy.ttl_seconds = $14
      AND candidate.generated_artifact_digest = $12
      AND candidate.canonical_artifact_digest = $13
      AND validation.snapshot_digest = $15
      AND validation.policy_digest = $10
      AND validation.evidence_snapshot_digest = $11
      AND validation.generated_candidate_digest = $12
      AND validation.canonical_artifact_digest = $13
      AND validation.target_ipv4 = $9
      AND validation.ttl_seconds = $14
      AND validation.created_at = $16::timestamptz
      AND validation.valid_until = $17::timestamptz
)
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM session_state) THEN 'authentication_invalid'
    WHEN (SELECT db_now.value > session_state.authenticated_at + interval '15 minutes'
          FROM db_now, session_state) THEN 'step_up_required'
    WHEN EXISTS (
        SELECT 1 FROM sentinelflow.decision_challenges
        WHERE idempotency_key_digest = $18
           OR challenge_id = $19::uuid
           OR nonce_digest = $20
    ) THEN 'conflict'
    WHEN EXISTS (
        SELECT 1 FROM validation_state, db_now
        WHERE validation_state.valid_until <= db_now.value
    ) THEN 'validation_stale'
    ELSE 'validation_failed'
END`

const databaseClockSQL = `SELECT clock_timestamp()`

const commitDecisionSQL = `
SELECT committed_decision_id::text, replayed, session_rotated
FROM sentinelflow.commit_hil_policy_decision_with_session_rotation(
    $1::uuid, $2, $3, $4, $5::timestamptz, $6::timestamptz,
    $7::uuid, $8, $9, $10, $11, $12, $13::uuid, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23::timestamptz,
    $24::timestamptz, $25, $26::uuid, $27, $28, $29, $30,
    $31::uuid, $32::timestamptz, $33::timestamptz, $34, $35,
    $36::uuid, $37::uuid, $38::uuid, $39, $40, $41::uuid,
    $42::timestamptz, $43::timestamptz, $44::uuid, $45::timestamptz,
    $46::uuid, $47, $48, $49, $50::timestamptz, $51::timestamptz,
    $52::timestamptz, $53::timestamptz, $54::uuid
)`

// verifyRetainedRotationChildSQL runs only after the coordinator reports an
// exact replay. The coordinator already holds a lock on this exact replacement
// row; this final database-clock check prevents a revoked, expired, idle,
// changed, or non-unique child from being treated as retained browser authority.
const verifyRetainedRotationChildSQL = `
WITH db_now AS MATERIALIZED (
    SELECT clock_timestamp() AS value
)
SELECT EXISTS (
    SELECT 1
    FROM sentinelflow.admin_sessions AS child, db_now
    WHERE child.session_id = $1::uuid
      AND child.actor_id = $2
      AND child.token_digest = $3
      AND child.csrf_digest = $4
      AND child.authenticated_at = $5::timestamptz
      AND child.created_at = $6::timestamptz
      AND child.last_seen_at = $7::timestamptz
      AND child.expires_at = $8::timestamptz
      AND child.rotation_parent_id = $9::uuid
      AND child.revoked_at IS NULL
      AND child.authenticated_at <= db_now.value
      AND child.created_at <= db_now.value
      AND child.last_seen_at <= db_now.value
      AND child.expires_at > db_now.value
      AND child.last_seen_at + interval '30 minutes' > db_now.value
      AND NOT EXISTS (
          SELECT 1
          FROM sentinelflow.admin_sessions AS sibling
          WHERE sibling.rotation_parent_id = child.rotation_parent_id
            AND sibling.session_id <> child.session_id
      )
)`

const lookupDecisionSQL = `
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
    decision.actor_id::text,
    decision.reason_digest::text,
    decision.challenge_nonce_digest::text,
    decision.idempotency_key_digest::text,
    decision.decided_at,
    decision.decision_valid_until,
    challenge.session_id::text,
    challenge.authenticated_at,
    challenge.validation_valid_until,
    challenge.issued_at,
    challenge.expires_at,
    challenge.consumed_at,
    challenge.consumed_decision_id::text,
    reason.actor_id::text,
    reason.operation,
    reason.normalized_reason,
    policy.state,
    candidate.generated_command,
    candidate.canonical_artifact,
    validation.created_at,
    validation.valid_until,
    authz.authorization_digest::text,
    authz.action_id::text,
    action.action_id::text,
    (SELECT count(*)::integer
       FROM sentinelflow.outbox_jobs AS job
      WHERE job.kind = 'dispatch_add'
        AND job.operation = 'add'
        AND job.aggregate_type = 'enforcement_action'
        AND job.aggregate_id = action.action_id),
    (SELECT job.job_id::text
       FROM sentinelflow.outbox_jobs AS job
      WHERE job.kind = 'dispatch_add'
        AND job.operation = 'add'
        AND job.aggregate_type = 'enforcement_action'
        AND job.aggregate_id = action.action_id
      ORDER BY job.job_id
      LIMIT 1),
    challenge.challenge_jcs,
    challenge.challenge_digest::text,
    reason.reason_code,
    reason.reason_jcs,
    decision.decision_jcs,
    decision.decision_digest::text,
    authz.authorization_jcs,
    authz.authorization_id::text,
    authz.decided_at,
    authz.valid_until
FROM sentinelflow.approval_decisions AS decision
JOIN sentinelflow.decision_challenges AS challenge
  ON challenge.challenge_id = decision.challenge_id
JOIN sentinelflow.hil_reasons AS reason
  ON reason.reason_id = decision.reason_id
JOIN sentinelflow.policy_proposals AS policy
  ON policy.policy_id = decision.policy_id
 AND policy.version = decision.policy_version
JOIN sentinelflow.command_candidates AS candidate
  ON candidate.command_candidate_id = policy.command_candidate_id
JOIN sentinelflow.validation_snapshots AS validation
  ON validation.validation_snapshot_id = decision.validation_snapshot_id
LEFT JOIN sentinelflow.enforcement_authorizations AS authz
  ON authz.approval_decision_id = decision.decision_id
 AND authz.authorization_kind = 'add'
LEFT JOIN sentinelflow.enforcement_actions AS action
  ON action.add_authorization_id = authz.authorization_id
WHERE decision.idempotency_key_digest = $1
LIMIT 1`
