package dispatchstore

const (
	databaseClockSQL = `SELECT clock_timestamp()`
	listEligibleSQL  = `
SELECT job_id::text, kind, state, available_at, attempts, max_attempts,
    operation, action_id::text, policy_id::text, policy_version,
    host(target_ipv4), artifact, artifact_digest::text,
    original_add_digest::text, evidence_snapshot_digest::text,
    validation_snapshot_digest::text, authorization_digest::text,
    actor_id::text, reason_digest::text, owned_schema_digest::text,
    not_before, valid_until
FROM sentinelflow.dispatcher_approved_outbox
ORDER BY available_at ASC, job_id ASC
LIMIT $1`
	listRecoveryEligibleSQL = `
SELECT job_id::text, kind, state, available_at, attempts, max_attempts,
    operation, action_id::text, policy_id::text, policy_version,
    host(target_ipv4), artifact, artifact_digest::text,
    original_add_digest::text, evidence_snapshot_digest::text,
    validation_snapshot_digest::text, authorization_digest::text,
    actor_id::text, reason_digest::text, owned_schema_digest::text,
    not_before, valid_until
FROM sentinelflow.dispatcher_recovery_outbox_000025
ORDER BY available_at ASC, job_id ASC
LIMIT $1`
	claimJobSQL = `
SELECT sentinelflow.claim_dispatch_job($1::uuid, $2::uuid, $3, $4)`
	claimRecoveryJobSQL = `
SELECT sentinelflow.claim_dispatch_recovery_job_000025($1::uuid, $2::uuid, $3, $4)`
	recordCapabilitySQL = `
SELECT sentinelflow.record_execution_capability(
    $1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6::uuid, $7,
    $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18, $19, $20, $21, $22, $23, $24
)::text`
	recordResultSQL = `
SELECT sentinelflow.record_execution_result(
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7::uuid,
    $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18, $19, $20, $21, $22
)::text`
	recordResultV2SQL = `
SELECT sentinelflow.record_execution_result_v2(
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7::uuid,
    $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18, $19, $20, $21, $22, $23, $24
)::text`
	finishJobSQL = `
SELECT sentinelflow.finish_dispatch_job(
    $1::uuid, $2::uuid, $3, $4, $5, $6
)`
	finishRecoveryJobSQL = `
SELECT sentinelflow.finish_dispatch_recovery_job_000025($1::uuid, $2::uuid)`
	recoverExecutionSQL = `
SELECT recovery_state, capability_id::text, capability_jcs,
    capability_digest::text, capability_signature, capability_artifact,
    result_id::text, result_jcs, result_digest::text, result_signature
FROM sentinelflow.recover_dispatch_execution($1::uuid, $2::uuid)`
)
