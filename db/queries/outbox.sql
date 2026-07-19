-- name: EnqueueOutboxJob :one
INSERT INTO sentinelflow.outbox_jobs (
    job_id,
    kind,
    aggregate_type,
    aggregate_id,
    aggregate_version,
    operation,
    idempotency_key,
    state,
    available_at,
    max_attempts
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    'pending',
    $8,
    $9
)
RETURNING job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, state, available_at, attempts, max_attempts, created_at, updated_at;

-- name: LeaseWorkerOutboxJob :one
SELECT job_id, kind, aggregate_type, aggregate_id, aggregate_version, state,
    available_at, lease_token, lease_owner, lease_expires_at, attempts,
    max_attempts
FROM sentinelflow.lease_worker_outbox_job($1, $2, $3, $4);

-- name: FinishWorkerOutboxJob :one
SELECT job_id, kind, aggregate_type, aggregate_id, aggregate_version, state,
    available_at, attempts, last_error_code, last_error_digest, updated_at
FROM sentinelflow.finish_worker_outbox_job($1, $2, $3, $4, $5, $6, $7);

-- name: ListApprovedDispatchJobs :many
SELECT job_id, kind, state, available_at, attempts, max_attempts, operation,
    action_id, policy_id, policy_version, target_ipv4, artifact,
    artifact_digest, original_add_digest, evidence_snapshot_digest,
    validation_snapshot_digest, authorization_digest, actor_id, reason_digest,
    owned_schema_digest, not_before, valid_until
FROM sentinelflow.dispatcher_approved_outbox
ORDER BY available_at, job_id
LIMIT $1;

-- name: ClaimDispatchJob :one
SELECT sentinelflow.claim_dispatch_job(
    $1,
    $2,
    $3,
    $4
);

-- name: FinishDispatchJob :one
SELECT sentinelflow.finish_dispatch_job(
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
);
