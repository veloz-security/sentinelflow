-- name: ConsumeIngestReplayNonce :one
INSERT INTO sentinelflow.ingest_replay_nonces (
    sender_id,
    endpoint_kind,
    endpoint_path,
    nonce_digest,
    authenticated_at,
    expires_at
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5::timestamptz,
    $5::timestamptz + interval '5 minutes'
)
RETURNING sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at;

-- name: GetActiveIngestReplayNonce :one
SELECT sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
FROM sentinelflow.ingest_replay_nonces
WHERE sender_id = $1
  AND endpoint_kind = $2
  AND endpoint_path = $3
  AND nonce_digest = $4
  AND expires_at > $5;

-- name: PruneExpiredIngestReplayNonces :one
SELECT sentinelflow.prune_ingest_replay_nonces($1, $2);

-- name: InsertIngestBatch :one
INSERT INTO sentinelflow.ingest_batches (
    sender_id,
    sender_epoch,
    batch_id,
    sequence,
    endpoint_kind,
    schema_version,
    raw_body_digest,
    raw_body_size,
    record_count,
    sent_at,
    received_at
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    'event-batch-v1',
    $6,
    $7,
    $8,
    $9,
    $10
)
RETURNING sender_id, sender_epoch, batch_id, sequence, raw_body_digest,
    acknowledgement, received_at;

-- name: GetIngestBatchIdentity :one
SELECT sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at,
    acknowledgement
FROM sentinelflow.ingest_batches
WHERE sender_id = $1
  AND sender_epoch = $2
  AND batch_id = $3;

-- name: GetIngestBatchBySenderAndBatchID :one
SELECT sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at,
    acknowledgement
FROM sentinelflow.ingest_batches
WHERE sender_id = $1
  AND batch_id = $2;

-- name: InsertGatewayEvent :one
INSERT INTO sentinelflow.gateway_events (
    event_id,
    schema_version,
    sender_id,
    sender_epoch,
    batch_id,
    idempotency_key,
    request_id,
    trace_id,
    started_at,
    completed_at,
    source_ip,
    method,
    protocol,
    route_label,
    path_catalog_version,
    suspicious_path_id,
    host,
    service_label,
    status_code,
    request_bytes,
    response_bytes,
    latency_ms,
    received_at,
    trust_state,
    trust_reason
) VALUES (
    $1,
    'gateway-http-v1',
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
    'HTTP/1.1',
    $12,
    'path-catalog-v1',
    $13,
    $14,
    $15,
    $16,
    $17,
    $18,
    $19,
    $20,
    $21,
    $22
)
RETURNING event_id, idempotency_key, request_id, trace_id, source_ip,
    route_label, service_label, status_code, received_at, trust_state, trust_reason;

-- name: InsertAuthEvent :one
INSERT INTO sentinelflow.auth_events (
    event_id,
    schema_version,
    sender_id,
    sender_epoch,
    batch_id,
    idempotency_key,
    gateway_request_id,
    trace_id,
    occurred_at,
    source_ip,
    service_label,
    route_label,
    account_hash,
    outcome,
    received_at,
    trust_state,
    trust_reason,
    binding_deadline
) VALUES (
    $1,
    'auth-event-v1',
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
    $15,
    $16,
    $17
)
RETURNING event_id, idempotency_key, gateway_request_id, trace_id, source_ip,
    service_label, route_label, outcome, received_at, binding_state,
    binding_reason, binding_deadline;

-- name: InsertSourceHealthInterval :one
INSERT INTO sentinelflow.source_health_intervals (
    event_id,
    schema_version,
    sender_id,
    sender_epoch,
    batch_id,
    idempotency_key,
    occurred_at,
    source_id,
    cause,
    state,
    affected_sender_epoch,
    sequence_start,
    sequence_end,
    interval_start,
    interval_end,
    dropped_count,
    detail_code,
    received_at,
    trust_state,
    trust_reason
) VALUES (
    $1,
    'source-health-v1',
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
    $15,
    $16,
    $17,
    $18,
    $19
)
RETURNING event_id, idempotency_key, source_id, cause, state,
    affected_sender_epoch, sequence_start, sequence_end, interval_start,
    interval_end, dropped_count, received_at, trust_state, trust_reason;

-- name: ListPendingAuthBindings :many
SELECT event_id, gateway_request_id, trace_id, occurred_at, source_ip,
    service_label, route_label, binding_deadline
FROM sentinelflow.auth_events
WHERE binding_state = 'pending'
  AND binding_deadline >= $1
ORDER BY occurred_at, event_id
LIMIT $2;

-- name: BindAuthEvent :one
UPDATE sentinelflow.auth_events
SET binding_state = 'verified',
    binding_reason = 'verified',
    bound_gateway_event_id = $1
WHERE event_id = $2
  AND binding_state = 'pending'
  AND binding_deadline >= $3
RETURNING event_id, binding_state, binding_reason, bound_gateway_event_id;

-- name: ExpireAuthBindings :many
UPDATE sentinelflow.auth_events
SET binding_state = 'untrusted',
    binding_reason = 'expired',
    bound_gateway_event_id = NULL
WHERE binding_state = 'pending'
  AND binding_deadline < $1
RETURNING event_id;

-- name: EnsureSenderCheckpoint :exec
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id,
    endpoint_kind,
    sender_epoch,
    last_acknowledged_sequence,
    last_acknowledged_body_digest,
    clean_shutdown,
    unknown_loss,
    updated_at
) VALUES (
    $1,
    $2,
    $3,
    0,
    NULL,
    false,
    false,
    $4
)
ON CONFLICT (sender_id, endpoint_kind) DO NOTHING;

-- name: LockAndClassifySenderSequence :one
SELECT sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at,
    CASE
        WHEN sender_epoch = $3 AND $4 = last_acknowledged_sequence + 1 THEN 'next'
        WHEN sender_epoch = $3 AND $4 <= last_acknowledged_sequence THEN 'duplicate_or_rewind'
        WHEN sender_epoch = $3 THEN 'gap'
        WHEN $4 = 1 THEN 'new_epoch'
        ELSE 'new_epoch_gap'
    END AS sequence_disposition
FROM sentinelflow.sender_checkpoints
WHERE sender_id = $1
  AND endpoint_kind = $2
FOR UPDATE;

-- name: RegisterIngestSequence :one
SELECT sentinelflow.register_ingest_sequence(
    $1::text,
    $2::text,
    $3::text,
    $4::bigint,
    $5::uuid,
    $6::text,
    $7::timestamptz
) AS sequence_disposition;

-- name: ListUnresolvedIngestSequenceGaps :many
SELECT gap_id, sender_id, endpoint_kind, sender_epoch, sequence_start,
    sequence_end, detected_by_batch_id, detected_at
FROM sentinelflow.ingest_sequence_gaps
WHERE sender_id = $1
  AND endpoint_kind = $2
  AND sender_epoch = $3
ORDER BY sequence_start, sequence_end;

-- name: ListIngestSequenceGapResolutions :many
SELECT resolution_id, sender_id, endpoint_kind, sender_epoch, sequence_start,
    sequence_end, resolution, resolution_batch_id, source_health_event_id,
    resolved_at
FROM sentinelflow.ingest_sequence_gap_resolutions
WHERE sender_id = $1
  AND endpoint_kind = $2
  AND sender_epoch = $3
ORDER BY sequence_start, sequence_end, resolved_at;

-- name: ResolveIngestGapAsLost :exec
SELECT sentinelflow.resolve_ingest_gap_as_lost($1::uuid);
