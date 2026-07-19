package repository

const (
	pruneReplayNoncesSQL = `SELECT sentinelflow.prune_ingest_replay_nonces($1, $2)`

	consumeReplayNonceSQL = `
INSERT INTO sentinelflow.ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES ($1, $2, $3, $4, $5::timestamptz, $5::timestamptz + interval '5 minutes')
RETURNING expires_at`

	getBatchBySenderAndIDSQL = `
SELECT sender_epoch, sequence, endpoint_kind, auth_key_id, raw_body_digest,
    raw_body_size, record_count, sent_at
FROM sentinelflow.ingest_batches
WHERE sender_id = $1 AND batch_id = $2`

	ensureSenderCheckpointSQL = `
INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES ($1, $2, $3, 0, NULL, false, false, $4)
ON CONFLICT (sender_id, endpoint_kind) DO NOTHING`

	lockSenderIngestSQL = `
SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended($1::text || ':' || $2::text, 0)
)`

	insertIngestBatchSQL = `
INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
    auth_key_id, schema_version, raw_body_digest, raw_body_size, record_count,
    sent_at, received_at
) VALUES ($1, $2, $3, $4, $5, $6, 'event-batch-v1', $7, $8, $9, $10, $11)`

	insertGatewayEventSQL = `
INSERT INTO sentinelflow.gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, request_id, trace_id, started_at, completed_at,
    source_ip, method, protocol, route_label, path_catalog_version,
    suspicious_path_id, host, service_label, status_code, request_bytes,
    response_bytes, latency_ms, received_at, trust_state, trust_reason
) VALUES (
    $1, 'gateway-http-v1', $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, 'HTTP/1.1', $12, 'path-catalog-v1', $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22
)`

	insertAuthEventSQL = `
INSERT INTO sentinelflow.auth_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, gateway_request_id, trace_id, occurred_at, source_ip,
    service_label, route_label, account_hash, outcome, received_at,
    trust_state, trust_reason, binding_deadline
) VALUES (
    $1, 'auth-event-v1', $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13, $14, $15, $16, $17
)`

	insertSourceHealthSQL = `
INSERT INTO sentinelflow.source_health_intervals (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, occurred_at, source_id, cause, state,
    affected_sender_epoch, sequence_start, sequence_end, interval_start,
    interval_end, dropped_count, detail_code, received_at,
    trust_state, trust_reason
) VALUES (
    $1, 'source-health-v1', $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
)`

	insertSourceCoverageSQL = `
SELECT coverage_event_id::text, coverage_digest::text
FROM sentinelflow.append_source_coverage_attestation(
    $1::uuid, $2::text, $3::text, $4::text, $5::text, $6::uuid,
    $7::text, $8::timestamptz, $9::timestamptz, $10::uuid,
    $11::bigint, $12::integer, $13::text, $14::text
)`

	registerIngestSequenceSQL = `
SELECT sentinelflow.register_ingest_sequence(
    $1::text, $2::text, $3::text, $4::bigint,
    $5::uuid, $6::text, $7::timestamptz
)`

	matchingUnresolvedGapSQL = `
SELECT EXISTS (
    SELECT 1
    FROM sentinelflow.ingest_sequence_gaps
    WHERE sender_id = $1
      AND endpoint_kind = $2
      AND sender_epoch = $3
      AND sequence_start = $4
      AND sequence_end = $5
)`

	resolveIngestGapAsLostSQL = `
SELECT sentinelflow.resolve_ingest_gap_as_lost($1::uuid)`

	forceDeferredConstraintsSQL = `SET CONSTRAINTS ALL IMMEDIATE`

	insertOutboxSQL = `
SELECT sentinelflow.append_ingest_detect_outbox(
    $1::text, $2::uuid, $3::text, $4::uuid, $5::text
)::text`
)
