BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

INSERT INTO ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES (
    'gateway-replay-test', 'gateway', '/internal/v1/gateway-events',
    'sha256:1010101010101010101010101010101010101010101010101010101010101010',
    '2026-07-18T04:08:00Z', '2026-07-18T04:13:00Z'
);

DO $same_sender_endpoint_replay_is_rejected$
BEGIN
    BEGIN
        INSERT INTO ingest_replay_nonces (
            sender_id, endpoint_kind, endpoint_path, nonce_digest,
            authenticated_at, expires_at
        ) VALUES (
            'gateway-replay-test', 'gateway', '/internal/v1/gateway-events',
            'sha256:1010101010101010101010101010101010101010101010101010101010101010',
            '2026-07-18T04:08:01Z', '2026-07-18T04:13:01Z'
        );
        RAISE EXCEPTION 'same sender and endpoint replay was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
END
$same_sender_endpoint_replay_is_rejected$;

INSERT INTO ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES
(
    'gateway-replay-test', 'auth', '/internal/v1/auth-events',
    'sha256:1010101010101010101010101010101010101010101010101010101010101010',
    '2026-07-18T04:08:00Z', '2026-07-18T04:13:00Z'
),
(
    'other-replay-test', 'gateway', '/internal/v1/gateway-events',
    'sha256:1010101010101010101010101010101010101010101010101010101010101010',
    '2026-07-18T04:08:00Z', '2026-07-18T04:13:00Z'
);

DO $endpoint_sender_isolation_and_window$
BEGIN
    IF (
        SELECT count(*)
        FROM ingest_replay_nonces
        WHERE nonce_digest =
            'sha256:1010101010101010101010101010101010101010101010101010101010101010'
    ) <> 3 THEN
        RAISE EXCEPTION 'sender and endpoint replay isolation is not explicit';
    END IF;
    BEGIN
        INSERT INTO ingest_replay_nonces (
            sender_id, endpoint_kind, endpoint_path, nonce_digest,
            authenticated_at, expires_at
        ) VALUES (
            'mismatched-endpoint', 'gateway', '/internal/v1/auth-events',
            'sha256:2020202020202020202020202020202020202020202020202020202020202020',
            '2026-07-18T04:00:00Z', '2026-07-18T04:05:00Z'
        );
        RAISE EXCEPTION 'endpoint kind/path mismatch was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    BEGIN
        INSERT INTO ingest_replay_nonces (
            sender_id, endpoint_kind, endpoint_path, nonce_digest,
            authenticated_at, expires_at
        ) VALUES (
            'wrong-window', 'gateway', '/internal/v1/gateway-events',
            'sha256:3030303030303030303030303030303030303030303030303030303030303030',
            '2026-07-18T04:00:00Z', '2026-07-18T04:05:01Z'
        );
        RAISE EXCEPTION 'replay nonce security window was not exactly five minutes';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$endpoint_sender_isolation_and_window$;

INSERT INTO ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES
(
    'expired-replay-one', 'gateway', '/internal/v1/gateway-events',
    'sha256:4040404040404040404040404040404040404040404040404040404040404040',
    '2026-07-18T03:50:00Z', '2026-07-18T03:55:00Z'
),
(
    'expired-replay-two', 'gateway', '/internal/v1/gateway-events',
    'sha256:5050505050505050505050505050505050505050505050505050505050505050',
    '2026-07-18T03:51:00Z', '2026-07-18T03:56:00Z'
),
(
    'active-replay', 'gateway', '/internal/v1/gateway-events',
    'sha256:6060606060606060606060606060606060606060606060606060606060606060',
    '2026-07-18T04:08:00Z', '2026-07-18T04:13:00Z'
);

DO $expiry_cleanup_is_bounded$
DECLARE
    deleted_count integer;
BEGIN
    deleted_count := prune_ingest_replay_nonces('2026-07-18T04:10:00Z', 1);
    IF deleted_count <> 1 OR (
        SELECT count(*)
        FROM ingest_replay_nonces
        WHERE sender_id IN ('expired-replay-one', 'expired-replay-two')
    ) <> 1 THEN
        RAISE EXCEPTION 'bounded replay cleanup did not honor its row limit';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM ingest_replay_nonces WHERE sender_id = 'active-replay'
    ) THEN
        RAISE EXCEPTION 'bounded replay cleanup removed an active nonce';
    END IF;
    deleted_count := prune_ingest_replay_nonces('2026-07-18T04:10:00Z', 1);
    IF deleted_count <> 1 OR EXISTS (
        SELECT 1
        FROM ingest_replay_nonces
        WHERE sender_id IN ('expired-replay-one', 'expired-replay-two')
    ) THEN
        RAISE EXCEPTION 'bounded replay cleanup did not finish the expired set';
    END IF;
    BEGIN
        PERFORM prune_ingest_replay_nonces('2026-07-18T04:10:00Z', 0);
        RAISE EXCEPTION 'unbounded replay cleanup limit was accepted';
    EXCEPTION WHEN invalid_parameter_value THEN
        NULL;
    END;
END
$expiry_cleanup_is_bounded$;

DO $later_batch_failure_rolls_back_nonce$
BEGIN
    BEGIN
        INSERT INTO ingest_replay_nonces (
            sender_id, endpoint_kind, endpoint_path, nonce_digest,
            authenticated_at, expires_at
        ) VALUES (
            'rollback-replay-test', 'gateway', '/internal/v1/gateway-events',
            'sha256:7070707070707070707070707070707070707070707070707070707070707070',
            '2026-07-18T04:00:00Z', '2026-07-18T04:05:00Z'
        );
        INSERT INTO ingest_batches (
            sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
            schema_version, raw_body_digest, raw_body_size, record_count,
            sent_at, received_at
        ) VALUES (
            'rollback-replay-test', 'RrRrRrRrRrRrRrRrRrRrRg',
            '019b0000-0000-7000-8000-000000008001', 1, 'gateway',
            'event-batch-v1',
            'sha256:7171717171717171717171717171717171717171717171717171717171717171',
            128, 0, '2026-07-18T04:00:00Z', '2026-07-18T04:00:01Z'
        );
        RAISE EXCEPTION 'invalid batch was accepted after nonce consumption';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    IF EXISTS (
        SELECT 1
        FROM ingest_replay_nonces
        WHERE sender_id = 'rollback-replay-test'
    ) THEN
        RAISE EXCEPTION 'later batch failure consumed the replay nonce';
    END IF;
    INSERT INTO ingest_replay_nonces (
        sender_id, endpoint_kind, endpoint_path, nonce_digest,
        authenticated_at, expires_at
    ) VALUES (
        'rollback-replay-test', 'gateway', '/internal/v1/gateway-events',
        'sha256:7070707070707070707070707070707070707070707070707070707070707070',
        '2026-07-18T04:00:00Z', '2026-07-18T04:05:00Z'
    );
END
$later_batch_failure_rolls_back_nonce$;

INSERT INTO sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES (
    'gateway-sequence-test', 'gateway', 'KkKkKkKkKkKkKkKkKkKkKg',
    0, NULL, false, false, '2026-07-18T04:00:00Z'
);

INSERT INTO ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES (
    'gateway-sequence-test', 'gateway', '/internal/v1/gateway-events',
    'sha256:8080808080808080808080808080808080808080808080808080808080808080',
    '2026-07-18T04:00:00Z', '2026-07-18T04:05:00Z'
);

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway-sequence-test', 'KkKkKkKkKkKkKkKkKkKkKg',
    '019b0000-0000-7000-8000-000000008010', 1, 'gateway', 'event-batch-v1',
    'sha256:8181818181818181818181818181818181818181818181818181818181818181',
    512, 1, '2026-07-18T04:00:00Z', '2026-07-18T04:00:01Z'
);

INSERT INTO gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, received_at
) VALUES (
    '019b0000-0000-7000-8000-000000008011', 'gateway-http-v1',
    'gateway-sequence-test', 'KkKkKkKkKkKkKkKkKkKkKg',
    '019b0000-0000-7000-8000-000000008010',
    'sha256:8282828282828282828282828282828282828282828282828282828282828282',
    '019b0000-0000-7000-8000-000000008012',
    '019b0000-0000-7000-8000-000000008013',
    '2026-07-18T04:00:00Z', '2026-07-18T04:00:00.005Z', '203.0.113.40',
    'GET', 'HTTP/1.1', 'home', 'path-catalog-v1', 'none', 'app.example.test',
    'demo-app', 200, 0, 64, 5, '2026-07-18T04:00:01Z'
);

SELECT register_ingest_sequence(
    'gateway-sequence-test', 'gateway', 'KkKkKkKkKkKkKkKkKkKkKg', 1,
    '019b0000-0000-7000-8000-000000008010',
    'sha256:8181818181818181818181818181818181818181818181818181818181818181',
    '2026-07-18T04:00:01Z'
);

SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

DO $checkpoint_lock_classifies_gap$
DECLARE
    disposition text;
BEGIN
    SELECT CASE
        WHEN sender_epoch = 'KkKkKkKkKkKkKkKkKkKkKg' AND
             3 = last_acknowledged_sequence + 1 THEN 'next'
        WHEN sender_epoch = 'KkKkKkKkKkKkKkKkKkKkKg' AND
             3 <= last_acknowledged_sequence THEN 'duplicate_or_rewind'
        WHEN sender_epoch = 'KkKkKkKkKkKkKkKkKkKkKg' THEN 'gap'
        WHEN 3 = 1 THEN 'new_epoch'
        ELSE 'new_epoch_gap'
    END
    INTO disposition
    FROM sender_checkpoints
    WHERE sender_id = 'gateway-sequence-test' AND endpoint_kind = 'gateway'
    FOR UPDATE;
    IF disposition <> 'gap' THEN
        RAISE EXCEPTION 'locked sender checkpoint did not classify the sequence gap';
    END IF;
END
$checkpoint_lock_classifies_gap$;

INSERT INTO ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES (
    'gateway-sequence-test', 'gateway', '/internal/v1/gateway-events',
    'sha256:8383838383838383838383838383838383838383838383838383838383838383',
    '2026-07-18T04:01:00Z', '2026-07-18T04:06:00Z'
);

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway-sequence-test', 'KkKkKkKkKkKkKkKkKkKkKg',
    '019b0000-0000-7000-8000-000000008020', 3, 'gateway', 'event-batch-v1',
    'sha256:8484848484848484848484848484848484848484848484848484848484848484',
    384, 1, '2026-07-18T04:01:00Z', '2026-07-18T04:01:01Z'
);

SELECT register_ingest_sequence(
    'gateway-sequence-test', 'gateway', 'KkKkKkKkKkKkKkKkKkKkKg', 3,
    '019b0000-0000-7000-8000-000000008020',
    'sha256:8484848484848484848484848484848484848484848484848484848484848484',
    '2026-07-18T04:01:01Z'
);

SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

DO $gap_checkpoint_and_range_are_atomic$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sender_checkpoints checkpoint
        JOIN ingest_batches batch
          ON batch.sender_id = checkpoint.sender_id
         AND batch.endpoint_kind = checkpoint.endpoint_kind
         AND batch.sender_epoch = checkpoint.sender_epoch
         AND batch.sequence = checkpoint.last_acknowledged_sequence
         AND batch.raw_body_digest = checkpoint.last_acknowledged_body_digest
        JOIN ingest_sequence_gaps gap
          ON gap.sender_id = batch.sender_id
         AND gap.endpoint_kind = batch.endpoint_kind
         AND gap.sender_epoch = batch.sender_epoch
         AND gap.detected_by_batch_id = batch.batch_id
        WHERE checkpoint.sender_id = 'gateway-sequence-test'
          AND checkpoint.last_acknowledged_sequence = 3
          AND NOT checkpoint.unknown_loss
          AND gap.sequence_start = 2
          AND gap.sequence_end = 2
    ) THEN
        RAISE EXCEPTION 'batch, high-water checkpoint, and unresolved range are not atomic';
    END IF;
END
$gap_checkpoint_and_range_are_atomic$;

INSERT INTO ingest_replay_nonces (
    sender_id, endpoint_kind, endpoint_path, nonce_digest,
    authenticated_at, expires_at
) VALUES (
    'gateway-sequence-test', 'gateway', '/internal/v1/gateway-events',
    'sha256:8989898989898989898989898989898989898989898989898989898989898989',
    '2026-07-18T04:01:30Z', '2026-07-18T04:06:30Z'
);

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway-sequence-test', 'KkKkKkKkKkKkKkKkKkKkKg',
    '019b0000-0000-7000-8000-000000008040', 2, 'gateway', 'event-batch-v1',
    'sha256:9090909090909090909090909090909090909090909090909090909090909090',
    420, 1, '2026-07-18T04:00:30Z', '2026-07-18T04:01:30Z'
);

INSERT INTO gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, received_at
) VALUES (
    '019b0000-0000-7000-8000-000000008041', 'gateway-http-v1',
    'gateway-sequence-test', 'KkKkKkKkKkKkKkKkKkKkKg',
    '019b0000-0000-7000-8000-000000008040',
    'sha256:9191919191919191919191919191919191919191919191919191919191919191',
    '019b0000-0000-7000-8000-000000008042',
    '019b0000-0000-7000-8000-000000008043',
    '2026-07-18T04:00:30Z', '2026-07-18T04:00:30.005Z', '203.0.113.40',
    'GET', 'HTTP/1.1', 'home', 'path-catalog-v1', 'none', 'app.example.test',
    'demo-app', 200, 0, 64, 5, '2026-07-18T04:01:30Z'
);

DO $late_batch_closes_gap_without_checkpoint_rewind$
DECLARE
    disposition text;
BEGIN
    SELECT register_ingest_sequence(
        'gateway-sequence-test', 'gateway', 'KkKkKkKkKkKkKkKkKkKkKg', 2,
        '019b0000-0000-7000-8000-000000008040',
        'sha256:9090909090909090909090909090909090909090909090909090909090909090',
        '2026-07-18T04:01:30Z'
    ) INTO disposition;
    IF disposition <> 'late_gap_closed' OR EXISTS (
        SELECT 1 FROM ingest_sequence_gaps
        WHERE sender_id = 'gateway-sequence-test'
          AND endpoint_kind = 'gateway'
          AND sender_epoch = 'KkKkKkKkKkKkKkKkKkKkKg'
    ) OR NOT EXISTS (
        SELECT 1 FROM sender_checkpoints
        WHERE sender_id = 'gateway-sequence-test'
          AND endpoint_kind = 'gateway'
          AND last_acknowledged_sequence = 3
          AND last_acknowledged_body_digest =
              'sha256:8484848484848484848484848484848484848484848484848484848484848484'
    ) THEN
        RAISE EXCEPTION 'late missing batch did not close only its gap';
    END IF;
END
$late_batch_closes_gap_without_checkpoint_rewind$;

SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

INSERT INTO sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES (
    'cross-epoch-test', 'gateway', 'LmLmLmLmLmLmLmLmLmLmLg',
    0, NULL, false, false, '2026-07-18T05:00:00Z'
);

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'cross-epoch-test', 'LmLmLmLmLmLmLmLmLmLmLg',
    '019b0000-0000-7000-8000-000000008100', 2, 'gateway', 'event-batch-v1',
    'sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
    128, 1, '2026-07-18T05:00:00Z', '2026-07-18T05:00:01Z'
);
SELECT register_ingest_sequence(
    'cross-epoch-test', 'gateway', 'LmLmLmLmLmLmLmLmLmLmLg', 2,
    '019b0000-0000-7000-8000-000000008100',
    'sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
    '2026-07-18T05:00:01Z'
);
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'cross-epoch-test', 'NmNmNmNmNmNmNmNmNmNmNg',
    '019b0000-0000-7000-8000-000000008110', 1, 'gateway', 'event-batch-v1',
    'sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1',
    128, 1, '2026-07-18T05:01:00Z', '2026-07-18T05:01:01Z'
);
SELECT register_ingest_sequence(
    'cross-epoch-test', 'gateway', 'NmNmNmNmNmNmNmNmNmNmNg', 1,
    '019b0000-0000-7000-8000-000000008110',
    'sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1',
    '2026-07-18T05:01:01Z'
);
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'cross-epoch-test', 'LmLmLmLmLmLmLmLmLmLmLg',
    '019b0000-0000-7000-8000-000000008120', 1, 'gateway', 'event-batch-v1',
    'sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
    128, 1, '2026-07-18T05:00:30Z', '2026-07-18T05:02:01Z'
);

DO $prior_epoch_late_batch_does_not_rewind_current_epoch$
DECLARE
    disposition text;
BEGIN
    SELECT register_ingest_sequence(
        'cross-epoch-test', 'gateway', 'LmLmLmLmLmLmLmLmLmLmLg', 1,
        '019b0000-0000-7000-8000-000000008120',
        'sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
        '2026-07-18T05:02:01Z'
    ) INTO disposition;
    IF disposition <> 'late_gap_closed' OR NOT EXISTS (
        SELECT 1 FROM sender_checkpoints
        WHERE sender_id = 'cross-epoch-test'
          AND endpoint_kind = 'gateway'
          AND sender_epoch = 'NmNmNmNmNmNmNmNmNmNmNg'
          AND last_acknowledged_sequence = 1
    ) OR EXISTS (
        SELECT 1 FROM ingest_sequence_gaps
        WHERE sender_id = 'cross-epoch-test'
          AND sender_epoch = 'LmLmLmLmLmLmLmLmLmLmLg'
    ) OR NOT EXISTS (
        SELECT 1 FROM ingest_sequence_gap_resolutions
        WHERE sender_id = 'cross-epoch-test'
          AND sender_epoch = 'LmLmLmLmLmLmLmLmLmLmLg'
          AND sequence_start = 1
          AND sequence_end = 1
          AND resolution = 'late_arrival'
          AND resolution_batch_id = '019b0000-0000-7000-8000-000000008120'
    ) THEN
        RAISE EXCEPTION 'prior epoch late closure rewound or lost resolution evidence';
    END IF;
END
$prior_epoch_late_batch_does_not_rewind_current_epoch$;

SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

DO $missing_gap_registration_rolls_back_batch$
BEGIN
    BEGIN
        INSERT INTO ingest_replay_nonces (
            sender_id, endpoint_kind, endpoint_path, nonce_digest,
            authenticated_at, expires_at
        ) VALUES (
            'gateway-sequence-test', 'gateway', '/internal/v1/gateway-events',
            'sha256:8686868686868686868686868686868686868686868686868686868686868686',
            '2026-07-18T04:02:00Z', '2026-07-18T04:07:00Z'
        );
        INSERT INTO ingest_batches (
            sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
            schema_version, raw_body_digest, raw_body_size, record_count,
            sent_at, received_at
        ) VALUES (
            'gateway-sequence-test', 'KkKkKkKkKkKkKkKkKkKkKg',
            '019b0000-0000-7000-8000-000000008030', 5, 'gateway',
            'event-batch-v1',
            'sha256:8787878787878787878787878787878787878787878787878787878787878787',
            256, 1, '2026-07-18T04:02:00Z', '2026-07-18T04:02:01Z'
        );
        SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
        RAISE EXCEPTION 'sequence gap committed without high-water and range registration';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;
    IF EXISTS (
        SELECT 1 FROM ingest_batches
        WHERE batch_id = '019b0000-0000-7000-8000-000000008030'
    ) OR EXISTS (
        SELECT 1 FROM ingest_replay_nonces
        WHERE nonce_digest =
            'sha256:8686868686868686868686868686868686868686868686868686868686868686'
    ) OR EXISTS (
        SELECT 1 FROM sender_checkpoints
        WHERE sender_id = 'gateway-sequence-test'
          AND last_acknowledged_sequence <> 3
    ) THEN
        RAISE EXCEPTION 'failed gap transaction left partial ingest state';
    END IF;
END
$missing_gap_registration_rolls_back_batch$;

ROLLBACK;
