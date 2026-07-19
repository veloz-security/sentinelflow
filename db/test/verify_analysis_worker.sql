BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $schema_is_present$
BEGIN
    IF to_regclass('sentinelflow.analysis_attempt_claims') IS NULL OR
       to_regclass('sentinelflow.analysis_attempt_results') IS NULL OR
       to_regclass('sentinelflow.analysis_output_staging') IS NULL THEN
        RAISE EXCEPTION 'analysis worker persistence schema is incomplete';
    END IF;
    IF sentinelflow.analysis_json_no_duplicate_keys('{"a":{"b":1,"b":2}}'::json) OR
       NOT sentinelflow.analysis_json_no_duplicate_keys('{"a":{"b":1},"c":[1,2]}'::json) THEN
        RAISE EXCEPTION 'recursive duplicate-key validation is not strict';
    END IF;
END
$schema_is_present$;

-- Establish continuous, gap-free boundary receipts for both independently
-- checkpointed producers. The analysis adapter must not infer 24-hour
-- completeness from an empty history table.
INSERT INTO sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
) VALUES
    ('gateway.analysis', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
     NULL, false, false, clock_timestamp() - interval '26 hours'),
    ('auth.analysis', 'auth', 'BBBBBBBBBBBBBBBBBBBBBB', 0,
     NULL, false, false, clock_timestamp() - interval '26 hours');

UPDATE sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:0101010101010101010101010101010101010101010101010101010101010101',
    updated_at = clock_timestamp() - interval '25 hours'
WHERE sender_id = 'gateway.analysis' AND endpoint_kind = 'gateway';
INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway.analysis', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-000000008001', 1, 'gateway', 'event-batch-v1',
    'sha256:0101010101010101010101010101010101010101010101010101010101010101',
    128, 1, clock_timestamp() - interval '25 hours', clock_timestamp() - interval '25 hours'
);
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

UPDATE sender_checkpoints
SET last_acknowledged_sequence = 2,
    last_acknowledged_body_digest =
        'sha256:0202020202020202020202020202020202020202020202020202020202020202',
    updated_at = clock_timestamp() - interval '1 minute'
WHERE sender_id = 'gateway.analysis' AND endpoint_kind = 'gateway';
INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway.analysis', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019b0000-0000-7000-8000-000000008002', 2, 'gateway', 'event-batch-v1',
    'sha256:0202020202020202020202020202020202020202020202020202020202020202',
    128, 1, clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute'
);
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

UPDATE sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:0303030303030303030303030303030303030303030303030303030303030303',
    updated_at = clock_timestamp() - interval '25 hours'
WHERE sender_id = 'auth.analysis' AND endpoint_kind = 'auth';
INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'auth.analysis', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019b0000-0000-7000-8000-000000008003', 1, 'auth', 'event-batch-v1',
    'sha256:0303030303030303030303030303030303030303030303030303030303030303',
    128, 1, clock_timestamp() - interval '25 hours', clock_timestamp() - interval '25 hours'
);
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

UPDATE sender_checkpoints
SET last_acknowledged_sequence = 2,
    last_acknowledged_body_digest =
        'sha256:0404040404040404040404040404040404040404040404040404040404040404',
    updated_at = clock_timestamp() - interval '1 minute'
WHERE sender_id = 'auth.analysis' AND endpoint_kind = 'auth';
INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'auth.analysis', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019b0000-0000-7000-8000-000000008004', 2, 'auth', 'event-batch-v1',
    'sha256:0404040404040404040404040404040404040404040404040404040404040404',
    128, 1, clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute'
);
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint IMMEDIATE;
SET CONSTRAINTS ingest_batches_require_atomic_checkpoint DEFERRED;

CREATE OR REPLACE FUNCTION pg_temp.make_analysis_fixture(
    p_incident_id uuid,
    p_signal_id uuid,
    p_gateway_event_id uuid,
    p_snapshot_id uuid,
    p_job_id uuid,
    p_digest sentinelflow.sha256_digest,
    p_source_health_status text DEFAULT 'complete',
    p_max_attempts integer DEFAULT 2
)
RETURNS void
LANGUAGE plpgsql
SET search_path = sentinelflow, pg_catalog
AS $fixture$
DECLARE
    event_time timestamptz := clock_timestamp() - interval '1 minute';
BEGIN
    INSERT INTO gateway_events (
        event_id, schema_version, sender_id, sender_epoch, batch_id,
        idempotency_key, request_id, trace_id, started_at, completed_at,
        source_ip, method, protocol, route_label, path_catalog_version,
        suspicious_path_id, host, service_label, status_code,
        request_bytes, response_bytes, latency_ms, received_at,
        trust_state, trust_reason
    ) VALUES (
        p_gateway_event_id, 'gateway-http-v1', 'gateway.analysis',
        'AAAAAAAAAAAAAAAAAAAAAA',
        '019b0000-0000-7000-8000-000000008002',
        sentinelflow.analysis_sha256(convert_to('event-' || p_gateway_event_id::text, 'UTF8')),
        gen_random_uuid(), gen_random_uuid(), event_time, event_time,
        '198.51.100.42/32', 'GET', 'HTTP/1.1', 'home', 'path-catalog-v1',
        'admin_console', 'demo.example', 'demo', 404, 0, 0, 1,
        event_time, 'trusted', 'none'
    );
    INSERT INTO signals (
        signal_id, schema_version, rule_id, rule_version, kind, source_ip,
        service_label, window_start, window_end, observed_count, distinct_count,
        threshold_count, threshold_distinct, source_health_status,
        evidence_digest, created_at
    ) VALUES (
        p_signal_id, 'signal-v1', 'path_scan.v1', 1, 'path_scan',
        '198.51.100.42/32', 'demo', event_time, event_time, 1, 1, 1, 1,
        p_source_health_status, p_digest, event_time
    );
    INSERT INTO signal_evidence (
        evidence_link_id, signal_id, event_kind, gateway_event_id,
        event_time, relation_reason, created_at
    ) VALUES (
        gen_random_uuid(), p_signal_id, 'gateway', p_gateway_event_id,
        event_time, 'threshold_member', event_time
    );
    INSERT INTO incidents (
        incident_id, kind, state, source_ip, service_label, first_seen,
        last_seen, deterministic_score, version, created_at, updated_at
    ) VALUES (
        p_incident_id, 'path_scan', 'open', '198.51.100.42/32', 'demo',
        event_time, event_time, 0.90000, 1, event_time, event_time
    );
    INSERT INTO incident_signals (
        incident_id, signal_id, incident_version, relation_reason, linked_at
    ) VALUES (p_incident_id, p_signal_id, 1, 'same_source_overlap', event_time);
    INSERT INTO incident_events (
        incident_event_id, incident_id, incident_version, event_kind,
        gateway_event_id, relation_reason, linked_at
    ) VALUES (
        gen_random_uuid(), p_incident_id, 1, 'gateway', p_gateway_event_id,
        'signal_expansion', event_time
    );
    INSERT INTO evidence_snapshots (
        evidence_snapshot_id, schema_version, incident_id, incident_version,
        source_ip, service_label, window_start, window_end, source_health_status,
        signal_count, expanded_event_count, snapshot_digest, created_at, expires_at
    ) VALUES (
        p_snapshot_id, 'evidence-snapshot-v1', p_incident_id, 1,
        '198.51.100.42/32', 'demo', event_time, event_time,
        p_source_health_status, 1, 1, p_digest, event_time,
        clock_timestamp() + interval '30 minutes'
    );
    INSERT INTO evidence_snapshot_signals (
        evidence_snapshot_id, ordinal, signal_id, evidence_id,
        evidence_digest, expanded_event_count
    ) VALUES (p_snapshot_id, 1, p_signal_id, p_signal_id::text, p_digest, 1);
    INSERT INTO evidence_snapshot_events (
        evidence_snapshot_event_id, evidence_snapshot_id, signal_id,
        event_kind, gateway_event_id, event_time
    ) VALUES (gen_random_uuid(), p_snapshot_id, p_signal_id, 'gateway', p_gateway_event_id, event_time);
    INSERT INTO outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, max_attempts,
        created_at, updated_at
    ) VALUES (
        p_job_id, 'analyze', 'incident', p_incident_id, 1, NULL,
        sentinelflow.analysis_sha256(convert_to('job-' || p_job_id::text, 'UTF8')),
        'pending', clock_timestamp() - interval '1 minute', p_max_attempts,
        clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute'
    );
END
$fixture$;

-- A non-analysis job sorts first but must never be leased by the dedicated
-- adapter.
INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts,
    created_at, updated_at
) VALUES (
    '019b0000-0000-7000-8000-000000008010', 'detect', 'incident',
    '019b0000-0000-7000-8000-000000008110', 1, NULL,
    'sha256:1010101010101010101010101010101010101010101010101010101010101010',
    'pending', clock_timestamp() - interval '2 minutes', 2,
    clock_timestamp() - interval '2 minutes', clock_timestamp() - interval '2 minutes'
);

SELECT pg_temp.make_analysis_fixture(
    '019b0000-0000-7000-8000-000000008101',
    '019b0000-0000-7000-8000-000000008201',
    '019b0000-0000-7000-8000-000000008301',
    '019b0000-0000-7000-8000-000000008401',
    '019b0000-0000-7000-8000-000000008501',
    'sha256:1111111111111111111111111111111111111111111111111111111111111111'
);

DO $lease_prepare_and_success_finalize$
DECLARE
    client_now timestamptz := clock_timestamp();
    leased outbox_jobs%ROWTYPE;
    none outbox_jobs%ROWTYPE;
    prepared record;
    wrong record;
    finished record;
    mutation jsonb;
    analysis_document jsonb;
    policy_document jsonb;
    candidate_document jsonb;
    analysis_text text;
    policy_text text;
    candidate_text text;
    expected_output_digest sha256_digest;
    command_digest sha256_digest;
    analysis_id_value uuid;
BEGIN
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008601',
        'analysis-worker', client_now + interval '30 seconds'
    );
    IF leased.job_id <> '019b0000-0000-7000-8000-000000008501' OR
       leased.kind <> 'analyze' OR leased.attempts <> 1 THEN
        RAISE EXCEPTION 'analysis-only lease selected the wrong job';
    END IF;
    SELECT * INTO none FROM lease_analysis_outbox_job(
        client_now + interval '1 hour',
        '019b0000-0000-4000-8000-000000008602',
        'analysis-worker-two', client_now + interval '1 hour 30 seconds'
    );
    IF none.job_id IS NOT NULL THEN
        RAISE EXCEPTION 'caller clock or concurrent lease bypassed live analysis lease';
    END IF;
    SELECT * INTO wrong FROM prepare_analysis_attempt(
        leased.job_id, '019b0000-0000-4000-8000-000000008699'
    );
    IF wrong.status IS NOT NULL THEN
        RAISE EXCEPTION 'wrong token prepared an analysis';
    END IF;
    SELECT * INTO prepared FROM prepare_analysis_attempt(leased.job_id, leased.lease_token);
    IF prepared.status <> 'prepared' OR prepared.snapshot IS NULL OR
       prepared.snapshot->>'incident_id' <> leased.aggregate_id::text OR
       jsonb_array_length(prepared.snapshot->'signals') <> 1 OR
       prepared.snapshot#>>'{signals,0,signal_id}' <>
           '019b0000-0000-7000-8000-000000008201' OR
       (prepared.snapshot#>>'{historical_impact,lookback_end}')::timestamptz -
           (prepared.snapshot#>>'{historical_impact,lookback_start}')::timestamptz <>
           interval '24 hours' THEN
        RAISE EXCEPTION 'complete evidence did not prepare one compact snapshot: %', prepared.snapshot;
    END IF;
    analysis_id_value := (prepared.snapshot->>'analysis_id')::uuid;

    -- A malformed success must roll back every domain mutation while leaving
    -- the same live claim available for the valid terminal statement.
    BEGIN
        PERFORM * FROM finalize_analysis_attempt(
            leased.job_id, leased.lease_token, 'completed', NULL, clock_timestamp(),
            NULL, NULL,
            jsonb_build_object(
                'incident_id', leased.aggregate_id::text, 'incident_version', 1,
                'analysis_id', analysis_id_value::text,
                'evidence_snapshot_id', prepared.snapshot->>'evidence_snapshot_id',
                'evidence_snapshot_digest', prepared.snapshot->>'evidence_snapshot_digest',
                'state', 'review_ready', 'audit_action', 'analysis_succeeded',
                'validation_requested', true, 'failure', NULL,
                'success', jsonb_build_object('model', 'untrusted-model')
            )
        );
        RAISE EXCEPTION 'malformed success was accepted';
    EXCEPTION WHEN invalid_parameter_value THEN
        NULL;
    END;
    IF (SELECT state FROM analysis_attempt_claims WHERE analysis_id = analysis_id_value) <> 'started' OR
       EXISTS (SELECT 1 FROM ai_analyses WHERE analysis_id = analysis_id_value) OR
       (SELECT state FROM outbox_jobs WHERE job_id = leased.job_id) <> 'leased' THEN
        RAISE EXCEPTION 'failed finalize left partial effects';
    END IF;

    policy_document := jsonb_build_object(
        'schema_version', 'response-policy-v1', 'action', 'block_ip',
        'target_ip', '198.51.100.42', 'ttl_seconds', 1800,
        'evidence_ids', jsonb_build_array('019b0000-0000-7000-8000-000000008201'),
        'rationale', 'Synthetic deterministic path-scan evidence warrants review.'
    );
    candidate_document := jsonb_build_object(
        'schema_version', 'nft-blacklist-v1', 'target_ip', '198.51.100.42',
        'timeout', '30m',
        'evidence_ids', jsonb_build_array('019b0000-0000-7000-8000-000000008201'),
        'command', 'add element inet sentinelflow blacklist_ipv4 { 198.51.100.42 timeout 30m }'
    );
    analysis_document := jsonb_build_object(
        'schema_version', 'sentinelflow_analysis_v1',
        'incident_summary', 'Synthetic path scan detected.',
        'classification', 'path_scan', 'confidence', 0.91,
        'uncertainty', 'Synthetic integration fixture.',
        'false_positive_factors', jsonb_build_array('Authorized scanner'),
        'evidence_ids', jsonb_build_array('019b0000-0000-7000-8000-000000008201'),
        'policy', policy_document, 'nftables_command_candidate', candidate_document
    );
    analysis_text := analysis_document::text;
    policy_text := policy_document::text;
    candidate_text := candidate_document::text;
    expected_output_digest := sentinelflow.analysis_sha256(convert_to(analysis_text, 'UTF8'));
    command_digest := sentinelflow.analysis_sha256(convert_to(
        candidate_document->>'command', 'UTF8'));
    mutation := jsonb_build_object(
        'incident_id', leased.aggregate_id::text, 'incident_version', 1,
        'analysis_id', analysis_id_value::text,
        'evidence_snapshot_id', prepared.snapshot->>'evidence_snapshot_id',
        'evidence_snapshot_digest', prepared.snapshot->>'evidence_snapshot_digest',
        'state', 'review_ready', 'audit_action', 'analysis_succeeded',
        'validation_requested', true, 'failure', NULL,
        'success', jsonb_build_object(
            'model', 'gpt-5.6-sol', 'reasoning_effort', 'medium',
            'rate_card_version', 'operator-v1', 'response_id', 'resp_analysis_test',
            'attempts', 1, 'input_bytes', 512,
            'input_digest', 'sha256:2121212121212121212121212121212121212121212121212121212121212121',
            'input_schema_digest', 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
            'prompt_digest', 'sha256:2323232323232323232323232323232323232323232323232323232323232323',
            'output_schema_digest', 'sha256:2424242424242424242424242424242424242424242424242424242424242424',
            'output_digest', expected_output_digest,
            'analysis_hex', encode(convert_to(analysis_text, 'UTF8'), 'hex'),
            'policy_hex', encode(convert_to(policy_text, 'UTF8'), 'hex'),
            'command_candidate_hex', encode(convert_to(candidate_text, 'UTF8'), 'hex'),
            'generated_command_digest', command_digest,
            'evidence_ids', jsonb_build_array('019b0000-0000-7000-8000-000000008201'),
            'usage', jsonb_build_object(
                'input_tokens', 120, 'cached_input_tokens', 20,
                'output_tokens', 80, 'trusted', true
            )
        )
    );
    SELECT * INTO wrong FROM finalize_analysis_attempt(
        leased.job_id, '019b0000-0000-4000-8000-000000008698',
        'completed', NULL, clock_timestamp(), NULL, NULL, mutation
    );
    IF wrong.job_id IS NOT NULL OR EXISTS (
        SELECT 1 FROM ai_analyses WHERE analysis_id = analysis_id_value
    ) THEN
        RAISE EXCEPTION 'wrong finalize token committed analysis state';
    END IF;
    SELECT * INTO finished FROM finalize_analysis_attempt(
        leased.job_id, leased.lease_token, 'completed', NULL,
        clock_timestamp(), NULL, NULL, mutation
    );
    IF finished.state <> 'completed' OR
       (SELECT state FROM analysis_attempt_claims WHERE analysis_id = analysis_id_value) <> 'succeeded' OR
       NOT EXISTS (
           SELECT 1 FROM ai_analyses analysis
           WHERE analysis.analysis_id = analysis_id_value
             AND analysis.model = 'gpt-5.6-sol' AND analysis.reasoning_effort = 'medium'
             AND analysis.store_enabled = false AND analysis.result_state = 'succeeded'
             AND analysis.output_digest = expected_output_digest
       ) OR NOT EXISTS (
           SELECT 1 FROM analysis_output_staging staging
           WHERE staging.analysis_id = analysis_id_value
             AND staging.state = 'pre_validation'
             AND staging.structured_output = convert_to(analysis_text, 'UTF8')
       ) OR NOT EXISTS (
           SELECT 1 FROM outbox_jobs validation
           WHERE validation.kind = 'validate' AND validation.aggregate_type = 'analysis_staging'
             AND validation.aggregate_id = analysis_id_value AND validation.state = 'pending'
       ) OR NOT EXISTS (
           SELECT 1 FROM audit_events audit
           WHERE audit.object_id = analysis_id_value AND audit.action = 'analysis_succeeded'
             AND audit.outcome = 'succeeded'
       ) OR (SELECT state FROM incidents WHERE incident_id = leased.aggregate_id) <> 'review_ready' THEN
        RAISE EXCEPTION 'successful finalize did not atomically persist provenance/staging/audit/outbox';
    END IF;
    SELECT * INTO wrong FROM finalize_analysis_attempt(
        leased.job_id, leased.lease_token, 'completed', NULL,
        clock_timestamp(), NULL, NULL, mutation
    );
    IF wrong.job_id IS NOT NULL OR
       (SELECT count(*) FROM ai_analyses WHERE analysis_id = analysis_id_value) <> 1 THEN
        RAISE EXCEPTION 'terminal finalize was not idempotently fenced';
    END IF;
END
$lease_prepare_and_success_finalize$;

-- A crash after Prepare has an unknown provider outcome. Recovering the lease
-- must atomically interrupt and dead-letter it without producing a second
-- prepared snapshot.
SELECT pg_temp.make_analysis_fixture(
    '019b0000-0000-7000-8000-000000008102',
    '019b0000-0000-7000-8000-000000008202',
    '019b0000-0000-7000-8000-000000008302',
    '019b0000-0000-7000-8000-000000008402',
    '019b0000-0000-7000-8000-000000008502',
    'sha256:1212121212121212121212121212121212121212121212121212121212121212',
    'complete', 2
);

DO $crash_after_prepare_never_calls_twice$
DECLARE
    client_now timestamptz := clock_timestamp();
    first_lease outbox_jobs%ROWTYPE;
    second_lease outbox_jobs%ROWTYPE;
    first_prepare record;
    second_prepare record;
    analysis_id_value uuid;
BEGIN
    SELECT * INTO first_lease FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008603',
        'analysis-crash-one', client_now + interval '30 seconds'
    );
    SELECT * INTO first_prepare FROM prepare_analysis_attempt(
        first_lease.job_id, first_lease.lease_token
    );
    IF first_prepare.status <> 'prepared' THEN
        RAISE EXCEPTION 'crash fixture did not prepare';
    END IF;
    analysis_id_value := (first_prepare.snapshot->>'analysis_id')::uuid;
    UPDATE outbox_jobs
    SET updated_at = clock_timestamp() - interval '2 seconds',
        lease_expires_at = clock_timestamp() - interval '1 second'
    WHERE job_id = first_lease.job_id;
    client_now := clock_timestamp();
    SELECT * INTO second_lease FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008604',
        'analysis-crash-two', client_now + interval '30 seconds'
    );
    IF second_lease.job_id <> first_lease.job_id OR second_lease.attempts <> 2 THEN
        RAISE EXCEPTION 'expired prepared lease was not recovered once';
    END IF;
    SELECT * INTO second_prepare FROM prepare_analysis_attempt(
        second_lease.job_id, second_lease.lease_token
    );
    IF second_prepare.status <> 'interrupted' OR second_prepare.snapshot IS NOT NULL OR
       (SELECT state FROM analysis_attempt_claims WHERE analysis_id = analysis_id_value) <> 'interrupted' OR
       (SELECT result_state FROM analysis_attempt_results WHERE analysis_id = analysis_id_value) <>
           'interrupted' OR
       (SELECT state FROM outbox_jobs WHERE job_id = second_lease.job_id) <> 'dead' OR
       NOT EXISTS (SELECT 1 FROM dead_letter_jobs WHERE job_id = second_lease.job_id) OR
       EXISTS (SELECT 1 FROM ai_analyses WHERE analysis_id = analysis_id_value) OR
       EXISTS (SELECT 1 FROM analysis_output_staging WHERE analysis_id = analysis_id_value) THEN
        RAISE EXCEPTION 'crash recovery allowed a second provider call or enforcing result';
    END IF;
END
$crash_after_prepare_never_calls_twice$;

-- History loss produces a typed, audited no-call terminal outcome.
SELECT pg_temp.make_analysis_fixture(
    '019b0000-0000-7000-8000-000000008103',
    '019b0000-0000-7000-8000-000000008203',
    '019b0000-0000-7000-8000-000000008303',
    '019b0000-0000-7000-8000-000000008403',
    '019b0000-0000-7000-8000-000000008503',
    'sha256:1313131313131313131313131313131313131313131313131313131313131313'
);
UPDATE sender_checkpoints SET unknown_loss = true WHERE endpoint_kind = 'auth';

DO $history_incomplete_is_no_call$
DECLARE
    client_now timestamptz := clock_timestamp();
    leased outbox_jobs%ROWTYPE;
    prepared record;
    claim analysis_attempt_claims%ROWTYPE;
BEGIN
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008605',
        'analysis-history', client_now + interval '30 seconds'
    );
    SELECT * INTO prepared FROM prepare_analysis_attempt(leased.job_id, leased.lease_token);
    SELECT * INTO claim FROM analysis_attempt_claims WHERE job_id = leased.job_id;
    IF prepared.status <> 'no_call' OR prepared.snapshot IS NOT NULL OR
       claim.state <> 'no_call' OR claim.no_call_code <> 'history_incomplete' OR
       (SELECT failure_reason FROM analysis_attempt_results WHERE analysis_id = claim.analysis_id) <>
           'history_incomplete' OR
       (SELECT state FROM outbox_jobs WHERE job_id = leased.job_id) <> 'completed' OR
       (SELECT state FROM incidents WHERE incident_id = leased.aggregate_id) <> 'analysis_failed' OR
       EXISTS (SELECT 1 FROM ai_analyses WHERE analysis_id = claim.analysis_id) THEN
        RAISE EXCEPTION 'history incompleteness did not fail closed before provider call';
    END IF;
END
$history_incomplete_is_no_call$;
UPDATE sender_checkpoints SET unknown_loss = false WHERE endpoint_kind = 'auth';

-- Snapshot source health is independently fail-closed even with otherwise
-- complete transport history.
SELECT pg_temp.make_analysis_fixture(
    '019b0000-0000-7000-8000-000000008104',
    '019b0000-0000-7000-8000-000000008204',
    '019b0000-0000-7000-8000-000000008304',
    '019b0000-0000-7000-8000-000000008404',
    '019b0000-0000-7000-8000-000000008504',
    'sha256:1414141414141414141414141414141414141414141414141414141414141414',
    'incomplete'
);

DO $source_health_incomplete_is_no_call$
DECLARE
    client_now timestamptz := clock_timestamp();
    leased outbox_jobs%ROWTYPE;
    prepared record;
BEGIN
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008606',
        'analysis-health', client_now + interval '30 seconds'
    );
    SELECT * INTO prepared FROM prepare_analysis_attempt(leased.job_id, leased.lease_token);
    IF prepared.status <> 'no_call' OR NOT EXISTS (
        SELECT 1 FROM analysis_attempt_claims claim
        JOIN analysis_attempt_results result USING (analysis_id)
        WHERE claim.job_id = leased.job_id AND claim.state = 'no_call'
          AND claim.no_call_code = 'source_health_incomplete'
          AND result.failure_reason = 'source_health_incomplete'
    ) THEN
        RAISE EXCEPTION 'incomplete source-health snapshot reached provider boundary';
    END IF;
END
$source_health_incomplete_is_no_call$;

-- Typed provider failure commits atomically without staging or validation.
SELECT pg_temp.make_analysis_fixture(
    '019b0000-0000-7000-8000-000000008105',
    '019b0000-0000-7000-8000-000000008205',
    '019b0000-0000-7000-8000-000000008305',
    '019b0000-0000-7000-8000-000000008405',
    '019b0000-0000-7000-8000-000000008505',
    'sha256:1515151515151515151515151515151515151515151515151515151515151515'
);

DO $typed_failure_is_atomic$
DECLARE
    client_now timestamptz := clock_timestamp();
    leased outbox_jobs%ROWTYPE;
    prepared record;
    finished record;
    analysis_id_value uuid;
    mutation jsonb;
BEGIN
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008607',
        'analysis-failure', client_now + interval '30 seconds'
    );
    SELECT * INTO prepared FROM prepare_analysis_attempt(leased.job_id, leased.lease_token);
    analysis_id_value := (prepared.snapshot->>'analysis_id')::uuid;
    mutation := jsonb_build_object(
        'incident_id', leased.aggregate_id::text, 'incident_version', 1,
        'analysis_id', analysis_id_value::text,
        'evidence_snapshot_id', prepared.snapshot->>'evidence_snapshot_id',
        'evidence_snapshot_digest', prepared.snapshot->>'evidence_snapshot_digest',
        'state', 'analysis_failed', 'audit_action', 'analysis_failed',
        'validation_requested', false, 'success', NULL,
        'failure', jsonb_build_object(
            'reason', 'timeout', 'attempts', 2, 'retry_eligible', true,
            'input_bytes', 512,
            'input_digest', 'sha256:2525252525252525252525252525252525252525252525252525252525252525'
        )
    );
    SELECT * INTO finished FROM finalize_analysis_attempt(
        leased.job_id, leased.lease_token, 'completed', NULL,
        clock_timestamp(), NULL, NULL, mutation
    );
    IF finished.state <> 'completed' OR
       (SELECT state FROM analysis_attempt_claims WHERE analysis_id = analysis_id_value) <> 'failed' OR
       (SELECT failure_reason FROM analysis_attempt_results WHERE analysis_id = analysis_id_value) <>
           'timeout' OR
       (SELECT analysis_failure_reason FROM incidents WHERE incident_id = leased.aggregate_id) <>
           'timeout' OR
       EXISTS (SELECT 1 FROM ai_analyses WHERE analysis_id = analysis_id_value) OR
       EXISTS (SELECT 1 FROM analysis_output_staging WHERE analysis_id = analysis_id_value) OR
       EXISTS (
           SELECT 1 FROM outbox_jobs
           WHERE kind = 'validate' AND aggregate_id = analysis_id_value
       ) THEN
        RAISE EXCEPTION 'typed failure produced partial or enforcing state';
    END IF;
END
$typed_failure_is_atomic$;

-- Operational retry and dead paths remain token-fenced and server-timed even
-- when Prepare was never reached.
INSERT INTO outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    operation, idempotency_key, state, available_at, max_attempts,
    created_at, updated_at
) VALUES
    ('019b0000-0000-7000-8000-000000008506', 'analyze', 'incident',
     '019b0000-0000-7000-8000-000000008106', 1, NULL,
     'sha256:1616161616161616161616161616161616161616161616161616161616161616',
     'pending', clock_timestamp() - interval '1 minute', 2,
     clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute'),
    ('019b0000-0000-7000-8000-000000008507', 'analyze', 'incident',
     '019b0000-0000-7000-8000-000000008107', 1, NULL,
     'sha256:1717171717171717171717171717171717171717171717171717171717171717',
     'pending', clock_timestamp() - interval '30 seconds', 1,
     clock_timestamp() - interval '30 seconds', clock_timestamp() - interval '30 seconds');

DO $retry_and_dead_paths$
DECLARE
    client_now timestamptz := clock_timestamp();
    leased outbox_jobs%ROWTYPE;
    finished record;
BEGIN
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008608',
        'analysis-retry', client_now + interval '30 seconds'
    );
    SELECT * INTO finished FROM finalize_analysis_attempt(
        leased.job_id, leased.lease_token, 'retry', client_now + interval '1 second',
        client_now, 'snapshot_unavailable',
        'sha256:2626262626262626262626262626262626262626262626262626262626262626', NULL
    );
    IF finished.state <> 'retry' OR
       (SELECT available_at - updated_at FROM outbox_jobs WHERE job_id = leased.job_id) <>
           interval '1 second' THEN
        RAISE EXCEPTION 'analysis retry was not server-clock scheduled';
    END IF;
    UPDATE outbox_jobs
    SET available_at = statement_timestamp() - interval '1 second',
        updated_at = statement_timestamp() - interval '1 second'
    WHERE job_id = leased.job_id;
    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008609',
        'analysis-dead', client_now + interval '30 seconds'
    );
    SELECT * INTO finished FROM finalize_analysis_attempt(
        leased.job_id, leased.lease_token, 'dead', NULL, client_now,
        'snapshot_unavailable',
        'sha256:2727272727272727272727272727272727272727272727272727272727272727', NULL
    );
    IF finished.state <> 'dead' OR NOT EXISTS (
        SELECT 1 FROM dead_letter_jobs dead
        WHERE dead.job_id = leased.job_id AND dead.failure_code = 'snapshot_unavailable'
    ) THEN
        RAISE EXCEPTION 'analysis dead-letter was not atomic';
    END IF;
END
$retry_and_dead_paths$;

-- A queued D-version job can be overtaken before Prepare. Immutable history
-- distinguishes that expected supersession from an aggregate that never
-- existed, so the old job completes without a provider claim or dead letter.
DO $queued_stale_version_is_terminal_without_provider$
DECLARE
    client_now timestamptz;
    leased outbox_jobs%ROWTYPE;
    prepared record;
    incident_id_value uuid := '019b0000-0000-7000-8000-000000008110';
    signal_id_value uuid := '019b0000-0000-7000-8000-000000008210';
    job_id_value uuid := '019b0000-0000-7000-8000-000000008510';
BEGIN
    IF to_regprocedure(
        'sentinelflow.resolve_queued_stale_analysis_000033(uuid,uuid)'
    ) IS NULL THEN
        RETURN;
    END IF;

    PERFORM pg_temp.make_analysis_fixture(
        incident_id_value, signal_id_value,
        '019b0000-0000-7000-8000-000000008310',
        '019b0000-0000-7000-8000-000000008410', job_id_value,
        'sha256:1818181818181818181818181818181818181818181818181818181818181818'
    );
    INSERT INTO incident_version_history (
        incident_id, incident_version, state, kind, source_ip, service_label,
        first_seen, last_seen, deterministic_score, mutation_kind,
        mutation_digest, evidence_digest, signal_count, recorded_at
    )
    SELECT incident_id, 1, state, kind, source_ip, service_label,
           first_seen, last_seen, deterministic_score, 'created',
           'sha256:2818181818181818181818181818181818181818181818181818181818181818',
           'sha256:1818181818181818181818181818181818181818181818181818181818181818',
           1, updated_at
    FROM incidents WHERE incident_id = incident_id_value;
    INSERT INTO incident_version_signals (
        incident_id, incident_version, signal_id, ordinal
    ) VALUES (incident_id_value, 1, signal_id_value, 1);

    UPDATE incidents
    SET version = 2, evidence_version = 2,
        updated_at = clock_timestamp()
    WHERE incident_id = incident_id_value AND version = 1;
    UPDATE incident_signals SET incident_version = 2
    WHERE incident_id = incident_id_value;
    UPDATE incident_events SET incident_version = 2
    WHERE incident_id = incident_id_value;
    INSERT INTO incident_version_history (
        incident_id, incident_version, state, kind, source_ip, service_label,
        first_seen, last_seen, deterministic_score, mutation_kind,
        mutation_digest, evidence_digest, signal_count, recorded_at
    )
    SELECT incident_id, 2, state, kind, source_ip, service_label,
           first_seen, last_seen, deterministic_score, 'signal_added',
           'sha256:2918181818181818181818181818181818181818181818181818181818181818',
           'sha256:1918181818181818181818181818181818181818181818181818181818181818',
           1, updated_at
    FROM incidents WHERE incident_id = incident_id_value;
    INSERT INTO incident_version_signals (
        incident_id, incident_version, signal_id, ordinal
    ) VALUES (incident_id_value, 2, signal_id_value, 1);

    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008610',
        'analysis-stale-queued', client_now + interval '30 seconds'
    );
    IF leased.job_id <> job_id_value OR leased.aggregate_version <> 1 THEN
        RAISE EXCEPTION 'stale queued analysis fixture was not leased';
    END IF;
    SELECT * INTO prepared FROM prepare_analysis_attempt(
        leased.job_id, leased.lease_token
    );
    IF prepared.status <> 'terminal' OR prepared.snapshot IS NOT NULL OR
       (SELECT state FROM outbox_jobs WHERE job_id = job_id_value) <> 'completed' OR
       EXISTS (SELECT 1 FROM analysis_attempt_claims WHERE job_id = job_id_value) OR
       EXISTS (SELECT 1 FROM dead_letter_jobs WHERE job_id = job_id_value) OR
       (SELECT version FROM incidents WHERE incident_id = incident_id_value) <> 2 OR
       (SELECT evidence_version FROM incidents WHERE incident_id = incident_id_value) <> 2 OR
       (SELECT state FROM incidents WHERE incident_id = incident_id_value) <> 'open' OR
       (SELECT count(*) FROM audit_events
        WHERE action = 'analysis_superseded' AND object_id = job_id_value
          AND outcome = 'rejected') <> 1 THEN
        RAISE EXCEPTION 'stale queued analysis did not resolve provider-free';
    END IF;

    INSERT INTO outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        operation, idempotency_key, state, available_at, max_attempts,
        created_at, updated_at
    ) VALUES (
        '019b0000-0000-7000-8000-000000008511', 'analyze', 'incident',
        '019b0000-0000-7000-8000-000000008111', 1, NULL,
        'sha256:3118181818181818181818181818181818181818181818181818181818181818',
        'pending', clock_timestamp() - interval '1 minute', 1,
        clock_timestamp() - interval '1 minute', clock_timestamp() - interval '1 minute'
    );
    client_now := clock_timestamp();
    SELECT * INTO leased FROM lease_analysis_outbox_job(
        client_now, '019b0000-0000-4000-8000-000000008611',
        'analysis-truly-missing', client_now + interval '30 seconds'
    );
    SELECT * INTO prepared FROM prepare_analysis_attempt(
        leased.job_id, leased.lease_token
    );
    IF prepared.status <> 'no_call' OR prepared.snapshot IS NOT NULL OR
       (SELECT state FROM outbox_jobs WHERE job_id = leased.job_id) <> 'dead' OR
       NOT EXISTS (
           SELECT 1 FROM dead_letter_jobs dead
           WHERE dead.job_id = leased.job_id
             AND dead.failure_code = 'analysis_incident_missing'
             AND dead.resolution_state = 'unresolved'
       ) OR EXISTS (
           SELECT 1 FROM audit_events audit
           WHERE audit.object_id = leased.job_id
             AND audit.action = 'analysis_superseded'
       ) THEN
        RAISE EXCEPTION 'truly missing analysis aggregate did not remain dead';
    END IF;
END
$queued_stale_version_is_terminal_without_provider$;

-- The service role can call the exact functions but cannot forge claims,
-- analyses, staging output, incident transitions, or outbox completion.
SET LOCAL ROLE sentinelflow_worker;
DO $worker_direct_writes_are_denied$
BEGIN
    BEGIN
        INSERT INTO sentinelflow.analysis_attempt_claims (
            analysis_id, job_id, incident_id, incident_version,
            outbox_attempt, state, generated_at
        ) VALUES (
            '019b0000-0000-4000-8000-000000008999',
            '019b0000-0000-7000-8000-000000008501',
            '019b0000-0000-7000-8000-000000008101', 1, 1, 'started', clock_timestamp()
        );
        RAISE EXCEPTION 'worker forged analysis claim';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        UPDATE sentinelflow.incidents SET state = 'review_ready'
        WHERE incident_id = '019b0000-0000-7000-8000-000000008101';
        RAISE EXCEPTION 'worker forged incident analysis state';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        INSERT INTO sentinelflow.ai_analyses DEFAULT VALUES;
        RAISE EXCEPTION 'worker forged ai analysis';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        UPDATE sentinelflow.outbox_jobs SET state = state WHERE false;
        RAISE EXCEPTION 'worker directly mutated outbox state';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
END
$worker_direct_writes_are_denied$;
RESET ROLE;

ROLLBACK;
