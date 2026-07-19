BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $contracts$
BEGIN
    IF current_setting('server_version_num')::integer < 170000 THEN
        RAISE EXCEPTION 'PostgreSQL 17 or newer is required';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 14 AND name = 'exact_hil_artifacts'
    ) OR to_regclass('sentinelflow.evidence_snapshot_artifacts') IS NULL OR
       to_regclass('sentinelflow.hil_exact_artifacts') IS NULL THEN
        RAISE EXCEPTION 'exact HIL artifact schema is incomplete';
    END IF;
    IF NOT has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.insert_exact_evidence_snapshot(json,bytea)', 'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.prepare_validation_attempt_exact(uuid,uuid)', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.prepare_validation_attempt(uuid,uuid)', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)', 'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.finalize_validation_attempt_exact(uuid,uuid,text,timestamptz,timestamptz,text,text,json,bytea)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.finalize_validation_attempt(uuid,uuid,text,timestamptz,timestamptz,text,text,json)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.finalize_validation_attempt_normalized(uuid,uuid,text,timestamptz,timestamptz,text,text,json)',
        'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_api', 'sentinelflow.read_hil_exact_artifact(uuid,integer)', 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'exact artifact coordinator grants are invalid';
    END IF;
    IF has_table_privilege('sentinelflow_worker', 'sentinelflow.evidence_snapshots', 'INSERT') OR
       has_table_privilege('sentinelflow_worker', 'sentinelflow.evidence_snapshot_artifacts', 'SELECT') OR
       has_table_privilege('sentinelflow_api', 'sentinelflow.evidence_snapshot_artifacts', 'SELECT') OR
       has_table_privilege('sentinelflow_api', 'sentinelflow.hil_exact_artifacts', 'SELECT') THEN
        RAISE EXCEPTION 'canonical artifact table authority is too broad';
    END IF;
END
$contracts$;

CREATE TEMPORARY TABLE exact_evidence_fixture (
    payload json NOT NULL,
    canonical bytea NOT NULL,
    snapshot_digest sentinelflow.sha256_digest NOT NULL,
    captured_at timestamptz NOT NULL
) ON COMMIT DROP;
GRANT SELECT ON exact_evidence_fixture TO sentinelflow_worker;

DO $fixture$
DECLARE
    captured_at timestamptz := date_trunc('second', clock_timestamp());
    window_start timestamptz := captured_at - interval '1 minute';
    captured_text text := to_char(
        captured_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'
    );
    window_text text := to_char(
        window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'
    );
    canonical_text text;
    canonical_bytes bytea;
    canonical_digest sentinelflow.sha256_digest;
    payload jsonb;
BEGIN
    INSERT INTO sentinelflow.sender_checkpoints (
        sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
        last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
    ) VALUES (
        'exact-verifier', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
        NULL, false, false, captured_at
    );
    INSERT INTO sentinelflow.ingest_batches (
        sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
        schema_version, raw_body_digest, raw_body_size, record_count,
        sent_at, received_at
    ) VALUES (
        'exact-verifier', 'AAAAAAAAAAAAAAAAAAAAAA',
        '019b0000-0000-7000-8000-00000000e001', 1, 'gateway',
        'event-batch-v1',
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        100, 1, captured_at, captured_at
    );
    UPDATE sentinelflow.sender_checkpoints
    SET last_acknowledged_sequence = 1,
        last_acknowledged_body_digest =
            'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        clean_shutdown = true, updated_at = captured_at
    WHERE sender_id = 'exact-verifier' AND endpoint_kind = 'gateway';
    INSERT INTO sentinelflow.gateway_events (
        event_id, schema_version, sender_id, sender_epoch, batch_id,
        idempotency_key, request_id, trace_id, started_at, completed_at,
        source_ip, method, protocol, route_label, path_catalog_version,
        suspicious_path_id, host, service_label, status_code,
        request_bytes, response_bytes, latency_ms, trust_state, trust_reason
    ) VALUES (
        '019b0000-0000-7000-8000-00000000e002', 'gateway-http-v1',
        'exact-verifier', 'AAAAAAAAAAAAAAAAAAAAAA',
        '019b0000-0000-7000-8000-00000000e001',
        'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        '019b0000-0000-7000-8000-00000000e003',
        '019b0000-0000-7000-8000-00000000e004', captured_at, captured_at,
        '8.8.8.8', 'GET', 'HTTP/1.1', 'public', 'path-catalog-v1',
        'admin_console', 'example.test', 'gateway', 404, 0, 0, 1,
        'trusted', 'none'
    );
    INSERT INTO sentinelflow.signals (
        signal_id, schema_version, rule_id, rule_version, kind, source_ip,
        service_label, window_start, window_end, observed_count,
        distinct_count, threshold_count, threshold_distinct,
        source_health_status, evidence_digest
    ) VALUES (
        '019b0000-0000-7000-8000-00000000e005', 'signal-v1',
        'path_scan.v1', 1, 'path_scan', '8.8.8.8', 'gateway',
        window_start, captured_at, 1, 1, 1, 1, 'complete',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    );
    INSERT INTO sentinelflow.signal_evidence (
        evidence_link_id, signal_id, event_kind, gateway_event_id,
        event_time, relation_reason, created_at
    ) VALUES (
        '019b0000-0000-7000-8000-00000000e006',
        '019b0000-0000-7000-8000-00000000e005', 'gateway',
        '019b0000-0000-7000-8000-00000000e002', captured_at,
        'threshold_member', captured_at
    );
    INSERT INTO sentinelflow.incidents (
        incident_id, kind, state, source_ip, service_label, first_seen,
        last_seen, deterministic_score, version, created_at, updated_at
    ) VALUES (
        '019b0000-0000-7000-8000-00000000e007', 'path_scan', 'open',
        '8.8.8.8', 'gateway', window_start, captured_at, 0.9, 1,
        captured_at, captured_at
    );

    canonical_text := format(
        '{"created_at":"%s","event_ids":["019b0000-0000-7000-8000-00000000e002"],"incident_id":"019b0000-0000-7000-8000-00000000e007","incident_version":1,"schema_version":"evidence-snapshot-v1","service_label":"gateway","signal_ids":["019b0000-0000-7000-8000-00000000e005"],"snapshot_id":"019b0000-0000-7000-8000-00000000e008","source_health_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_ipv4":"8.8.8.8","window_end":"%s","window_start":"%s"}',
        captured_text, captured_text, window_text
    );
    canonical_bytes := convert_to(canonical_text, 'UTF8');
    canonical_digest := sentinelflow.validation_sha256(canonical_bytes);
    payload := jsonb_build_object(
        'snapshot_id', '019b0000-0000-7000-8000-00000000e008',
        'schema_version', 'evidence-snapshot-v1',
        'incident_id', '019b0000-0000-7000-8000-00000000e007',
        'incident_version', 1, 'source_ipv4', '8.8.8.8',
        'service_label', 'gateway', 'window_start', window_start,
        'window_end', captured_at, 'source_health_status', 'complete',
        'signal_count', 1, 'expanded_event_count', 1,
        'snapshot_digest', canonical_digest, 'created_at', captured_at,
        'expires_at', captured_at + interval '1 day',
        'signals', jsonb_build_array(jsonb_build_object(
            'ordinal', 1, 'signal_id', '019b0000-0000-7000-8000-00000000e005',
            'evidence_digest',
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'expanded_event_count', 1
        )),
        'events', jsonb_build_array(jsonb_build_object(
            'event_row_id', '019b0000-0000-7000-8000-00000000e009',
            'signal_id', '019b0000-0000-7000-8000-00000000e005',
            'event_kind', 'gateway',
            'event_id', '019b0000-0000-7000-8000-00000000e002',
            'event_time', captured_at
        ))
    );
    INSERT INTO pg_temp.exact_evidence_fixture
    VALUES (payload::json, canonical_bytes, canonical_digest, captured_at);
END
$fixture$;

SET LOCAL ROLE sentinelflow_worker;

DO $producer$
DECLARE
    fixture pg_temp.exact_evidence_fixture%ROWTYPE;
    result record;
    conflict jsonb;
BEGIN
    SELECT * INTO fixture FROM pg_temp.exact_evidence_fixture;
    SELECT * INTO result
    FROM sentinelflow.insert_exact_evidence_snapshot(fixture.payload, fixture.canonical);
    IF result.evidence_snapshot_id <>
            '019b0000-0000-7000-8000-00000000e008'::uuid OR
       result.snapshot_digest <> fixture.snapshot_digest OR NOT result.inserted THEN
        RAISE EXCEPTION 'exact evidence insertion mismatch';
    END IF;
    SELECT * INTO result
    FROM sentinelflow.insert_exact_evidence_snapshot(fixture.payload, fixture.canonical);
    IF result.inserted THEN
        RAISE EXCEPTION 'exact evidence replay inserted a second row';
    END IF;

    conflict := fixture.payload::jsonb;
    conflict := jsonb_set(
        conflict, '{expires_at}',
        to_jsonb(fixture.captured_at + interval '2 days')
    );
    BEGIN
        PERFORM * FROM sentinelflow.insert_exact_evidence_snapshot(
            conflict::json, fixture.canonical
        );
        RAISE EXCEPTION 'conflicting exact replay was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO sentinelflow.evidence_snapshots DEFAULT VALUES;
        RAISE EXCEPTION 'worker retained direct evidence insert authority';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$producer$;

RESET ROLE;

DO $rollback_and_immutability$
DECLARE
    fixture pg_temp.exact_evidence_fixture%ROWTYPE;
    missing_canonical bytea;
    missing_digest sentinelflow.sha256_digest;
    missing_payload jsonb;
BEGIN
    SELECT * INTO fixture FROM pg_temp.exact_evidence_fixture;
    missing_canonical := convert_to(replace(replace(
        convert_from(fixture.canonical, 'UTF8'),
        '019b0000-0000-7000-8000-00000000e008',
        '019b0000-0000-7000-8000-00000000e108'),
        '019b0000-0000-7000-8000-00000000e002',
        '019b0000-0000-7000-8000-00000000e102'), 'UTF8');
    missing_digest := sentinelflow.validation_sha256(missing_canonical);
    missing_payload := fixture.payload::jsonb;
    missing_payload := jsonb_set(
        missing_payload, '{snapshot_id}',
        to_jsonb('019b0000-0000-7000-8000-00000000e108'::text)
    );
    missing_payload := jsonb_set(
        missing_payload, '{snapshot_digest}', to_jsonb(missing_digest::text)
    );
    missing_payload := jsonb_set(
        missing_payload, '{events,0,event_row_id}',
        to_jsonb('019b0000-0000-7000-8000-00000000e109'::text)
    );
    missing_payload := jsonb_set(
        missing_payload, '{events,0,event_id}',
        to_jsonb('019b0000-0000-7000-8000-00000000e102'::text)
    );
    BEGIN
        PERFORM * FROM sentinelflow.insert_exact_evidence_snapshot(
            missing_payload::json, missing_canonical
        );
        RAISE EXCEPTION 'missing source relation was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.evidence_snapshots
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-00000000e108'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.evidence_snapshot_artifacts
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-00000000e108'
    ) THEN
        RAISE EXCEPTION 'failed producer call left partial rows';
    END IF;

    BEGIN
        UPDATE sentinelflow.evidence_snapshot_artifacts
        SET canonical_bytes = canonical_bytes
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-00000000e008';
        RAISE EXCEPTION 'canonical evidence update was accepted';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
    BEGIN
        DELETE FROM sentinelflow.evidence_snapshot_artifacts
        WHERE evidence_snapshot_id = '019b0000-0000-7000-8000-00000000e008';
        RAISE EXCEPTION 'canonical evidence delete was accepted';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END
$rollback_and_immutability$;

SET LOCAL ROLE sentinelflow_api;

DO $api_boundary$
DECLARE
    row_count integer;
BEGIN
    BEGIN
        PERFORM * FROM sentinelflow.evidence_snapshot_artifacts;
        RAISE EXCEPTION 'API read canonical evidence table directly';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
    SELECT count(*) INTO row_count
    FROM sentinelflow.read_hil_exact_artifact(
        '019b0000-0000-7000-8000-00000000e008', 1
    );
    IF row_count <> 0 THEN
        RAISE EXCEPTION 'evidence-only or legacy row became HIL eligible';
    END IF;
END
$api_boundary$;

ROLLBACK;
