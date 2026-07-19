BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $contract$
BEGIN
    IF current_setting('server_version_num')::integer < 170000 THEN
        RAISE EXCEPTION 'PostgreSQL 17 or newer is required';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 23 AND name = 'retention_runtime'
    ) OR to_regclass('sentinelflow.retention_runs') IS NULL THEN
        RAISE EXCEPTION 'retention runtime schema is incomplete';
    END IF;
    IF NOT has_function_privilege(
        'sentinelflow_retention',
        'sentinelflow.run_retention_000023(uuid,timestamptz,integer)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.run_retention_000023(uuid,timestamptz,integer)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.run_retention_000023(uuid,timestamptz,integer)',
        'EXECUTE'
    ) OR has_table_privilege(
        'sentinelflow_retention', 'sentinelflow.gateway_events', 'DELETE'
    ) OR has_table_privilege(
        'sentinelflow_retention', 'sentinelflow.audit_events', 'DELETE'
    ) OR has_table_privilege(
        'sentinelflow_retention', 'sentinelflow.retention_runs', 'INSERT'
    ) OR EXISTS (
        SELECT 1 FROM pg_roles role
        WHERE role.rolname = 'sentinelflow_retention'
          AND (role.rolinherit OR role.rolsuper OR role.rolcreatedb OR
               role.rolcreaterole OR role.rolreplication OR role.rolbypassrls)
    ) OR EXISTS (
        SELECT 1 FROM pg_auth_members membership
        JOIN pg_roles retention_role
          ON retention_role.oid IN (membership.member, membership.roleid)
        WHERE retention_role.rolname = 'sentinelflow_retention'
    ) THEN
        RAISE EXCEPTION 'retention least-privilege boundary is invalid';
    END IF;
END
$contract$;

CREATE TEMPORARY TABLE retention_test_context (
    as_of timestamptz NOT NULL,
    evidence_bytes bytea NOT NULL,
    evidence_digest sentinelflow.sha256_digest NOT NULL
) ON COMMIT DROP;
GRANT SELECT ON retention_test_context TO sentinelflow_retention;

DO $fixture$
DECLARE
    test_now timestamptz := date_trunc('seconds', clock_timestamp());
    event_old timestamptz;
    control_old timestamptz;
    audit_old timestamptz;
    evidence_bytes_value bytea;
    evidence_digest_value sentinelflow.sha256_digest;
    policy_bytes_value bytea := convert_to('{"policy":1}', 'UTF8');
    validation_bytes_value bytea := convert_to('{"validation":1}', 'UTF8');
    generated_bytes_value bytea := convert_to(
        'add element inet sentinelflow blacklist_ipv4 { 8.8.4.4 timeout 1m }',
        'UTF8'
    );
    canonical_bytes_value bytea := convert_to(
        'add element inet sentinelflow blacklist_ipv4 { 8.8.4.4 timeout 1m }' || chr(10),
        'UTF8'
    );
    session_created timestamptz := test_now - interval '9 hours';
    challenge_issued timestamptz;
BEGIN
    event_old := test_now - interval '8 days';
    control_old := test_now - interval '31 days';
    audit_old := test_now - interval '91 days';
    evidence_bytes_value := convert_to(
        '{"snapshot_id":"019f0000-0000-7000-8000-000000002308"}',
        'UTF8'
    );
    evidence_digest_value := sentinelflow.validation_sha256(evidence_bytes_value);
    challenge_issued := session_created + interval '10 minutes';

    INSERT INTO pg_temp.retention_test_context
    VALUES (test_now, evidence_bytes_value, evidence_digest_value);

    INSERT INTO sentinelflow.ingest_batches (
        sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
        schema_version, raw_body_digest, raw_body_size, record_count,
        sent_at, received_at
    ) VALUES (
        'retention-test', 'AAAAAAAAAAAAAAAAAAAAAA',
        '019f0000-0000-7000-8000-000000002301', 1, 'gateway',
        'event-batch-v1',
        'sha256:0101010101010101010101010101010101010101010101010101010101010101',
        100, 1, event_old, event_old
    );
    INSERT INTO sentinelflow.gateway_events (
        event_id, schema_version, sender_id, sender_epoch, batch_id,
        idempotency_key, request_id, trace_id, started_at, completed_at,
        source_ip, method, protocol, route_label, path_catalog_version,
        suspicious_path_id, host, service_label, status_code,
        request_bytes, response_bytes, latency_ms, received_at,
        trust_state, trust_reason
    ) VALUES (
        '019f0000-0000-7000-8000-000000002302', 'gateway-http-v1',
        'retention-test', 'AAAAAAAAAAAAAAAAAAAAAA',
        '019f0000-0000-7000-8000-000000002301',
        'sha256:0202020202020202020202020202020202020202020202020202020202020202',
        '019f0000-0000-7000-8000-000000002303',
        '019f0000-0000-7000-8000-000000002304', event_old, event_old,
        '8.8.8.8', 'GET', 'HTTP/1.1', 'public', 'path-catalog-v1',
        'none', 'example.test', 'gateway', 200, 0, 0, 1, event_old,
        'trusted', 'none'
    );
    -- Mirror the production late-arrival sequence: the current unresolved gap
    -- is removed before its terminal resolution evidence is appended.
    INSERT INTO sentinelflow.ingest_sequence_gaps (
        gap_id, sender_id, endpoint_kind, sender_epoch, sequence_start,
        sequence_end, detected_by_batch_id, detected_at
    ) VALUES (
        '019f0000-0000-7000-8000-000000002310', 'retention-test',
        'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 2, 2,
        '019f0000-0000-7000-8000-000000002301', event_old
    );
    DELETE FROM sentinelflow.ingest_sequence_gaps
    WHERE gap_id = '019f0000-0000-7000-8000-000000002310';
    INSERT INTO sentinelflow.ingest_sequence_gap_resolutions (
        resolution_id, sender_id, endpoint_kind, sender_epoch,
        sequence_start, sequence_end, resolution, resolution_batch_id,
        resolved_at
    ) VALUES (
        '019f0000-0000-7000-8000-000000002311', 'retention-test',
        'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 2, 2, 'late_arrival',
        '019f0000-0000-7000-8000-000000002301', event_old + interval '1 minute'
    );
    INSERT INTO sentinelflow.signals (
        signal_id, schema_version, rule_id, rule_version, kind, source_ip,
        service_label, window_start, window_end, observed_count,
        distinct_count, threshold_count, threshold_distinct,
        source_health_status, evidence_digest, created_at,
        configuration_version, configuration_digest, signal_digest
    ) VALUES (
        '019f0000-0000-7000-8000-000000002305', 'signal-v1',
        'request_burst.v1', 1, 'request_burst', '8.8.8.8', 'gateway',
        event_old - interval '10 seconds', event_old, 120, NULL, 120, NULL,
        'complete',
        'sha256:0303030303030303030303030303030303030303030303030303030303030303',
        event_old, 'detector-v1',
        'sha256:0404040404040404040404040404040404040404040404040404040404040404',
        'sha256:0505050505050505050505050505050505050505050505050505050505050505'
    );
    INSERT INTO sentinelflow.signal_evidence (
        evidence_link_id, signal_id, event_kind, gateway_event_id,
        event_time, relation_reason, created_at
    ) VALUES (
        '019f0000-0000-7000-8000-000000002306',
        '019f0000-0000-7000-8000-000000002305', 'gateway',
        '019f0000-0000-7000-8000-000000002302', event_old,
        'threshold_member', event_old
    );
    INSERT INTO sentinelflow.incidents (
        incident_id, kind, state, source_ip, service_label, first_seen,
        last_seen, closed_at, reopen_until, deterministic_score, version,
        created_at, updated_at, evidence_version
    ) VALUES
    (
        '019f0000-0000-7000-8000-000000002307', 'request_burst', 'open',
        '8.8.8.8', 'gateway', event_old, event_old, NULL, NULL, 0.9, 1,
        test_now - interval '1 day', test_now - interval '1 day', 1
    ),
    (
        '019f0000-0000-7000-8000-000000002320', 'path_scan', 'closed',
        '9.9.9.9', 'gateway', control_old - interval '1 hour', control_old,
        control_old, control_old + interval '30 minutes',
        0.5, 1, control_old, control_old, 1
    ),
    (
        '019f0000-0000-7000-8000-000000002321', 'path_scan', 'open',
        '1.1.1.1', 'gateway', control_old - interval '1 hour', control_old,
        NULL, NULL, 0.5, 1,
        test_now - interval '1 day', test_now - interval '1 day', 1
    ),
    (
        '019f0000-0000-7000-8000-000000002322', 'path_scan', 'closed',
        '1.0.0.1', 'gateway', control_old - interval '1 hour', control_old,
        control_old, control_old + interval '30 minutes',
        0.5, 1, control_old, control_old, 1
    ),
    (
        '019f0000-0000-7000-8000-000000002323', 'path_scan', 'closed',
        '1.0.0.2', 'gateway', control_old - interval '1 hour', control_old,
        control_old, control_old + interval '30 minutes',
        0.5, 1, control_old, control_old, 1
    ),
    (
        '019f0000-0000-7000-8000-000000002324', 'path_scan', 'closed',
        '1.0.0.3', 'gateway', control_old - interval '1 hour', control_old,
        control_old, control_old + interval '30 minutes',
        0.5, 1, control_old, control_old, 1
    );
    INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        idempotency_key, state, available_at, lease_token, lease_owner,
        lease_expires_at, attempts, last_error_code, last_error_digest,
        created_at, updated_at
    ) VALUES
    (
        '019f0000-0000-7000-8000-000000002330', 'analyze', 'incident',
        '019f0000-0000-7000-8000-000000002322', 1,
        'sha256:3030303030303030303030303030303030303030303030303030303030303030',
        'pending', test_now - interval '1 day', NULL, NULL, NULL, 0,
        NULL, NULL, test_now - interval '1 day', test_now - interval '1 day'
    ),
    (
        '019f0000-0000-7000-8000-000000002331', 'analyze', 'incident',
        '019f0000-0000-7000-8000-000000002323', 1,
        'sha256:3131313131313131313131313131313131313131313131313131313131313131',
        'leased', test_now - interval '1 day',
        '019f0000-0000-7000-8000-000000002339', 'retention-test-worker',
        test_now - interval '1 day' + interval '30 seconds', 1,
        NULL, NULL, test_now - interval '1 day', test_now - interval '1 day'
    ),
    (
        '019f0000-0000-7000-8000-000000002332', 'analyze', 'incident',
        '019f0000-0000-7000-8000-000000002324', 1,
        'sha256:3232323232323232323232323232323232323232323232323232323232323232',
        'retry', test_now - interval '1 day', NULL, NULL, NULL, 1,
        'synthetic_retry',
        'sha256:3333333333333333333333333333333333333333333333333333333333333333',
        test_now - interval '1 day', test_now - interval '1 day'
    );
    INSERT INTO sentinelflow.incident_signals (
        incident_id, signal_id, incident_version, relation_reason, linked_at
    ) VALUES (
        '019f0000-0000-7000-8000-000000002307',
        '019f0000-0000-7000-8000-000000002305', 1,
        'same_source_overlap', event_old
    );

    INSERT INTO sentinelflow.evidence_snapshots (
        evidence_snapshot_id, schema_version, incident_id, incident_version,
        source_ip, service_label, window_start, window_end,
        source_health_status, signal_count, expanded_event_count,
        snapshot_digest, created_at, expires_at
    ) VALUES (
        '019f0000-0000-7000-8000-000000002308', 'evidence-snapshot-v1',
        '019f0000-0000-7000-8000-000000002307', 1, '8.8.8.8', 'gateway',
        event_old - interval '1 minute', event_old, 'complete', 1, 1,
        evidence_digest_value, event_old, event_old + interval '1 day'
    );
    INSERT INTO sentinelflow.evidence_snapshot_artifacts (
        evidence_snapshot_id, schema_version, source_health_digest,
        canonical_bytes, canonical_digest, created_at
    ) VALUES (
        '019f0000-0000-7000-8000-000000002308', 'evidence-snapshot-v1',
        'sha256:0606060606060606060606060606060606060606060606060606060606060606',
        evidence_bytes_value, evidence_digest_value, event_old
    );

    INSERT INTO sentinelflow.ai_analyses (
        analysis_id, incident_id, incident_version, evidence_snapshot_id,
        evidence_snapshot_digest, attempt, model, reasoning_effort,
        store_enabled, input_schema_digest, prompt_digest,
        output_schema_digest, input_digest, input_bytes, result_state,
        failure_reason, started_at, completed_at, provider_kind, adapter_id,
        rate_card_version
    ) VALUES (
        '019f0000-0000-7000-8000-000000002309',
        '019f0000-0000-7000-8000-000000002307', 1,
        '019f0000-0000-7000-8000-000000002308', evidence_digest_value,
        1, NULL, NULL, false,
        'sha256:0707070707070707070707070707070707070707070707070707070707070707',
        'sha256:0808080808080808080808080808080808080808080808080808080808080808',
        'sha256:0909090909090909090909090909090909090909090909090909090909090909',
        'sha256:1010101010101010101010101010101010101010101010101010101010101010',
        2, 'failed', 'configuration_error', test_now - interval '1 day',
        test_now - interval '1 day', 'deterministic_stub',
        'sentinelflow-deterministic-ai-stub-v1', NULL
    );
    INSERT INTO sentinelflow.command_candidates (
        command_candidate_id, schema_version, analysis_id,
        evidence_snapshot_id, evidence_snapshot_digest, target_ipv4,
        timeout_token, ttl_seconds, generated_command,
        generated_artifact_digest, parse_state, canonical_artifact,
        canonical_artifact_digest, created_at, updated_at
    ) VALUES (
        '019f0000-0000-7000-8000-00000000230a', 'nft-blacklist-v1',
        '019f0000-0000-7000-8000-000000002309',
        '019f0000-0000-7000-8000-000000002308', evidence_digest_value,
        '8.8.4.4', '1m', 60, convert_from(generated_bytes_value, 'UTF8'),
        sentinelflow.validation_sha256(generated_bytes_value), 'canonical',
        canonical_bytes_value,
        sentinelflow.validation_sha256(canonical_bytes_value),
        test_now - interval '1 day', test_now - interval '1 day'
    );
    INSERT INTO sentinelflow.policy_proposals (
        policy_id, version, schema_version, incident_id, incident_version,
        analysis_id, command_candidate_id, evidence_snapshot_id,
        evidence_snapshot_digest, policy_digest, generated_artifact_digest,
        canonical_artifact_digest, target_ipv4, action, ttl_seconds,
        rationale, state, created_at, updated_at
    ) VALUES (
        '019f0000-0000-7000-8000-00000000230b', 1, 'response-policy-v1',
        '019f0000-0000-7000-8000-000000002307', 1,
        '019f0000-0000-7000-8000-000000002309',
        '019f0000-0000-7000-8000-00000000230a',
        '019f0000-0000-7000-8000-000000002308', evidence_digest_value,
        sentinelflow.validation_sha256(policy_bytes_value),
        sentinelflow.validation_sha256(generated_bytes_value),
        sentinelflow.validation_sha256(canonical_bytes_value),
        '8.8.4.4', 'block_ip', 60, 'synthetic retention verification',
        'draft', test_now - interval '1 day', test_now - interval '1 day'
    );
    INSERT INTO sentinelflow.validation_snapshots (
        validation_snapshot_id, schema_version, policy_id, policy_version,
        command_candidate_id, evidence_snapshot_id, snapshot_digest,
        policy_digest, evidence_snapshot_digest, analysis_input_digest,
        analysis_output_schema_digest, prompt_digest,
        generated_candidate_digest, canonical_artifact_digest,
        grammar_version, parser_version, validator_version,
        base_chain_contract_raw_digest, live_owned_schema_digest,
        protected_ipv4_static_digest, protected_ipv4_effective_config_digest,
        nft_binary_digest, nft_version, historical_impact_digest,
        target_ipv4, ttl_seconds, historical_impact_lookback_seconds,
        state, source_health_status, created_at, valid_until
    ) VALUES (
        '019f0000-0000-7000-8000-00000000230c', 'validation-snapshot-v1',
        '019f0000-0000-7000-8000-00000000230b', 1,
        '019f0000-0000-7000-8000-00000000230a',
        '019f0000-0000-7000-8000-000000002308',
        sentinelflow.validation_sha256(validation_bytes_value),
        sentinelflow.validation_sha256(policy_bytes_value), evidence_digest_value,
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        'sha256:1212121212121212121212121212121212121212121212121212121212121212',
        'sha256:1313131313131313131313131313131313131313131313131313131313131313',
        sentinelflow.validation_sha256(generated_bytes_value),
        sentinelflow.validation_sha256(canonical_bytes_value),
        'nft-blacklist-v1', 'parser-v1', 'validator-v1',
        'sha256:1414141414141414141414141414141414141414141414141414141414141414',
        'sha256:1515151515151515151515151515151515151515151515151515151515151515',
        'sha256:1616161616161616161616161616161616161616161616161616161616161616',
        'sha256:1717171717171717171717171717171717171717171717171717171717171717',
        'sha256:1818181818181818181818181818181818181818181818181818181818181818',
        '1.1.0',
        'sha256:1919191919191919191919191919191919191919191919191919191919191919',
        '8.8.4.4', 60, 86400, 'draft', 'complete',
        test_now - interval '1 day', test_now - interval '1 day' + interval '5 minutes'
    );
    INSERT INTO sentinelflow.hil_exact_artifacts (
        policy_id, policy_version, command_candidate_id,
        validation_snapshot_id, evidence_snapshot_id, target_ipv4,
        ttl_seconds, policy_bytes, policy_digest, evidence_bytes,
        evidence_digest, validation_bytes, validation_digest,
        generated_bytes, generated_digest, canonical_bytes, canonical_digest,
        validation_created_at, validation_valid_until, persisted_at
    ) VALUES (
        '019f0000-0000-7000-8000-00000000230b', 1,
        '019f0000-0000-7000-8000-00000000230a',
        '019f0000-0000-7000-8000-00000000230c',
        '019f0000-0000-7000-8000-000000002308', '8.8.4.4', 60,
        policy_bytes_value, sentinelflow.validation_sha256(policy_bytes_value),
        evidence_bytes_value, evidence_digest_value,
        validation_bytes_value,
        sentinelflow.validation_sha256(validation_bytes_value),
        generated_bytes_value,
        sentinelflow.validation_sha256(generated_bytes_value),
        canonical_bytes_value,
        sentinelflow.validation_sha256(canonical_bytes_value),
        test_now - interval '1 day',
        test_now - interval '1 day' + interval '5 minutes',
        test_now - interval '1 day'
    );

    INSERT INTO sentinelflow.admin_sessions (
        session_id, actor_id, token_digest, csrf_digest, authenticated_at,
        created_at, last_seen_at, expires_at
    ) VALUES (
        '019f0000-0000-7000-8000-00000000230d', 'administrator',
        'sha256:2020202020202020202020202020202020202020202020202020202020202020',
        'sha256:2121212121212121212121212121212121212121212121212121212121212121',
        session_created, session_created, challenge_issued,
        session_created + interval '8 hours'
    );
    INSERT INTO sentinelflow.decision_challenges (
        challenge_id, schema_version, nonce_digest, session_id,
        session_digest, actor_id, operation, resource_type, resource_id,
        resource_version, policy_id, policy_version, target_ipv4,
        policy_digest, evidence_snapshot_digest, generated_artifact_digest,
        canonical_artifact_digest, validation_snapshot_digest,
        validation_valid_until, idempotency_key_digest, authenticated_at,
        issued_at, expires_at, challenge_jcs, challenge_digest
    ) VALUES (
        '019f0000-0000-7000-8000-00000000230e', 'hil-challenge-v1',
        'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        '019f0000-0000-7000-8000-00000000230d',
        'sha256:2020202020202020202020202020202020202020202020202020202020202020',
        'administrator', 'reject', 'policy',
        '019f0000-0000-7000-8000-00000000230b', 1,
        '019f0000-0000-7000-8000-00000000230b', 1, '8.8.4.4',
        sentinelflow.validation_sha256(policy_bytes_value), evidence_digest_value,
        sentinelflow.validation_sha256(generated_bytes_value),
        sentinelflow.validation_sha256(canonical_bytes_value),
        sentinelflow.validation_sha256(validation_bytes_value),
        challenge_issued + interval '5 minutes',
        'sha256:2323232323232323232323232323232323232323232323232323232323232323',
        session_created, challenge_issued,
        challenge_issued + interval '5 minutes', convert_to('{}', 'UTF8'),
        sentinelflow.validation_sha256(convert_to('{}', 'UTF8'))
    );

    INSERT INTO sentinelflow.ingest_replay_nonces (
        sender_id, endpoint_kind, endpoint_path, nonce_digest,
        authenticated_at, expires_at
    ) VALUES (
        'retention-test', 'gateway', '/internal/v1/gateway-events',
        'sha256:2424242424242424242424242424242424242424242424242424242424242424',
        event_old, event_old + interval '5 minutes'
    );
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        primary_digest, outcome, occurred_at, recorded_at
    ) OVERRIDING SYSTEM VALUE VALUES (
        '019f0000-0000-7000-8000-00000000230f', 'system', 'retention-test',
        'synthetic_old_event', 'retention_fixture',
        '019f0000-0000-7000-8000-00000000230f',
        'sha256:2525252525252525252525252525252525252525252525252525252525252525',
        'succeeded', audit_old, audit_old
    );
END
$fixture$;

DO $negative_source_binding$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    BEGIN
        UPDATE sentinelflow.ai_analyses
        SET evidence_snapshot_id = NULL
        WHERE analysis_id = '019f0000-0000-7000-8000-000000002309';
        RAISE EXCEPTION 'analysis source reference was manually detached';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
    BEGIN
        UPDATE sentinelflow.ai_analyses
        SET provider_kind = 'openai_responses',
            adapter_id = 'openai-responses-v1',
            model = 'gpt-5.6-sol', reasoning_effort = 'medium',
            rate_card_version = 'operator-rate-v1'
        WHERE analysis_id = '019f0000-0000-7000-8000-000000002309';
        RAISE EXCEPTION 'analysis provider provenance was rewritten';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
    BEGIN
        INSERT INTO sentinelflow.hil_exact_artifacts (
            policy_id, policy_version, command_candidate_id,
            validation_snapshot_id, evidence_snapshot_id, target_ipv4,
            ttl_seconds, policy_bytes, policy_digest, evidence_bytes,
            evidence_digest, validation_bytes, validation_digest,
            generated_bytes, generated_digest, canonical_bytes,
            canonical_digest, validation_created_at,
            validation_valid_until, persisted_at
        ) VALUES (
            '019f0000-0000-7000-8000-00000000231a', 1,
            '019f0000-0000-7000-8000-00000000231b',
            '019f0000-0000-7000-8000-00000000231c',
            '019f0000-0000-7000-8000-000000002308', '8.8.4.4', 60,
            convert_to('{}', 'UTF8'),
            sentinelflow.validation_sha256(convert_to('{}', 'UTF8')),
            convert_to('{"different":true}', 'UTF8'),
            sentinelflow.validation_sha256(convert_to('{"different":true}', 'UTF8')),
            convert_to('{}', 'UTF8'),
            sentinelflow.validation_sha256(convert_to('{}', 'UTF8')),
            convert_to('x', 'UTF8'),
            sentinelflow.validation_sha256(convert_to('x', 'UTF8')),
            convert_to('x' || chr(10), 'UTF8'),
            sentinelflow.validation_sha256(convert_to('x' || chr(10), 'UTF8')),
            context.as_of, context.as_of + interval '5 minutes', context.as_of
        );
        RAISE EXCEPTION 'mismatched retained HIL evidence was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$negative_source_binding$;

-- Privilege inherited through either side of a role membership must never
-- become an alternate path into the SECURITY DEFINER retention coordinator.
RESET ROLE;
CREATE ROLE sentinelflow_retention_downstream INHERIT NOLOGIN;
GRANT sentinelflow_retention TO sentinelflow_retention_downstream;
DO $transitive_contract$
BEGIN
    IF NOT has_function_privilege(
        'sentinelflow_retention_downstream',
        'sentinelflow.run_retention_000023(uuid,timestamptz,integer)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'test role did not inherit retention EXECUTE';
    END IF;
END
$transitive_contract$;
SET SESSION AUTHORIZATION sentinelflow_retention_downstream;
DO $transitive_rejected$
BEGIN
    BEGIN
        PERFORM * FROM sentinelflow.run_retention_000023(
            '019f0000-0000-7000-8000-0000000023d0', clock_timestamp(), 1
        );
        RAISE EXCEPTION 'transitive retention caller was accepted';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$transitive_rejected$;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION sentinelflow_retention;
DO $membership_guard_rejected$
BEGIN
    BEGIN
        PERFORM * FROM sentinelflow.run_retention_000023(
            '019f0000-0000-7000-8000-0000000023d1', clock_timestamp(), 1
        );
        RAISE EXCEPTION 'retention caller with downstream membership was accepted';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$membership_guard_rejected$;
RESET SESSION AUTHORIZATION;
REVOKE sentinelflow_retention FROM sentinelflow_retention_downstream;
GRANT sentinelflow_retention_downstream TO sentinelflow_retention;
SET SESSION AUTHORIZATION sentinelflow_retention;
DO $upstream_membership_guard_rejected$
BEGIN
    BEGIN
        PERFORM * FROM sentinelflow.run_retention_000023(
            '019f0000-0000-7000-8000-0000000023d2', clock_timestamp(), 1
        );
        RAISE EXCEPTION 'retention caller with upstream membership was accepted';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$upstream_membership_guard_rejected$;
RESET SESSION AUTHORIZATION;
REVOKE sentinelflow_retention_downstream FROM sentinelflow_retention;
DROP ROLE sentinelflow_retention_downstream;

SET SESSION AUTHORIZATION sentinelflow_retention;

DO $least_privilege$
BEGIN
    BEGIN
        DELETE FROM sentinelflow.gateway_events;
        RAISE EXCEPTION 'retention role received direct event DELETE';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$least_privilege$;

DO $run$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
    result record;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    SELECT * INTO result
    FROM sentinelflow.run_retention_000023(
        '019f0000-0000-7000-8000-0000000023f0', context.as_of, 1000
    );
    IF result.replayed OR result.outcome <> 'succeeded' OR
       result.failure_code <> '' OR result.anomaly_count <> 0 OR
       result.event_evidence_deleted < 5 OR
       result.control_plane_deleted < 1 OR result.transient_deleted < 2 OR
       result.audit_deleted < 1 OR result.run_digest IS NULL OR
       result.event_evidence_deleted + result.control_plane_deleted +
       result.transient_deleted + result.audit_deleted > 1000 THEN
        RAISE EXCEPTION 'retention result counts are incomplete: %', row_to_json(result);
    END IF;
    SELECT * INTO result
    FROM sentinelflow.run_retention_000023(
        '019f0000-0000-7000-8000-0000000023f0', context.as_of, 1000
    );
    IF NOT result.replayed THEN
        RAISE EXCEPTION 'exact retention replay was not idempotent';
    END IF;
    BEGIN
        PERFORM * FROM sentinelflow.run_retention_000023(
            '019f0000-0000-7000-8000-0000000023f0', context.as_of, 999
        );
        RAISE EXCEPTION 'retention replay accepted parameter drift';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
    BEGIN
        PERFORM * FROM sentinelflow.run_retention_000023(
            '019f0000-0000-7000-8000-0000000023ef',
            context.as_of - interval '1 day', 1000
        );
        RAISE EXCEPTION 'new retention run accepted a stale as-of';
    EXCEPTION WHEN invalid_parameter_value THEN
        NULL;
    END;
END
$run$;

RESET SESSION AUTHORIZATION;
SET LOCAL ROLE sentinelflow_migration;

DO $postconditions$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
    retained_bytes bytea;
    retained_digest sentinelflow.sha256_digest;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    IF EXISTS (SELECT 1 FROM sentinelflow.gateway_events
               WHERE event_id = '019f0000-0000-7000-8000-000000002302') OR
       EXISTS (SELECT 1 FROM sentinelflow.signals
               WHERE signal_id = '019f0000-0000-7000-8000-000000002305') OR
       EXISTS (SELECT 1 FROM sentinelflow.ingest_batches
               WHERE batch_id = '019f0000-0000-7000-8000-000000002301') OR
       EXISTS (SELECT 1 FROM sentinelflow.ingest_sequence_gap_resolutions
               WHERE resolution_id = '019f0000-0000-7000-8000-000000002311') OR
       EXISTS (SELECT 1 FROM sentinelflow.ingest_gap_lifecycle
               WHERE sender_id = 'retention-test'
                 AND sender_epoch = 'AAAAAAAAAAAAAAAAAAAAAA'
                 AND sequence_start = 2 AND sequence_end = 2) OR
       EXISTS (SELECT 1 FROM sentinelflow.evidence_snapshots
               WHERE evidence_snapshot_id = '019f0000-0000-7000-8000-000000002308') OR
       EXISTS (SELECT 1 FROM sentinelflow.evidence_snapshot_artifacts
               WHERE evidence_snapshot_id = '019f0000-0000-7000-8000-000000002308') THEN
        RAISE EXCEPTION 'seven-day normalized evidence was retained';
    END IF;
    IF EXISTS (SELECT 1 FROM sentinelflow.incidents
               WHERE incident_id = '019f0000-0000-7000-8000-000000002320') OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.incidents
                   WHERE incident_id = '019f0000-0000-7000-8000-000000002307') OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.incidents
                   WHERE incident_id = '019f0000-0000-7000-8000-000000002321'
                     AND state = 'open') OR
       (SELECT count(*) FROM sentinelflow.incidents
        WHERE incident_id IN (
            '019f0000-0000-7000-8000-000000002322',
            '019f0000-0000-7000-8000-000000002323',
            '019f0000-0000-7000-8000-000000002324'
        )) <> 3 OR
       (SELECT count(*) FROM sentinelflow.outbox_jobs
        WHERE job_id IN (
            '019f0000-0000-7000-8000-000000002330',
            '019f0000-0000-7000-8000-000000002331',
            '019f0000-0000-7000-8000-000000002332'
        ) AND state IN ('pending', 'leased', 'retry')) <> 3 THEN
        RAISE EXCEPTION 'thirty-day incident retention boundary is wrong';
    END IF;
    SELECT evidence_bytes, evidence_digest
    INTO retained_bytes, retained_digest
    FROM sentinelflow.hil_exact_artifacts
    WHERE policy_id = '019f0000-0000-7000-8000-00000000230b'
      AND policy_version = 1;
    IF NOT FOUND OR retained_bytes <> context.evidence_bytes OR
       retained_digest <> context.evidence_digest THEN
        RAISE EXCEPTION 'retained HIL evidence copy drifted or disappeared';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.ai_analyses
        WHERE analysis_id = '019f0000-0000-7000-8000-000000002309'
          AND evidence_snapshot_id IS NULL
          AND evidence_snapshot_digest = context.evidence_digest
          AND provider_kind = 'deterministic_stub'
          AND adapter_id = 'sentinelflow-deterministic-ai-stub-v1'
          AND model IS NULL AND reasoning_effort IS NULL
          AND rate_card_version IS NULL
    ) THEN
        RAISE EXCEPTION 'analysis retention tombstone changed provenance';
    END IF;
    IF EXISTS (SELECT 1 FROM sentinelflow.admin_sessions
               WHERE session_id = '019f0000-0000-7000-8000-00000000230d') OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.decision_challenges
                   WHERE challenge_id = '019f0000-0000-7000-8000-00000000230e'
                     AND session_digest =
                       'sha256:2020202020202020202020202020202020202020202020202020202020202020') THEN
        RAISE EXCEPTION 'expired session cleanup lost challenge digest history';
    END IF;
    IF EXISTS (SELECT 1 FROM sentinelflow.audit_events
               WHERE event_id = '019f0000-0000-7000-8000-00000000230f') OR
       (SELECT count(*) FROM sentinelflow.audit_events
        WHERE action = 'retention_run_completed'
          AND object_id = '019f0000-0000-7000-8000-0000000023f0') <> 1 OR
       (SELECT count(*) FROM sentinelflow.retention_runs
        WHERE run_id = '019f0000-0000-7000-8000-0000000023f0') <> 1 THEN
        RAISE EXCEPTION 'ninety-day audit pruning or run audit is wrong';
    END IF;
    BEGIN
        UPDATE sentinelflow.ai_analyses
        SET failure_reason = 'cancelled'
        WHERE analysis_id = '019f0000-0000-7000-8000-000000002309';
        RAISE EXCEPTION 'retained analysis became mutable';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
    BEGIN
        UPDATE sentinelflow.hil_exact_artifacts
        SET evidence_bytes = evidence_bytes
        WHERE policy_id = '019f0000-0000-7000-8000-00000000230b';
        RAISE EXCEPTION 'retained HIL evidence became mutable';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END
$postconditions$;

-- p_max_rows is one global delete budget, not a per-statement or per-relation
-- limit. Three independently eligible rows must require three bounded runs.
DO $global_cap_fixture$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    INSERT INTO sentinelflow.ingest_replay_nonces (
        sender_id, endpoint_kind, endpoint_path, nonce_digest,
        authenticated_at, expires_at
    ) VALUES
    (
        'retention-cap', 'gateway', '/internal/v1/gateway-events',
        'sha256:3434343434343434343434343434343434343434343434343434343434343434',
        context.as_of - interval '1 day',
        context.as_of - interval '1 day' + interval '5 minutes'
    ),
    (
        'retention-cap', 'gateway', '/internal/v1/gateway-events',
        'sha256:3535353535353535353535353535353535353535353535353535353535353535',
        context.as_of - interval '1 day',
        context.as_of - interval '1 day' + interval '5 minutes'
    ),
    (
        'retention-cap', 'gateway', '/internal/v1/gateway-events',
        'sha256:3636363636363636363636363636363636363636363636363636363636363636',
        context.as_of - interval '1 day',
        context.as_of - interval '1 day' + interval '5 minutes'
    );
    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        primary_digest, outcome, occurred_at, recorded_at
    ) VALUES (
        '019f0000-0000-7000-8000-0000000023c0', 'system', 'retention-test',
        'synthetic_cap_event', 'retention_fixture',
        '019f0000-0000-7000-8000-0000000023c0',
        'sha256:3939393939393939393939393939393939393939393939393939393939393939',
        'succeeded', context.as_of - interval '91 days',
        context.as_of - interval '91 days'
    );
END
$global_cap_fixture$;
RESET ROLE;
SET SESSION AUTHORIZATION sentinelflow_retention;
DO $global_cap_run$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
    result record;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    SELECT * INTO result
    FROM sentinelflow.run_retention_000023(
        '019f0000-0000-7000-8000-0000000023f2', context.as_of, 1
    );
    IF result.outcome <> 'succeeded' OR
       result.event_evidence_deleted + result.control_plane_deleted +
       result.transient_deleted + result.audit_deleted <> 1 THEN
        RAISE EXCEPTION 'global retention cap was not enforced: %', row_to_json(result);
    END IF;
END
$global_cap_run$;
RESET SESSION AUTHORIZATION;
SET LOCAL ROLE sentinelflow_migration;
DO $global_cap_postcondition$
BEGIN
    IF (SELECT count(*) FROM sentinelflow.ingest_replay_nonces
        WHERE sender_id = 'retention-cap') <> 2 OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.audit_events
                   WHERE event_id = '019f0000-0000-7000-8000-0000000023c0') THEN
        RAISE EXCEPTION 'global retention cap removed more than one row';
    END IF;
END
$global_cap_postcondition$;

-- Stale live authority creates a committed, digest-only failed run. It never
-- terminalizes the authority and never consumes the deletion budget.
DO $stale_live_fixture$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
    control_old timestamptz;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    control_old := context.as_of - interval '31 days';
    INSERT INTO sentinelflow.incidents (
        incident_id, kind, state, source_ip, service_label, first_seen,
        last_seen, closed_at, reopen_until, deterministic_score, version,
        created_at, updated_at, evidence_version
    ) VALUES
    (
        '019f0000-0000-7000-8000-0000000023a0', 'path_scan', 'open',
        '8.8.4.4', 'gateway', control_old, control_old,
        NULL, NULL, 0.5, 1, control_old, control_old, 1
    ),
    (
        '019f0000-0000-7000-8000-0000000023a1', 'path_scan', 'closed',
        '8.8.4.5', 'gateway', control_old, control_old,
        control_old, control_old + interval '30 minutes',
        0.5, 1, control_old, control_old, 1
    );
    INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        idempotency_key, state, available_at, attempts, created_at, updated_at
    ) VALUES (
        '019f0000-0000-7000-8000-0000000023a2', 'analyze', 'incident',
        '019f0000-0000-7000-8000-0000000023a1', 1,
        'sha256:3737373737373737373737373737373737373737373737373737373737373737',
        'pending', control_old, 0, control_old, control_old
    );
    INSERT INTO sentinelflow.ingest_replay_nonces (
        sender_id, endpoint_kind, endpoint_path, nonce_digest,
        authenticated_at, expires_at
    ) VALUES (
        'retention-stale', 'gateway', '/internal/v1/gateway-events',
        'sha256:3838383838383838383838383838383838383838383838383838383838383838',
        context.as_of - interval '1 day',
        context.as_of - interval '1 day' + interval '5 minutes'
    );
END
$stale_live_fixture$;
RESET ROLE;
SET SESSION AUTHORIZATION sentinelflow_retention;
DO $stale_live_run$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
    result record;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    SELECT * INTO result
    FROM sentinelflow.run_retention_000023(
        '019f0000-0000-7000-8000-0000000023f3', context.as_of, 1000
    );
    IF result.replayed OR result.outcome <> 'failed' OR
       result.failure_code <> 'stale_live_state' OR result.anomaly_count < 2 OR
       result.event_evidence_deleted <> 0 OR result.control_plane_deleted <> 0 OR
       result.transient_deleted <> 0 OR result.audit_deleted <> 0 THEN
        RAISE EXCEPTION 'stale live failure was unsafe: %', row_to_json(result);
    END IF;
    SELECT * INTO result
    FROM sentinelflow.run_retention_000023(
        '019f0000-0000-7000-8000-0000000023f3', context.as_of, 1000
    );
    IF NOT result.replayed OR result.outcome <> 'failed' OR
       result.failure_code <> 'stale_live_state' THEN
        RAISE EXCEPTION 'stale live failed replay drifted';
    END IF;
END
$stale_live_run$;
RESET SESSION AUTHORIZATION;
SET LOCAL ROLE sentinelflow_migration;
DO $stale_live_postcondition$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sentinelflow.incidents
                   WHERE incident_id = '019f0000-0000-7000-8000-0000000023a0'
                     AND state = 'open') OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.incidents
                   WHERE incident_id = '019f0000-0000-7000-8000-0000000023a1'
                     AND state = 'closed') OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.outbox_jobs
                   WHERE job_id = '019f0000-0000-7000-8000-0000000023a2'
                     AND state = 'pending') OR
       NOT EXISTS (SELECT 1 FROM sentinelflow.ingest_replay_nonces
                   WHERE sender_id = 'retention-stale') OR
       (SELECT count(*) FROM sentinelflow.audit_events audit
        JOIN sentinelflow.retention_runs run
          ON run.run_id = audit.object_id AND run.run_digest = audit.primary_digest
        WHERE audit.action = 'retention_run_failed'
          AND audit.object_id = '019f0000-0000-7000-8000-0000000023f3'
          AND audit.outcome = 'failed' AND run.outcome = 'failed'
          AND run.failure_code = 'stale_live_state'
          AND run.event_evidence_deleted = 0
          AND run.control_plane_deleted = 0
          AND run.transient_deleted = 0 AND run.audit_deleted = 0) <> 1 THEN
        RAISE EXCEPTION 'stale live failure mutated authority or lost audit evidence';
    END IF;
END
$stale_live_postcondition$;
DELETE FROM sentinelflow.outbox_jobs
WHERE job_id = '019f0000-0000-7000-8000-0000000023a2';
DELETE FROM sentinelflow.incidents
WHERE incident_id IN (
    '019f0000-0000-7000-8000-0000000023a0',
    '019f0000-0000-7000-8000-0000000023a1'
);
DELETE FROM sentinelflow.ingest_replay_nonces
WHERE sender_id IN ('retention-cap', 'retention-stale');

-- An unresolved old sequence gap blocks the complete transaction before any
-- otherwise eligible row is removed or a run summary is written.
DO $fail_closed_fixture$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    INSERT INTO sentinelflow.ingest_batches (
        sender_id, sender_epoch, batch_id, sequence, endpoint_kind,
        schema_version, raw_body_digest, raw_body_size, record_count,
        sent_at, received_at
    ) VALUES (
        'retention-gap', 'BBBBBBBBBBBBBBBBBBBBBB',
        '019f0000-0000-7000-8000-0000000023e1', 2, 'gateway',
        'event-batch-v1',
        'sha256:2626262626262626262626262626262626262626262626262626262626262626',
        100, 1, context.as_of - interval '8 days',
        context.as_of - interval '8 days'
    );
    INSERT INTO sentinelflow.ingest_sequence_gaps (
        gap_id, sender_id, endpoint_kind, sender_epoch, sequence_start,
        sequence_end, detected_by_batch_id, detected_at
    ) VALUES (
        '019f0000-0000-7000-8000-0000000023e2', 'retention-gap',
        'gateway', 'BBBBBBBBBBBBBBBBBBBBBB', 1, 1,
        '019f0000-0000-7000-8000-0000000023e1',
        context.as_of - interval '8 days'
    );
END
$fail_closed_fixture$;
RESET ROLE;
SET SESSION AUTHORIZATION sentinelflow_retention;
DO $fail_closed_run$
DECLARE
    context pg_temp.retention_test_context%ROWTYPE;
BEGIN
    SELECT * INTO context FROM pg_temp.retention_test_context;
    BEGIN
        PERFORM * FROM sentinelflow.run_retention_000023(
            '019f0000-0000-7000-8000-0000000023f1', context.as_of, 1000
        );
        RAISE EXCEPTION 'ambiguous source history did not block retention';
    EXCEPTION WHEN SQLSTATE 'SF302' THEN
        NULL;
    END;
END
$fail_closed_run$;
RESET SESSION AUTHORIZATION;
SET LOCAL ROLE sentinelflow_migration;
DO $fail_closed_postcondition$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.ingest_batches
        WHERE batch_id = '019f0000-0000-7000-8000-0000000023e1'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.retention_runs
        WHERE run_id = '019f0000-0000-7000-8000-0000000023f1'
    ) THEN
        RAISE EXCEPTION 'failed retention run was not atomic';
    END IF;
END
$fail_closed_postcondition$;

ROLLBACK;
