BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $role_and_privileges$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles role
        WHERE role.rolname = 'sentinelflow_metrics'
          AND NOT role.rolinherit AND NOT role.rolsuper AND NOT role.rolcreatedb
          AND NOT role.rolcreaterole AND NOT role.rolreplication
          AND NOT role.rolbypassrls
    ) OR EXISTS (
        SELECT 1 FROM pg_auth_members membership
        JOIN pg_roles member ON member.oid = membership.member
        JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
        WHERE member.rolname = 'sentinelflow_metrics'
           OR granted_role.rolname = 'sentinelflow_metrics'
    ) OR NOT has_function_privilege(
        'sentinelflow_metrics',
        'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_metrics',
        'sentinelflow.control_observability_utc_date_000024(timestamptz)', 'EXECUTE'
    ) OR EXISTS (
        SELECT 1 FROM information_schema.role_table_grants privilege
        WHERE privilege.grantee = 'sentinelflow_metrics'
    ) OR EXISTS (
        SELECT 1
        FROM pg_proc function
        CROSS JOIN LATERAL aclexplode(
            COALESCE(function.proacl, acldefault('f', function.proowner))
        ) privilege
        WHERE function.oid = 'sentinelflow.control_observability_samples_000028()'::regprocedure
          AND privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_read',
        'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_dispatcher',
        'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_retention',
        'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.register_sse_client_lease_000024(uuid,text)', 'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.touch_sse_client_lease_000024(uuid,text)', 'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.unregister_sse_client_lease_000024(uuid,text)', 'EXECUTE'
    ) OR EXISTS (
        SELECT 1 FROM pg_proc function
        JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
        WHERE namespace.nspname = 'sentinelflow'
          AND function.oid <>
              'sentinelflow.control_observability_samples_000028()'::regprocedure
          AND has_function_privilege(
              'sentinelflow_metrics', function.oid, 'EXECUTE'
          )
    ) OR EXISTS (
        SELECT 1
        FROM pg_proc function
        JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(function.proacl, acldefault('f', function.proowner))
        ) privilege
        WHERE namespace.nspname = 'sentinelflow'
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
    ) OR EXISTS (
        SELECT 1 FROM information_schema.role_table_grants privilege
        WHERE privilege.grantee = 'sentinelflow_api'
          AND privilege.table_schema = 'sentinelflow'
          AND privilege.table_name = 'sse_client_leases'
    ) THEN
        RAISE EXCEPTION 'control metrics role or aggregate privilege boundary is incorrect';
    END IF;
END
$role_and_privileges$;

DO $utc_and_clock_contract$
BEGIN
    PERFORM set_config('TimeZone', 'Pacific/Kiritimati', true);
    IF sentinelflow.control_observability_utc_date_000024(
        '2026-01-01 00:30:00+00'::timestamptz
    ) <> DATE '2026-01-01' THEN
        RAISE EXCEPTION 'UTC budget date drifted at the positive-offset day boundary';
    END IF;
    PERFORM set_config('TimeZone', 'America/Los_Angeles', true);
    IF sentinelflow.control_observability_utc_date_000024(
        '2026-01-01 23:30:00+00'::timestamptz
    ) <> DATE '2026-01-01' THEN
        RAISE EXCEPTION 'UTC budget date drifted at the negative-offset day boundary';
    END IF;
    IF pg_get_functiondef(
        'sentinelflow.control_observability_samples_000028()'::regprocedure
    ) NOT LIKE '%statement_timestamp()%' OR pg_get_functiondef(
        'sentinelflow.control_observability_samples_000028()'::regprocedure
    ) LIKE '%clock_timestamp()%' THEN
        RAISE EXCEPTION 'one-scrape observability cutoff is not statement-stable';
    END IF;
END
$utc_and_clock_contract$;

SET LOCAL ROLE sentinelflow_migration;

CREATE FUNCTION sentinelflow.observability_default_privilege_probe_000024()
RETURNS integer
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS 'SELECT 1';

DO $global_function_default_privilege$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_proc function
        CROSS JOIN LATERAL aclexplode(
            COALESCE(function.proacl, acldefault('f', function.proowner))
        ) privilege
        WHERE function.oid =
              'sentinelflow.observability_default_privilege_probe_000024()'::regprocedure
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'global default PUBLIC function EXECUTE was not revoked';
    END IF;
END
$global_function_default_privilege$;

DROP FUNCTION sentinelflow.observability_default_privilege_probe_000024();

INSERT INTO sentinelflow.expected_source_bindings (
    binding_id, sender_id, endpoint_kind, endpoint_path, service_label,
    key_id, config_digest, binding_digest, effective_at
) VALUES (
    '019f0000-0000-7000-8000-000000002420', 'metrics.gap', 'gateway',
    '/internal/v1/gateway-events', 'metrics-service', 'metrics-key',
    'sha256:2400000000000000000000000000000000000000000000000000000000000001',
    'sha256:2400000000000000000000000000000000000000000000000000000000000002',
    statement_timestamp() - interval '1 minute'
);

-- Expected-source health is current-state evidence, not historical evidence.
-- Exercise stale trusted coverage, a newer untrusted report, trusted recovery,
-- epoch rotation, and retirement before leaving only metrics.gap active for
-- the final aggregate/cardinality assertions below.
INSERT INTO sentinelflow.expected_source_bindings (
    binding_id, sender_id, endpoint_kind, endpoint_path, service_label,
    key_id, config_digest, binding_digest, effective_at
) VALUES (
    '019f0000-0000-7000-8000-000000002430', 'metrics.coverage', 'gateway',
    '/internal/v1/gateway-events', 'metrics-service', 'metrics-key',
    'sha256:2400000000000000000000000000000000000000000000000000000000000030',
    'sha256:2400000000000000000000000000000000000000000000000000000000000031',
    statement_timestamp() - interval '10 minutes'
);

INSERT INTO sentinelflow.sender_checkpoints (
    sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
    last_acknowledged_body_digest, updated_at
) VALUES (
    'metrics.coverage', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA', 0,
    NULL, statement_timestamp() - interval '7 minutes'
);

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'metrics.coverage', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f0000-0000-7000-8000-000000002431', 1, 'gateway', 'event-batch-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000032',
    128, 1, statement_timestamp() - interval '6 minutes',
    statement_timestamp() - interval '6 minutes', 'metrics-key'
);

UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:2400000000000000000000000000000000000000000000000000000000000032',
    updated_at = statement_timestamp() - interval '6 minutes'
WHERE sender_id = 'metrics.coverage' AND endpoint_kind = 'gateway';

INSERT INTO sentinelflow.source_coverage_attestations (
    coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
    sender_epoch, segment_id, previous_coverage_digest, coverage_start,
    coverage_end, covered_through_batch_id, covered_through_sequence,
    coverage_digest, binding_id, raw_body_digest, received_at, trust_state,
    trust_reason
) VALUES (
    '019f0000-0000-7000-8000-000000002432', 'source-coverage-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000033',
    'metrics.coverage', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f0000-0000-7000-8000-000000002433', NULL,
    date_trunc('milliseconds', statement_timestamp() - interval '7 minutes'),
    date_trunc('milliseconds', statement_timestamp() - interval '6 minutes'),
    '019f0000-0000-7000-8000-000000002431', 1,
    'sha256:2400000000000000000000000000000000000000000000000000000000000034',
    '019f0000-0000-7000-8000-000000002430',
    'sha256:2400000000000000000000000000000000000000000000000000000000000032',
    statement_timestamp() - interval '6 minutes', 'trusted', 'none'
);

DO $old_trusted_is_not_current$
DECLARE missing double precision; healthy double precision; stale double precision;
BEGIN
    SELECT sample_value INTO missing FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
    SELECT sample_value INTO healthy FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'healthy';
    SELECT sample_value INTO stale FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'checkpoint_stale';
    IF missing <> 2 OR healthy <> 0 OR stale <> 2 THEN
        RAISE EXCEPTION 'old trusted source coverage incorrectly remained healthy';
    END IF;
END
$old_trusted_is_not_current$;

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'metrics.coverage', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f0000-0000-7000-8000-000000002434', 2, 'gateway', 'event-batch-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000035',
    128, 1, statement_timestamp() - interval '4 minutes',
    statement_timestamp() - interval '4 minutes', 'metrics-key'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 2,
    last_acknowledged_body_digest =
        'sha256:2400000000000000000000000000000000000000000000000000000000000035',
    updated_at = statement_timestamp() - interval '4 minutes'
WHERE sender_id = 'metrics.coverage' AND endpoint_kind = 'gateway';
INSERT INTO sentinelflow.source_coverage_attestations (
    coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
    sender_epoch, segment_id, previous_coverage_digest, coverage_start,
    coverage_end, covered_through_batch_id, covered_through_sequence,
    coverage_digest, binding_id, raw_body_digest, received_at, trust_state,
    trust_reason
) VALUES (
    '019f0000-0000-7000-8000-000000002435', 'source-coverage-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000036',
    'metrics.coverage', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f0000-0000-7000-8000-000000002437',
    'sha256:2400000000000000000000000000000000000000000000000000000000000034',
    date_trunc('milliseconds', statement_timestamp() - interval '6 minutes'),
    date_trunc('milliseconds', statement_timestamp() - interval '4 minutes'),
    '019f0000-0000-7000-8000-000000002434', 2,
    'sha256:2400000000000000000000000000000000000000000000000000000000000037',
    '019f0000-0000-7000-8000-000000002430',
    'sha256:2400000000000000000000000000000000000000000000000000000000000035',
    statement_timestamp() - interval '4 minutes', 'untrusted', 'timestamp_skew'
);

DO $new_untrusted_masks_old_trusted$
DECLARE missing double precision; healthy double precision; stale double precision;
BEGIN
    SELECT sample_value INTO missing FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
    SELECT sample_value INTO healthy FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'healthy';
    SELECT sample_value INTO stale FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'checkpoint_stale';
    IF missing <> 2 OR healthy <> 0 OR stale <> 1 THEN
        RAISE EXCEPTION 'new untrusted source coverage failed closed incorrectly';
    END IF;
END
$new_untrusted_masks_old_trusted$;

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'metrics.coverage', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f0000-0000-7000-8000-000000002438', 3, 'gateway', 'event-batch-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000038',
    128, 1, statement_timestamp() - interval '1 minute',
    statement_timestamp() - interval '1 minute', 'metrics-key'
);
UPDATE sentinelflow.sender_checkpoints
SET last_acknowledged_sequence = 3,
    last_acknowledged_body_digest =
        'sha256:2400000000000000000000000000000000000000000000000000000000000038',
    updated_at = statement_timestamp() - interval '1 minute'
WHERE sender_id = 'metrics.coverage' AND endpoint_kind = 'gateway';
INSERT INTO sentinelflow.source_coverage_attestations (
    coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
    sender_epoch, segment_id, previous_coverage_digest, coverage_start,
    coverage_end, covered_through_batch_id, covered_through_sequence,
    coverage_digest, binding_id, raw_body_digest, received_at, trust_state,
    trust_reason
) VALUES (
    '019f0000-0000-7000-8000-000000002439', 'source-coverage-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000039',
    'metrics.coverage', 'gateway', 'AAAAAAAAAAAAAAAAAAAAAA',
    '019f0000-0000-7000-8000-000000002440',
    'sha256:2400000000000000000000000000000000000000000000000000000000000037',
    date_trunc('milliseconds', statement_timestamp() - interval '4 minutes'),
    date_trunc('milliseconds', statement_timestamp() - interval '1 minute'),
    '019f0000-0000-7000-8000-000000002438', 3,
    'sha256:2400000000000000000000000000000000000000000000000000000000000040',
    '019f0000-0000-7000-8000-000000002430',
    'sha256:2400000000000000000000000000000000000000000000000000000000000038',
    statement_timestamp() - interval '1 minute', 'trusted', 'none'
);

DO $trusted_current_sequence_recovers$
DECLARE missing double precision; healthy double precision;
BEGIN
    SELECT sample_value INTO missing FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
    SELECT sample_value INTO healthy FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'healthy';
    IF missing <> 1 OR healthy <> 1 THEN
        RAISE EXCEPTION 'trusted exact current source coverage did not recover';
    END IF;
END
$trusted_current_sequence_recovers$;

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at, auth_key_id
) VALUES (
    'metrics.coverage', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019f0000-0000-7000-8000-000000002441', 1, 'gateway', 'event-batch-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000041',
    128, 1, statement_timestamp() - interval '30 seconds',
    statement_timestamp() - interval '30 seconds', 'metrics-key'
);
UPDATE sentinelflow.sender_checkpoints
SET sender_epoch = 'BBBBBBBBBBBBBBBBBBBBBB', last_acknowledged_sequence = 1,
    last_acknowledged_body_digest =
        'sha256:2400000000000000000000000000000000000000000000000000000000000041',
    updated_at = statement_timestamp() - interval '30 seconds'
WHERE sender_id = 'metrics.coverage' AND endpoint_kind = 'gateway';

DO $epoch_rotation_requires_current_attestation$
DECLARE missing double precision; healthy double precision;
BEGIN
    SELECT sample_value INTO missing FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
    SELECT sample_value INTO healthy FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'healthy';
    IF missing <> 2 OR healthy <> 0 THEN
        RAISE EXCEPTION 'old epoch coverage survived checkpoint epoch rotation';
    END IF;
END
$epoch_rotation_requires_current_attestation$;

INSERT INTO sentinelflow.source_coverage_attestations (
    coverage_event_id, schema_version, idempotency_key, sender_id, endpoint_kind,
    sender_epoch, segment_id, previous_coverage_digest, coverage_start,
    coverage_end, covered_through_batch_id, covered_through_sequence,
    coverage_digest, binding_id, raw_body_digest, received_at, trust_state,
    trust_reason
) VALUES (
    '019f0000-0000-7000-8000-000000002442', 'source-coverage-v1',
    'sha256:2400000000000000000000000000000000000000000000000000000000000042',
    'metrics.coverage', 'gateway', 'BBBBBBBBBBBBBBBBBBBBBB',
    '019f0000-0000-7000-8000-000000002443', NULL,
    date_trunc('milliseconds', statement_timestamp() - interval '1 minute'),
    date_trunc('milliseconds', statement_timestamp() - interval '30 seconds'),
    '019f0000-0000-7000-8000-000000002441', 1,
    'sha256:2400000000000000000000000000000000000000000000000000000000000043',
    '019f0000-0000-7000-8000-000000002430',
    'sha256:2400000000000000000000000000000000000000000000000000000000000041',
    statement_timestamp() - interval '30 seconds', 'trusted', 'none'
);

DO $new_epoch_recovers_then_retirement_removes$
DECLARE missing double precision; healthy double precision;
BEGIN
    SELECT sample_value INTO missing FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
    SELECT sample_value INTO healthy FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'healthy';
    IF missing <> 1 OR healthy <> 1 THEN
        RAISE EXCEPTION 'new epoch trusted source coverage did not recover';
    END IF;
END
$new_epoch_recovers_then_retirement_removes$;

INSERT INTO sentinelflow.expected_source_binding_retirements (
    retirement_id, binding_id, reason_digest, retired_at
) VALUES (
    '019f0000-0000-7000-8000-000000002444',
    '019f0000-0000-7000-8000-000000002430',
    'sha256:2400000000000000000000000000000000000000000000000000000000000044',
    statement_timestamp()
);

DO $retired_binding_is_not_expected$
DECLARE missing double precision; healthy double precision;
BEGIN
    SELECT sample_value INTO missing FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
    SELECT sample_value INTO healthy FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_expected_sources'
      AND label_1_value = 'gateway' AND label_2_value = 'healthy';
    IF missing <> 1 OR healthy <> 0 THEN
        RAISE EXCEPTION 'retired source binding remained expected';
    END IF;
END
$retired_binding_is_not_expected$;

INSERT INTO sentinelflow.ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES
    ('metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002421', 1, 'gateway', 'event-batch-v1',
     'sha256:2400000000000000000000000000000000000000000000000000000000000011',
     128, 1, statement_timestamp() - interval '4 minutes',
     statement_timestamp() - interval '4 minutes'),
    ('metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002422', 2, 'gateway', 'event-batch-v1',
     'sha256:2400000000000000000000000000000000000000000000000000000000000012',
     128, 1, statement_timestamp() - interval '3 minutes',
     statement_timestamp() - interval '3 minutes'),
    ('metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002423', 3, 'gateway', 'event-batch-v1',
     'sha256:2400000000000000000000000000000000000000000000000000000000000013',
     128, 1, statement_timestamp() - interval '2 minutes',
     statement_timestamp() - interval '2 minutes'),
    ('metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002424', 4, 'gateway', 'event-batch-v1',
     'sha256:2400000000000000000000000000000000000000000000000000000000000014',
     128, 1, statement_timestamp() - interval '2 minutes',
     statement_timestamp() - interval '2 minutes');

INSERT INTO sentinelflow.source_health_intervals (
    event_id, schema_version, sender_id, sender_epoch, batch_id,
    idempotency_key, occurred_at, source_id, cause, state,
    affected_sender_epoch, sequence_start, sequence_end, interval_start,
    interval_end, dropped_count, detail_code, received_at, trust_state,
    trust_reason
) VALUES
    ('019f0000-0000-7000-8000-000000002425', 'source-health-v1',
     'metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002421',
     'sha256:2400000000000000000000000000000000000000000000000000000000000021',
     statement_timestamp() - interval '4 minutes', 'metrics.health',
     'queue_overflow', 'degraded', 'AAAAAAAAAAAAAAAAAAAAAA', 1, 1,
     statement_timestamp() - interval '5 minutes',
     statement_timestamp() - interval '4 minutes', 1, 'known_range',
     statement_timestamp() - interval '4 minutes', 'trusted', 'none'),
    ('019f0000-0000-7000-8000-000000002426', 'source-health-v1',
     'metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002422',
     'sha256:2400000000000000000000000000000000000000000000000000000000000022',
     statement_timestamp() - interval '1 minute', 'metrics.health',
     'recovered', 'recovered', 'AAAAAAAAAAAAAAAAAAAAAA', NULL, NULL,
     NULL, NULL, 0, 'delivery_restored',
     statement_timestamp() - interval '1 minute', 'untrusted', 'timestamp_skew'),
    -- Same trusted timestamps deliberately place the lexically larger UUID on
    -- recovered. Risk ordering must still retain lost without UUID tie-breaking.
    ('019f0000-0000-7000-8000-000000002429', 'source-health-v1',
     'metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002423',
     'sha256:2400000000000000000000000000000000000000000000000000000000000023',
     statement_timestamp() - interval '2 minutes', 'metrics.health',
     'recovered', 'recovered', 'AAAAAAAAAAAAAAAAAAAAAA', NULL, NULL,
     NULL, NULL, 0, 'delivery_restored',
     statement_timestamp() - interval '2 minutes', 'trusted', 'none'),
    ('019f0000-0000-7000-8000-000000002428', 'source-health-v1',
     'metrics.health', 'AAAAAAAAAAAAAAAAAAAAAA',
     '019f0000-0000-7000-8000-000000002424',
     'sha256:2400000000000000000000000000000000000000000000000000000000000024',
     statement_timestamp() - interval '2 minutes', 'metrics.health',
     'permanent_loss', 'lost', 'AAAAAAAAAAAAAAAAAAAAAA', 2, 2,
     statement_timestamp() - interval '3 minutes',
     statement_timestamp() - interval '2 minutes', 1, 'known_range',
     statement_timestamp() - interval '2 minutes', 'trusted', 'none');

SELECT set_config('sentinelflow.sse_notification_prune', '000013-prune-v1', true);
DELETE FROM sentinelflow.sse_notification_ledger;
UPDATE sentinelflow.sse_notification_replay_state
SET replay_floor = 41, watermark = 41, updated_at = statement_timestamp()
WHERE singleton;

-- Two current gap rows are retained. The second receives a terminal lifecycle
-- record while deliberately remaining in the base table, proving the metric
-- uses lifecycle state rather than blindly counting base rows.
INSERT INTO sentinelflow.ingest_sequence_gaps (
    gap_id, sender_id, endpoint_kind, sender_epoch, sequence_start,
    sequence_end, detected_by_batch_id, detected_at
) VALUES
    ('019f0000-0000-7000-8000-000000002401', 'metrics.gap', 'gateway',
     'AAAAAAAAAAAAAAAAAAAAAA', 10, 10,
     '019f0000-0000-7000-8000-000000002411', statement_timestamp()),
    ('019f0000-0000-7000-8000-000000002402', 'metrics.gap', 'gateway',
     'AAAAAAAAAAAAAAAAAAAAAA', 20, 20,
     '019f0000-0000-7000-8000-000000002412', statement_timestamp());

INSERT INTO sentinelflow.ingest_sequence_gap_resolutions (
    resolution_id, sender_id, endpoint_kind, sender_epoch, sequence_start,
    sequence_end, resolution, resolution_batch_id, resolved_at
) VALUES (
    '019f0000-0000-7000-8000-000000002403', 'metrics.gap', 'gateway',
    'AAAAAAAAAAAAAAAAAAAAAA', 20, 20, 'late_arrival',
    '019f0000-0000-7000-8000-000000002413', statement_timestamp()
);

-- A crashed process leaves no permanent client count: expired leases are
-- excluded from the aggregate and are pruned by the next registration.
INSERT INTO sentinelflow.sse_client_leases (
    lease_id, process_instance, connected_at, touched_at, expires_at
) VALUES (
    '019f0000-0000-7000-8000-000000002450', 'crashed-process',
    statement_timestamp() - interval '2 minutes',
    statement_timestamp() - interval '46 seconds',
    statement_timestamp() - interval '1 second'
);

SET LOCAL ROLE sentinelflow_api;

DO $api_lease_boundary$
DECLARE lease_expiry timestamptz; touched_expiry timestamptz;
BEGIN
    BEGIN
        PERFORM count(*) FROM sentinelflow.sse_client_leases;
        RAISE EXCEPTION 'API role unexpectedly selected raw SSE leases';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    SELECT sentinelflow.register_sse_client_lease_000024(
        '019f0000-0000-7000-8000-000000002451', 'api-process-000024'
    ) INTO lease_expiry;
    IF lease_expiry <= statement_timestamp() + interval '44 seconds' OR
       lease_expiry > statement_timestamp() + interval '46 seconds' THEN
        RAISE EXCEPTION 'SSE registration did not use bounded database time';
    END IF;
    SELECT sentinelflow.touch_sse_client_lease_000024(
        '019f0000-0000-7000-8000-000000002451', 'api-process-000024'
    ) INTO touched_expiry;
    IF touched_expiry < lease_expiry OR
       touched_expiry > statement_timestamp() + interval '46 seconds' THEN
        RAISE EXCEPTION 'SSE touch did not refresh the exact bounded lease';
    END IF;
END
$api_lease_boundary$;

SET LOCAL ROLE sentinelflow_migration;

DO $crashed_lease_pruned$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sentinelflow.sse_client_leases
        WHERE lease_id = '019f0000-0000-7000-8000-000000002450'
    ) OR (SELECT count(*) FROM sentinelflow.sse_client_leases) <> 1 THEN
        RAISE EXCEPTION 'expired SSE lease was not pruned on registration';
    END IF;
END
$crashed_lease_pruned$;

SET LOCAL ROLE sentinelflow_metrics;

DO $aggregate_contract$
DECLARE
    total_rows integer;
    distinct_rows integer;
	open_gaps double precision;
	sse_lag double precision;
	expected_missing double precision;
	expected_gap double precision;
	expected_stale double precision;
	source_lost double precision;
	source_recovered double precision;
	untrusted_health double precision;
	sse_clients double precision;
	sse_clients_observable double precision;
BEGIN
    SELECT count(*), count(DISTINCT ROW(
        metric_name, label_1_name, label_1_value, label_2_name, label_2_value
    ))
    INTO total_rows, distinct_rows
    FROM sentinelflow.control_observability_samples_000028();

	SELECT sample_value INTO open_gaps
    FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_ingest_gaps_open';

	SELECT sample_value INTO sse_lag
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_sse_watermark_lag';

	SELECT sample_value INTO expected_missing
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_expected_sources'
	  AND label_1_value = 'gateway' AND label_2_value = 'missing_report';
	SELECT sample_value INTO expected_gap
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_expected_sources'
	  AND label_1_value = 'gateway' AND label_2_value = 'open_gap';
	SELECT sample_value INTO expected_stale
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_expected_sources'
	  AND label_1_value = 'gateway' AND label_2_value = 'checkpoint_stale';

	SELECT sample_value INTO source_lost
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_sources_current'
	  AND label_1_value = 'lost';
	SELECT sample_value INTO source_recovered
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_sources_current'
	  AND label_1_value = 'recovered';
	SELECT sample_value INTO untrusted_health
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_source_health_untrusted_retained'
	  AND label_1_value = 'timestamp_skew';
	SELECT sample_value INTO sse_clients
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_sse_clients';
	SELECT sample_value INTO sse_clients_observable
	FROM sentinelflow.control_observability_samples_000028()
	WHERE metric_name = 'sentinelflow_control_sse_clients_observable';

	IF total_rows <> 362 OR distinct_rows <> total_rows OR open_gaps <> 1 OR
	   sse_lag <> 0 OR expected_missing <> 1 OR expected_gap <> 1 OR expected_stale <> 1 OR
	   source_lost <> 1 OR source_recovered <> 0 OR untrusted_health <> 1 OR
	   sse_clients <> 1 OR sse_clients_observable <> 1 THEN
        RAISE EXCEPTION 'control observability cardinality or gap lifecycle is incorrect';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.control_observability_samples_000028() sample
        WHERE sample.sample_value < 0 OR sample.sample_value = 'NaN'::double precision OR
              sample.metric_name LIKE '%_total' OR
              lower(sample.metric_name) ~ '(incident|policy|action|request|trace|source_ip|target|actor|account|digest|path)_?id' OR
              COALESCE(sample.label_1_name, '') NOT IN (
				  '', 'state', 'cause', 'purpose', 'kind', 'provider', 'gate', 'result',
				  'operation', 'decision', 'outcome', 'reason', 'endpoint',
				  'statistic'
			  ) OR
			  COALESCE(sample.label_2_name, '') NOT IN (
			      '', 'cause', 'state', 'result', 'source_health', 'classification'
			  ) OR
              (sample.label_1_name IS NULL) <> (sample.label_1_value IS NULL) OR
              (sample.label_2_name IS NULL) <> (sample.label_2_value IS NULL)
    ) THEN
        RAISE EXCEPTION 'control observability aggregate emitted unsafe or malformed data';
    END IF;
END
$aggregate_contract$;

DO $metrics_role_negative_authority$
BEGIN
    BEGIN
        PERFORM count(*) FROM sentinelflow.audit_events;
        RAISE EXCEPTION 'sentinelflow_metrics unexpectedly selected raw audit data';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        INSERT INTO sentinelflow.audit_events DEFAULT VALUES;
        RAISE EXCEPTION 'sentinelflow_metrics unexpectedly inserted audit data';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    IF has_function_privilege(
        current_user,
        'sentinelflow.run_retention_000023(uuid,timestamptz,integer)', 'EXECUTE'
    ) OR has_function_privilege(
        current_user,
        'sentinelflow.claim_dispatch_job(uuid,uuid,sentinelflow.ascii_id,timestamptz)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'sentinelflow_metrics inherited mutation function authority';
    END IF;
END
$metrics_role_negative_authority$;

SET LOCAL ROLE sentinelflow_api;

DO $unregister_and_expiry_contract$
BEGIN
    IF NOT sentinelflow.unregister_sse_client_lease_000024(
        '019f0000-0000-7000-8000-000000002451', 'api-process-000024'
    ) OR sentinelflow.unregister_sse_client_lease_000024(
        '019f0000-0000-7000-8000-000000002451', 'api-process-000024'
    ) THEN
        RAISE EXCEPTION 'SSE lease unregister is not exact and idempotent';
    END IF;
END
$unregister_and_expiry_contract$;

SET LOCAL ROLE sentinelflow_metrics;

DO $unregister_clears_metric$
DECLARE clients double precision;
BEGIN
    SELECT sample_value INTO clients
    FROM sentinelflow.control_observability_samples_000028()
    WHERE metric_name = 'sentinelflow_control_sse_clients';
    IF clients <> 0 THEN
        RAISE EXCEPTION 'unregistered SSE lease remained observable';
    END IF;
END
$unregister_clears_metric$;

SET LOCAL ROLE sentinelflow_migration;

INSERT INTO sentinelflow.sse_client_leases (
    lease_id, process_instance, connected_at, touched_at, expires_at
)
SELECT gen_random_uuid(), ('capacity-' || sequence)::sentinelflow.ascii_id,
       statement_timestamp(), statement_timestamp(),
       statement_timestamp() + interval '45 seconds'
FROM generate_series(1, 256) sequence;

SET LOCAL ROLE sentinelflow_api;

DO $lease_capacity_is_hard$
BEGIN
    BEGIN
        PERFORM sentinelflow.register_sse_client_lease_000024(
            '019f0000-0000-7000-8000-000000002452', 'over-capacity'
        );
        RAISE EXCEPTION 'SSE lease cap was not enforced';
    EXCEPTION WHEN SQLSTATE '53300' THEN NULL;
    END;
END
$lease_capacity_is_hard$;

SET LOCAL ROLE sentinelflow_migration;
DELETE FROM sentinelflow.sse_client_leases;

RESET ROLE;

DO $migration_recorded$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 24 AND name = 'control_observability'
    ) THEN
        RAISE EXCEPTION 'control observability migration is not recorded';
    END IF;
END
$migration_recorded$;

ROLLBACK;
