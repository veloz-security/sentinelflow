BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $required_relations$
DECLARE
    relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'ingest_replay_nonces', 'ingest_batches', 'gateway_events', 'auth_events',
        'source_health_intervals', 'sender_checkpoints', 'ingest_sequence_gaps',
        'ingest_sequence_gap_resolutions', 'signals', 'signal_evidence', 'incidents',
        'incident_signals', 'incident_events', 'evidence_snapshots',
        'evidence_snapshot_signals', 'evidence_snapshot_events', 'ai_analyses',
        'analysis_false_positive_factors', 'analysis_evidence',
        'command_candidates', 'policy_proposals', 'validation_snapshots',
        'validation_gates', 'admin_sessions', 'decision_challenges', 'hil_reasons',
        'approval_decisions', 'enforcement_authorizations', 'enforcement_actions',
        'revocation_operations', 'inspection_authorizations', 'execution_capabilities',
        'execution_results', 'dispatch_operations', 'ai_budget_ledger',
        'audit_events', 'outbox_jobs', 'dead_letter_jobs'
    ]
    LOOP
        IF to_regclass('sentinelflow.' || relation_name) IS NULL THEN
            RAISE EXCEPTION 'missing relation';
        END IF;
    END LOOP;
END
$required_relations$;

DO $privacy_columns$
DECLARE
    forbidden_name text;
BEGIN
    SELECT column_name
    INTO forbidden_name
    FROM information_schema.columns
    WHERE table_schema = 'sentinelflow'
      AND column_name IN (
          'path', 'raw_path', 'decoded_path', 'exact_path', 'request_target', 'raw_target',
          'query', 'query_string', 'raw_query', 'request_body', 'response_body', 'body',
          'cookie', 'cookies', 'authorization', 'authorization_header', 'raw_headers',
          'headers', 'username', 'email', 'password', 'session_token', 'csrf_token'
      )
    LIMIT 1;
    IF forbidden_name IS NOT NULL THEN
        RAISE EXCEPTION 'forbidden persistence column exists';
    END IF;
END
$privacy_columns$;

DO $replay_nonce_minimization$
BEGIN
    IF (
        SELECT array_agg(column_name::text ORDER BY ordinal_position)
        FROM information_schema.columns
        WHERE table_schema = 'sentinelflow'
          AND table_name = 'ingest_replay_nonces'
    ) <> ARRAY[
        'sender_id', 'endpoint_kind', 'endpoint_path', 'nonce_digest',
        'authenticated_at', 'expires_at'
    ]::text[] THEN
        RAISE EXCEPTION 'replay store contains missing or forbidden authentication metadata';
    END IF;
END
$replay_nonce_minimization$;

DO $role_boundary$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN ('sentinelflow_gateway', 'sentinelflow_executor')
    ) THEN
        RAISE EXCEPTION 'gateway or executor database role must not exist';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN (
            'sentinelflow_migration', 'sentinelflow_api', 'sentinelflow_worker',
            'sentinelflow_read', 'sentinelflow_dispatcher'
        )
          AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'capability roles must be NOLOGIN and unprivileged';
    END IF;
    IF has_table_privilege('sentinelflow_dispatcher', 'sentinelflow.outbox_jobs', 'SELECT') OR
       has_table_privilege('sentinelflow_dispatcher', 'sentinelflow.incidents', 'SELECT') OR
       has_table_privilege('sentinelflow_dispatcher', 'sentinelflow.admin_sessions', 'SELECT') THEN
        RAISE EXCEPTION 'dispatcher has a forbidden base-table privilege';
    END IF;
    IF NOT has_table_privilege(
        'sentinelflow_dispatcher',
        'sentinelflow.dispatcher_approved_outbox',
        'SELECT'
    ) THEN
        RAISE EXCEPTION 'dispatcher approved-outbox privilege is missing';
    END IF;
    IF has_table_privilege('sentinelflow_api', 'sentinelflow.gateway_events', 'UPDATE') OR
       has_column_privilege('sentinelflow_api', 'sentinelflow.auth_events', 'account_hash', 'UPDATE') OR
       has_table_privilege('sentinelflow_api', 'sentinelflow.approval_decisions', 'UPDATE') OR
       has_table_privilege('sentinelflow_api', 'sentinelflow.enforcement_authorizations', 'UPDATE') OR
       has_table_privilege('sentinelflow_api', 'sentinelflow.enforcement_actions', 'UPDATE') OR
       has_column_privilege('sentinelflow_api', 'sentinelflow.enforcement_actions', 'state', 'UPDATE') OR
       has_table_privilege('sentinelflow_api', 'sentinelflow.sender_checkpoints', 'UPDATE') OR
       has_column_privilege('sentinelflow_api', 'sentinelflow.outbox_jobs', 'state', 'UPDATE') OR
       has_table_privilege('sentinelflow_worker', 'sentinelflow.outbox_jobs', 'UPDATE') OR
       has_column_privilege('sentinelflow_worker', 'sentinelflow.outbox_jobs', 'state', 'UPDATE') OR
       has_table_privilege('sentinelflow_worker', 'sentinelflow.policy_proposals', 'UPDATE') OR
       has_column_privilege('sentinelflow_worker', 'sentinelflow.policy_proposals', 'state_revision', 'UPDATE') OR
       has_table_privilege('sentinelflow_worker', 'sentinelflow.signals', 'UPDATE') THEN
        RAISE EXCEPTION 'append-only or minimized data has an unsafe update grant';
    END IF;
    IF NOT has_column_privilege(
        'sentinelflow_api', 'sentinelflow.auth_events', 'binding_state', 'UPDATE'
    ) OR NOT has_table_privilege(
        'sentinelflow_worker', 'sentinelflow.enforcement_actions', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'required narrow service privilege is missing';
    END IF;
    IF NOT has_table_privilege(
        'sentinelflow_api', 'sentinelflow.ingest_replay_nonces', 'SELECT,INSERT'
    ) OR has_table_privilege(
        'sentinelflow_api', 'sentinelflow.ingest_replay_nonces', 'UPDATE,DELETE'
    ) OR has_table_privilege(
        'sentinelflow_worker', 'sentinelflow.ingest_replay_nonces', 'SELECT'
    ) OR has_table_privilege(
        'sentinelflow_read', 'sentinelflow.ingest_replay_nonces', 'SELECT'
    ) OR has_table_privilege(
        'sentinelflow_dispatcher', 'sentinelflow.ingest_replay_nonces', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'replay nonce store privileges are broader than the ingest boundary';
    END IF;
    IF NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.prune_ingest_replay_nonces(timestamp with time zone,integer)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.prune_ingest_replay_nonces(timestamp with time zone,integer)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'bounded replay cleanup function privilege is incorrect';
    END IF;
    IF NOT has_table_privilege(
        'sentinelflow_api', 'sentinelflow.ingest_sequence_gaps', 'SELECT'
    ) OR has_table_privilege(
        'sentinelflow_api', 'sentinelflow.ingest_sequence_gaps', 'INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
        'sentinelflow_api', 'sentinelflow.ingest_sequence_gap_resolutions', 'INSERT,UPDATE,DELETE'
    ) OR NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.register_ingest_sequence(text,text,text,bigint,uuid,text,timestamp with time zone)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.register_ingest_sequence(text,text,text,bigint,uuid,text,timestamp with time zone)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'ingest gap authority is broader than the atomic API boundary';
    END IF;
    IF NOT has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.lease_worker_outbox_job(timestamp with time zone,uuid,text,timestamp with time zone)',
        'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.finish_worker_outbox_job(text,timestamp with time zone,text,text,timestamp with time zone,uuid,uuid)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.lease_worker_outbox_job(timestamp with time zone,uuid,text,timestamp with time zone)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'worker lease functions have an unsafe authority boundary';
    END IF;
    IF NOT has_function_privilege(
        'sentinelflow_dispatcher',
        'sentinelflow.claim_dispatch_job(uuid,uuid,sentinelflow.ascii_id,timestamp with time zone)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'dispatcher claim function privilege is missing';
    END IF;
END
$role_boundary$;

DO $indexes_and_triggers$
BEGIN
    IF to_regclass('sentinelflow.gateway_events_received_at_idx') IS NULL OR
       to_regclass('sentinelflow.ingest_replay_nonces_expiry_idx') IS NULL OR
       to_regclass('sentinelflow.incidents_created_at_idx') IS NULL OR
       to_regclass('sentinelflow.audit_events_occurred_at_idx') IS NULL OR
       to_regclass('sentinelflow.outbox_jobs_available_idx') IS NULL OR
       to_regclass('sentinelflow.outbox_jobs_business_effect_idx') IS NULL OR
       to_regclass('sentinelflow.ingest_sequence_gaps_lookup_idx') IS NULL OR
       to_regclass('sentinelflow.ingest_sequence_gap_resolutions_lookup_idx') IS NULL THEN
        RAISE EXCEPTION 'required retention or queue index is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.audit_events'::regclass
          AND tgname = 'audit_events_append_only'
          AND NOT tgisinternal
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.sender_checkpoints'::regclass
          AND tgname = 'sender_checkpoints_require_progress'
          AND NOT tgisinternal
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.ingest_batches'::regclass
          AND tgname = 'ingest_batches_require_atomic_checkpoint'
          AND NOT tgisinternal
          AND tgdeferrable
          AND tginitdeferred
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.policy_proposals'::regclass
          AND tgname = 'policy_proposals_enforce_state_transition'
          AND NOT tgisinternal
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.auth_events'::regclass
          AND tgname = 'auth_events_require_binding_match'
          AND NOT tgisinternal
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.validation_snapshots'::regclass
          AND tgname = 'validation_snapshots_require_gates'
          AND NOT tgisinternal
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'sentinelflow.validation_gates'::regclass
          AND tgname = 'validation_gates_protect_valid_snapshot'
          AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'required invariant trigger is missing';
    END IF;
END
$indexes_and_triggers$;

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'gateway-test', 'IiIiIiIiIiIiIiIiIiIiIg', '019b0000-0000-7000-8000-000000009001',
    1, 'gateway', 'event-batch-v1',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    1024, 1, '2026-07-18T02:00:00Z', '2026-07-18T02:00:00Z'
);

INSERT INTO gateway_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
    route_label, path_catalog_version, suspicious_path_id, host, service_label,
    status_code, request_bytes, response_bytes, latency_ms, received_at
) VALUES (
    '019b0000-0000-7000-8000-000000009002', 'gateway-http-v1', 'gateway-test',
    'IiIiIiIiIiIiIiIiIiIiIg', '019b0000-0000-7000-8000-000000009001',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    '019b0000-0000-7000-8000-000000009003',
    '019b0000-0000-7000-8000-000000009004',
    '2026-07-18T02:00:00Z', '2026-07-18T02:00:00.007Z', '203.0.113.20',
    'POST', 'HTTP/1.1', 'login', 'path-catalog-v1', 'none', 'app.example.test',
    'demo-app', 401, 128, 431, 7, '2026-07-18T02:00:00.010Z'
);

INSERT INTO ingest_batches (
    sender_id, sender_epoch, batch_id, sequence, endpoint_kind, schema_version,
    raw_body_digest, raw_body_size, record_count, sent_at, received_at
) VALUES (
    'auth-test', 'JjJjJjJjJjJjJjJjJjJjJg', '019b0000-0000-7000-8000-000000009040',
    1, 'auth', 'event-batch-v1',
    'sha256:1212121212121212121212121212121212121212121212121212121212121212',
    1024, 2, '2026-07-18T02:00:00Z', '2026-07-18T02:00:00Z'
);

INSERT INTO auth_events (
    event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
    gateway_request_id, trace_id, occurred_at, source_ip, service_label,
    route_label, account_hash, outcome, received_at, binding_deadline
) VALUES
(
    '019b0000-0000-7000-8000-000000009041', 'auth-event-v1', 'auth-test',
    'JjJjJjJjJjJjJjJjJjJjJg', '019b0000-0000-7000-8000-000000009040',
    'sha256:1313131313131313131313131313131313131313131313131313131313131313',
    '019b0000-0000-7000-8000-000000009003',
    '019b0000-0000-7000-8000-000000009004', '2026-07-18T02:00:00.005Z',
    '203.0.113.20', 'demo-app', 'login',
    'hmac-sha256:1414141414141414141414141414141414141414141414141414141414141414',
    'failed', '2026-07-18T02:00:00.011Z', '2026-07-18T02:05:00Z'
),
(
    '019b0000-0000-7000-8000-000000009042', 'auth-event-v1', 'auth-test',
    'JjJjJjJjJjJjJjJjJjJjJg', '019b0000-0000-7000-8000-000000009040',
    'sha256:1515151515151515151515151515151515151515151515151515151515151515',
    '019b0000-0000-7000-8000-000000009043',
    '019b0000-0000-7000-8000-000000009004', '2026-07-18T02:00:00.006Z',
    '203.0.113.20', 'demo-app', 'login',
    'hmac-sha256:1616161616161616161616161616161616161616161616161616161616161616',
    'failed', '2026-07-18T02:00:00.012Z', '2026-07-18T02:05:00Z'
);

UPDATE auth_events
SET binding_state = 'verified',
    binding_reason = 'verified',
    bound_gateway_event_id = '019b0000-0000-7000-8000-000000009002'
WHERE event_id = '019b0000-0000-7000-8000-000000009041';

DO $auth_binding_invariants$
BEGIN
    BEGIN
        UPDATE auth_events
        SET binding_state = 'untrusted',
            binding_reason = 'expired',
            bound_gateway_event_id = NULL
        WHERE event_id = '019b0000-0000-7000-8000-000000009041';
        RAISE EXCEPTION 'terminal authentication binding was mutable';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    BEGIN
        UPDATE auth_events
        SET binding_state = 'verified',
            binding_reason = 'verified',
            bound_gateway_event_id = '019b0000-0000-7000-8000-000000009002'
        WHERE event_id = '019b0000-0000-7000-8000-000000009042';
        RAISE EXCEPTION 'mismatched authentication binding was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$auth_binding_invariants$;

DO $duplicate_idempotency$
BEGIN
    BEGIN
        INSERT INTO gateway_events (
            event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
            request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
            route_label, path_catalog_version, suspicious_path_id, host, service_label,
            status_code, request_bytes, response_bytes, latency_ms, received_at
        ) VALUES (
            '019b0000-0000-7000-8000-000000009012', 'gateway-http-v1', 'gateway-test',
            'IiIiIiIiIiIiIiIiIiIiIg', '019b0000-0000-7000-8000-000000009001',
            'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            '019b0000-0000-7000-8000-000000009013',
            '019b0000-0000-7000-8000-000000009014',
            '2026-07-18T02:00:01Z', '2026-07-18T02:00:01.007Z', '203.0.113.20',
            'POST', 'HTTP/1.1', 'login', 'path-catalog-v1', 'none', 'app.example.test',
            'demo-app', 401, 128, 431, 7, '2026-07-18T02:00:01.010Z'
        );
        RAISE EXCEPTION 'duplicate idempotency key was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
END
$duplicate_idempotency$;

DO $foreign_key_and_outbox_shape$
BEGIN
    BEGIN
        INSERT INTO gateway_events (
            event_id, schema_version, sender_id, sender_epoch, batch_id, idempotency_key,
            request_id, trace_id, started_at, completed_at, source_ip, method, protocol,
            route_label, path_catalog_version, suspicious_path_id, host, service_label,
            status_code, request_bytes, response_bytes, latency_ms, received_at
        ) VALUES (
            '019b0000-0000-7000-8000-000000009022', 'gateway-http-v1', 'gateway-test',
            'IiIiIiIiIiIiIiIiIiIiIg', '019b0000-0000-7000-8000-000000009099',
            'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
            '019b0000-0000-7000-8000-000000009023',
            '019b0000-0000-7000-8000-000000009024',
            '2026-07-18T02:00:03Z', '2026-07-18T02:00:03.007Z', '203.0.113.21',
            'GET', 'HTTP/1.1', 'home', 'path-catalog-v1', 'none', 'app.example.test',
            'demo-app', 200, 0, 12, 7, '2026-07-18T02:00:03.010Z'
        );
        SET CONSTRAINTS gateway_event_batch_fk IMMEDIATE;
        RAISE EXCEPTION 'missing batch foreign key was accepted';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;
    SET CONSTRAINTS gateway_event_batch_fk DEFERRED;

    BEGIN
        INSERT INTO outbox_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            operation, idempotency_key
        ) VALUES (
            '019b0000-0000-7000-8000-000000009030', 'detect', 'gateway_event',
            '019b0000-0000-7000-8000-000000009002', 1, 'add',
            'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
        );
        RAISE EXCEPTION 'non-dispatch outbox operation was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$foreign_key_and_outbox_shape$;

DO $invalid_gateway_values$
BEGIN
    BEGIN
        UPDATE gateway_events SET status_code = 99
        WHERE event_id = '019b0000-0000-7000-8000-000000009002';
        RAISE EXCEPTION 'invalid status was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    BEGIN
        UPDATE gateway_events SET source_ip = '2001:db8::1'
        WHERE event_id = '019b0000-0000-7000-8000-000000009002';
        RAISE EXCEPTION 'IPv6 source was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$invalid_gateway_values$;

SET LOCAL ROLE sentinelflow_api;
SELECT sentinelflow.append_audit_event(
    '019b0000-0000-7000-8000-000000009020',
    'administrator',
    'admin-test',
    'verify_append',
    'gateway_event',
    '019b0000-0000-7000-8000-000000009002',
    NULL,
    NULL,
    NULL,
    NULL,
    '019b0000-0000-7000-8000-000000009004',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    NULL,
    'succeeded',
    '2026-07-18T02:00:02Z'
);
RESET ROLE;

DO $append_only_audit$
BEGIN
    BEGIN
        UPDATE audit_events SET outcome = 'failed'
        WHERE event_id = '019b0000-0000-7000-8000-000000009020';
        RAISE EXCEPTION 'audit update was accepted';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    BEGIN
        DELETE FROM audit_events
        WHERE event_id = '019b0000-0000-7000-8000-000000009020';
        RAISE EXCEPTION 'audit delete was accepted';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END
$append_only_audit$;

ROLLBACK;
