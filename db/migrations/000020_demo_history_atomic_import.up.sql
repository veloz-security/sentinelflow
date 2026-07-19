BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

CREATE TABLE IF NOT EXISTS demo_history_imports (
    import_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (schema_version = 'demo-history-import-v1'),
    manifest_id uuid NOT NULL UNIQUE,
    profile text NOT NULL CHECK (profile = 'isolated-demo'),
    dataset_id uuid NOT NULL UNIQUE CHECK (
        dataset_id = '019b0000-0000-7000-8000-000000000100'::uuid
    ),
    dataset_schema_version text NOT NULL CHECK (
        dataset_schema_version = 'demo-history-dataset-v1'
    ),
    dataset_locator text NOT NULL CHECK (
        dataset_locator = 'contracts/fixtures/demo_history_dataset_v1.json'
    ),
    raw_file_byte_sha256 sha256_digest NOT NULL,
    manifest_dataset_jcs_digest sha256_digest NOT NULL CHECK (
        manifest_dataset_jcs_digest =
            'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00'
    ),
    imported_rows_jcs_digest sha256_digest NOT NULL CHECK (
        imported_rows_jcs_digest =
            'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807'
    ),
    imported_record_count safe_integer NOT NULL CHECK (imported_record_count = 4),
    source_health_jcs_digest sha256_digest NOT NULL CHECK (
        source_health_jcs_digest =
            'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe'
    ),
    manifest_digest sha256_digest NOT NULL UNIQUE,
    run_scope_digest sha256_digest NOT NULL,
    public_key_digest sha256_digest NOT NULL,
    signature_verification_digest sha256_digest NOT NULL,
    path_catalog_version text NOT NULL CHECK (path_catalog_version = 'path-catalog-v1'),
    clock_at timestamptz NOT NULL,
    issued_at timestamptz NOT NULL,
    coverage_start timestamptz NOT NULL,
    coverage_end timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('importing', 'completed', 'failed')),
    failure_code ascii_id NULL,
    attempt_count integer NOT NULL CHECK (attempt_count BETWEEN 1 AND 100),
    gateway_record_count integer NOT NULL DEFAULT 0 CHECK (gateway_record_count BETWEEN 0 AND 3),
    auth_record_count integer NOT NULL DEFAULT 0 CHECK (auth_record_count BETWEEN 0 AND 1),
    source_coverage_count integer NOT NULL DEFAULT 0 CHECK (source_coverage_count BETWEEN 0 AND 2),
    started_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    CONSTRAINT demo_history_import_coverage CHECK (
        clock_at = coverage_end AND issued_at >= coverage_end AND
        coverage_end = coverage_start + interval '24 hours' AND
        date_trunc('milliseconds', coverage_start) = coverage_start AND
        date_trunc('milliseconds', coverage_end) = coverage_end
    ),
    CONSTRAINT demo_history_import_state CHECK (
        (status = 'importing' AND failure_code IS NULL AND completed_at IS NULL AND
            gateway_record_count = 0 AND auth_record_count = 0 AND source_coverage_count = 0) OR
        (status = 'failed' AND failure_code IS NOT NULL AND completed_at IS NOT NULL AND
            gateway_record_count = 0 AND auth_record_count = 0 AND source_coverage_count = 0) OR
        (status = 'completed' AND failure_code IS NULL AND completed_at IS NOT NULL AND
            gateway_record_count = 3 AND auth_record_count = 1 AND source_coverage_count = 2)
    ),
    CONSTRAINT demo_history_import_time_order CHECK (
        completed_at IS NULL OR completed_at >= started_at
    )
);

CREATE TABLE IF NOT EXISTS demo_history_import_batches (
    import_id uuid NOT NULL REFERENCES demo_history_imports (import_id) ON DELETE RESTRICT,
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_id ascii_id NOT NULL,
    sender_epoch sender_epoch NOT NULL,
    sequence safe_integer NOT NULL CHECK (sequence >= 1),
    batch_id uuid NOT NULL,
    raw_body_digest sha256_digest NOT NULL,
    event_kind text NOT NULL CHECK (event_kind IN ('gateway-http-v1', 'auth-event-v1')),
    event_id uuid NOT NULL,
    PRIMARY KEY (import_id, endpoint_kind, sequence),
    UNIQUE (batch_id),
    UNIQUE (event_id),
    CONSTRAINT demo_history_import_batch_endpoint CHECK (
        (endpoint_kind = 'gateway' AND sender_id = 'gateway-demo' AND
            sender_epoch = 'IiIiIiIiIiIiIiIiIiIiIg' AND sequence BETWEEN 1 AND 3 AND
            event_kind = 'gateway-http-v1') OR
        (endpoint_kind = 'auth' AND sender_id = 'auth-demo' AND
            sender_epoch = 'EREREREREREREREREREREQ' AND sequence = 1 AND
            event_kind = 'auth-event-v1')
    ),
    CONSTRAINT demo_history_import_batch_fk FOREIGN KEY (
        sender_id, sender_epoch, batch_id, raw_body_digest
    ) REFERENCES ingest_batches (sender_id, sender_epoch, batch_id, raw_body_digest)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS demo_history_source_coverage (
    import_id uuid NOT NULL REFERENCES demo_history_imports (import_id) ON DELETE RESTRICT,
    sender_id ascii_id NOT NULL,
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('gateway', 'auth')),
    sender_epoch sender_epoch NOT NULL UNIQUE,
    coverage_start timestamptz NOT NULL,
    coverage_end timestamptz NOT NULL,
    coverage_status text NOT NULL CHECK (coverage_status = 'complete'),
    first_sequence safe_integer NOT NULL CHECK (first_sequence >= 1),
    last_sequence safe_integer NOT NULL CHECK (last_sequence >= first_sequence),
    unresolved_interval_count integer NOT NULL CHECK (unresolved_interval_count = 0),
    PRIMARY KEY (import_id, sender_id),
    UNIQUE (import_id, endpoint_kind),
    CONSTRAINT demo_history_source_coverage_endpoint CHECK (
        (sender_id = 'gateway-demo' AND endpoint_kind = 'gateway' AND
            sender_epoch = 'IiIiIiIiIiIiIiIiIiIiIg' AND
            first_sequence = 1 AND last_sequence = 3) OR
        (sender_id = 'auth-demo' AND endpoint_kind = 'auth' AND
            sender_epoch = 'EREREREREREREREREREREQ' AND
            first_sequence = 1 AND last_sequence = 1)
    ),
    CONSTRAINT demo_history_source_coverage_time CHECK (
        coverage_end = coverage_start + interval '24 hours' AND
        date_trunc('milliseconds', coverage_start) = coverage_start AND
        date_trunc('milliseconds', coverage_end) = coverage_end
    )
);

CREATE OR REPLACE FUNCTION sentinelflow.guard_demo_history_import_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history import ledger is append-only';
    END IF;
    IF ROW(
        NEW.import_id, NEW.schema_version, NEW.manifest_id, NEW.profile,
        NEW.dataset_id, NEW.dataset_schema_version, NEW.dataset_locator,
        NEW.raw_file_byte_sha256,
        NEW.manifest_dataset_jcs_digest, NEW.imported_rows_jcs_digest,
        NEW.imported_record_count, NEW.source_health_jcs_digest,
        NEW.manifest_digest, NEW.run_scope_digest, NEW.public_key_digest,
        NEW.signature_verification_digest, NEW.path_catalog_version,
        NEW.clock_at, NEW.issued_at, NEW.coverage_start, NEW.coverage_end
    ) IS DISTINCT FROM ROW(
        OLD.import_id, OLD.schema_version, OLD.manifest_id, OLD.profile,
        OLD.dataset_id, OLD.dataset_schema_version, OLD.dataset_locator,
        OLD.raw_file_byte_sha256,
        OLD.manifest_dataset_jcs_digest, OLD.imported_rows_jcs_digest,
        OLD.imported_record_count, OLD.source_health_jcs_digest,
        OLD.manifest_digest, OLD.run_scope_digest, OLD.public_key_digest,
        OLD.signature_verification_digest, OLD.path_catalog_version,
        OLD.clock_at, OLD.issued_at, OLD.coverage_start, OLD.coverage_end
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history import identity is immutable';
    END IF;
    IF OLD.status = 'completed' OR
       (OLD.status = 'importing' AND NEW.status NOT IN ('completed', 'failed')) OR
       (OLD.status = 'failed' AND NEW.status NOT IN ('failed', 'importing')) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'invalid demo history import state transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.reject_demo_history_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'demo history import evidence is append-only';
END
$function$;

DROP TRIGGER IF EXISTS demo_history_import_update_guard ON demo_history_imports;
CREATE TRIGGER demo_history_import_update_guard
BEFORE UPDATE OR DELETE ON demo_history_imports
FOR EACH ROW EXECUTE FUNCTION sentinelflow.guard_demo_history_import_update();

DROP TRIGGER IF EXISTS demo_history_import_batches_append_only ON demo_history_import_batches;
CREATE TRIGGER demo_history_import_batches_append_only
BEFORE UPDATE OR DELETE ON demo_history_import_batches
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_demo_history_evidence_mutation();

DROP TRIGGER IF EXISTS demo_history_source_coverage_append_only ON demo_history_source_coverage;
CREATE TRIGGER demo_history_source_coverage_append_only
BEFORE UPDATE OR DELETE ON demo_history_source_coverage
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_demo_history_evidence_mutation();

CREATE OR REPLACE FUNCTION sentinelflow.demo_history_event_jcs(
    p_event_id uuid,
    p_event_kind text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    result text;
BEGIN
    IF p_event_kind = 'gateway-http-v1' THEN
        SELECT
            '{"completed_at":' || to_json(to_char(event.completed_at AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
            ',"event_id":' || to_json(event.event_id::text)::text ||
            ',"host":' || to_json(event.host)::text ||
            ',"idempotency_key":' || to_json(event.idempotency_key::text)::text ||
            ',"latency_ms":' || event.latency_ms::text ||
            ',"method":' || to_json(event.method)::text ||
            ',"path_catalog_version":' || to_json(event.path_catalog_version)::text ||
            ',"protocol":' || to_json(event.protocol)::text ||
            ',"request_bytes":' || event.request_bytes::text ||
            ',"request_id":' || to_json(event.request_id::text)::text ||
            ',"response_bytes":' || event.response_bytes::text ||
            ',"route_label":' || to_json(event.route_label::text)::text ||
            ',"schema_version":' || to_json(event.schema_version)::text ||
            ',"service_label":' || to_json(event.service_label::text)::text ||
            ',"source_ip":' || to_json(host(event.source_ip))::text ||
            ',"started_at":' || to_json(to_char(event.started_at AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
            ',"status_code":' || event.status_code::text ||
            ',"suspicious_path_id":' || to_json(event.suspicious_path_id)::text ||
            ',"trace_id":' || to_json(event.trace_id::text)::text || '}'
        INTO result
        FROM sentinelflow.gateway_events event
        WHERE event.event_id = p_event_id;
    ELSIF p_event_kind = 'auth-event-v1' THEN
        SELECT
            '{"account_hash":' || to_json(event.account_hash::text)::text ||
            ',"event_id":' || to_json(event.event_id::text)::text ||
            ',"gateway_request_id":' || to_json(event.gateway_request_id::text)::text ||
            ',"idempotency_key":' || to_json(event.idempotency_key::text)::text ||
            ',"occurred_at":' || to_json(to_char(event.occurred_at AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
            ',"outcome":' || to_json(event.outcome)::text ||
            ',"route_label":' || to_json(event.route_label::text)::text ||
            ',"schema_version":' || to_json(event.schema_version)::text ||
            ',"service_label":' || to_json(event.service_label::text)::text ||
            ',"source_ip":' || to_json(host(event.source_ip))::text ||
            ',"trace_id":' || to_json(event.trace_id::text)::text || '}'
        INTO result
        FROM sentinelflow.auth_events event
        WHERE event.event_id = p_event_id;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'unsupported demo history event kind';
    END IF;
    IF result IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = 'demo history event is missing';
    END IF;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.demo_history_rows_valid(p_import_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    ledger sentinelflow.demo_history_imports%ROWTYPE;
    records_jcs text;
    health_jcs text;
    dataset_jcs text;
    rows_digest text;
    health_digest text;
    dataset_digest text;
BEGIN
    SELECT * INTO ledger
    FROM sentinelflow.demo_history_imports
    WHERE import_id = p_import_id;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    SELECT '[' || string_agg(
        sentinelflow.demo_history_event_jcs(mapping.event_id, mapping.event_kind),
        ',' ORDER BY event_time, mapping.event_id::text
    ) || ']'
    INTO records_jcs
    FROM sentinelflow.demo_history_import_batches mapping
    LEFT JOIN sentinelflow.gateway_events gateway
      ON mapping.event_kind = 'gateway-http-v1' AND gateway.event_id = mapping.event_id
    LEFT JOIN sentinelflow.auth_events auth
      ON mapping.event_kind = 'auth-event-v1' AND auth.event_id = mapping.event_id
    CROSS JOIN LATERAL (
        SELECT CASE WHEN mapping.event_kind = 'gateway-http-v1'
            THEN gateway.started_at ELSE auth.occurred_at END AS event_time
    ) ordering
    WHERE mapping.import_id = p_import_id;

    SELECT '[' || string_agg(
        '{"coverage_end":' || to_json(to_char(coverage.coverage_end AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
        ',"coverage_start":' || to_json(to_char(coverage.coverage_start AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
        ',"coverage_status":' || to_json(coverage.coverage_status)::text ||
        ',"first_sequence":' || coverage.first_sequence::text ||
        ',"last_sequence":' || coverage.last_sequence::text ||
        ',"sender_epoch":' || to_json(coverage.sender_epoch::text)::text ||
        ',"sender_id":' || to_json(coverage.sender_id::text)::text ||
        ',"unresolved_intervals":[]}',
        ',' ORDER BY coverage.sender_id::text, coverage.sender_epoch::text
    ) || ']'
    INTO health_jcs
    FROM sentinelflow.demo_history_source_coverage coverage
    WHERE coverage.import_id = p_import_id;

    IF records_jcs IS NULL OR health_jcs IS NULL THEN
        RETURN false;
    END IF;
    rows_digest := 'sha256:' || encode(sha256(convert_to(records_jcs, 'UTF8')), 'hex');
    health_digest := 'sha256:' || encode(sha256(convert_to(health_jcs, 'UTF8')), 'hex');
    dataset_jcs :=
        '{"coverage_end":' || to_json(to_char(ledger.coverage_end AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
        ',"coverage_start":' || to_json(to_char(ledger.coverage_start AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
        ',"dataset_id":' || to_json(ledger.dataset_id::text)::text ||
        ',"path_catalog_version":' || to_json(ledger.path_catalog_version)::text ||
        ',"records":' || records_jcs ||
        ',"schema_version":' || to_json(ledger.dataset_schema_version)::text ||
        ',"source_health":' || health_jcs || '}';
    dataset_digest := 'sha256:' || encode(sha256(convert_to(dataset_jcs, 'UTF8')), 'hex');

    RETURN
        (SELECT count(*) = 4 FROM sentinelflow.demo_history_import_batches
            WHERE import_id = p_import_id) AND
        (SELECT count(*) = 3 FROM sentinelflow.demo_history_import_batches
            WHERE import_id = p_import_id AND endpoint_kind = 'gateway') AND
        (SELECT count(*) = 1 FROM sentinelflow.demo_history_import_batches
            WHERE import_id = p_import_id AND endpoint_kind = 'auth') AND
        (SELECT count(*) = 2 FROM sentinelflow.demo_history_source_coverage
            WHERE import_id = p_import_id) AND
        (SELECT count(*) = 3
         FROM sentinelflow.demo_history_import_batches mapping
         JOIN sentinelflow.gateway_events event ON event.event_id = mapping.event_id
         WHERE mapping.import_id = p_import_id AND mapping.endpoint_kind = 'gateway' AND
             event.sender_id = mapping.sender_id AND event.sender_epoch = mapping.sender_epoch AND
             event.batch_id = mapping.batch_id) AND
        (SELECT count(*) = 1
         FROM sentinelflow.demo_history_import_batches mapping
         JOIN sentinelflow.auth_events event ON event.event_id = mapping.event_id
         WHERE mapping.import_id = p_import_id AND mapping.endpoint_kind = 'auth' AND
             event.sender_id = mapping.sender_id AND event.sender_epoch = mapping.sender_epoch AND
             event.batch_id = mapping.batch_id AND event.binding_state = 'verified' AND
             event.binding_reason = 'verified' AND event.bound_gateway_event_id IS NOT NULL) AND
        NOT EXISTS (
            SELECT 1 FROM sentinelflow.ingest_sequence_gaps
            WHERE (sender_id = 'gateway-demo' AND endpoint_kind = 'gateway' AND
                    sender_epoch = 'IiIiIiIiIiIiIiIiIiIiIg' AND
                    sequence_start <= 3 AND sequence_end >= 1) OR
                  (sender_id = 'auth-demo' AND endpoint_kind = 'auth' AND
                    sender_epoch = 'EREREREREREREREREREREQ' AND
                    sequence_start <= 1 AND sequence_end >= 1)
        ) AND
        EXISTS (
            SELECT 1 FROM sentinelflow.sender_checkpoints checkpoint
            WHERE checkpoint.sender_id = 'gateway-demo' AND checkpoint.endpoint_kind = 'gateway' AND
                checkpoint.sender_epoch = 'IiIiIiIiIiIiIiIiIiIiIg' AND
                checkpoint.last_acknowledged_sequence >= 3 AND NOT checkpoint.unknown_loss
        ) AND
        EXISTS (
            SELECT 1 FROM sentinelflow.sender_checkpoints checkpoint
            WHERE checkpoint.sender_id = 'auth-demo' AND checkpoint.endpoint_kind = 'auth' AND
                checkpoint.sender_epoch = 'EREREREREREREREREREREQ' AND
                checkpoint.last_acknowledged_sequence >= 1 AND NOT checkpoint.unknown_loss
        ) AND
        rows_digest = ledger.imported_rows_jcs_digest::text AND
        health_digest = ledger.source_health_jcs_digest::text AND
        dataset_digest = ledger.manifest_dataset_jcs_digest::text;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.begin_demo_history_import(
    p_import_id uuid,
    p_manifest_id uuid,
    p_raw_file_byte_sha256 text,
    p_manifest_dataset_jcs_digest text,
    p_imported_rows_jcs_digest text,
    p_imported_record_count bigint,
    p_source_health_jcs_digest text,
    p_manifest_digest text,
    p_run_scope_digest text,
    p_public_key_digest text,
    p_signature_verification_digest text,
    p_clock_at timestamptz,
    p_issued_at timestamptz,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    existing sentinelflow.demo_history_imports%ROWTYPE;
    now_at timestamptz := clock_timestamp();
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('sentinelflow:demo-history-dataset-v1', 0)
    );
    IF p_import_id IS NULL OR p_manifest_id IS NULL OR
       p_raw_file_byte_sha256 !~ '^sha256:[0-9a-f]{64}$' OR
       p_manifest_dataset_jcs_digest <>
           'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00' OR
       p_imported_rows_jcs_digest <>
           'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807' OR
       p_imported_record_count <> 4 OR
       p_source_health_jcs_digest <>
           'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe' OR
       p_manifest_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_run_scope_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_public_key_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_signature_verification_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_clock_at <> p_coverage_end OR p_issued_at < p_coverage_end OR
       p_coverage_end <> p_coverage_start + interval '24 hours' OR
       date_trunc('milliseconds', p_coverage_start) <> p_coverage_start OR
       date_trunc('milliseconds', p_coverage_end) <> p_coverage_end THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid pinned demo history import claims';
    END IF;

    SELECT * INTO existing
    FROM sentinelflow.demo_history_imports
    WHERE dataset_id = '019b0000-0000-7000-8000-000000000100'::uuid
    FOR UPDATE;
    IF FOUND THEN
        IF existing.import_id <> p_import_id OR existing.manifest_id <> p_manifest_id OR
           existing.raw_file_byte_sha256::text <> p_raw_file_byte_sha256 OR
           existing.manifest_dataset_jcs_digest::text <> p_manifest_dataset_jcs_digest OR
           existing.imported_rows_jcs_digest::text <> p_imported_rows_jcs_digest OR
           existing.imported_record_count <> p_imported_record_count OR
           existing.source_health_jcs_digest::text <> p_source_health_jcs_digest OR
           existing.manifest_digest::text <> p_manifest_digest OR
           existing.run_scope_digest::text <> p_run_scope_digest OR
           existing.public_key_digest::text <> p_public_key_digest OR
           existing.signature_verification_digest::text <> p_signature_verification_digest OR
           existing.clock_at <> p_clock_at OR existing.issued_at <> p_issued_at OR
           existing.coverage_start <> p_coverage_start OR
           existing.coverage_end <> p_coverage_end THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'demo history import authority conflict';
        END IF;
        IF existing.status = 'completed' THEN
            IF NOT sentinelflow.demo_history_rows_valid(existing.import_id) THEN
                RAISE EXCEPTION USING ERRCODE = '55000',
                    MESSAGE = 'completed demo history import evidence drift';
            END IF;
            RETURN 'historical';
        END IF;
        IF existing.status <> 'failed' THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'demo history import state conflict';
        END IF;
        UPDATE sentinelflow.demo_history_imports
        SET raw_file_byte_sha256 = p_raw_file_byte_sha256::sentinelflow.sha256_digest,
            status = 'importing', failure_code = NULL,
            attempt_count = attempt_count + 1,
            started_at = now_at, completed_at = NULL
        WHERE import_id = existing.import_id;
        RETURN 'started';
    END IF;

    INSERT INTO sentinelflow.demo_history_imports (
        import_id, schema_version, manifest_id, profile, dataset_id,
        dataset_schema_version, dataset_locator, raw_file_byte_sha256,
        manifest_dataset_jcs_digest, imported_rows_jcs_digest,
        imported_record_count, source_health_jcs_digest, manifest_digest,
        run_scope_digest, public_key_digest, signature_verification_digest,
        path_catalog_version, clock_at, issued_at, coverage_start, coverage_end, status,
        failure_code, attempt_count, started_at
    ) VALUES (
        p_import_id, 'demo-history-import-v1', p_manifest_id, 'isolated-demo',
        '019b0000-0000-7000-8000-000000000100'::uuid,
        'demo-history-dataset-v1',
        'contracts/fixtures/demo_history_dataset_v1.json',
        p_raw_file_byte_sha256::sentinelflow.sha256_digest,
        p_manifest_dataset_jcs_digest::sentinelflow.sha256_digest,
        p_imported_rows_jcs_digest::sentinelflow.sha256_digest,
        p_imported_record_count, p_source_health_jcs_digest::sentinelflow.sha256_digest,
        p_manifest_digest::sentinelflow.sha256_digest,
        p_run_scope_digest::sentinelflow.sha256_digest,
        p_public_key_digest::sentinelflow.sha256_digest,
        p_signature_verification_digest::sentinelflow.sha256_digest,
        'path-catalog-v1',
        p_clock_at, p_issued_at, p_coverage_start, p_coverage_end,
        'importing', NULL, 1, now_at
    );
    RETURN 'started';
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.append_demo_history_gateway(
    p_import_id uuid, p_sender_epoch text, p_sequence bigint,
    p_batch_id uuid, p_raw_body_digest text, p_raw_body_size integer,
    p_event_id uuid, p_idempotency_key text, p_request_id uuid, p_trace_id uuid,
    p_started_at timestamptz, p_completed_at timestamptz, p_source_ip text,
    p_method text, p_protocol text, p_route_label text,
    p_path_catalog_version text, p_suspicious_path_id text, p_host text,
    p_service_label text, p_status_code integer, p_request_bytes bigint,
    p_response_bytes bigint, p_latency_ms integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    received_at timestamptz := clock_timestamp();
    disposition text;
    expected_batch_id uuid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.demo_history_imports
        WHERE import_id = p_import_id AND status = 'importing'
    ) OR p_sender_epoch <> 'IiIiIiIiIiIiIiIiIiIiIg' OR
       p_sequence NOT BETWEEN 1 AND 3 OR p_raw_body_size NOT BETWEEN 2 AND 262144 OR
       p_raw_body_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_protocol <> 'HTTP/1.1' OR p_path_catalog_version <> 'path-catalog-v1' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid demo history gateway row';
    END IF;
    expected_batch_id := CASE p_sequence
        WHEN 1 THEN '019b0000-0000-7000-8000-000000000201'::uuid
        WHEN 2 THEN '019b0000-0000-7000-8000-000000000202'::uuid
        WHEN 3 THEN '019b0000-0000-7000-8000-000000000203'::uuid
    END;
    IF p_batch_id <> expected_batch_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'demo history gateway batch identity mismatch';
    END IF;
    IF p_sequence = 1 THEN
        INSERT INTO sentinelflow.sender_checkpoints (
            sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
            last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
        ) VALUES ('gateway-demo', 'gateway', p_sender_epoch, 0, NULL, false, false, received_at);
    END IF;
    INSERT INTO sentinelflow.ingest_batches (
        sender_id, sender_epoch, batch_id, sequence, endpoint_kind, auth_key_id,
        schema_version, raw_body_digest, raw_body_size, record_count,
        sent_at, received_at, acknowledgement
    ) VALUES (
        'gateway-demo', p_sender_epoch, p_batch_id, p_sequence, 'gateway', NULL,
        'event-batch-v1', p_raw_body_digest::sentinelflow.sha256_digest,
        p_raw_body_size, 1, p_completed_at, received_at, 'accepted'
    );
    disposition := sentinelflow.register_ingest_sequence(
        'gateway-demo', 'gateway', p_sender_epoch, p_sequence,
        p_batch_id, p_raw_body_digest, received_at
    );
    IF disposition <> 'next' THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'demo history gateway sequence is not contiguous';
    END IF;
    INSERT INTO sentinelflow.gateway_events (
        event_id, schema_version, sender_id, sender_epoch, batch_id,
        idempotency_key, request_id, trace_id, started_at, completed_at,
        source_ip, method, protocol, route_label, path_catalog_version,
        suspicious_path_id, host, service_label, status_code, request_bytes,
        response_bytes, latency_ms, received_at, trust_state, trust_reason
    ) VALUES (
        p_event_id, 'gateway-http-v1', 'gateway-demo', p_sender_epoch, p_batch_id,
        p_idempotency_key::sentinelflow.sha256_digest, p_request_id, p_trace_id,
        p_started_at, p_completed_at, p_source_ip::sentinelflow.canonical_ipv4,
        p_method, p_protocol, p_route_label::sentinelflow.event_label,
        p_path_catalog_version, p_suspicious_path_id, p_host,
        p_service_label::sentinelflow.event_label, p_status_code,
        p_request_bytes, p_response_bytes, p_latency_ms,
        received_at, 'trusted', 'none'
    );
    INSERT INTO sentinelflow.demo_history_import_batches (
        import_id, endpoint_kind, sender_id, sender_epoch, sequence,
        batch_id, raw_body_digest, event_kind, event_id
    ) VALUES (
        p_import_id, 'gateway', 'gateway-demo', p_sender_epoch, p_sequence,
        p_batch_id, p_raw_body_digest::sentinelflow.sha256_digest,
        'gateway-http-v1', p_event_id
    );
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.append_demo_history_auth(
    p_import_id uuid, p_sender_epoch text, p_sequence bigint,
    p_batch_id uuid, p_raw_body_digest text, p_raw_body_size integer,
    p_event_id uuid, p_idempotency_key text, p_gateway_request_id uuid,
    p_trace_id uuid, p_occurred_at timestamptz, p_source_ip text,
    p_service_label text, p_route_label text, p_account_hash text, p_outcome text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    received_at timestamptz := clock_timestamp();
    disposition text;
    bound_event_id uuid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.demo_history_imports
        WHERE import_id = p_import_id AND status = 'importing'
    ) OR p_sender_epoch <> 'EREREREREREREREREREREQ' OR p_sequence <> 1 OR
       p_batch_id <> '019b0000-0000-7000-8000-000000000204'::uuid OR
       p_raw_body_size NOT BETWEEN 2 AND 262144 OR
       p_raw_body_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid demo history auth row';
    END IF;
    INSERT INTO sentinelflow.sender_checkpoints (
        sender_id, endpoint_kind, sender_epoch, last_acknowledged_sequence,
        last_acknowledged_body_digest, clean_shutdown, unknown_loss, updated_at
    ) VALUES ('auth-demo', 'auth', p_sender_epoch, 0, NULL, false, false, received_at);
    INSERT INTO sentinelflow.ingest_batches (
        sender_id, sender_epoch, batch_id, sequence, endpoint_kind, auth_key_id,
        schema_version, raw_body_digest, raw_body_size, record_count,
        sent_at, received_at, acknowledgement
    ) VALUES (
        'auth-demo', p_sender_epoch, p_batch_id, p_sequence, 'auth', NULL,
        'event-batch-v1', p_raw_body_digest::sentinelflow.sha256_digest,
        p_raw_body_size, 1, p_occurred_at, received_at, 'accepted'
    );
    disposition := sentinelflow.register_ingest_sequence(
        'auth-demo', 'auth', p_sender_epoch, p_sequence,
        p_batch_id, p_raw_body_digest, received_at
    );
    IF disposition <> 'next' THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'demo history auth sequence is not contiguous';
    END IF;
    INSERT INTO sentinelflow.auth_events (
        event_id, schema_version, sender_id, sender_epoch, batch_id,
        idempotency_key, gateway_request_id, trace_id, occurred_at, source_ip,
        service_label, route_label, account_hash, outcome, received_at,
        trust_state, trust_reason, binding_state, binding_deadline, binding_reason
    ) VALUES (
        p_event_id, 'auth-event-v1', 'auth-demo', p_sender_epoch, p_batch_id,
        p_idempotency_key::sentinelflow.sha256_digest, p_gateway_request_id,
        p_trace_id, p_occurred_at, p_source_ip::sentinelflow.canonical_ipv4,
        p_service_label::sentinelflow.event_label, p_route_label::sentinelflow.event_label,
        p_account_hash::sentinelflow.hmac_sha256_digest, p_outcome,
        received_at, 'trusted', 'none', 'pending', received_at + interval '5 minutes',
        'awaiting_gateway_event'
    );
    SELECT event_id INTO bound_event_id
    FROM sentinelflow.gateway_events
    WHERE request_id = p_gateway_request_id AND trace_id = p_trace_id AND
        source_ip = p_source_ip::sentinelflow.canonical_ipv4 AND
        service_label = p_service_label::sentinelflow.event_label AND
        route_label = p_route_label::sentinelflow.event_label;
    IF bound_event_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'demo history auth binding is missing';
    END IF;
    UPDATE sentinelflow.auth_events
    SET binding_state = 'verified', binding_reason = 'verified',
        bound_gateway_event_id = bound_event_id
    WHERE event_id = p_event_id;
    INSERT INTO sentinelflow.demo_history_import_batches (
        import_id, endpoint_kind, sender_id, sender_epoch, sequence,
        batch_id, raw_body_digest, event_kind, event_id
    ) VALUES (
        p_import_id, 'auth', 'auth-demo', p_sender_epoch, p_sequence,
        p_batch_id, p_raw_body_digest::sentinelflow.sha256_digest,
        'auth-event-v1', p_event_id
    );
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.append_demo_history_source_coverage(
    p_import_id uuid, p_sender_id text, p_endpoint_kind text, p_sender_epoch text,
    p_coverage_start timestamptz, p_coverage_end timestamptz,
    p_first_sequence bigint, p_last_sequence bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    ledger sentinelflow.demo_history_imports%ROWTYPE;
BEGIN
    SELECT * INTO ledger FROM sentinelflow.demo_history_imports
    WHERE import_id = p_import_id AND status = 'importing';
    IF NOT FOUND OR p_coverage_start <> ledger.coverage_start OR
       p_coverage_end <> ledger.coverage_end OR
       NOT (
          (p_sender_id = 'gateway-demo' AND p_endpoint_kind = 'gateway' AND
           p_sender_epoch = 'IiIiIiIiIiIiIiIiIiIiIg' AND
           p_first_sequence = 1 AND p_last_sequence = 3) OR
          (p_sender_id = 'auth-demo' AND p_endpoint_kind = 'auth' AND
           p_sender_epoch = 'EREREREREREREREREREREQ' AND
           p_first_sequence = 1 AND p_last_sequence = 1)
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid demo history source coverage';
    END IF;
    INSERT INTO sentinelflow.demo_history_source_coverage (
        import_id, sender_id, endpoint_kind, sender_epoch,
        coverage_start, coverage_end, coverage_status,
        first_sequence, last_sequence, unresolved_interval_count
    ) VALUES (
        p_import_id, p_sender_id::sentinelflow.ascii_id, p_endpoint_kind,
        p_sender_epoch::sentinelflow.sender_epoch, p_coverage_start,
        p_coverage_end, 'complete', p_first_sequence, p_last_sequence, 0
    );
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.complete_demo_history_import(p_import_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.demo_history_imports
        WHERE import_id = p_import_id AND status = 'importing'
        FOR UPDATE
    ) OR NOT sentinelflow.demo_history_rows_valid(p_import_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'demo history imported rows failed canonical verification';
    END IF;
    UPDATE sentinelflow.demo_history_imports
    SET status = 'completed', failure_code = NULL,
        gateway_record_count = 3, auth_record_count = 1,
        source_coverage_count = 2, completed_at = clock_timestamp()
    WHERE import_id = p_import_id;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.record_demo_history_import_failure(
    p_import_id uuid, p_manifest_id uuid, p_raw_file_byte_sha256 text,
    p_manifest_dataset_jcs_digest text, p_imported_rows_jcs_digest text,
    p_imported_record_count bigint, p_source_health_jcs_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text,
    p_clock_at timestamptz, p_issued_at timestamptz,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_failure_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    existing sentinelflow.demo_history_imports%ROWTYPE;
    now_at timestamptz := clock_timestamp();
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('sentinelflow:demo-history-dataset-v1', 0)
    );
    IF p_failure_code !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR
       p_raw_file_byte_sha256 !~ '^sha256:[0-9a-f]{64}$' OR
       p_manifest_dataset_jcs_digest <>
           'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00' OR
       p_imported_rows_jcs_digest <>
           'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807' OR
       p_imported_record_count <> 4 OR
       p_source_health_jcs_digest <>
           'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe' OR
       p_manifest_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_run_scope_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_public_key_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_signature_verification_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_clock_at <> p_coverage_end OR p_issued_at < p_coverage_end OR
       p_coverage_end <> p_coverage_start + interval '24 hours' THEN
        RETURN;
    END IF;
    SELECT * INTO existing
    FROM sentinelflow.demo_history_imports
    WHERE dataset_id = '019b0000-0000-7000-8000-000000000100'::uuid
    FOR UPDATE;
    IF FOUND THEN
        IF existing.import_id <> p_import_id OR existing.manifest_id <> p_manifest_id OR
           existing.raw_file_byte_sha256::text <> p_raw_file_byte_sha256 OR
           existing.manifest_dataset_jcs_digest::text <> p_manifest_dataset_jcs_digest OR
           existing.imported_rows_jcs_digest::text <> p_imported_rows_jcs_digest OR
           existing.imported_record_count <> p_imported_record_count OR
           existing.source_health_jcs_digest::text <> p_source_health_jcs_digest OR
           existing.manifest_digest::text <> p_manifest_digest OR
           existing.run_scope_digest::text <> p_run_scope_digest OR
           existing.public_key_digest::text <> p_public_key_digest OR
           existing.signature_verification_digest::text <> p_signature_verification_digest OR
           existing.clock_at <> p_clock_at OR existing.issued_at <> p_issued_at OR
           existing.coverage_start <> p_coverage_start OR
           existing.coverage_end <> p_coverage_end OR
           existing.status = 'completed' THEN
            RETURN;
        END IF;
        UPDATE sentinelflow.demo_history_imports
        SET raw_file_byte_sha256 = p_raw_file_byte_sha256::sentinelflow.sha256_digest,
            status = 'failed', failure_code = p_failure_code::sentinelflow.ascii_id,
            attempt_count = attempt_count + 1,
            gateway_record_count = 0, auth_record_count = 0,
            source_coverage_count = 0, started_at = now_at, completed_at = now_at
        WHERE import_id = p_import_id;
        RETURN;
    END IF;
    INSERT INTO sentinelflow.demo_history_imports (
        import_id, schema_version, manifest_id, profile, dataset_id,
        dataset_schema_version, dataset_locator, raw_file_byte_sha256,
        manifest_dataset_jcs_digest, imported_rows_jcs_digest,
        imported_record_count, source_health_jcs_digest, manifest_digest,
        run_scope_digest, public_key_digest, signature_verification_digest,
        path_catalog_version, clock_at, issued_at, coverage_start, coverage_end, status,
        failure_code, attempt_count, started_at, completed_at
    ) VALUES (
        p_import_id, 'demo-history-import-v1', p_manifest_id, 'isolated-demo',
        '019b0000-0000-7000-8000-000000000100'::uuid,
        'demo-history-dataset-v1',
        'contracts/fixtures/demo_history_dataset_v1.json',
        p_raw_file_byte_sha256::sentinelflow.sha256_digest,
        p_manifest_dataset_jcs_digest::sentinelflow.sha256_digest,
        p_imported_rows_jcs_digest::sentinelflow.sha256_digest,
        p_imported_record_count, p_source_health_jcs_digest::sentinelflow.sha256_digest,
        p_manifest_digest::sentinelflow.sha256_digest,
        p_run_scope_digest::sentinelflow.sha256_digest,
        p_public_key_digest::sentinelflow.sha256_digest,
        p_signature_verification_digest::sentinelflow.sha256_digest,
        'path-catalog-v1',
        p_clock_at, p_issued_at, p_coverage_start, p_coverage_end, 'failed',
        p_failure_code::sentinelflow.ascii_id, 1, now_at, now_at
    );
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.read_demo_history_import(p_import_id uuid)
RETURNS TABLE (
    import_id uuid, manifest_id uuid, dataset_id uuid,
    raw_file_byte_sha256 text, manifest_dataset_jcs_digest text,
    imported_rows_jcs_digest text, imported_record_count bigint,
    source_health_jcs_digest text, manifest_digest text,
    run_scope_digest text, public_key_digest text,
    signature_verification_digest text,
    clock_at timestamptz, issued_at timestamptz,
    coverage_start timestamptz, coverage_end timestamptz,
    status text, failure_code text, attempt_count integer,
    gateway_record_count integer, auth_record_count integer,
    source_coverage_count integer, completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sentinelflow.demo_history_imports ledger
        WHERE ledger.import_id = p_import_id AND ledger.status = 'completed'
    ) AND NOT sentinelflow.demo_history_rows_valid(p_import_id) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'completed demo history import evidence drift';
    END IF;
    RETURN QUERY
    SELECT ledger.import_id, ledger.manifest_id, ledger.dataset_id,
        ledger.raw_file_byte_sha256::text,
        ledger.manifest_dataset_jcs_digest::text,
        ledger.imported_rows_jcs_digest::text,
        ledger.imported_record_count::bigint,
        ledger.source_health_jcs_digest::text,
        ledger.manifest_digest::text,
        ledger.run_scope_digest::text, ledger.public_key_digest::text,
        ledger.signature_verification_digest::text,
        ledger.clock_at, ledger.issued_at, ledger.coverage_start, ledger.coverage_end,
        ledger.status, ledger.failure_code::text, ledger.attempt_count,
        ledger.gateway_record_count, ledger.auth_record_count,
        ledger.source_coverage_count, ledger.completed_at
    FROM sentinelflow.demo_history_imports ledger
    WHERE ledger.import_id = p_import_id;
END
$function$;

REVOKE ALL ON demo_history_imports, demo_history_import_batches,
    demo_history_source_coverage FROM PUBLIC, sentinelflow_api,
    sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;

REVOKE ALL ON FUNCTION sentinelflow.guard_demo_history_import_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.reject_demo_history_evidence_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.demo_history_event_jcs(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.demo_history_rows_valid(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.begin_demo_history_import(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.append_demo_history_gateway(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, timestamptz, text, text, text, text, text, text, text,
    text, integer, bigint, bigint, integer
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.append_demo_history_auth(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, text, text, text, text, text
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.append_demo_history_source_coverage(
    uuid, text, text, text, timestamptz, timestamptz, bigint, bigint
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.complete_demo_history_import(uuid)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.record_demo_history_import_failure(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz, text
) FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.read_demo_history_import(uuid)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;

GRANT EXECUTE ON FUNCTION sentinelflow.begin_demo_history_import(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_gateway(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, timestamptz, text, text, text, text, text, text, text,
    text, integer, bigint, bigint, integer
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_auth(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, text, text, text, text, text
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_source_coverage(
    uuid, text, text, text, timestamptz, timestamptz, bigint, bigint
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.complete_demo_history_import(uuid)
    TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.record_demo_history_import_failure(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz, text
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.read_demo_history_import(uuid)
    TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (20, 'demo_history_atomic_import')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
