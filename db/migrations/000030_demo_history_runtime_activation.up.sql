BEGIN;

DO $authority_roles$
DECLARE
    role_name text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 29 AND name = 'retention_action_tombstone') OR
       EXISTS (SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 30) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history runtime activation requires the exact version-29 prefix';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = SESSION_USER
          AND role.rolsuper
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'demo history runtime activation requires a session superuser';
    END IF;

    FOREACH role_name IN ARRAY ARRAY[
        'sentinelflow_demo_importer',
        'sentinelflow_demo_activator'
    ]
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB '
                'NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 '
                'VALID UNTIL ''1970-01-01 00:00:00+00''',
                role_name
            );
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_authid role
            WHERE role.rolname = role_name
              AND (role.rolcanlogin OR role.rolpassword IS NOT NULL OR
                   role.rolinherit OR role.rolsuper OR role.rolcreatedb OR
                   role.rolcreaterole OR role.rolreplication OR
                   role.rolbypassrls OR role.rolconnlimit <> 2 OR
                   role.rolvaliduntil IS DISTINCT FROM
                       '1970-01-01 00:00:00+00'::timestamptz)
        ) OR EXISTS (
            SELECT 1 FROM pg_auth_members membership
            JOIN pg_roles member ON member.oid = membership.member
            JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
            WHERE member.rolname = role_name OR granted_role.rolname = role_name
        ) OR EXISTS (
            SELECT 1 FROM pg_stat_activity activity
            WHERE activity.usename = role_name
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'demo history authority role is not inert and exact';
        END IF;
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), role_name);
        EXECUTE format(
            'ALTER ROLE %I IN DATABASE %I SET search_path = sentinelflow, pg_catalog',
            role_name,
            current_database()
        );
    END LOOP;
END
$authority_roles$;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF to_regprocedure(
        'sentinelflow.verify_demo_history_validation_binding_000022('
        'uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,'
        'timestamptz,timestamptz,timestamptz,timestamptz,text)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.prepare_validation_attempt_exact(uuid,uuid)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_pre_000017(uuid,uuid)'
    ) IS NULL OR to_regclass('sentinelflow.demo_history_runtime_activations') IS NOT NULL OR
       to_regclass('sentinelflow.demo_history_runtime_uses') IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history runtime activation prerequisites are unavailable';
    END IF;
END
$preflight$;

CREATE TABLE demo_history_runtime_activations (
    activation_secret_digest sha256_digest PRIMARY KEY,
    activation_id uuid NOT NULL UNIQUE,
    consumer text NOT NULL CHECK (consumer IN ('analysis', 'validation')),
    claims_digest sha256_digest NOT NULL,
    import_id uuid NOT NULL REFERENCES demo_history_imports (import_id) ON DELETE RESTRICT,
    manifest_id uuid NOT NULL, dataset_id uuid NOT NULL,
    raw_file_digest sha256_digest NOT NULL,
    dataset_jcs_digest sha256_digest NOT NULL,
    imported_rows_digest sha256_digest NOT NULL,
    imported_record_count safe_integer NOT NULL,
    manifest_source_health_digest sha256_digest NOT NULL,
    manifest_digest sha256_digest NOT NULL,
    run_scope_digest sha256_digest NOT NULL,
    public_key_digest sha256_digest NOT NULL,
    signature_verification_digest sha256_digest NOT NULL,
    clock_at timestamptz NOT NULL, issued_at timestamptz NOT NULL,
    coverage_start timestamptz NOT NULL, coverage_end timestamptz NOT NULL,
    impact_source_health_digest sha256_digest NOT NULL,
    activated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    UNIQUE (activation_secret_digest, consumer),
    UNIQUE (consumer),
    UNIQUE (consumer, claims_digest),
    CONSTRAINT demo_history_runtime_activation_lifetime CHECK (
        expires_at = activated_at + interval '1 hour'
    ),
    CONSTRAINT demo_history_runtime_activation_window CHECK (
        clock_at = coverage_end AND coverage_start = clock_at - interval '24 hours'
        AND issued_at >= coverage_end
    )
);

CREATE TABLE demo_history_runtime_capability_expectation (
    bootstrap_id smallint PRIMARY KEY CHECK (bootstrap_id = 1),
    analysis_secret_digest sha256_digest NOT NULL,
    validation_secret_digest sha256_digest NOT NULL,
    pinned_at timestamptz NOT NULL,
    importer_lease_expires_at timestamptz NOT NULL,
    CONSTRAINT demo_history_runtime_capability_distinct CHECK (
        analysis_secret_digest <> validation_secret_digest
    ),
    CONSTRAINT demo_history_runtime_importer_lease_window CHECK (
        importer_lease_expires_at > pinned_at
        AND importer_lease_expires_at <= pinned_at + interval '5 minutes'
    )
);

CREATE TABLE demo_history_runtime_uses (
    consumer text NOT NULL CHECK (consumer IN ('analysis', 'validation')),
    job_id uuid NOT NULL, aggregate_id uuid NOT NULL,
    aggregate_version integer NOT NULL CHECK (aggregate_version >= 1),
    activation_secret_digest sha256_digest NOT NULL,
    used_at timestamptz NOT NULL,
    PRIMARY KEY (consumer, job_id),
    UNIQUE (consumer, aggregate_id, aggregate_version),
    FOREIGN KEY (activation_secret_digest, consumer)
        REFERENCES demo_history_runtime_activations (
            activation_secret_digest, consumer
        ) ON DELETE RESTRICT
);

CREATE TRIGGER demo_history_runtime_activation_append_only
BEFORE UPDATE OR DELETE ON demo_history_runtime_activations
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_demo_history_evidence_mutation();
CREATE TRIGGER demo_history_runtime_capability_expectation_append_only
BEFORE UPDATE OR DELETE ON demo_history_runtime_capability_expectation
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_demo_history_evidence_mutation();
CREATE TRIGGER demo_history_runtime_use_append_only
BEFORE UPDATE OR DELETE ON demo_history_runtime_uses
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_demo_history_evidence_mutation();

CREATE FUNCTION sentinelflow.verify_demo_history_immutable_binding_000030(
    p_import_id uuid,
    p_manifest_id uuid,
    p_dataset_id uuid,
    p_raw_file_digest text,
    p_dataset_jcs_digest text,
    p_imported_rows_digest text,
    p_imported_record_count bigint,
    p_manifest_source_health_digest text,
    p_manifest_digest text,
    p_run_scope_digest text,
    p_public_key_digest text,
    p_signature_verification_digest text,
    p_clock_at timestamptz,
    p_issued_at timestamptz,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz,
    p_impact_source_health_digest text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    ledger sentinelflow.demo_history_imports%ROWTYPE;
BEGIN
    IF p_import_id IS NULL OR p_manifest_id IS NULL OR p_dataset_id IS NULL OR
       p_clock_at IS NULL OR p_issued_at IS NULL OR
       p_coverage_start IS NULL OR p_coverage_end IS NULL OR
       NOT isfinite(p_clock_at) OR NOT isfinite(p_issued_at) OR
       NOT isfinite(p_coverage_start) OR NOT isfinite(p_coverage_end) THEN
        RETURN false;
    END IF;

    SELECT current_ledger.* INTO ledger
    FROM sentinelflow.demo_history_imports current_ledger
    WHERE current_ledger.import_id = p_import_id;
    IF NOT FOUND OR ledger.status <> 'completed' OR ledger.failure_code IS NOT NULL OR
       ledger.completed_at IS NULL OR ledger.schema_version <> 'demo-history-import-v1' OR
       ledger.profile <> 'isolated-demo' OR
       ledger.dataset_schema_version <> 'demo-history-dataset-v1' OR
       ledger.dataset_locator <> 'contracts/fixtures/demo_history_dataset_v1.json' OR
       ledger.path_catalog_version <> 'path-catalog-v1' OR
       ledger.import_id <> p_import_id OR ledger.manifest_id <> p_manifest_id OR
       ledger.dataset_id <> p_dataset_id OR
       ledger.raw_file_byte_sha256::text <> p_raw_file_digest OR
       ledger.manifest_dataset_jcs_digest::text <> p_dataset_jcs_digest OR
       ledger.imported_rows_jcs_digest::text <> p_imported_rows_digest OR
       ledger.imported_record_count::bigint <> p_imported_record_count OR
       ledger.source_health_jcs_digest::text <> p_manifest_source_health_digest OR
       ledger.manifest_digest::text <> p_manifest_digest OR
       ledger.run_scope_digest::text <> p_run_scope_digest OR
       ledger.public_key_digest::text <> p_public_key_digest OR
       ledger.signature_verification_digest::text <> p_signature_verification_digest OR
       ledger.clock_at <> p_clock_at OR ledger.issued_at <> p_issued_at OR
       ledger.coverage_start <> p_coverage_start OR ledger.coverage_end <> p_coverage_end OR
       ledger.gateway_record_count <> 3 OR ledger.auth_record_count <> 1 OR
       ledger.source_coverage_count <> 2 OR
       p_raw_file_digest <> 'sha256:fe1b9e9ed59c74b1522acb63e1c0239cc3defb53f56fbe6125894403b3d341f9' OR
       p_dataset_jcs_digest <> 'sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00' OR
       p_imported_rows_digest <> 'sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807' OR
       p_imported_record_count <> 4 OR
       p_manifest_source_health_digest <> 'sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe' OR
       p_impact_source_health_digest <> 'sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3' OR
       p_dataset_id <> '019b0000-0000-7000-8000-000000000100'::uuid OR
       p_clock_at <> p_coverage_end OR
       p_coverage_start <> p_clock_at - interval '24 hours' OR
       p_issued_at < p_coverage_end OR
       NOT sentinelflow.demo_history_rows_valid(p_import_id) THEN
        RETURN false;
    END IF;
    RETURN true;
END
$function$;

CREATE FUNCTION sentinelflow.read_demo_history_import_recovery_000030(
    p_import_id uuid
)
RETURNS TABLE(
    import_id uuid, manifest_id uuid, schema_version text, profile text,
    dataset_id uuid, dataset_schema_version text, dataset_locator text,
    path_catalog_version text, raw_file_byte_sha256 text,
    manifest_dataset_jcs_digest text, imported_rows_jcs_digest text,
    imported_record_count bigint, source_health_jcs_digest text,
    manifest_digest text, run_scope_digest text, public_key_digest text,
    signature_verification_digest text, clock_at timestamptz,
    issued_at timestamptz, coverage_start timestamptz,
    coverage_end timestamptz, status text, failure_code text,
    attempt_count integer, gateway_record_count integer,
    auth_record_count integer, source_coverage_count integer,
    completed_at timestamptz, rows_valid boolean,
    mapped_gateway_count integer, mapped_auth_count integer,
    coverage_row_count integer
)
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
SELECT ledger.import_id, ledger.manifest_id, ledger.schema_version,
       ledger.profile, ledger.dataset_id, ledger.dataset_schema_version,
       ledger.dataset_locator, ledger.path_catalog_version,
       ledger.raw_file_byte_sha256::text,
       ledger.manifest_dataset_jcs_digest::text,
       ledger.imported_rows_jcs_digest::text,
       ledger.imported_record_count::bigint,
       ledger.source_health_jcs_digest::text,
       ledger.manifest_digest::text, ledger.run_scope_digest::text,
       ledger.public_key_digest::text,
       ledger.signature_verification_digest::text, ledger.clock_at,
       ledger.issued_at, ledger.coverage_start, ledger.coverage_end,
       ledger.status, ledger.failure_code, ledger.attempt_count,
       ledger.gateway_record_count, ledger.auth_record_count,
       ledger.source_coverage_count, ledger.completed_at,
       sentinelflow.demo_history_rows_valid(ledger.import_id),
       (SELECT count(*)::integer
        FROM sentinelflow.demo_history_import_batches mapping
        WHERE mapping.import_id = ledger.import_id
          AND mapping.endpoint_kind = 'gateway'),
       (SELECT count(*)::integer
        FROM sentinelflow.demo_history_import_batches mapping
        WHERE mapping.import_id = ledger.import_id
          AND mapping.endpoint_kind = 'auth'),
       (SELECT count(*)::integer
        FROM sentinelflow.demo_history_source_coverage coverage
        WHERE coverage.import_id = ledger.import_id)
FROM sentinelflow.demo_history_imports ledger
WHERE ledger.import_id = p_import_id
$function$;

CREATE FUNCTION sentinelflow.demo_history_bootstrap_timeouts_exact_000030(
    p_role_name text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    settings text[];
    expected text[];
BEGIN
    expected := CASE p_role_name
        WHEN 'sentinelflow_demo_importer' THEN ARRAY[
            'statement_timeout=30s',
            'transaction_timeout=2min',
            'idle_in_transaction_session_timeout=5s',
            'idle_session_timeout=30s'
        ]
        WHEN 'sentinelflow_demo_activator' THEN ARRAY[
            'statement_timeout=15s',
            'transaction_timeout=30s',
            'idle_in_transaction_session_timeout=5s',
            'idle_session_timeout=30s'
        ]
        ELSE NULL
    END;
    IF expected IS NULL THEN
        RETURN false;
    END IF;
    SELECT role_setting.setconfig INTO settings
    FROM pg_catalog.pg_db_role_setting AS role_setting
    WHERE role_setting.setdatabase = (
              SELECT database.oid FROM pg_catalog.pg_database AS database
              WHERE database.datname = current_database()
          )
      AND role_setting.setrole = pg_catalog.to_regrole(p_role_name);
    RETURN settings IS NOT NULL
       AND settings @> expected
       AND settings @> ARRAY['search_path=sentinelflow, pg_catalog']
       AND pg_catalog.cardinality(settings) = 5;
END
$function$;

CREATE FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
    p_analysis_secret_digest text,
    p_validation_secret_digest text,
    p_importer_lease_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    pinned timestamptz := clock_timestamp();
BEGIN
    IF p_analysis_secret_digest IS NULL OR p_validation_secret_digest IS NULL OR
       p_analysis_secret_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_validation_secret_digest !~ '^sha256:[0-9a-f]{64}$' OR
       p_analysis_secret_digest = p_validation_secret_digest OR
       p_importer_lease_expires_at IS NULL OR
       NOT isfinite(p_importer_lease_expires_at) OR
       p_importer_lease_expires_at <= pinned OR
       p_importer_lease_expires_at > pinned + interval '5 minutes' OR
       NOT sentinelflow.demo_history_bootstrap_timeouts_exact_000030(
           'sentinelflow_demo_importer'
       ) OR NOT sentinelflow.demo_history_bootstrap_timeouts_exact_000030(
           'sentinelflow_demo_activator'
       ) THEN
        RETURN false;
    END IF;
    IF (
        SELECT count(*)
        FROM pg_catalog.pg_authid AS role
        WHERE (
            (
                role.rolname = 'sentinelflow_demo_importer'
            AND role.rolcanlogin
            AND role.rolpassword IS NOT NULL
            AND role.rolpassword ~ '^SCRAM-SHA-256[$][1-9][0-9]*:[A-Za-z0-9+/]+={0,2}[$][A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$'
            AND role.rolvaliduntil = p_importer_lease_expires_at
            ) OR (
                role.rolname = 'sentinelflow_demo_activator'
            AND NOT role.rolcanlogin
            AND role.rolpassword IS NULL
            AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
            )
        )
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
    ) <> 2 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
    ) THEN
        RETURN false;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.demo_history_runtime_capability_expectation
    ) THEN
        -- A same-volume runner restart may only reuse the exact, still-live
        -- immutable bootstrap lease. It never refreshes the five-minute
        -- window, rewrites a digest, or reopens authority after import or
        -- activation state has begun.
        RETURN (
            SELECT count(*) = 1
            FROM sentinelflow.demo_history_runtime_capability_expectation AS expectation
            WHERE expectation.bootstrap_id = 1
              AND expectation.analysis_secret_digest::text = p_analysis_secret_digest
              AND expectation.validation_secret_digest::text = p_validation_secret_digest
              AND expectation.importer_lease_expires_at = p_importer_lease_expires_at
              AND expectation.importer_lease_expires_at > pinned
              AND expectation.pinned_at < expectation.importer_lease_expires_at
        ) AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.demo_history_imports
        ) AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.demo_history_runtime_activations
        ) AND NOT EXISTS (
            SELECT 1 FROM sentinelflow.demo_history_runtime_uses
        );
    END IF;
    INSERT INTO sentinelflow.demo_history_runtime_capability_expectation (
        bootstrap_id, analysis_secret_digest, validation_secret_digest,
        pinned_at, importer_lease_expires_at
    ) VALUES (
        1, p_analysis_secret_digest::sentinelflow.sha256_digest,
        p_validation_secret_digest::sentinelflow.sha256_digest,
        pinned, p_importer_lease_expires_at
    );
    RETURN true;
END
$function$;

CREATE FUNCTION sentinelflow.demo_history_importer_lease_valid_000030()
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
BEGIN
    RETURN SESSION_USER = 'sentinelflow_demo_importer'
       AND sentinelflow.demo_history_bootstrap_timeouts_exact_000030(
           'sentinelflow_demo_importer'
       )
       AND EXISTS (
           SELECT 1
           FROM sentinelflow.demo_history_runtime_capability_expectation AS expectation
           JOIN pg_catalog.pg_roles AS role
             ON role.rolname = 'sentinelflow_demo_importer'
           WHERE expectation.bootstrap_id = 1
             AND expectation.importer_lease_expires_at > server_now
             AND role.rolcanlogin
             AND role.rolpassword IS NOT NULL
             AND role.rolvaliduntil = expectation.importer_lease_expires_at
             AND NOT role.rolinherit AND NOT role.rolsuper
             AND NOT role.rolcreatedb AND NOT role.rolcreaterole
             AND NOT role.rolreplication AND NOT role.rolbypassrls
             AND role.rolconnlimit = 2
       )
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.roleid = pg_catalog.to_regrole('sentinelflow_demo_importer')
              OR membership.member = pg_catalog.to_regrole('sentinelflow_demo_importer')
       );
END
$function$;

CREATE FUNCTION sentinelflow.assert_demo_history_importer_lease_000030()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    -- Acquire the same transaction lock used by every import mutation before
    -- checking wall-clock expiry. A lock wait therefore cannot carry an
    -- otherwise valid call past the server-side lease deadline.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('sentinelflow:demo-history-dataset-v1', 0)
    );
    IF NOT sentinelflow.demo_history_importer_lease_valid_000030() THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'demo history importer lease rejected';
    END IF;
END
$function$;

CREATE FUNCTION sentinelflow.begin_demo_history_import_leased_000030(
    p_import_id uuid, p_manifest_id uuid, p_raw_file_byte_sha256 text,
    p_manifest_dataset_jcs_digest text, p_imported_rows_jcs_digest text,
    p_imported_record_count bigint, p_source_health_jcs_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    RETURN sentinelflow.begin_demo_history_import(
        p_import_id, p_manifest_id, p_raw_file_byte_sha256,
        p_manifest_dataset_jcs_digest, p_imported_rows_jcs_digest,
        p_imported_record_count, p_source_health_jcs_digest,
        p_manifest_digest, p_run_scope_digest, p_public_key_digest,
        p_signature_verification_digest, p_clock_at, p_issued_at,
        p_coverage_start, p_coverage_end
    );
END
$function$;

CREATE FUNCTION sentinelflow.append_demo_history_gateway_leased_000030(
    p_import_id uuid, p_sender_epoch text, p_sequence bigint,
    p_batch_id uuid, p_raw_body_digest text, p_raw_body_size integer,
    p_event_id uuid, p_idempotency_key text, p_request_id uuid,
    p_trace_id uuid, p_started_at timestamptz, p_completed_at timestamptz,
    p_source_ip text, p_method text, p_protocol text, p_route_label text,
    p_path_catalog_version text, p_suspicious_path_id text, p_host text,
    p_service_label text, p_status_code integer, p_request_bytes bigint,
    p_response_bytes bigint, p_latency_ms integer
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    PERFORM sentinelflow.append_demo_history_gateway(
        p_import_id, p_sender_epoch, p_sequence, p_batch_id,
        p_raw_body_digest, p_raw_body_size, p_event_id, p_idempotency_key,
        p_request_id, p_trace_id, p_started_at, p_completed_at, p_source_ip,
        p_method, p_protocol, p_route_label, p_path_catalog_version,
        p_suspicious_path_id, p_host, p_service_label, p_status_code,
        p_request_bytes, p_response_bytes, p_latency_ms
    );
END
$function$;

CREATE FUNCTION sentinelflow.append_demo_history_auth_leased_000030(
    p_import_id uuid, p_sender_epoch text, p_sequence bigint,
    p_batch_id uuid, p_raw_body_digest text, p_raw_body_size integer,
    p_event_id uuid, p_idempotency_key text, p_gateway_request_id uuid,
    p_trace_id uuid, p_occurred_at timestamptz, p_source_ip text,
    p_service_label text, p_route_label text, p_account_hash text,
    p_outcome text
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    PERFORM sentinelflow.append_demo_history_auth(
        p_import_id, p_sender_epoch, p_sequence, p_batch_id,
        p_raw_body_digest, p_raw_body_size, p_event_id, p_idempotency_key,
        p_gateway_request_id, p_trace_id, p_occurred_at, p_source_ip,
        p_service_label, p_route_label, p_account_hash, p_outcome
    );
END
$function$;

CREATE FUNCTION sentinelflow.append_demo_history_source_coverage_leased_000030(
    p_import_id uuid, p_sender_id text, p_endpoint_kind text,
    p_sender_epoch text, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_first_sequence bigint,
    p_last_sequence bigint
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    PERFORM sentinelflow.append_demo_history_source_coverage(
        p_import_id, p_sender_id, p_endpoint_kind, p_sender_epoch,
        p_coverage_start, p_coverage_end, p_first_sequence, p_last_sequence
    );
END
$function$;

CREATE FUNCTION sentinelflow.complete_demo_history_import_leased_000030(
    p_import_id uuid
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    PERFORM sentinelflow.complete_demo_history_import(p_import_id);
END
$function$;

CREATE FUNCTION sentinelflow.record_demo_history_import_failure_leased_000030(
    p_import_id uuid, p_manifest_id uuid, p_raw_file_byte_sha256 text,
    p_manifest_dataset_jcs_digest text, p_imported_rows_jcs_digest text,
    p_imported_record_count bigint, p_source_health_jcs_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_failure_code text
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    PERFORM sentinelflow.record_demo_history_import_failure(
        p_import_id, p_manifest_id, p_raw_file_byte_sha256,
        p_manifest_dataset_jcs_digest, p_imported_rows_jcs_digest,
        p_imported_record_count, p_source_health_jcs_digest,
        p_manifest_digest, p_run_scope_digest, p_public_key_digest,
        p_signature_verification_digest, p_clock_at, p_issued_at,
        p_coverage_start, p_coverage_end, p_failure_code
    );
END
$function$;

CREATE FUNCTION sentinelflow.read_demo_history_import_leased_000030(
    p_import_id uuid
)
RETURNS TABLE (
    import_id uuid, manifest_id uuid, dataset_id uuid,
    raw_file_byte_sha256 text, manifest_dataset_jcs_digest text,
    imported_rows_jcs_digest text, imported_record_count bigint,
    source_health_jcs_digest text, manifest_digest text,
    run_scope_digest text, public_key_digest text,
    signature_verification_digest text, clock_at timestamptz,
    issued_at timestamptz, coverage_start timestamptz,
    coverage_end timestamptz, status text, failure_code text,
    attempt_count integer, gateway_record_count integer,
    auth_record_count integer, source_coverage_count integer,
    completed_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    RETURN QUERY SELECT *
    FROM sentinelflow.read_demo_history_import(p_import_id);
END
$function$;

CREATE FUNCTION sentinelflow.read_demo_history_import_recovery_leased_000030(
    p_import_id uuid
)
RETURNS TABLE(
    import_id uuid, manifest_id uuid, schema_version text, profile text,
    dataset_id uuid, dataset_schema_version text, dataset_locator text,
    path_catalog_version text, raw_file_byte_sha256 text,
    manifest_dataset_jcs_digest text, imported_rows_jcs_digest text,
    imported_record_count bigint, source_health_jcs_digest text,
    manifest_digest text, run_scope_digest text, public_key_digest text,
    signature_verification_digest text, clock_at timestamptz,
    issued_at timestamptz, coverage_start timestamptz,
    coverage_end timestamptz, status text, failure_code text,
    attempt_count integer, gateway_record_count integer,
    auth_record_count integer, source_coverage_count integer,
    completed_at timestamptz, rows_valid boolean,
    mapped_gateway_count integer, mapped_auth_count integer,
    coverage_row_count integer
)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    PERFORM sentinelflow.assert_demo_history_importer_lease_000030();
    RETURN QUERY SELECT *
    FROM sentinelflow.read_demo_history_import_recovery_000030(p_import_id);
END
$function$;

CREATE FUNCTION sentinelflow.verify_demo_history_runtime_activation_000030(
    p_activation_secret bytea, p_consumer text, p_import_id uuid,
    p_manifest_id uuid, p_dataset_id uuid, p_raw_file_digest text,
    p_dataset_jcs_digest text, p_imported_rows_digest text,
    p_imported_record_count bigint, p_manifest_source_health_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_impact_source_health_digest text,
    p_claims_digest text
)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE secret_digest sentinelflow.sha256_digest;
BEGIN
    IF p_activation_secret IS NULL OR octet_length(p_activation_secret) <> 32 OR
       p_activation_secret = decode(repeat('00', 32), 'hex') OR
       p_consumer NOT IN ('analysis', 'validation') OR p_claims_digest IS NULL OR
       p_claims_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RETURN false;
    END IF;
    secret_digest := sentinelflow.validation_sha256(p_activation_secret);
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.demo_history_runtime_activations activation
        WHERE activation.activation_secret_digest = secret_digest
          AND activation.consumer = p_consumer
          AND activation.claims_digest::text = p_claims_digest
          AND activation.import_id = p_import_id AND activation.manifest_id = p_manifest_id
          AND activation.dataset_id = p_dataset_id
          AND activation.raw_file_digest::text = p_raw_file_digest
          AND activation.dataset_jcs_digest::text = p_dataset_jcs_digest
          AND activation.imported_rows_digest::text = p_imported_rows_digest
          AND activation.imported_record_count::bigint = p_imported_record_count
          AND activation.manifest_source_health_digest::text = p_manifest_source_health_digest
          AND activation.manifest_digest::text = p_manifest_digest
          AND activation.run_scope_digest::text = p_run_scope_digest
          AND activation.public_key_digest::text = p_public_key_digest
          AND activation.signature_verification_digest::text = p_signature_verification_digest
          AND activation.clock_at = p_clock_at AND activation.issued_at = p_issued_at
          AND activation.coverage_start = p_coverage_start
          AND activation.coverage_end = p_coverage_end
          AND activation.impact_source_health_digest::text = p_impact_source_health_digest
          AND activation.expires_at > clock_timestamp()
    ) THEN RETURN false; END IF;
    RETURN sentinelflow.verify_demo_history_immutable_binding_000030(
        p_import_id, p_manifest_id, p_dataset_id, p_raw_file_digest,
        p_dataset_jcs_digest, p_imported_rows_digest, p_imported_record_count,
        p_manifest_source_health_digest, p_manifest_digest, p_run_scope_digest,
        p_public_key_digest, p_signature_verification_digest, p_clock_at,
        p_issued_at, p_coverage_start, p_coverage_end,
        p_impact_source_health_digest
    );
END
$function$;

CREATE FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_000030(
    p_analysis_secret bytea, p_validation_secret bytea, p_import_id uuid,
    p_manifest_id uuid, p_dataset_id uuid, p_raw_file_digest text,
    p_dataset_jcs_digest text, p_imported_rows_digest text,
    p_imported_record_count bigint, p_manifest_source_health_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_impact_source_health_digest text,
    p_claims_digest text
)
RETURNS TABLE(analysis_activation_id uuid, validation_activation_id uuid,
    activated_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    analysis_digest sentinelflow.sha256_digest;
    validation_digest sentinelflow.sha256_digest;
    existing_count integer; total_count integer;
    validation_activated_at timestamptz;
    validation_expires_at timestamptz;
    activation_time timestamptz;
BEGIN
    IF p_analysis_secret IS NULL OR p_validation_secret IS NULL OR
       octet_length(p_analysis_secret) <> 32 OR octet_length(p_validation_secret) <> 32 OR
       p_analysis_secret = decode(repeat('00', 32), 'hex') OR
       p_validation_secret = decode(repeat('00', 32), 'hex') OR
       p_analysis_secret = p_validation_secret OR p_claims_digest IS NULL OR
       p_claims_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006', MESSAGE = 'demo activation pair rejected';
    END IF;
    analysis_digest := sentinelflow.validation_sha256(p_analysis_secret);
    validation_digest := sentinelflow.validation_sha256(p_validation_secret);
    IF analysis_digest = validation_digest THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006', MESSAGE = 'demo activation pair rejected';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('sentinelflow:demo-history-activation-pair-v1', 0)
    );
    activation_time := clock_timestamp();
    IF SESSION_USER <> 'sentinelflow_demo_activator' OR
       NOT sentinelflow.demo_history_bootstrap_timeouts_exact_000030(
           'sentinelflow_demo_activator'
       ) OR NOT EXISTS (
           SELECT 1
           FROM sentinelflow.demo_history_runtime_capability_expectation AS expectation
           WHERE expectation.bootstrap_id = 1
             AND expectation.analysis_secret_digest = analysis_digest
             AND expectation.validation_secret_digest = validation_digest
       ) OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'sentinelflow_demo_activator'
             AND role.rolcanlogin
             AND role.rolpassword IS NOT NULL
             AND role.rolvaliduntil > activation_time
             AND role.rolvaliduntil <= activation_time + interval '5 minutes'
             AND NOT role.rolinherit AND NOT role.rolsuper
             AND NOT role.rolcreatedb AND NOT role.rolcreaterole
             AND NOT role.rolreplication AND NOT role.rolbypassrls
             AND role.rolconnlimit = 2
       ) OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.roleid = pg_catalog.to_regrole('sentinelflow_demo_activator')
              OR membership.member = pg_catalog.to_regrole('sentinelflow_demo_activator')
       ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'demo activation bootstrap authority rejected';
    END IF;
    SELECT count(*)::integer INTO total_count
    FROM sentinelflow.demo_history_runtime_activations;
    SELECT count(*)::integer INTO existing_count
    FROM sentinelflow.demo_history_runtime_activations activation
    WHERE activation.claims_digest::text = p_claims_digest
      AND activation.consumer IN ('analysis', 'validation');
    IF total_count = 0 AND existing_count = 0 THEN
        IF p_issued_at < activation_time - interval '5 minutes' OR
	       p_issued_at > activation_time + interval '30 seconds' OR
	       NOT sentinelflow.verify_demo_history_validation_binding_000022(
            p_import_id, p_manifest_id, p_dataset_id, p_raw_file_digest,
            p_dataset_jcs_digest, p_imported_rows_digest, p_imported_record_count,
            p_manifest_source_health_digest, p_manifest_digest, p_run_scope_digest,
            p_public_key_digest, p_signature_verification_digest, p_clock_at,
            p_issued_at, p_coverage_start, p_coverage_end,
            p_impact_source_health_digest
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'SF006',
                MESSAGE = 'fresh demo activation pair unavailable';
        END IF;
        analysis_activation_id := gen_random_uuid();
        validation_activation_id := gen_random_uuid();
        activated_at := activation_time; expires_at := activation_time + interval '1 hour';
        INSERT INTO sentinelflow.demo_history_runtime_activations (
            activation_secret_digest, activation_id, consumer, claims_digest,
            import_id, manifest_id, dataset_id, raw_file_digest, dataset_jcs_digest,
            imported_rows_digest, imported_record_count, manifest_source_health_digest,
            manifest_digest, run_scope_digest, public_key_digest,
            signature_verification_digest, clock_at, issued_at, coverage_start,
            coverage_end, impact_source_health_digest, activated_at, expires_at
        ) VALUES
        (analysis_digest, analysis_activation_id, 'analysis', p_claims_digest::sentinelflow.sha256_digest,
         p_import_id, p_manifest_id, p_dataset_id, p_raw_file_digest::sentinelflow.sha256_digest,
         p_dataset_jcs_digest::sentinelflow.sha256_digest, p_imported_rows_digest::sentinelflow.sha256_digest,
         p_imported_record_count, p_manifest_source_health_digest::sentinelflow.sha256_digest,
         p_manifest_digest::sentinelflow.sha256_digest, p_run_scope_digest::sentinelflow.sha256_digest,
         p_public_key_digest::sentinelflow.sha256_digest,
         p_signature_verification_digest::sentinelflow.sha256_digest,
         p_clock_at, p_issued_at, p_coverage_start, p_coverage_end,
         p_impact_source_health_digest::sentinelflow.sha256_digest, activated_at, expires_at),
        (validation_digest, validation_activation_id, 'validation', p_claims_digest::sentinelflow.sha256_digest,
         p_import_id, p_manifest_id, p_dataset_id, p_raw_file_digest::sentinelflow.sha256_digest,
         p_dataset_jcs_digest::sentinelflow.sha256_digest, p_imported_rows_digest::sentinelflow.sha256_digest,
         p_imported_record_count, p_manifest_source_health_digest::sentinelflow.sha256_digest,
         p_manifest_digest::sentinelflow.sha256_digest, p_run_scope_digest::sentinelflow.sha256_digest,
         p_public_key_digest::sentinelflow.sha256_digest,
         p_signature_verification_digest::sentinelflow.sha256_digest,
         p_clock_at, p_issued_at, p_coverage_start, p_coverage_end,
         p_impact_source_health_digest::sentinelflow.sha256_digest, activated_at, expires_at);
        RETURN NEXT; RETURN;
    END IF;
    IF total_count <> 2 OR existing_count <> 2 OR NOT sentinelflow.verify_demo_history_runtime_activation_000030(
        p_analysis_secret, 'analysis', p_import_id, p_manifest_id, p_dataset_id,
        p_raw_file_digest, p_dataset_jcs_digest, p_imported_rows_digest,
        p_imported_record_count, p_manifest_source_health_digest, p_manifest_digest,
        p_run_scope_digest, p_public_key_digest, p_signature_verification_digest,
        p_clock_at, p_issued_at, p_coverage_start, p_coverage_end,
        p_impact_source_health_digest, p_claims_digest
    ) OR NOT sentinelflow.verify_demo_history_runtime_activation_000030(
        p_validation_secret, 'validation', p_import_id, p_manifest_id, p_dataset_id,
        p_raw_file_digest, p_dataset_jcs_digest, p_imported_rows_digest,
        p_imported_record_count, p_manifest_source_health_digest, p_manifest_digest,
        p_run_scope_digest, p_public_key_digest, p_signature_verification_digest,
        p_clock_at, p_issued_at, p_coverage_start, p_coverage_end,
        p_impact_source_health_digest, p_claims_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'exact demo activation pair unavailable';
    END IF;
    SELECT activation.activation_id, activation.activated_at, activation.expires_at
      INTO analysis_activation_id, activated_at, expires_at
    FROM sentinelflow.demo_history_runtime_activations activation
    WHERE activation.claims_digest::text = p_claims_digest
      AND activation.consumer = 'analysis';
    SELECT activation.activation_id, activation.activated_at, activation.expires_at
      INTO validation_activation_id, validation_activated_at, validation_expires_at
    FROM sentinelflow.demo_history_runtime_activations activation
    WHERE activation.claims_digest::text = p_claims_digest
      AND activation.consumer = 'validation';
    IF activated_at <> validation_activated_at OR expires_at <> validation_expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'exact demo activation pair unavailable';
    END IF;
    RETURN NEXT;
END
$function$;

-- These fixed-scope fences are reassigned to the migration session superuser
-- below. They deliberately accept no role name or credential material. The
-- importer may disable only itself; the activator may disable both bootstrap
-- roles. Each caller is the sole excluded backend and must close immediately
-- after the result is checked.
CREATE FUNCTION sentinelflow.fence_demo_history_importer_role_000030()
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    fence_ready boolean := true;
BEGIN
    EXECUTE 'ALTER ROLE sentinelflow_demo_importer '
            'NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL '
            'VALID UNTIL ''1970-01-01 00:00:00+00''';
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_authid AS role
        WHERE role.rolname = 'sentinelflow_demo_importer'
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = pg_catalog.to_regrole('sentinelflow_demo_importer')
           OR membership.member = pg_catalog.to_regrole('sentinelflow_demo_importer')
    ) THEN
        fence_ready := false;
    END IF;
    RETURN fence_ready;
END
$function$;

CREATE FUNCTION sentinelflow.fence_demo_history_bootstrap_roles_000030()
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    fence_ready boolean := true;
BEGIN
    EXECUTE 'ALTER ROLE sentinelflow_demo_importer '
            'NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL '
            'VALID UNTIL ''1970-01-01 00:00:00+00''';
    EXECUTE 'ALTER ROLE sentinelflow_demo_activator '
            'NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL '
            'VALID UNTIL ''1970-01-01 00:00:00+00''';
    IF (
        SELECT count(*) FROM pg_catalog.pg_authid AS role
        WHERE role.rolname IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
    ) <> 2 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
    ) THEN
        fence_ready := false;
    END IF;
    RETURN fence_ready;
END
$function$;

-- Phase two is deliberately a separate statement. Phase one must commit the
-- NOLOGIN/password-null/expired-valid-until state before phase two scans and
-- terminates sessions; otherwise a login could race between the last scan and
-- the phase-one transaction commit.
CREATE FUNCTION sentinelflow.finalize_demo_history_importer_role_fence_000030()
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    fence_ready boolean := true;
    target_pid integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_authid AS role
        WHERE role.rolname = 'sentinelflow_demo_importer'
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = pg_catalog.to_regrole('sentinelflow_demo_importer')
           OR membership.member = pg_catalog.to_regrole('sentinelflow_demo_importer')
    ) THEN
        RETURN false;
    END IF;
    FOR target_pid IN
        SELECT activity.pid
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename = 'sentinelflow_demo_importer'
          AND activity.pid <> pg_catalog.pg_backend_pid()
        ORDER BY activity.pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(target_pid, 5000) THEN
            fence_ready := false;
        END IF;
    END LOOP;
    PERFORM pg_catalog.pg_stat_clear_snapshot();
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename = 'sentinelflow_demo_importer'
          AND activity.pid <> pg_catalog.pg_backend_pid()
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_authid AS role
        WHERE role.rolname = 'sentinelflow_demo_importer'
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = pg_catalog.to_regrole('sentinelflow_demo_importer')
           OR membership.member = pg_catalog.to_regrole('sentinelflow_demo_importer')
    ) THEN
        fence_ready := false;
    END IF;
    RETURN fence_ready;
END
$function$;

CREATE FUNCTION sentinelflow.finalize_demo_history_bootstrap_role_fence_000030()
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    fence_ready boolean := true;
    target_pid integer;
BEGIN
    IF (
        SELECT count(*) FROM pg_catalog.pg_authid AS role
        WHERE role.rolname IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
    ) <> 2 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
    ) THEN
        RETURN false;
    END IF;
    FOR target_pid IN
        SELECT activity.pid
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND activity.pid <> pg_catalog.pg_backend_pid()
        ORDER BY activity.pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(target_pid, 5000) THEN
            fence_ready := false;
        END IF;
    END LOOP;
    PERFORM pg_catalog.pg_stat_clear_snapshot();
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND activity.pid <> pg_catalog.pg_backend_pid()
    ) OR (
        SELECT count(*) FROM pg_catalog.pg_authid AS role
        WHERE role.rolname IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil = '1970-01-01 00:00:00+00'::timestamptz
    ) <> 2 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
    ) THEN
        fence_ready := false;
    END IF;
    RETURN fence_ready;
END
$function$;

-- This is the only activator-callable entry point. The inner activation
-- function remains owned by the non-login migration role and is never granted
-- to the runtime activator. This wrapper is reassigned to the migration
-- session superuser below so it can atomically turn both cluster-global
-- bootstrap roles inert. Activation
-- errors are contained in a subtransaction: the wrapper still commits the
-- phase-one NOLOGIN/password-null/expired-valid-until fence and reports failure
-- as an empty result. The already-authenticated caller must then execute the
-- separate finalizer statement before treating the activation as successful.
CREATE FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_and_fence_000030(
    p_analysis_secret bytea, p_validation_secret bytea, p_import_id uuid,
    p_manifest_id uuid, p_dataset_id uuid, p_raw_file_digest text,
    p_dataset_jcs_digest text, p_imported_rows_digest text,
    p_imported_record_count bigint, p_manifest_source_health_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_impact_source_health_digest text,
    p_claims_digest text
)
RETURNS TABLE(analysis_activation_id uuid, validation_activation_id uuid,
    activated_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    pair_ready boolean := false;
    fence_ready boolean := true;
BEGIN
    BEGIN
        SELECT pair.analysis_activation_id, pair.validation_activation_id,
               pair.activated_at, pair.expires_at
        INTO analysis_activation_id, validation_activation_id,
             activated_at, expires_at
        FROM sentinelflow.create_demo_history_runtime_activation_pair_000030(
            p_analysis_secret, p_validation_secret, p_import_id,
            p_manifest_id, p_dataset_id, p_raw_file_digest,
            p_dataset_jcs_digest, p_imported_rows_digest,
            p_imported_record_count, p_manifest_source_health_digest,
            p_manifest_digest, p_run_scope_digest, p_public_key_digest,
            p_signature_verification_digest, p_clock_at, p_issued_at,
            p_coverage_start, p_coverage_end,
            p_impact_source_health_digest, p_claims_digest
        ) AS pair;
        pair_ready := FOUND;
    EXCEPTION WHEN OTHERS THEN
        pair_ready := false;
        analysis_activation_id := NULL;
        validation_activation_id := NULL;
        activated_at := NULL;
        expires_at := NULL;
    END;

    fence_ready := sentinelflow.fence_demo_history_bootstrap_roles_000030();

    IF pair_ready AND fence_ready THEN
        RETURN NEXT;
    END IF;
    RETURN;
END
$function$;

CREATE FUNCTION sentinelflow.attach_demo_history_runtime_activation_000030(
    p_activation_secret bytea, p_consumer text, p_import_id uuid,
    p_manifest_id uuid, p_dataset_id uuid, p_raw_file_digest text,
    p_dataset_jcs_digest text, p_imported_rows_digest text,
    p_imported_record_count bigint, p_manifest_source_health_digest text,
    p_manifest_digest text, p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_impact_source_health_digest text,
    p_claims_digest text
)
RETURNS TABLE(activation_id uuid, activated_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF NOT sentinelflow.verify_demo_history_runtime_activation_000030(
        p_activation_secret, p_consumer, p_import_id, p_manifest_id, p_dataset_id,
        p_raw_file_digest, p_dataset_jcs_digest, p_imported_rows_digest,
        p_imported_record_count, p_manifest_source_health_digest, p_manifest_digest,
        p_run_scope_digest, p_public_key_digest, p_signature_verification_digest,
        p_clock_at, p_issued_at, p_coverage_start, p_coverage_end,
        p_impact_source_health_digest, p_claims_digest
    ) THEN RETURN; END IF;
    RETURN QUERY SELECT activation.activation_id, activation.activated_at, activation.expires_at
    FROM sentinelflow.demo_history_runtime_activations activation
    WHERE activation.activation_secret_digest = sentinelflow.validation_sha256(p_activation_secret)
      AND activation.consumer = p_consumer;
END
$function$;

CREATE FUNCTION sentinelflow.record_demo_history_runtime_use_000030(
    p_activation_secret bytea, p_consumer text, p_job_id uuid,
    p_aggregate_id uuid, p_aggregate_version integer
)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE secret_digest sentinelflow.sha256_digest; used timestamptz := clock_timestamp();
BEGIN
    IF p_activation_secret IS NULL OR octet_length(p_activation_secret) <> 32 OR
       p_activation_secret = decode(repeat('00', 32), 'hex') OR
       p_consumer NOT IN ('analysis', 'validation') OR p_job_id IS NULL OR
       p_aggregate_id IS NULL OR p_aggregate_version < 1 THEN RETURN false; END IF;
    secret_digest := sentinelflow.validation_sha256(p_activation_secret);
    IF NOT EXISTS (SELECT 1 FROM sentinelflow.demo_history_runtime_activations activation
        WHERE activation.activation_secret_digest = secret_digest
          AND activation.consumer = p_consumer AND activation.expires_at > used) THEN
        RETURN false;
    END IF;
    INSERT INTO sentinelflow.demo_history_runtime_uses (
        consumer, job_id, aggregate_id, aggregate_version, activation_secret_digest, used_at
    ) VALUES (p_consumer, p_job_id, p_aggregate_id, p_aggregate_version, secret_digest, used)
    ON CONFLICT DO NOTHING;
    RETURN EXISTS (SELECT 1 FROM sentinelflow.demo_history_runtime_uses runtime_use
        WHERE runtime_use.consumer = p_consumer AND runtime_use.job_id = p_job_id
          AND runtime_use.aggregate_id = p_aggregate_id
          AND runtime_use.aggregate_version = p_aggregate_version
          AND runtime_use.activation_secret_digest = secret_digest);
END
$function$;

CREATE FUNCTION sentinelflow.demo_history_impact_digest_000030(
    p_import_id uuid, p_source_ip inet, p_service_label text,
    p_coverage_start timestamptz, p_coverage_end timestamptz,
    p_impact_source_health_digest text
)
RETURNS sentinelflow.sha256_digest LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = pg_catalog, sentinelflow
AS $function$
WITH ledger AS (
    SELECT import_id, manifest_digest, imported_rows_jcs_digest,
           signature_verification_digest, source_health_jcs_digest
    FROM sentinelflow.demo_history_imports
    WHERE import_id = p_import_id AND status = 'completed'
), gateway_projection AS (
    SELECT count(*) AS event_count,
           sentinelflow.validation_sha256(convert_to(COALESCE(string_agg(
               event.event_id::text, chr(10) ORDER BY event.event_id::text), ''), 'UTF8')) AS event_digest
    FROM sentinelflow.demo_history_import_batches mapping
    JOIN sentinelflow.gateway_events event ON mapping.event_kind = 'gateway-http-v1'
     AND event.event_id = mapping.event_id AND event.sender_id = mapping.sender_id
     AND event.sender_epoch = mapping.sender_epoch AND event.batch_id = mapping.batch_id
    WHERE mapping.import_id = p_import_id AND mapping.endpoint_kind = 'gateway'
      AND event.source_ip = p_source_ip AND event.service_label::text = p_service_label
      AND event.completed_at BETWEEN p_coverage_start AND p_coverage_end
), auth_projection AS (
    SELECT count(*) AS event_count,
           count(*) FILTER (WHERE event.outcome = 'succeeded') AS success_count,
           sentinelflow.validation_sha256(convert_to(COALESCE(string_agg(
               event.event_id::text, chr(10) ORDER BY event.event_id::text), ''), 'UTF8')) AS event_digest
    FROM sentinelflow.demo_history_import_batches mapping
    JOIN sentinelflow.auth_events event ON mapping.event_kind = 'auth-event-v1'
     AND event.event_id = mapping.event_id AND event.sender_id = mapping.sender_id
     AND event.sender_epoch = mapping.sender_epoch AND event.batch_id = mapping.batch_id
    WHERE mapping.import_id = p_import_id AND mapping.endpoint_kind = 'auth'
      AND event.source_ip = p_source_ip AND event.service_label::text = p_service_label
      AND event.occurred_at BETWEEN p_coverage_start AND p_coverage_end
)
SELECT sentinelflow.analysis_sha256(convert_to(
    'historical-impact-demo-v1' || chr(10) || ledger.import_id::text || chr(10) ||
    ledger.manifest_digest::text || chr(10) || ledger.imported_rows_jcs_digest::text || chr(10) ||
    ledger.signature_verification_digest::text || chr(10) ||
    ledger.source_health_jcs_digest::text || chr(10) || p_impact_source_health_digest || chr(10) ||
    host(p_source_ip) || chr(10) || p_service_label || chr(10) ||
    to_char(p_coverage_start AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10) ||
    to_char(p_coverage_end AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10) ||
    gateway_projection.event_count::text || chr(10) || gateway_projection.event_digest::text || chr(10) ||
    auth_projection.event_count::text || chr(10) || auth_projection.success_count::text || chr(10) ||
    auth_projection.event_digest::text || chr(10), 'UTF8'))
FROM ledger CROSS JOIN gateway_projection CROSS JOIN auth_projection
$function$;

CREATE FUNCTION sentinelflow.prepare_analysis_attempt_demo_legacy_000030(
    p_job_id uuid,
    p_lease_token uuid,
    p_import_id uuid,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz,
    p_impact_source_health_digest text
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    history_start timestamptz := p_coverage_start;
    history_end timestamptz := p_coverage_end;
    job sentinelflow.outbox_jobs%ROWTYPE;
    incident sentinelflow.incidents%ROWTYPE;
    evidence sentinelflow.evidence_snapshots%ROWTYPE;
    prior sentinelflow.analysis_attempt_claims%ROWTYPE;
    analysis_id_value uuid := gen_random_uuid();
    no_call_code text;
    failure_reason text;
    signal_total integer;
    expanded_total integer;
    signals_json jsonb;
    impact_digest sentinelflow.sha256_digest;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL OR p_import_id IS NULL OR
       p_coverage_start IS NULL OR p_coverage_end IS NULL OR
       p_coverage_end - p_coverage_start <> interval '24 hours' OR
       p_impact_source_health_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid analysis prepare request';
    END IF;

    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'analyze'
      AND current_job.aggregate_type = 'incident'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO incident
    FROM sentinelflow.incidents current_incident
    WHERE current_incident.incident_id = job.aggregate_id
      AND current_incident.version = job.aggregate_version
    FOR UPDATE;
    IF NOT FOUND THEN
        UPDATE sentinelflow.outbox_jobs
        SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = 'analysis_incident_missing',
            last_error_digest = sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8')),
            updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.dead_letter_jobs (
            job_id, kind, aggregate_type, aggregate_id, aggregate_version,
            attempts, failure_code, failure_digest, dead_at
        ) VALUES (
            job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
            job.aggregate_version, job.attempts, 'analysis_incident_missing',
            sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8')), server_now
        ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'analysis-worker', 'analysis_incident_missing',
            'outbox_job', job.job_id, job.aggregate_id,
            sentinelflow.analysis_sha256(convert_to('analysis_incident_missing', 'UTF8')),
            'failed', server_now
        );
        status := 'no_call'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO prior
    FROM sentinelflow.analysis_attempt_claims claim
    WHERE claim.incident_id = incident.incident_id
      AND claim.incident_version = incident.version
    FOR UPDATE;
    IF FOUND THEN
        IF prior.state = 'started' THEN
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'interrupted', no_call_code = 'analysis_interrupted', terminal_at = server_now
            WHERE analysis_id = prior.analysis_id;
            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, failure_reason, completed_at
            ) VALUES (prior.analysis_id, 'interrupted', 'analysis_interrupted', server_now);
            UPDATE sentinelflow.incidents
            SET state = 'analysis_failed', analysis_failure_reason = 'incomplete', updated_at = server_now
            WHERE incident_id = incident.incident_id AND version = incident.version;
            UPDATE sentinelflow.outbox_jobs
            SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
                last_error_code = 'analysis_interrupted',
                last_error_digest = sentinelflow.analysis_sha256(convert_to('analysis_interrupted', 'UTF8')),
                updated_at = server_now
            WHERE job_id = job.job_id;
            INSERT INTO sentinelflow.dead_letter_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                attempts, failure_code, failure_digest, dead_at
            ) VALUES (
                job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
                job.aggregate_version, job.attempts, 'analysis_interrupted',
                sentinelflow.analysis_sha256(convert_to('analysis_interrupted', 'UTF8')), server_now
            ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker', 'analysis_interrupted',
                'analysis', prior.analysis_id, incident.incident_id,
                prior.evidence_snapshot_digest, 'indeterminate', server_now
            );
            status := 'interrupted'; snapshot := NULL; RETURN NEXT; RETURN;
        END IF;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL, last_error_digest = NULL,
            updated_at = server_now
        WHERE job_id = job.job_id;
        status := 'terminal'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO evidence
    FROM sentinelflow.evidence_snapshots candidate
    WHERE candidate.incident_id = incident.incident_id
      AND candidate.incident_version = incident.version
    ORDER BY candidate.created_at DESC, candidate.evidence_snapshot_id
    FOR UPDATE
    LIMIT 1;
    IF NOT FOUND THEN
        no_call_code := 'snapshot_incomplete';
    ELSIF evidence.source_health_status <> 'complete' THEN
        no_call_code := 'source_health_incomplete';
    ELSIF evidence.expires_at <= server_now OR
          evidence.source_ip <> incident.source_ip OR evidence.service_label <> incident.service_label OR
          evidence.signal_count > 50 OR evidence.window_start <> incident.first_seen OR
          evidence.window_end <> incident.last_seen THEN
        no_call_code := 'snapshot_incomplete';
    END IF;

    IF no_call_code IS NULL AND EXISTS (
        SELECT 1
        FROM sentinelflow.evidence_snapshot_signals link
        JOIN sentinelflow.signals signal USING (signal_id)
        WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
          AND signal.source_health_status <> 'complete'
    ) THEN
        no_call_code := 'source_health_incomplete';
    END IF;

    IF no_call_code IS NULL THEN
        SELECT count(*)::integer,
               COALESCE(sum(link.expanded_event_count), 0)::integer
        INTO signal_total, expanded_total
        FROM sentinelflow.evidence_snapshot_signals link
        WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id;

        IF signal_total <> evidence.signal_count OR expanded_total <> evidence.expanded_event_count OR
           NOT EXISTS (
               SELECT 1 FROM sentinelflow.evidence_snapshot_signals link
               WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id AND link.ordinal = 1
           ) OR EXISTS (
               SELECT 1
               FROM sentinelflow.evidence_snapshot_signals link
               JOIN sentinelflow.signals signal USING (signal_id)
               WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
                 AND (link.evidence_id <> signal.signal_id::text OR
                      link.evidence_digest <> signal.evidence_digest OR
                      link.expanded_event_count <> signal.observed_count OR
                      signal.source_ip <> incident.source_ip OR
                      signal.service_label <> incident.service_label OR
                      signal.observed_count < signal.threshold_count OR
                      (signal.threshold_distinct IS NOT NULL AND
                          (signal.distinct_count IS NULL OR signal.distinct_count < signal.threshold_distinct)) OR
                      signal.window_start < evidence.window_start OR signal.window_end > evidence.window_end OR
                      signal.rule_id NOT IN ('path_scan.v1', 'request_burst.v1',
                          'login_bruteforce.v1', 'credential_stuffing.v1'))
           ) OR EXISTS (
               SELECT 1
               FROM (
                   SELECT link.ordinal,
                          row_number() OVER (ORDER BY link.signal_id::text) AS sorted_ordinal
                   FROM sentinelflow.evidence_snapshot_signals link
                   WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id
               ) ordering
               WHERE ordering.ordinal <> ordering.sorted_ordinal
           ) OR EXISTS (
               SELECT 1
               FROM sentinelflow.incident_signals incident_link
               WHERE incident_link.incident_id = incident.incident_id
                 AND incident_link.incident_version = incident.version
                 AND NOT EXISTS (
                     SELECT 1 FROM sentinelflow.evidence_snapshot_signals snapshot_link
                     WHERE snapshot_link.evidence_snapshot_id = evidence.evidence_snapshot_id
                       AND snapshot_link.signal_id = incident_link.signal_id
                 )
           ) OR EXISTS (
               SELECT 1
               FROM sentinelflow.evidence_snapshot_signals snapshot_link
               WHERE snapshot_link.evidence_snapshot_id = evidence.evidence_snapshot_id
                 AND NOT EXISTS (
                     SELECT 1 FROM sentinelflow.incident_signals incident_link
                     WHERE incident_link.incident_id = incident.incident_id
                       AND incident_link.incident_version = incident.version
                       AND incident_link.signal_id = snapshot_link.signal_id
                 )
           ) THEN
            no_call_code := 'snapshot_incomplete';
        END IF;
    END IF;

    IF no_call_code IS NULL AND (
        (SELECT count(*) FROM sentinelflow.evidence_snapshot_events event
         WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id) <> evidence.expanded_event_count OR
        EXISTS (
            SELECT 1
            FROM sentinelflow.evidence_snapshot_events event
            LEFT JOIN sentinelflow.signal_evidence source
              ON source.signal_id = event.signal_id
             AND source.event_kind = event.event_kind
             AND source.gateway_event_id IS NOT DISTINCT FROM event.gateway_event_id
             AND source.auth_event_id IS NOT DISTINCT FROM event.auth_event_id
             AND source.source_health_event_id IS NOT DISTINCT FROM event.source_health_event_id
             AND source.event_time = event.event_time
            WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND source.evidence_link_id IS NULL
        ) OR EXISTS (
            SELECT 1
            FROM sentinelflow.evidence_snapshot_signals snapshot_signal
            JOIN sentinelflow.signal_evidence source ON source.signal_id = snapshot_signal.signal_id
            LEFT JOIN sentinelflow.evidence_snapshot_events event
              ON event.evidence_snapshot_id = snapshot_signal.evidence_snapshot_id
             AND event.signal_id = source.signal_id
             AND event.event_kind = source.event_kind
             AND event.gateway_event_id IS NOT DISTINCT FROM source.gateway_event_id
             AND event.auth_event_id IS NOT DISTINCT FROM source.auth_event_id
             AND event.source_health_event_id IS NOT DISTINCT FROM source.source_health_event_id
             AND event.event_time = source.event_time
            WHERE snapshot_signal.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND event.evidence_snapshot_event_id IS NULL
        ) OR EXISTS (
            SELECT 1
            FROM sentinelflow.evidence_snapshot_events snapshot_event
            LEFT JOIN sentinelflow.gateway_events gateway
              ON snapshot_event.event_kind = 'gateway'
             AND gateway.event_id = snapshot_event.gateway_event_id
             AND gateway.trust_state = 'trusted'
             AND gateway.source_ip = incident.source_ip
             AND gateway.service_label = incident.service_label
            LEFT JOIN sentinelflow.auth_events auth
              ON snapshot_event.event_kind = 'auth'
             AND auth.event_id = snapshot_event.auth_event_id
             AND auth.trust_state = 'trusted'
             AND auth.binding_state = 'verified'
             AND auth.source_ip = incident.source_ip
             AND auth.service_label = incident.service_label
            LEFT JOIN sentinelflow.source_health_intervals health
              ON snapshot_event.event_kind = 'source_health'
             AND health.event_id = snapshot_event.source_health_event_id
             AND health.trust_state = 'trusted'
             AND health.state = 'recovered'
             AND health.dropped_count = 0
            WHERE snapshot_event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND ((snapshot_event.event_kind = 'gateway' AND gateway.event_id IS NULL) OR
                   (snapshot_event.event_kind = 'auth' AND auth.event_id IS NULL) OR
                   (snapshot_event.event_kind = 'source_health' AND health.event_id IS NULL))
        )
    ) THEN
        no_call_code := 'snapshot_incomplete';
    END IF;

    -- Runtime demo history is selected only through the immutable import map.
    IF no_call_code IS NULL AND EXISTS (
        SELECT 1
        FROM sentinelflow.demo_history_import_batches mapping
        JOIN sentinelflow.auth_events auth
          ON mapping.event_kind = 'auth-event-v1'
         AND auth.event_id = mapping.event_id
         AND auth.sender_id = mapping.sender_id
         AND auth.sender_epoch = mapping.sender_epoch
         AND auth.batch_id = mapping.batch_id
        WHERE mapping.import_id = p_import_id
          AND mapping.endpoint_kind = 'auth'
          AND auth.source_ip = incident.source_ip
          AND auth.service_label = incident.service_label
          AND auth.occurred_at BETWEEN history_start AND history_end
          AND auth.outcome = 'succeeded'
          AND auth.trust_state = 'trusted'
          AND auth.binding_state = 'verified'
    ) THEN
        no_call_code := 'history_success_seen';
    END IF;

    IF no_call_code IS NOT NULL THEN
        failure_reason := CASE
            WHEN no_call_code = 'snapshot_incomplete' THEN 'snapshot_incomplete'
            WHEN no_call_code IN ('history_incomplete', 'history_success_seen') THEN 'history_incomplete'
            ELSE 'source_health_incomplete'
        END;
        INSERT INTO sentinelflow.analysis_attempt_claims (
            analysis_id, job_id, incident_id, incident_version,
            evidence_snapshot_id, evidence_snapshot_digest, outbox_attempt,
            state, no_call_code, generated_at, terminal_at
        ) VALUES (
            analysis_id_value, job.job_id, incident.incident_id, incident.version,
            evidence.evidence_snapshot_id, evidence.snapshot_digest, job.attempts,
            'no_call', no_call_code, server_now, server_now
        );
        INSERT INTO sentinelflow.analysis_attempt_results (
            analysis_id, result_state, failure_reason, completed_at
        ) VALUES (analysis_id_value, 'no_call', failure_reason, server_now);
        UPDATE sentinelflow.incidents
        SET state = 'analysis_failed',
            analysis_failure_reason = CASE
                WHEN no_call_code = 'snapshot_incomplete' THEN 'evidence_invalid'
                ELSE 'incomplete'
            END,
            updated_at = server_now
        WHERE incident_id = incident.incident_id AND version = incident.version;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL, last_error_digest = NULL,
            updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'analysis-worker', 'analysis_no_call',
            'analysis', analysis_id_value, incident.incident_id,
            evidence.snapshot_digest, 'rejected', server_now
        );
        status := 'no_call'; snapshot := NULL; RETURN NEXT; RETURN;
    END IF;

    impact_digest := sentinelflow.demo_history_impact_digest_000030(
        p_import_id, incident.source_ip, incident.service_label::text,
        history_start, history_end, p_impact_source_health_digest
    );

    INSERT INTO sentinelflow.analysis_attempt_claims (
        analysis_id, job_id, incident_id, incident_version,
        evidence_snapshot_id, evidence_snapshot_digest, outbox_attempt,
        state, generated_at
    ) VALUES (
        analysis_id_value, job.job_id, incident.incident_id, incident.version,
        evidence.evidence_snapshot_id, evidence.snapshot_digest, job.attempts,
        'started', server_now
    );
    UPDATE sentinelflow.incidents
    SET state = 'analyzing', analysis_failure_reason = NULL, updated_at = server_now
    WHERE incident_id = incident.incident_id AND version = incident.version;

    SELECT jsonb_agg(jsonb_build_object(
        'signal_id', signal.signal_id::text,
        'rule_id', signal.rule_id::text,
        'classification', CASE signal.rule_id::text
            WHEN 'path_scan.v1' THEN 'path_scan'
            WHEN 'request_burst.v1' THEN 'request_burst'
            WHEN 'login_bruteforce.v1' THEN 'brute_force'
            WHEN 'credential_stuffing.v1' THEN 'credential_stuffing'
        END,
        'window_start', signal.window_start,
        'window_end', signal.window_end,
        'event_count', signal.observed_count,
        'distinct_account_count', (
            SELECT count(DISTINCT auth.account_hash)
            FROM sentinelflow.evidence_snapshot_events event
            JOIN sentinelflow.auth_events auth ON auth.event_id = event.auth_event_id
            WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND event.signal_id = signal.signal_id
              AND event.event_kind = 'auth'
              AND auth.outcome = 'failed' AND auth.binding_state = 'verified'
        ),
        'distinct_suspicious_path_count', (
            SELECT count(DISTINCT gateway.suspicious_path_id)
            FROM sentinelflow.evidence_snapshot_events event
            JOIN sentinelflow.gateway_events gateway ON gateway.event_id = event.gateway_event_id
            WHERE event.evidence_snapshot_id = evidence.evidence_snapshot_id
              AND event.signal_id = signal.signal_id
              AND event.event_kind = 'gateway'
              AND gateway.suspicious_path_id <> 'none'
        ),
        'evidence_digest', signal.evidence_digest::text
    ) ORDER BY signal.signal_id::text)
    INTO signals_json
    FROM sentinelflow.evidence_snapshot_signals link
    JOIN sentinelflow.signals signal ON signal.signal_id = link.signal_id
    WHERE link.evidence_snapshot_id = evidence.evidence_snapshot_id;

    status := 'prepared';
    snapshot := jsonb_build_object(
        'incident_id', incident.incident_id::text,
        'incident_version', incident.version,
        'analysis_id', analysis_id_value::text,
        'generated_at', server_now,
        'evidence_snapshot_id', evidence.evidence_snapshot_id::text,
        'evidence_snapshot_digest', evidence.snapshot_digest::text,
        'source_ip', host(incident.source_ip),
        'service_label', incident.service_label::text,
        'window_start', evidence.window_start,
        'window_end', evidence.window_end,
        'detector_config_version', 'detector-config-v1',
        'signals', signals_json,
        'historical_impact', jsonb_build_object(
            'lookback_start', history_start,
            'lookback_end', history_end,
            'impact_digest', impact_digest::text
        )
    );
    RETURN NEXT;
END
$function$;
CREATE FUNCTION sentinelflow.prepare_analysis_attempt_demo_exact_000030(
    p_job_id uuid, p_lease_token uuid, p_import_id uuid,
    p_coverage_start timestamptz, p_coverage_end timestamptz,
    p_impact_source_health_digest text
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    base_status text; base_snapshot jsonb; artifact_bytes bytea;
    artifact_digest sentinelflow.sha256_digest;
BEGIN
    SELECT result.status, result.snapshot INTO base_status, base_snapshot
    FROM sentinelflow.prepare_analysis_attempt_demo_legacy_000030(
        p_job_id, p_lease_token, p_import_id, p_coverage_start,
        p_coverage_end, p_impact_source_health_digest
    ) result;
    IF NOT FOUND THEN RETURN; END IF;
    IF base_status = 'prepared' THEN
        SELECT artifact.canonical_bytes, artifact.canonical_digest
        INTO artifact_bytes, artifact_digest
        FROM sentinelflow.evidence_snapshot_artifacts artifact
        JOIN sentinelflow.evidence_snapshots evidence USING (evidence_snapshot_id)
        WHERE artifact.evidence_snapshot_id = (base_snapshot->>'evidence_snapshot_id')::uuid
          AND artifact.canonical_digest = base_snapshot->>'evidence_snapshot_digest'
          AND evidence.snapshot_digest = artifact.canonical_digest;
        IF NOT FOUND OR artifact_digest <> sentinelflow.validation_sha256(artifact_bytes) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'canonical analysis evidence unavailable';
        END IF;
    END IF;
    status := base_status; snapshot := base_snapshot; RETURN NEXT;
END
$function$;

CREATE FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    p_job_id uuid,
    p_lease_token uuid,
    p_activation_secret bytea, p_import_id uuid, p_manifest_id uuid,
    p_dataset_id uuid, p_raw_file_digest text, p_dataset_jcs_digest text,
    p_imported_rows_digest text, p_imported_record_count bigint,
    p_manifest_source_health_digest text, p_manifest_digest text,
    p_run_scope_digest text, p_public_key_digest text,
    p_signature_verification_digest text, p_clock_at timestamptz,
    p_issued_at timestamptz, p_coverage_start timestamptz,
    p_coverage_end timestamptz, p_impact_source_health_digest text,
    p_claims_digest text
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
    claim sentinelflow.analysis_attempt_claims%ROWTYPE;
    base_status text;
    base_snapshot jsonb;
    signal_total integer;
    analysis_id_value uuid;
    lifecycle_version integer;
    failure_digest sentinelflow.sha256_digest;
BEGIN
    IF NOT sentinelflow.verify_demo_history_runtime_activation_000030(
        p_activation_secret, 'analysis', p_import_id, p_manifest_id,
        p_dataset_id, p_raw_file_digest, p_dataset_jcs_digest,
        p_imported_rows_digest, p_imported_record_count,
        p_manifest_source_health_digest, p_manifest_digest,
        p_run_scope_digest, p_public_key_digest,
        p_signature_verification_digest, p_clock_at, p_issued_at,
        p_coverage_start, p_coverage_end,
        p_impact_source_health_digest, p_claims_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'activated demo analysis history unavailable';
    END IF;

    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid analysis prepare request';
    END IF;
    SELECT * INTO job
    FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id
      AND current_job.kind = 'analyze'
      AND current_job.aggregate_type = 'incident'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now
      AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT * INTO claim
    FROM sentinelflow.analysis_attempt_claims current_claim
    WHERE current_claim.job_id = job.job_id
    FOR UPDATE;
    IF FOUND THEN
        IF claim.state = 'started' THEN
            IF claim.analyzing_incident_version IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'started analysis lacks lifecycle fence';
            END IF;
            lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
                claim.incident_id, claim.analyzing_incident_version,
                'analyzing', 'analysis_failed', 'incomplete', claim.analysis_id
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET state = 'interrupted', no_call_code = 'analysis_interrupted',
                terminal_at = server_now,
                terminal_incident_version = lifecycle_version
            WHERE analysis_id = claim.analysis_id;
            INSERT INTO sentinelflow.analysis_attempt_results (
                analysis_id, result_state, failure_reason, completed_at
            ) VALUES (
                claim.analysis_id, 'interrupted', 'analysis_interrupted', server_now
            );
            failure_digest := sentinelflow.analysis_sha256(
                convert_to('analysis_interrupted', 'UTF8')
            );
            UPDATE sentinelflow.outbox_jobs
            SET state = 'dead', lease_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = 'analysis_interrupted',
                last_error_digest = failure_digest, updated_at = server_now
            WHERE job_id = job.job_id;
            INSERT INTO sentinelflow.dead_letter_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                attempts, failure_code, failure_digest, dead_at
            ) VALUES (
                job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
                job.aggregate_version, job.attempts, 'analysis_interrupted',
                failure_digest, server_now
            ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
            INSERT INTO sentinelflow.audit_events (
                event_id, actor_type, actor_id, action, object_type, object_id,
                incident_id, primary_digest, outcome, occurred_at
            ) VALUES (
                gen_random_uuid(), 'system', 'analysis-worker',
                'analysis_interrupted', 'analysis', claim.analysis_id,
                claim.incident_id, claim.evidence_snapshot_digest,
                'indeterminate', server_now
            );
			IF NOT sentinelflow.record_demo_history_runtime_use_000030(
				p_activation_secret, 'analysis', job.job_id,
				job.aggregate_id, job.aggregate_version
			) THEN
				RAISE EXCEPTION USING ERRCODE = 'SF006',
					MESSAGE = 'activated demo analysis use unavailable';
			END IF;
            status := 'interrupted';
            snapshot := NULL;
            RETURN NEXT;
            RETURN;
        END IF;

        IF claim.state = 'interrupted' THEN
            failure_digest := sentinelflow.analysis_sha256(
                convert_to('analysis_interrupted', 'UTF8')
            );
            UPDATE sentinelflow.outbox_jobs
            SET state = 'dead', lease_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = 'analysis_interrupted',
                last_error_digest = failure_digest, updated_at = server_now
            WHERE job_id = job.job_id;
            INSERT INTO sentinelflow.dead_letter_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                attempts, failure_code, failure_digest, dead_at
            ) VALUES (
                job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
                job.aggregate_version, job.attempts, 'analysis_interrupted',
                failure_digest, server_now
            ) ON CONFLICT ON CONSTRAINT dead_letter_jobs_pkey DO NOTHING;
        ELSE
            UPDATE sentinelflow.outbox_jobs
            SET state = 'completed', lease_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = NULL,
                last_error_digest = NULL, updated_at = server_now
            WHERE job_id = job.job_id;
        END IF;
		IF NOT sentinelflow.record_demo_history_runtime_use_000030(
			p_activation_secret, 'analysis', job.job_id,
			job.aggregate_id, job.aggregate_version
		) THEN
			RAISE EXCEPTION USING ERRCODE = 'SF006',
				MESSAGE = 'activated demo analysis use unavailable';
		END IF;
        status := 'terminal';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT history.signal_count INTO signal_total
    FROM sentinelflow.incident_version_history history
    JOIN sentinelflow.incidents incident
      ON incident.incident_id = history.incident_id
     AND incident.version = history.incident_version
     AND incident.evidence_version = history.incident_version
     AND incident.state = 'open'
    WHERE history.incident_id = job.aggregate_id
      AND history.incident_version = job.aggregate_version;
    IF FOUND AND signal_total > 50 THEN
        analysis_id_value := gen_random_uuid();
        INSERT INTO sentinelflow.analysis_attempt_claims (
            analysis_id, job_id, incident_id, incident_version,
            outbox_attempt, state, no_call_code, generated_at, terminal_at
        ) VALUES (
            analysis_id_value, job.job_id, job.aggregate_id,
            job.aggregate_version, job.attempts, 'no_call',
            'input_too_large', server_now, server_now
        );
        INSERT INTO sentinelflow.analysis_attempt_results (
            analysis_id, result_state, failure_reason, completed_at
        ) VALUES (
            analysis_id_value, 'no_call', 'input_too_large', server_now
        );
        lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
            job.aggregate_id, job.aggregate_version, 'open',
            'analysis_failed', 'input_too_large', analysis_id_value
        );
        UPDATE sentinelflow.analysis_attempt_claims
        SET terminal_incident_version = lifecycle_version
        WHERE analysis_id = analysis_id_value;
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL,
            last_error_digest = NULL, updated_at = server_now
        WHERE job_id = job.job_id;
        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'analysis-worker', 'analysis_no_call',
            'analysis', analysis_id_value, job.aggregate_id,
            sentinelflow.analysis_sha256(convert_to('input_too_large', 'UTF8')),
            'rejected', server_now
        );
		IF NOT sentinelflow.record_demo_history_runtime_use_000030(
			p_activation_secret, 'analysis', job.job_id,
			job.aggregate_id, job.aggregate_version
		) THEN
			RAISE EXCEPTION USING ERRCODE = 'SF006',
				MESSAGE = 'activated demo analysis use unavailable';
		END IF;
        status := 'no_call';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT result.status, result.snapshot INTO base_status, base_snapshot
    FROM sentinelflow.prepare_analysis_attempt_demo_exact_000030(
        p_job_id, p_lease_token, p_import_id, p_coverage_start,
        p_coverage_end, p_impact_source_health_digest
    ) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF base_status = 'prepared' THEN
        SELECT * INTO claim
        FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.job_id = job.job_id
          AND current_claim.state = 'started'
          AND current_claim.incident_version = job.aggregate_version
        FOR UPDATE;
        IF NOT FOUND OR
           (base_snapshot->>'incident_version')::integer <> job.aggregate_version THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'prepared analysis claim mismatch';
        END IF;
        lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
            claim.incident_id, claim.incident_version, 'analyzing',
            'analyzing', NULL, claim.analysis_id
        );
        UPDATE sentinelflow.analysis_attempt_claims
        SET analyzing_incident_version = lifecycle_version
        WHERE analysis_id = claim.analysis_id;
    ELSIF base_status = 'no_call' THEN
        SELECT * INTO claim
        FROM sentinelflow.analysis_attempt_claims current_claim
        WHERE current_claim.job_id = job.job_id
          AND current_claim.state = 'no_call'
          AND current_claim.incident_version = job.aggregate_version
        FOR UPDATE;
        IF NOT FOUND AND EXISTS (
            SELECT 1 FROM sentinelflow.outbox_jobs current_job
            WHERE current_job.job_id = job.job_id
              AND current_job.state = 'dead'
              AND current_job.last_error_code = 'analysis_incident_missing'
        ) THEN
            -- A job whose aggregate never existed has no incident lifecycle to
            -- advance. The preserved function already dead-lettered it.
            NULL;
        ELSIF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'no-call analysis claim mismatch';
        ELSE
            lifecycle_version := sentinelflow.advance_analysis_incident_lifecycle_000017(
                claim.incident_id, claim.incident_version, 'analysis_failed',
                'analysis_failed', (
                    SELECT incident.analysis_failure_reason
                    FROM sentinelflow.incidents incident
                    WHERE incident.incident_id = claim.incident_id
                      AND incident.version = claim.incident_version
                ), claim.analysis_id
            );
            UPDATE sentinelflow.analysis_attempt_claims
            SET terminal_incident_version = lifecycle_version
            WHERE analysis_id = claim.analysis_id;
        END IF;
    ELSIF base_status NOT IN ('interrupted', 'terminal') THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'unknown analysis prepare status';
    END IF;

	IF NOT sentinelflow.record_demo_history_runtime_use_000030(
		p_activation_secret, 'analysis', job.job_id,
		job.aggregate_id, job.aggregate_version
	) THEN
		RAISE EXCEPTION USING ERRCODE = 'SF006',
			MESSAGE = 'activated demo analysis use unavailable';
	END IF;

    status := base_status;
    snapshot := base_snapshot;
    RETURN NEXT;
END
$function$;

CREATE FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000030(
    p_job_id uuid,
    p_lease_token uuid,
    p_activation_secret bytea,
    p_import_id uuid,
    p_manifest_id uuid,
    p_dataset_id uuid,
    p_raw_file_digest text,
    p_dataset_jcs_digest text,
    p_imported_rows_digest text,
    p_imported_record_count bigint,
    p_manifest_source_health_digest text,
    p_manifest_digest text,
    p_run_scope_digest text,
    p_public_key_digest text,
    p_signature_verification_digest text,
    p_clock_at timestamptz,
    p_issued_at timestamptz,
    p_coverage_start timestamptz,
    p_coverage_end timestamptz,
    p_impact_source_health_digest text,
    p_claims_digest text
)
RETURNS TABLE(status text, snapshot jsonb, evidence_canonical bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    base_status text;
    base_snapshot jsonb;
    base_evidence bytea;
    gateway_json jsonb;
    auth_json jsonb;
    prepared jsonb;
    updated_count integer;
    job sentinelflow.outbox_jobs%ROWTYPE;
BEGIN
    IF NOT sentinelflow.verify_demo_history_runtime_activation_000030(
        p_activation_secret, 'validation', p_import_id, p_manifest_id,
        p_dataset_id, p_raw_file_digest, p_dataset_jcs_digest,
        p_imported_rows_digest, p_imported_record_count,
        p_manifest_source_health_digest, p_manifest_digest,
        p_run_scope_digest, p_public_key_digest,
        p_signature_verification_digest, p_clock_at, p_issued_at,
        p_coverage_start, p_coverage_end,
        p_impact_source_health_digest, p_claims_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'activated demo validation history unavailable';
    END IF;

    SELECT * INTO job FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id AND current_job.kind = 'validate'
      AND current_job.aggregate_type = 'analysis_staging'
      AND current_job.state = 'leased'
      AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > statement_timestamp()
    FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT result.status, result.snapshot, result.evidence_canonical
    INTO base_status, base_snapshot, base_evidence
    FROM sentinelflow.prepare_validation_attempt_exact(p_job_id, p_lease_token) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF base_status <> 'prepared' THEN
        status := base_status;
        snapshot := base_snapshot;
        evidence_canonical := base_evidence;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(row_value ORDER BY row_value->>'event_id'), '[]'::jsonb)
    INTO gateway_json
    FROM (
        SELECT jsonb_build_object(
            'event_id', event.event_id::text,
            'occurred_at', event.completed_at,
            'source_ipv4', host(event.source_ip),
            'status_code', event.status_code,
            'timestamp_trust', event.trust_state
        ) AS row_value
        FROM sentinelflow.demo_history_import_batches mapping
        JOIN sentinelflow.gateway_events event
          ON mapping.event_kind = 'gateway-http-v1'
         AND event.event_id = mapping.event_id
         AND event.sender_id = mapping.sender_id
         AND event.sender_epoch = mapping.sender_epoch
         AND event.batch_id = mapping.batch_id
        WHERE mapping.import_id = p_import_id
          AND mapping.endpoint_kind = 'gateway'
          AND event.source_ip = (base_snapshot->'evidence'->>'source_ipv4')::inet
          AND event.completed_at BETWEEN p_coverage_start AND p_coverage_end
    ) exact_gateway;

    SELECT COALESCE(jsonb_agg(row_value ORDER BY row_value->>'event_id'), '[]'::jsonb)
    INTO auth_json
    FROM (
        SELECT jsonb_build_object(
            'event_id', event.event_id::text,
            'occurred_at', event.occurred_at,
            'source_ipv4', host(event.source_ip),
            'outcome', event.outcome,
            'timestamp_trust', event.trust_state,
            'binding', event.binding_state
        ) AS row_value
        FROM sentinelflow.demo_history_import_batches mapping
        JOIN sentinelflow.auth_events event
          ON mapping.event_kind = 'auth-event-v1'
         AND event.event_id = mapping.event_id
         AND event.sender_id = mapping.sender_id
         AND event.sender_epoch = mapping.sender_epoch
         AND event.batch_id = mapping.batch_id
        WHERE mapping.import_id = p_import_id
          AND mapping.endpoint_kind = 'auth'
          AND event.source_ip = (base_snapshot->'evidence'->>'source_ipv4')::inet
          AND event.occurred_at BETWEEN p_coverage_start AND p_coverage_end
    ) exact_auth;

    prepared := jsonb_set(
        base_snapshot,
        '{history}',
        jsonb_build_object(
            'cutoff', p_clock_at,
            'window_start', p_coverage_start,
            'coverage_complete', true,
            'gateway_records', gateway_json,
            'auth_records', auth_json
        ),
        false
    );

    UPDATE sentinelflow.validation_attempt_claims claim
    SET prepared_snapshot = prepared,
        prepared_snapshot_digest = sentinelflow.validation_sha256(
            convert_to(prepared::text, 'UTF8')
        )
    WHERE claim.job_id = p_job_id
      AND claim.validation_attempt_id = (prepared->>'validation_attempt_id')::uuid
      AND claim.state = 'started';
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    IF updated_count <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'verified demo validation claim unavailable';
    END IF;

    IF NOT sentinelflow.record_demo_history_runtime_use_000030(
        p_activation_secret, 'validation', job.job_id,
        job.aggregate_id, job.aggregate_version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'activated demo validation use unavailable';
    END IF;

    status := 'prepared';
    snapshot := prepared;
    evidence_canonical := base_evidence;
    RETURN NEXT;
END
$function$;


REVOKE ALL ON demo_history_runtime_activations, demo_history_runtime_uses,
demo_history_runtime_capability_expectation
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
sentinelflow_dispatcher, sentinelflow_demo_importer, sentinelflow_demo_activator;

REVOKE ALL ON FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_000030(
bytea,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_demo_importer,sentinelflow_demo_activator;

REVOKE ALL ON FUNCTION sentinelflow.attach_demo_history_runtime_activation_000030(
bytea,text,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
FROM PUBLIC,sentinelflow_api,sentinelflow_read,sentinelflow_dispatcher,
sentinelflow_demo_importer,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.attach_demo_history_runtime_activation_000030(
bytea,text,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
TO sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
FROM PUBLIC,sentinelflow_api,sentinelflow_read,sentinelflow_dispatcher,
sentinelflow_demo_importer,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text) TO sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000030(
uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
FROM PUBLIC,sentinelflow_api,sentinelflow_read,sentinelflow_dispatcher,
sentinelflow_demo_importer,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000030(
uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text) TO sentinelflow_worker;

REVOKE EXECUTE ON FUNCTION sentinelflow.begin_demo_history_import(
uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz)
FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.append_demo_history_gateway(
uuid,text,bigint,uuid,text,integer,uuid,text,uuid,uuid,timestamptz,timestamptz,
text,text,text,text,text,text,text,text,integer,bigint,bigint,integer)
FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.append_demo_history_auth(
uuid,text,bigint,uuid,text,integer,uuid,text,uuid,uuid,timestamptz,
text,text,text,text,text) FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.append_demo_history_source_coverage(
uuid,text,text,text,timestamptz,timestamptz,bigint,bigint)
FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.complete_demo_history_import(uuid)
FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.record_demo_history_import_failure(
uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,
timestamptz,timestamptz,timestamptz,text)
FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.read_demo_history_import(uuid)
FROM sentinelflow_worker,sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.verify_demo_history_validation_binding_000022(
uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,
timestamptz,timestamptz,timestamptz,text) FROM sentinelflow_worker;
REVOKE EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000022(
uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text) FROM sentinelflow_worker;

GRANT USAGE ON SCHEMA sentinelflow TO sentinelflow_demo_importer,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.begin_demo_history_import_leased_000030(
uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz) TO sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_gateway_leased_000030(
uuid,text,bigint,uuid,text,integer,uuid,text,uuid,uuid,timestamptz,timestamptz,
text,text,text,text,text,text,text,text,integer,bigint,bigint,integer) TO sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_auth_leased_000030(
uuid,text,bigint,uuid,text,integer,uuid,text,uuid,uuid,timestamptz,
text,text,text,text,text) TO sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_source_coverage_leased_000030(
uuid,text,text,text,timestamptz,timestamptz,bigint,bigint) TO sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.complete_demo_history_import_leased_000030(uuid)
TO sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.record_demo_history_import_failure_leased_000030(
uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,
timestamptz,timestamptz,timestamptz,text) TO sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.read_demo_history_import_leased_000030(uuid)
TO sentinelflow_demo_importer;

REVOKE ALL ON FUNCTION sentinelflow.begin_demo_history_import_leased_000030(
uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.append_demo_history_gateway_leased_000030(
uuid,text,bigint,uuid,text,integer,uuid,text,uuid,uuid,timestamptz,timestamptz,
text,text,text,text,text,text,text,text,integer,bigint,bigint,integer)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.append_demo_history_auth_leased_000030(
uuid,text,bigint,uuid,text,integer,uuid,text,uuid,uuid,timestamptz,
text,text,text,text,text)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.append_demo_history_source_coverage_leased_000030(
uuid,text,text,text,timestamptz,timestamptz,bigint,bigint)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.complete_demo_history_import_leased_000030(uuid)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.record_demo_history_import_failure_leased_000030(
uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,
timestamptz,timestamptz,timestamptz,text)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.read_demo_history_import_leased_000030(uuid)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_retention,sentinelflow_lifecycle,
sentinelflow_metrics,sentinelflow_demo_activator;

REVOKE ALL ON FUNCTION sentinelflow.verify_demo_history_immutable_binding_000030(
uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,
timestamptz,timestamptz,timestamptz,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.verify_demo_history_runtime_activation_000030(
bytea,text,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.record_demo_history_runtime_use_000030(
bytea,text,uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.demo_history_impact_digest_000030(
uuid,inet,text,timestamptz,timestamptz,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_demo_legacy_000030(
uuid,uuid,uuid,timestamptz,timestamptz,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_demo_exact_000030(
uuid,uuid,uuid,timestamptz,timestamptz,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.read_demo_history_import_recovery_000030(uuid)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_demo_activator,sentinelflow_demo_importer;
REVOKE ALL ON FUNCTION sentinelflow.read_demo_history_import_recovery_leased_000030(uuid)
FROM PUBLIC,sentinelflow_api,sentinelflow_worker,sentinelflow_read,
sentinelflow_dispatcher,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.read_demo_history_import_recovery_leased_000030(uuid)
TO sentinelflow_demo_importer;
REVOKE ALL ON FUNCTION sentinelflow.demo_history_bootstrap_timeouts_exact_000030(text)
FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.demo_history_importer_lease_valid_000030()
FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.assert_demo_history_importer_lease_000030()
FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
text,text,timestamptz) FROM PUBLIC,sentinelflow_migration,sentinelflow_api,
sentinelflow_worker,sentinelflow_read,sentinelflow_dispatcher,
sentinelflow_retention,sentinelflow_lifecycle,sentinelflow_metrics,
sentinelflow_demo_importer,sentinelflow_demo_activator;

RESET ROLE;
ALTER FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
text,text,timestamptz) OWNER TO SESSION_USER;
ALTER FUNCTION sentinelflow.fence_demo_history_importer_role_000030()
OWNER TO SESSION_USER;
ALTER FUNCTION sentinelflow.finalize_demo_history_importer_role_fence_000030()
OWNER TO SESSION_USER;
ALTER FUNCTION sentinelflow.fence_demo_history_bootstrap_roles_000030()
OWNER TO SESSION_USER;
ALTER FUNCTION sentinelflow.finalize_demo_history_bootstrap_role_fence_000030()
OWNER TO SESSION_USER;
ALTER FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_and_fence_000030(
bytea,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text) OWNER TO SESSION_USER;
REVOKE ALL ON FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
text,text,timestamptz) FROM PUBLIC,sentinelflow_migration,sentinelflow_api,
sentinelflow_worker,sentinelflow_read,sentinelflow_dispatcher,
sentinelflow_retention,sentinelflow_lifecycle,sentinelflow_metrics,
sentinelflow_demo_importer,sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.fence_demo_history_importer_role_000030()
FROM PUBLIC,sentinelflow_migration,sentinelflow_api,sentinelflow_worker,
sentinelflow_read,sentinelflow_dispatcher,sentinelflow_retention,
sentinelflow_lifecycle,sentinelflow_metrics,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.fence_demo_history_importer_role_000030()
TO sentinelflow_demo_importer;
REVOKE ALL ON FUNCTION sentinelflow.finalize_demo_history_importer_role_fence_000030()
FROM PUBLIC,sentinelflow_migration,sentinelflow_api,sentinelflow_worker,
sentinelflow_read,sentinelflow_dispatcher,sentinelflow_retention,
sentinelflow_lifecycle,sentinelflow_metrics,sentinelflow_demo_activator;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_demo_history_importer_role_fence_000030()
TO sentinelflow_demo_importer;
REVOKE ALL ON FUNCTION sentinelflow.fence_demo_history_bootstrap_roles_000030()
FROM PUBLIC,sentinelflow_migration,sentinelflow_api,sentinelflow_worker,
sentinelflow_read,sentinelflow_dispatcher,sentinelflow_retention,
sentinelflow_lifecycle,sentinelflow_metrics,sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.fence_demo_history_bootstrap_roles_000030()
TO sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.finalize_demo_history_bootstrap_role_fence_000030()
FROM PUBLIC,sentinelflow_migration,sentinelflow_api,sentinelflow_worker,
sentinelflow_read,sentinelflow_dispatcher,sentinelflow_retention,
sentinelflow_lifecycle,sentinelflow_metrics,sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_demo_history_bootstrap_role_fence_000030()
TO sentinelflow_demo_activator;
REVOKE ALL ON FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_and_fence_000030(
bytea,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
FROM PUBLIC,sentinelflow_migration,sentinelflow_api,sentinelflow_worker,
sentinelflow_read,sentinelflow_dispatcher,sentinelflow_retention,
sentinelflow_lifecycle,sentinelflow_metrics,sentinelflow_demo_importer;
GRANT EXECUTE ON FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_and_fence_000030(
bytea,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,
timestamptz,timestamptz,timestamptz,timestamptz,text,text)
TO sentinelflow_demo_activator;
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

INSERT INTO sentinelflow.schema_migrations(version,name)
VALUES (30,'demo_history_runtime_activation');
COMMIT;
