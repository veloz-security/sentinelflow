BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Recheck every public claim minted by the strict Ed25519 verifier against
-- the completed import ledger and its canonical mapped rows. The function is
-- deliberately boolean and content-free: callers receive no event or key
-- material. issued_at is real security time; clock_at is only the sealed
-- historical cutoff, so issued_at may be later than clock_at.
CREATE OR REPLACE FUNCTION sentinelflow.verify_demo_history_validation_binding_000022(
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
    security_now timestamptz := statement_timestamp();
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
       p_issued_at < security_now - interval '5 minutes' OR
       p_issued_at > security_now + interval '30 seconds' OR
       NOT sentinelflow.demo_history_rows_valid(p_import_id) THEN
        RETURN false;
    END IF;
    RETURN true;
END
$function$;

-- Prepare through the evidence-version-fenced 000019 entry point first, then
-- replace only the historical projection with rows mapped to this exact demo
-- import. Arbitrary retained rows at the same IP/time can never enter this
-- projection. The real database generated_at remains untouched and therefore
-- owns validation validity; only history.cutoff uses the sealed demo clock.
CREATE OR REPLACE FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000022(
    p_job_id uuid,
    p_lease_token uuid,
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
BEGIN
    IF NOT sentinelflow.verify_demo_history_validation_binding_000022(
        p_import_id, p_manifest_id, p_dataset_id,
        p_raw_file_digest, p_dataset_jcs_digest, p_imported_rows_digest,
        p_imported_record_count, p_manifest_source_health_digest,
        p_manifest_digest, p_run_scope_digest, p_public_key_digest,
        p_signature_verification_digest, p_clock_at, p_issued_at,
        p_coverage_start, p_coverage_end, p_impact_source_health_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'SF006',
            MESSAGE = 'verified demo history binding unavailable';
    END IF;

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

    status := 'prepared';
    snapshot := prepared;
    evidence_canonical := base_evidence;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.verify_demo_history_validation_binding_000022(
    uuid, uuid, uuid, text, text, text, bigint, text, text, text, text,
    text, timestamptz, timestamptz, timestamptz, timestamptz, text
) FROM PUBLIC, sentinelflow_api, sentinelflow_read, sentinelflow_dispatcher;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000022(
    uuid, uuid, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz, text
) FROM PUBLIC, sentinelflow_api, sentinelflow_read, sentinelflow_dispatcher;

GRANT EXECUTE ON FUNCTION sentinelflow.verify_demo_history_validation_binding_000022(
    uuid, uuid, uuid, text, text, text, bigint, text, text, text, text,
    text, timestamptz, timestamptz, timestamptz, timestamptz, text
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000022(
    uuid, uuid, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz, text
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (22, 'demo_history_validation_binding')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
