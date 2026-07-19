BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 32 AND name = 'validation_attempt_api_projection'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 33
    ) OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_pre_000033(uuid,uuid)'
    ) IS NOT NULL OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_verified_demo_pre_000033(uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,timestamptz,timestamptz,timestamptz,text,text)'
    ) IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis stale-version resolution requires the exact version-32 prefix';
    END IF;
END
$preflight$;

-- A queued analysis job can become stale before it crosses the provider
-- boundary. The current incident projection is intentionally a single row, so
-- an exact lookup by the old aggregate version used to look indistinguishable
-- from a missing incident. Resolve only when immutable history proves that the
-- requested version existed and the current projection has moved forward.
CREATE FUNCTION sentinelflow.resolve_queued_stale_analysis_000033(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
    current_version integer;
    supersession_digest sentinelflow.sha256_digest;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid queued analysis supersession request';
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
        RETURN false;
    END IF;

    -- The row may have been blocked behind another transaction until after
    -- the lease expired. Never reuse the pre-lock clock value as authority.
    server_now := clock_timestamp();
    IF job.lease_expires_at IS NULL OR job.lease_expires_at <= server_now OR
       job.updated_at > server_now THEN
        RETURN false;
    END IF;

    -- A claim means the provider boundary was already crossed. Its immutable
    -- lifecycle remains owned by the existing in-flight interruption path.
    IF EXISTS (
        SELECT 1 FROM sentinelflow.analysis_attempt_claims claim
        WHERE claim.job_id = job.job_id
    ) THEN
        RETURN false;
    END IF;

    SELECT incident.version INTO current_version
    FROM sentinelflow.incidents incident
    WHERE incident.incident_id = job.aggregate_id
      AND incident.version > job.aggregate_version
    FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1
        FROM sentinelflow.incident_version_history history
        WHERE history.incident_id = job.aggregate_id
          AND history.incident_version = job.aggregate_version
    ) THEN
        RETURN false;
    END IF;

    supersession_digest := sentinelflow.analysis_sha256(convert_to(
        'queued-analysis-superseded-v1' || chr(10) ||
        job.job_id::text || chr(10) || job.aggregate_id::text || chr(10) ||
        job.aggregate_version::text || chr(10) || current_version::text || chr(10),
        'UTF8'
    ));

    UPDATE sentinelflow.outbox_jobs
    SET state = 'completed', lease_token = NULL, lease_owner = NULL,
        lease_expires_at = NULL, last_error_code = NULL,
        last_error_digest = NULL, updated_at = server_now
    WHERE job_id = job.job_id;

    INSERT INTO sentinelflow.audit_events (
        event_id, actor_type, actor_id, action, object_type, object_id,
        incident_id, primary_digest, outcome, occurred_at
    ) VALUES (
        gen_random_uuid(), 'system', 'analysis-worker',
        'analysis_superseded', 'outbox_job', job.job_id,
        job.aggregate_id, supersession_digest, 'rejected', server_now
    );

    RETURN true;
END
$function$;

ALTER FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    RENAME TO prepare_analysis_attempt_pre_000033;

CREATE FUNCTION sentinelflow.prepare_analysis_attempt(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF sentinelflow.resolve_queued_stale_analysis_000033(
        p_job_id, p_lease_token
    ) THEN
        status := 'terminal';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    RETURN QUERY
    SELECT prepared.status, prepared.snapshot
    FROM sentinelflow.prepare_analysis_attempt_pre_000033(
        p_job_id, p_lease_token
    ) prepared;
END
$function$;

ALTER FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
) RENAME TO prepare_analysis_attempt_verified_demo_pre_000033;

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
BEGIN
    -- Preserve the activated-demo capability boundary even when no provider
    -- call is needed for a stale queued job.
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

    IF sentinelflow.resolve_queued_stale_analysis_000033(
        p_job_id, p_lease_token
    ) THEN
        IF NOT sentinelflow.record_demo_history_runtime_use_000030(
            p_activation_secret, 'analysis', p_job_id,
            (SELECT job.aggregate_id FROM sentinelflow.outbox_jobs job
             WHERE job.job_id = p_job_id),
            (SELECT job.aggregate_version FROM sentinelflow.outbox_jobs job
             WHERE job.job_id = p_job_id)
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'SF006',
                MESSAGE = 'activated demo analysis use unavailable';
        END IF;
        status := 'terminal';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    RETURN QUERY
    SELECT prepared.status, prepared.snapshot
    FROM sentinelflow.prepare_analysis_attempt_verified_demo_pre_000033(
        p_job_id, p_lease_token, p_activation_secret, p_import_id,
        p_manifest_id, p_dataset_id, p_raw_file_digest,
        p_dataset_jcs_digest, p_imported_rows_digest,
        p_imported_record_count, p_manifest_source_health_digest,
        p_manifest_digest, p_run_scope_digest, p_public_key_digest,
        p_signature_verification_digest, p_clock_at, p_issued_at,
        p_coverage_start, p_coverage_end, p_impact_source_health_digest,
        p_claims_digest
    ) prepared;
END
$function$;

-- Repair only prior rows that were demonstrably misclassified as missing by
-- the old exact-current-version lookup. The dead-letter row must be a complete
-- byte-for-byte identity copy of the dead outbox failure and no provider claim
-- may exist. Any anomalous or intentional in-flight supersession evidence is
-- preserved untouched.
DO $repair_misclassified_stale_analysis$
DECLARE
    candidate record;
    corrected_at timestamptz;
    correction_digest sentinelflow.sha256_digest;
    changed_count integer;
BEGIN
    FOR candidate IN
        SELECT
            job.job_id, job.kind, job.aggregate_type, job.aggregate_id,
            job.aggregate_version, job.attempts, job.last_error_code,
            job.last_error_digest, incident.version AS current_version
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.dead_letter_jobs dead ON dead.job_id = job.job_id
        JOIN sentinelflow.incidents incident
          ON incident.incident_id = job.aggregate_id
         AND incident.version > job.aggregate_version
        WHERE job.kind = 'analyze'
          AND job.aggregate_type = 'incident'
          AND job.state = 'dead'
          AND job.last_error_code = 'analysis_incident_missing'
          AND job.last_error_digest = sentinelflow.analysis_sha256(
              convert_to('analysis_incident_missing', 'UTF8')
          )
          AND dead.resolution_state = 'unresolved'
          AND dead.kind = job.kind
          AND dead.aggregate_type::text = job.aggregate_type::text
          AND dead.aggregate_id = job.aggregate_id
          AND dead.aggregate_version = job.aggregate_version
          AND dead.attempts = job.attempts
          AND dead.failure_code::text = job.last_error_code::text
          AND dead.failure_digest = job.last_error_digest
          AND NOT EXISTS (
              SELECT 1 FROM sentinelflow.analysis_attempt_claims claim
              WHERE claim.job_id = job.job_id
          )
          AND EXISTS (
              SELECT 1 FROM sentinelflow.incident_version_history history
              WHERE history.incident_id = job.aggregate_id
                AND history.incident_version = job.aggregate_version
          )
        ORDER BY job.job_id
        FOR UPDATE OF job, dead, incident
    LOOP
        corrected_at := clock_timestamp();
        correction_digest := sentinelflow.analysis_sha256(convert_to(
            'queued-analysis-superseded-reconciliation-v1' || chr(10) ||
            candidate.job_id::text || chr(10) ||
            candidate.aggregate_id::text || chr(10) ||
            candidate.aggregate_version::text || chr(10) ||
            candidate.current_version::text || chr(10) ||
            candidate.last_error_digest::text || chr(10),
            'UTF8'
        ));

        UPDATE sentinelflow.dead_letter_jobs dead
        SET resolution_state = 'resolved', resolved_at = corrected_at,
            resolution_actor = 'sentinelflow_migration',
            resolution_digest = correction_digest
        WHERE dead.job_id = candidate.job_id
          AND dead.resolution_state = 'unresolved'
          AND dead.kind = candidate.kind
          AND dead.aggregate_type::text = candidate.aggregate_type::text
          AND dead.aggregate_id = candidate.aggregate_id
          AND dead.aggregate_version = candidate.aggregate_version
          AND dead.attempts = candidate.attempts
          AND dead.failure_code::text = candidate.last_error_code::text
          AND dead.failure_digest = candidate.last_error_digest;
        GET DIAGNOSTICS changed_count = ROW_COUNT;
        IF changed_count <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '40001',
                MESSAGE = 'analysis stale-version dead-letter changed';
        END IF;

        UPDATE sentinelflow.outbox_jobs job
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL,
            last_error_digest = NULL, updated_at = corrected_at
        WHERE job.job_id = candidate.job_id
          AND job.state = 'dead'
          AND job.kind = candidate.kind
          AND job.aggregate_type::text = candidate.aggregate_type::text
          AND job.aggregate_id = candidate.aggregate_id
          AND job.aggregate_version = candidate.aggregate_version
          AND job.attempts = candidate.attempts
          AND job.last_error_code::text = candidate.last_error_code::text
          AND job.last_error_digest = candidate.last_error_digest;
        GET DIAGNOSTICS changed_count = ROW_COUNT;
        IF changed_count <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '40001',
                MESSAGE = 'analysis stale-version outbox changed';
        END IF;

        INSERT INTO sentinelflow.audit_events (
            event_id, actor_type, actor_id, action, object_type, object_id,
            incident_id, primary_digest, secondary_digest, outcome, occurred_at
        ) VALUES (
            gen_random_uuid(), 'system', 'sentinelflow-migration',
            'analysis_superseded_reconciled', 'outbox_job', candidate.job_id,
            candidate.aggregate_id, correction_digest,
            candidate.last_error_digest, 'rejected', corrected_at
        );
    END LOOP;
END
$repair_misclassified_stale_analysis$;

REVOKE ALL ON FUNCTION sentinelflow.resolve_queued_stale_analysis_000033(
    uuid, uuid
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_pre_000033(
    uuid, uuid
) FROM PUBLIC, sentinelflow_worker;
REVOKE ALL ON FUNCTION
    sentinelflow.prepare_analysis_attempt_verified_demo_pre_000033(
        uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint,
        text, text, text, text, text, timestamptz, timestamptz,
        timestamptz, timestamptz, text, text
    )
FROM PUBLIC, sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
) TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (33, 'analysis_stale_version_resolution');

COMMIT;
