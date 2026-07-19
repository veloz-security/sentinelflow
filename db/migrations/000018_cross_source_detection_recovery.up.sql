BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Preserve the reviewed 000016 function for an evidence-safe rollback. The
-- source check deliberately fails on drift instead of patching an unknown
-- function body. Reapplying this migration verifies both definitions.
DO $preserve_detection_prepare$
DECLARE
    current_definition text;
    preserved_definition text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 17 AND name = 'analysis_lifecycle_alignment'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cross-source recovery requires migration 000017';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 18 AND name <> 'cross_source_detection_recovery'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'schema migration 18 identity conflict';
    END IF;

    IF to_regprocedure(
        'sentinelflow.prepare_detection_job_pre_000018(uuid,uuid)'
    ) IS NULL THEN
        IF to_regprocedure(
            'sentinelflow.prepare_detection_job(uuid,uuid)'
        ) IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'detection prepare function is missing';
        END IF;
        SELECT pg_get_functiondef(
            'sentinelflow.prepare_detection_job(uuid,uuid)'::regprocedure
        ) INTO current_definition;
        IF position(
            'evaluation_time := date_trunc(''milliseconds'', job.created_at);'
            IN current_definition
        ) = 0 OR position(
            'cross-source-evaluation-time-v2' IN current_definition
        ) > 0 THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'detection prepare source drift';
        END IF;
        ALTER FUNCTION sentinelflow.prepare_detection_job(uuid, uuid)
            RENAME TO prepare_detection_job_pre_000018;
    ELSE
        SELECT pg_get_functiondef(
            'sentinelflow.prepare_detection_job_pre_000018(uuid,uuid)'::regprocedure
        ) INTO preserved_definition;
        IF position(
            'evaluation_time := date_trunc(''milliseconds'', job.created_at);'
            IN preserved_definition
        ) = 0 THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'preserved detection prepare source drift';
        END IF;
        IF to_regprocedure(
            'sentinelflow.prepare_detection_job(uuid,uuid)'
        ) IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'cross-source detection prepare function is missing';
        END IF;
        SELECT pg_get_functiondef(
            'sentinelflow.prepare_detection_job(uuid,uuid)'::regprocedure
        ) INTO current_definition;
        -- A full repository reapply executes 000016 before reaching this
        -- migration again, so the public name may contain either the exact
        -- reviewed 000016 body or this migration's replacement. Anything else
        -- is unreviewed drift. CREATE OR REPLACE below reinstalls v2.
        IF position(
            'cross-source-evaluation-time-v2' IN current_definition
        ) = 0 AND position(
            'evaluation_time := date_trunc(''milliseconds'', job.created_at);'
            IN current_definition
        ) = 0 THEN
            RAISE EXCEPTION USING ERRCODE = '55000',
                MESSAGE = 'cross-source detection prepare source drift';
        END IF;
    END IF;
END
$preserve_detection_prepare$;

REVOKE ALL ON FUNCTION sentinelflow.prepare_detection_job_pre_000018(uuid, uuid)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
         sentinelflow_read, sentinelflow_dispatcher;

CREATE OR REPLACE FUNCTION sentinelflow.prepare_detection_job(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    -- cross-source-evaluation-time-v2
    server_now timestamptz := clock_timestamp();
    job sentinelflow.outbox_jobs%ROWTYPE;
    batch sentinelflow.ingest_batches%ROWTYPE;
    auth sentinelflow.auth_events%ROWTYPE;
    coverage sentinelflow.source_coverage_attestations%ROWTYPE;
    service_value text;
    evaluation_time timestamptz;
    bound_gateway_completed_at timestamptz;
    gateway_coverage_start timestamptz;
    auth_coverage_start timestamptz;
    candidate_ids jsonb;
BEGIN
    IF p_job_id IS NULL OR p_lease_token IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'invalid detection prepare request';
    END IF;
    SELECT * INTO job FROM sentinelflow.outbox_jobs current_job
    WHERE current_job.job_id = p_job_id AND current_job.kind = 'detect'
      AND current_job.aggregate_type IN ('ingest_batch', 'auth_binding')
      AND current_job.state = 'leased' AND current_job.lease_token = p_lease_token
      AND current_job.lease_expires_at > server_now AND current_job.updated_at <= server_now
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1 FROM sentinelflow.detector_runs run
        WHERE run.job_id = job.job_id
    ) THEN
        UPDATE sentinelflow.outbox_jobs
        SET state = 'completed', lease_token = NULL, lease_owner = NULL,
            lease_expires_at = NULL, last_error_code = NULL,
            last_error_digest = NULL, updated_at = server_now
        WHERE job_id = job.job_id;
        status := 'terminal';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    IF job.aggregate_type = 'ingest_batch' THEN
        SELECT candidate.* INTO batch
        FROM sentinelflow.ingest_batches candidate
        WHERE candidate.batch_id = job.aggregate_id
          AND job.idempotency_key = sentinelflow.detection_sha256(convert_to(
              'sentinelflow ingest detect outbox v1' || chr(10) ||
              candidate.sender_id || chr(10) || candidate.sender_epoch || chr(10) ||
              candidate.batch_id::text || chr(10), 'UTF8'))
        FOR KEY SHARE;
        IF NOT FOUND THEN
            status := 'missing';
            snapshot := NULL;
            RETURN NEXT;
            RETURN;
        END IF;
        SELECT candidate.* INTO coverage
        FROM sentinelflow.source_coverage_attestations candidate
        WHERE candidate.sender_id = batch.sender_id
          AND candidate.endpoint_kind = batch.endpoint_kind
          AND candidate.sender_epoch = batch.sender_epoch
          AND candidate.covered_through_batch_id = batch.batch_id
          AND candidate.covered_through_sequence = batch.sequence
          AND candidate.trust_state = 'trusted'
        LIMIT 1;
        evaluation_time := COALESCE(
            coverage.coverage_end,
            date_trunc('milliseconds', batch.received_at)
        );
        SELECT COALESCE(
            (SELECT event.service_label::text
             FROM sentinelflow.gateway_events event
             WHERE event.sender_id = batch.sender_id
               AND event.sender_epoch = batch.sender_epoch
               AND event.batch_id = batch.batch_id
             ORDER BY event.event_id LIMIT 1),
            (SELECT event.service_label::text
             FROM sentinelflow.auth_events event
             WHERE event.sender_id = batch.sender_id
               AND event.sender_epoch = batch.sender_epoch
               AND event.batch_id = batch.batch_id
             ORDER BY event.event_id LIMIT 1),
            (SELECT binding.service_label::text
             FROM sentinelflow.expected_source_bindings binding
             WHERE binding.binding_id = coverage.binding_id)
        ) INTO service_value;
        SELECT COALESCE(jsonb_agg(source_ip ORDER BY source_ip), '[]'::jsonb)
        INTO candidate_ids
        FROM (
            SELECT host(event.source_ip) AS source_ip
            FROM sentinelflow.gateway_events event
            WHERE event.sender_id = batch.sender_id
              AND event.sender_epoch = batch.sender_epoch
              AND event.batch_id = batch.batch_id
            UNION
            SELECT host(event.source_ip) AS source_ip
            FROM sentinelflow.auth_events event
            WHERE event.sender_id = batch.sender_id
              AND event.sender_epoch = batch.sender_epoch
              AND event.batch_id = batch.batch_id
        ) candidates;
    ELSE
        SELECT event.* INTO auth
        FROM sentinelflow.auth_events event
        WHERE event.event_id = job.aggregate_id
          AND event.binding_state <> 'pending'
        FOR KEY SHARE;
        IF NOT FOUND THEN
            status := 'missing';
            snapshot := NULL;
            RETURN NEXT;
            RETURN;
        END IF;
        SELECT candidate.* INTO batch
        FROM sentinelflow.ingest_batches candidate
        WHERE candidate.sender_id = auth.sender_id
          AND candidate.sender_epoch = auth.sender_epoch
          AND candidate.batch_id = auth.batch_id
        FOR KEY SHARE;
        IF NOT FOUND THEN
            status := 'missing';
            snapshot := NULL;
            RETURN NEXT;
            RETURN;
        END IF;

        IF auth.binding_state = 'verified' THEN
            SELECT event.completed_at INTO bound_gateway_completed_at
            FROM sentinelflow.gateway_events event
            WHERE event.event_id = auth.bound_gateway_event_id
              AND event.request_id = auth.gateway_request_id
              AND event.trace_id = auth.trace_id
              AND event.source_ip = auth.source_ip
              AND event.service_label = auth.service_label
              AND event.route_label = auth.route_label
            FOR KEY SHARE;
            IF NOT FOUND THEN
                status := 'missing';
                snapshot := NULL;
                RETURN NEXT;
                RETURN;
            END IF;
            evaluation_time := date_trunc(
                'milliseconds',
                GREATEST(auth.occurred_at, bound_gateway_completed_at)
            );
        ELSE
            evaluation_time := date_trunc('milliseconds', auth.occurred_at);
        END IF;
        service_value := auth.service_label::text;
        candidate_ids := jsonb_build_array(host(auth.source_ip));
    END IF;

    IF service_value IS NULL OR evaluation_time IS NULL OR
       NOT isfinite(evaluation_time) OR
       date_trunc('milliseconds', evaluation_time) <> evaluation_time THEN
        status := 'missing';
        snapshot := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    gateway_coverage_start := sentinelflow.detection_coverage_start(
        'gateway', service_value, evaluation_time
    );
    auth_coverage_start := sentinelflow.detection_coverage_start(
        'auth', service_value, evaluation_time
    );

    status := 'prepared';
    snapshot := jsonb_build_object(
        'job_id', job.job_id::text,
        'aggregate_type', job.aggregate_type::text,
        'aggregate_id', job.aggregate_id::text,
        'aggregate_version', job.aggregate_version,
        'batch_id', batch.batch_id::text,
        'endpoint_kind', batch.endpoint_kind,
        'service_label', service_value,
        'evaluated_at', evaluation_time,
        'gateway_coverage_start', gateway_coverage_start,
        'auth_coverage_start', auth_coverage_start,
        'candidate_source_ips', candidate_ids
    );
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION sentinelflow.prepare_detection_job(uuid, uuid)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
         sentinelflow_read, sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_detection_job(uuid, uuid)
    TO sentinelflow_worker;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (18, 'cross_source_detection_recovery')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
