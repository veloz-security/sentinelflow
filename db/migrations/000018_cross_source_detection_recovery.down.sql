BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Reverting the event-time authority after any auth-binding job or durable
-- incomplete-coverage retry exists would change the meaning of live evidence.
-- Refuse that rollback rather than deleting or reinterpreting it.
DO $fail_stop_live_detection_evidence$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sentinelflow.outbox_jobs
        WHERE aggregate_type = 'auth_binding'
           OR last_error_code = 'detection_source_coverage_incomplete'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.detector_runs
        WHERE aggregate_type = 'auth_binding'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard live cross-source detection recovery evidence';
    END IF;
END
$fail_stop_live_detection_evidence$;

DO $verify_detection_prepare_rollback$
DECLARE
    current_definition text;
    preserved_definition text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 18 AND name = 'cross_source_detection_recovery'
    ) OR to_regprocedure(
        'sentinelflow.prepare_detection_job(uuid,uuid)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.prepare_detection_job_pre_000018(uuid,uuid)'
    ) IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cross-source detection rollback state drift';
    END IF;
    SELECT pg_get_functiondef(
        'sentinelflow.prepare_detection_job(uuid,uuid)'::regprocedure
    ) INTO current_definition;
    SELECT pg_get_functiondef(
        'sentinelflow.prepare_detection_job_pre_000018(uuid,uuid)'::regprocedure
    ) INTO preserved_definition;
    IF position('cross-source-evaluation-time-v2' IN current_definition) = 0 OR
       position(
           'evaluation_time := date_trunc(''milliseconds'', job.created_at);'
           IN preserved_definition
       ) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cross-source detection rollback source drift';
    END IF;
END
$verify_detection_prepare_rollback$;

DROP FUNCTION sentinelflow.prepare_detection_job(uuid, uuid);
ALTER FUNCTION sentinelflow.prepare_detection_job_pre_000018(uuid, uuid)
    RENAME TO prepare_detection_job;

REVOKE ALL ON FUNCTION sentinelflow.prepare_detection_job(uuid, uuid)
    FROM PUBLIC, sentinelflow_api, sentinelflow_worker,
         sentinelflow_read, sentinelflow_dispatcher;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_detection_job(uuid, uuid)
    TO sentinelflow_worker;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 18 AND name = 'cross_source_detection_recovery';

COMMIT;
