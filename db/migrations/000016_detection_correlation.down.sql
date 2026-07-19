BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $fail_stop$
BEGIN
    IF EXISTS (SELECT 1 FROM detector_runs) OR
       EXISTS (SELECT 1 FROM incident_version_history) OR
       EXISTS (SELECT 1 FROM outbox_jobs WHERE aggregate_type = 'auth_binding') OR
       EXISTS (SELECT 1 FROM signals WHERE signal_digest IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard durable detection or incident version evidence';
    END IF;
END
$fail_stop$;

DROP TRIGGER IF EXISTS auth_events_enqueue_detection ON auth_events;
DROP TRIGGER IF EXISTS auth_events_binding_resolution_stamp ON auth_events;
DROP FUNCTION IF EXISTS sentinelflow.enqueue_auth_binding_detection();
DROP FUNCTION IF EXISTS sentinelflow.stamp_auth_binding_resolution();
DROP FUNCTION IF EXISTS sentinelflow.finish_detection_job(
    uuid, uuid, text, text, timestamptz, text, text, integer, integer
);
DROP FUNCTION IF EXISTS sentinelflow.prepare_detection_job(uuid, uuid);
DROP FUNCTION IF EXISTS sentinelflow.detection_coverage_start(text, text, timestamptz);
DROP FUNCTION IF EXISTS sentinelflow.lease_detection_outbox_job(
    timestamptz, uuid, text, timestamptz
);

DO $drop_immutable_projection_triggers$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'signals', 'signal_evidence', 'detector_runs', 'detector_run_signals',
        'incident_version_history', 'incident_version_signals'
    ]
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON sentinelflow.%I',
            table_name || '_reject_update', table_name);
    END LOOP;
END
$drop_immutable_projection_triggers$;

DROP TABLE IF EXISTS detector_run_signals;
DROP TABLE IF EXISTS detector_runs;
DROP TABLE IF EXISTS incident_version_signals;
DROP TABLE IF EXISTS incident_version_history;
DROP FUNCTION IF EXISTS sentinelflow.reject_detection_history_update();
DROP FUNCTION IF EXISTS sentinelflow.detection_uuid_v8(bytea);
DROP FUNCTION IF EXISTS sentinelflow.detection_sha256(bytea);

REVOKE UPDATE (incident_version) ON incident_signals FROM sentinelflow_worker;
REVOKE UPDATE (incident_version) ON incident_events FROM sentinelflow_worker;
REVOKE UPDATE (
    kind, state, first_seen, last_seen, closed_at, reopen_until,
    deterministic_score, version, analysis_failure_reason, updated_at
) ON incidents FROM sentinelflow_worker;

ALTER TABLE auth_events DROP CONSTRAINT IF EXISTS auth_event_binding_resolution;
ALTER TABLE auth_events DROP COLUMN IF EXISTS binding_resolved_at;
DROP INDEX IF EXISTS signals_signal_digest_idx;
ALTER TABLE signals
    DROP COLUMN IF EXISTS signal_digest,
    DROP COLUMN IF EXISTS configuration_digest,
    DROP COLUMN IF EXISTS configuration_version;

DELETE FROM sentinelflow.schema_migrations WHERE version = 16;

COMMIT;
