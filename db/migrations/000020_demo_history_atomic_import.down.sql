BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $fail_stop_populated_import$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.demo_history_imports) OR
       EXISTS (SELECT 1 FROM sentinelflow.demo_history_import_batches) OR
       EXISTS (SELECT 1 FROM sentinelflow.demo_history_source_coverage) OR
       EXISTS (
           SELECT 1 FROM sentinelflow.ingest_batches
           WHERE sender_id IN ('gateway-demo', 'auth-demo')
       ) OR EXISTS (
           SELECT 1 FROM sentinelflow.gateway_events WHERE sender_id = 'gateway-demo'
       ) OR EXISTS (
           SELECT 1 FROM sentinelflow.auth_events WHERE sender_id = 'auth-demo'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard populated demo history import evidence';
    END IF;
END
$fail_stop_populated_import$;

DROP FUNCTION sentinelflow.read_demo_history_import(uuid);
DROP FUNCTION sentinelflow.record_demo_history_import_failure(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.complete_demo_history_import(uuid);
DROP FUNCTION sentinelflow.append_demo_history_source_coverage(
    uuid, text, text, text, timestamptz, timestamptz, bigint, bigint
);
DROP FUNCTION sentinelflow.append_demo_history_auth(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, text, text, text, text, text
);
DROP FUNCTION sentinelflow.append_demo_history_gateway(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, timestamptz, text, text, text, text, text, text, text,
    text, integer, bigint, bigint, integer
);
DROP FUNCTION sentinelflow.begin_demo_history_import(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz
);
DROP FUNCTION sentinelflow.demo_history_rows_valid(uuid);
DROP FUNCTION sentinelflow.demo_history_event_jcs(uuid, text);

DROP TRIGGER demo_history_source_coverage_append_only ON demo_history_source_coverage;
DROP TRIGGER demo_history_import_batches_append_only ON demo_history_import_batches;
DROP TRIGGER demo_history_import_update_guard ON demo_history_imports;
DROP FUNCTION sentinelflow.reject_demo_history_evidence_mutation();
DROP FUNCTION sentinelflow.guard_demo_history_import_update();

DROP TABLE sentinelflow.demo_history_source_coverage;
DROP TABLE sentinelflow.demo_history_import_batches;
DROP TABLE sentinelflow.demo_history_imports;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 20 AND name = 'demo_history_atomic_import';

COMMIT;
