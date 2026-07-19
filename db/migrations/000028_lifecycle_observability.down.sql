BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

REVOKE ALL ON FUNCTION sentinelflow.control_observability_samples_000028()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
    sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle,
    sentinelflow_metrics;
DROP FUNCTION sentinelflow.control_observability_samples_000028();

-- Restore the exact pre-000028 exporter boundary.  Direct relation and
-- lifecycle-operation authority remains denied.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sentinelflow FROM sentinelflow_metrics;
GRANT EXECUTE ON FUNCTION sentinelflow.control_observability_samples_000024()
TO sentinelflow_metrics;

DELETE FROM sentinelflow.schema_migrations WHERE version = 28;

COMMIT;
