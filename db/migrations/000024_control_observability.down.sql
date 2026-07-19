BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DROP FUNCTION IF EXISTS sentinelflow.control_observability_samples_000024();
DROP FUNCTION IF EXISTS sentinelflow.control_observability_utc_date_000024(timestamptz);
DROP FUNCTION IF EXISTS sentinelflow.unregister_sse_client_lease_000024(uuid, text);
DROP FUNCTION IF EXISTS sentinelflow.touch_sse_client_lease_000024(uuid, text);
DROP FUNCTION IF EXISTS sentinelflow.register_sse_client_lease_000024(uuid, text);
DROP TABLE IF EXISTS sentinelflow.sse_client_leases;
DELETE FROM schema_migrations WHERE version = 24;

RESET ROLE;

DO $drop_metrics_role$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_metrics') THEN
        EXECUTE format(
            'REVOKE CONNECT ON DATABASE %I FROM sentinelflow_metrics', current_database()
        );
        EXECUTE format(
            'ALTER ROLE sentinelflow_metrics IN DATABASE %I RESET search_path', current_database()
        );
        REVOKE USAGE ON SCHEMA sentinelflow FROM sentinelflow_metrics;
        DROP ROLE sentinelflow_metrics;
    END IF;
END
$drop_metrics_role$;

COMMIT;
