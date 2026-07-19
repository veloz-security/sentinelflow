BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 32 AND name = 'validation_attempt_api_projection'
    ) OR to_regprocedure(
        'sentinelflow.read_policy_validation_attempt_000032(uuid)'
    ) IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'validation attempt API projection downgrade preflight failed';
    END IF;
END
$preflight$;

DROP FUNCTION sentinelflow.read_policy_validation_attempt_000032(uuid);

DELETE FROM sentinelflow.schema_migrations
WHERE version = 32 AND name = 'validation_attempt_api_projection';

COMMIT;
