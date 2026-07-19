BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- This downgrade restores only the callable wrapper stack. Version 33's
-- append-only corrective audits and resolved/completed data corrections are
-- durable evidence and are intentionally not reversed.

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 33 AND name = 'analysis_stale_version_resolution'
    ) OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_pre_000033(uuid,uuid)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_verified_demo_pre_000033(uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,timestamptz,timestamptz,timestamptz,text,text)'
    ) IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'analysis stale-version resolution downgrade preflight failed';
    END IF;
END
$preflight$;

DROP FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid);
ALTER FUNCTION sentinelflow.prepare_analysis_attempt_pre_000033(uuid, uuid)
    RENAME TO prepare_analysis_attempt;

DROP FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
);
ALTER FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_pre_000033(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
) RENAME TO prepare_analysis_attempt_verified_demo_000030;

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

DROP FUNCTION sentinelflow.resolve_queued_stale_analysis_000033(uuid, uuid);

DELETE FROM sentinelflow.schema_migrations
WHERE version = 33 AND name = 'analysis_stale_version_resolution';

COMMIT;
