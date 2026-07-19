BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Removing the exact-import validation boundary while demo history or a
-- demo-clock validation snapshot exists would silently widen future history
-- queries. Require an explicit offline reconciliation instead.
DO $fail_stop_populated_demo_validation$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.demo_history_imports) OR EXISTS (
        SELECT 1
        FROM sentinelflow.validation_attempt_claims claim
        WHERE claim.prepared_snapshot->'history'->>'cutoff' IS DISTINCT FROM
              claim.prepared_snapshot->>'generated_at'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'cannot discard verified demo history validation binding';
    END IF;
END
$fail_stop_populated_demo_validation$;

DROP FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000022(
    uuid, uuid, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.verify_demo_history_validation_binding_000022(
    uuid, uuid, uuid, text, text, text, bigint, text, text, text, text,
    text, timestamptz, timestamptz, timestamptz, timestamptz, text
);

DELETE FROM sentinelflow.schema_migrations
WHERE version = 22 AND name = 'demo_history_validation_binding';

COMMIT;
