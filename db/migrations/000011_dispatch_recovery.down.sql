BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Removing recovery while a nonterminal job already owns a capability would
-- strand exact signed authority after the next lease loss.  Fail before any
-- DDL; completed/dead jobs need no further dispatch recovery.
DO $dispatch_recovery_downgrade_preflight$
BEGIN
    IF to_regprocedure('sentinelflow.recover_dispatch_execution(uuid,uuid)') IS NOT NULL AND
       EXISTS (
           SELECT 1
           FROM sentinelflow.execution_capabilities capability
           JOIN sentinelflow.outbox_jobs job USING (job_id)
           WHERE job.state IN ('pending', 'retry', 'leased')
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot remove dispatch recovery with nonterminal persisted artifacts';
    END IF;
END
$dispatch_recovery_downgrade_preflight$;

DROP FUNCTION IF EXISTS sentinelflow.recover_dispatch_execution(uuid, uuid);

DELETE FROM sentinelflow.schema_migrations
WHERE version = 11 AND name = 'dispatch_recovery';

COMMIT;
