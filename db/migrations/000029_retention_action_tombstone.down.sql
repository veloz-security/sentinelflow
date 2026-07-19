BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $preflight$
DECLARE
    current_oid oid := to_regprocedure(
        'sentinelflow.enforce_action_transition_000026()'
    );
    prior_oid oid := to_regprocedure(
        'sentinelflow.enforce_action_transition_pre_000029()'
    );
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 29 AND name = 'retention_action_tombstone'
    ) OR current_oid IS NULL OR prior_oid IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_trigger trigger
        WHERE trigger.tgrelid = 'sentinelflow.enforcement_actions'::regclass
          AND trigger.tgname = 'enforcement_actions_transition_000026'
          AND trigger.tgfoid = current_oid
          AND NOT trigger.tgisinternal
          AND trigger.tgenabled = 'O'
    ) OR pg_get_functiondef(current_oid) NOT LIKE
        '%current_setting(''sentinelflow.retention_delete'', true)%' OR
       pg_get_functiondef(current_oid) NOT LIKE '%pg_trigger_depth() = 2%' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'version-29 enforcement transition is not attestable';
    END IF;
END
$preflight$;

DROP TRIGGER enforcement_actions_transition_000026
    ON sentinelflow.enforcement_actions;
DROP FUNCTION sentinelflow.enforce_action_transition_000026();
ALTER FUNCTION sentinelflow.enforce_action_transition_pre_000029()
RENAME TO enforce_action_transition_000026;
CREATE TRIGGER enforcement_actions_transition_000026
BEFORE INSERT OR UPDATE ON sentinelflow.enforcement_actions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.enforce_action_transition_000026();

REVOKE ALL ON FUNCTION sentinelflow.enforce_action_transition_000026()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle,
     sentinelflow_metrics;

DELETE FROM sentinelflow.schema_migrations WHERE version = 29;

COMMIT;
