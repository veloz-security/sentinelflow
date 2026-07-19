BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Version 000023 deliberately deletes expired evidence under one
-- transaction-local marker and a SECURITY DEFINER entry point granted only to
-- sentinelflow_retention.  The evidence foreign key then issues an internal
-- ON DELETE SET NULL update. Version 000026 made every non-lifecycle field
-- immutable and unintentionally rejected that exact referential tombstone.
DO $preflight$
DECLARE
    transition_oid oid;
    retention_oid oid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 28 AND name = 'lifecycle_observability'
    ) OR EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 29
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention action tombstone requires the exact version-28 prefix';
    END IF;

    transition_oid := to_regprocedure(
        'sentinelflow.enforce_action_transition_000026()'
    );
    retention_oid := to_regprocedure(
        'sentinelflow.run_retention_000023(uuid,timestamptz,integer)'
    );
    IF transition_oid IS NULL OR retention_oid IS NULL OR
       to_regprocedure(
           'sentinelflow.enforce_action_transition_pre_000029()'
       ) IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention action tombstone function boundary is not canonical';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_proc function
        JOIN pg_roles owner ON owner.oid = function.proowner
        WHERE function.oid = transition_oid
          AND owner.rolname = 'sentinelflow_migration'
          AND function.prosecdef
          AND function.proconfig = ARRAY['search_path=pg_catalog, sentinelflow']::text[]
          AND pg_get_functiondef(function.oid) LIKE
              '%MESSAGE = ''enforcement action immutable fields changed'';%'
          AND pg_get_functiondef(function.oid) LIKE
              '%to_jsonb(NEW) - ''state'' - ''queued_at'' - ''applied_at''%'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        WHERE trigger.tgrelid = 'sentinelflow.enforcement_actions'::regclass
          AND trigger.tgname = 'enforcement_actions_transition_000026'
          AND trigger.tgfoid = transition_oid
          AND NOT trigger.tgisinternal
          AND trigger.tgenabled = 'O'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'version-26 enforcement transition is not attestable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint foreign_key
        WHERE foreign_key.conrelid = 'sentinelflow.enforcement_actions'::regclass
          AND foreign_key.confrelid = 'sentinelflow.evidence_snapshots'::regclass
          AND foreign_key.contype = 'f'
          AND foreign_key.confdeltype = 'n'
          AND foreign_key.conkey = ARRAY[
              (
                  SELECT attribute.attnum
                  FROM pg_attribute attribute
                  WHERE attribute.attrelid = foreign_key.conrelid
                    AND attribute.attname = 'evidence_snapshot_id'
                    AND NOT attribute.attisdropped
              )::smallint
          ]::smallint[]
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'enforcement evidence SET NULL foreign key is not canonical';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_proc function
        JOIN pg_roles owner ON owner.oid = function.proowner
        WHERE function.oid = retention_oid
          AND owner.rolname = 'sentinelflow_migration'
          AND function.prosecdef
          AND function.proconfig = ARRAY['search_path=pg_catalog, sentinelflow']::text[]
          AND pg_get_functiondef(function.oid) LIKE
              '%IF session_user <> ''sentinelflow_retention''%'
          AND pg_get_functiondef(function.oid) LIKE
              '%''sentinelflow.retention_delete'', ''000023-retention-v1'', true%'
          AND has_function_privilege(
              'sentinelflow_retention', function.oid, 'EXECUTE'
          )
          AND NOT has_function_privilege(
              'sentinelflow_api', function.oid, 'EXECUTE'
          )
          AND NOT has_function_privilege(
              'sentinelflow_worker', function.oid, 'EXECUTE'
          )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'retention marker and caller authority are not attestable';
    END IF;
END
$preflight$;

ALTER FUNCTION sentinelflow.enforce_action_transition_000026()
RENAME TO enforce_action_transition_pre_000029;

CREATE FUNCTION sentinelflow.enforce_action_transition_000026()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'approved' OR NEW.version <> 1 OR
           NEW.queued_at IS NOT NULL OR NEW.applied_at IS NOT NULL OR
           NEW.expected_expires_at IS NOT NULL OR NEW.finished_at IS NOT NULL OR
           NEW.nft_element_handle IS NOT NULL OR NOT EXISTS (
               SELECT 1 FROM sentinelflow.policy_proposals policy
               WHERE policy.policy_id = NEW.policy_id
                 AND policy.version = NEW.policy_version
                 AND policy.state = 'approved'
                 AND policy.target_ipv4 = NEW.target_ipv4
                 AND policy.canonical_artifact_digest = NEW.canonical_artifact_digest
                 AND policy.ttl_seconds = NEW.ttl_seconds
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'enforcement action must begin as an exact approved policy action';
        END IF;
        RETURN NEW;
    END IF;

    -- Only the internal RI_FKey_setnull_del path may tombstone this reference:
    -- the retention SECURITY DEFINER must have armed its exact marker, the
    -- parent row must already be gone, and every other column must remain
    -- byte-equivalent. Direct UPDATE is trigger depth one and cannot use this
    -- exception even if an untrusted caller sets the custom GUC itself.
    IF pg_trigger_depth() = 2 AND
       current_setting('sentinelflow.retention_delete', true) =
           '000023-retention-v1' AND
       OLD.evidence_snapshot_id IS NOT NULL AND
       NEW.evidence_snapshot_id IS NULL AND
       (to_jsonb(NEW) - 'evidence_snapshot_id') =
           (to_jsonb(OLD) - 'evidence_snapshot_id') AND
       NOT EXISTS (
           SELECT 1 FROM sentinelflow.evidence_snapshots evidence
           WHERE evidence.evidence_snapshot_id = OLD.evidence_snapshot_id
       ) THEN
        RETURN NEW;
    END IF;

    IF (to_jsonb(NEW) - 'state' - 'queued_at' - 'applied_at' -
            'expected_expires_at' - 'finished_at' - 'version' - 'updated_at') <>
       (to_jsonb(OLD) - 'state' - 'queued_at' - 'applied_at' -
            'expected_expires_at' - 'finished_at' - 'version' - 'updated_at') OR
       NEW.nft_element_handle IS NOT NULL OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'enforcement action immutable fields changed';
    END IF;

    IF NEW.state = OLD.state THEN
        IF NEW.version <> OLD.version OR NEW.queued_at IS DISTINCT FROM OLD.queued_at OR
           NEW.applied_at IS DISTINCT FROM OLD.applied_at OR
           NEW.expected_expires_at IS DISTINCT FROM OLD.expected_expires_at OR
           NEW.finished_at IS DISTINCT FROM OLD.finished_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'idempotent enforcement action write changed lifecycle data';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.version <> OLD.version + 1 OR NOT (
        (OLD.state = 'approved' AND NEW.state = 'queued') OR
        (OLD.state = 'queued' AND NEW.state IN ('active', 'failed', 'indeterminate')) OR
        (OLD.state = 'active' AND NEW.state IN ('expired', 'failed', 'revoked', 'indeterminate')) OR
        (OLD.state = 'indeterminate' AND NEW.state IN ('active', 'expired', 'failed', 'revoked'))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'enforcement action state transition is not allowed';
    END IF;

    IF NEW.state = 'queued' AND (
        NEW.queued_at IS NULL OR NEW.applied_at IS NOT NULL OR
        NEW.expected_expires_at IS NOT NULL OR NEW.finished_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid queued action shape';
    ELSIF NEW.state = 'active' AND (
        NEW.queued_at IS NULL OR NEW.applied_at IS NULL OR
        NEW.expected_expires_at IS NULL OR
        NEW.expected_expires_at <= NEW.applied_at OR NEW.finished_at IS NOT NULL OR
        NEW.expected_expires_at > NEW.applied_at + make_interval(secs => NEW.ttl_seconds)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid active action shape';
    ELSIF NEW.state IN ('expired', 'failed', 'revoked') AND NEW.finished_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal action lacks finish time';
    ELSIF NEW.state = 'indeterminate' AND NEW.finished_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'indeterminate action cannot be terminal';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.policy_proposals policy
        WHERE policy.policy_id = NEW.policy_id
          AND policy.version = NEW.policy_version
          AND policy.state = NEW.state
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'policy and enforcement action lifecycle state diverged';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER enforcement_actions_transition_000026
    ON sentinelflow.enforcement_actions;
CREATE TRIGGER enforcement_actions_transition_000026
BEFORE INSERT OR UPDATE ON sentinelflow.enforcement_actions
FOR EACH ROW EXECUTE FUNCTION sentinelflow.enforce_action_transition_000026();

REVOKE ALL ON FUNCTION sentinelflow.enforce_action_transition_000026(),
    sentinelflow.enforce_action_transition_pre_000029()
FROM PUBLIC, sentinelflow_api, sentinelflow_worker, sentinelflow_read,
     sentinelflow_dispatcher, sentinelflow_retention, sentinelflow_lifecycle,
     sentinelflow_metrics;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (29, 'retention_action_tombstone');

COMMIT;
