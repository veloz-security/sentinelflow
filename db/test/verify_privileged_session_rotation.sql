\set ON_ERROR_STOP on

BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $verify_privileged_session_rotation$
DECLARE
    rotation_oid oid;
    wrapper_oid oid;
    pre_evidence_wrapper_oid oid;
    old_coordinator_oid oid;
    rotation_definition text;
    wrapper_definition text;
    pre_evidence_wrapper_definition text;
    evidence_fence_applied boolean;
BEGIN
    IF (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 12 AND name = 'privileged_session_rotation') <> 1 THEN
        RAISE EXCEPTION 'privileged session rotation migration is not applied exactly once';
    END IF;

    SELECT proc.oid, pg_get_functiondef(proc.oid)
    INTO rotation_oid, rotation_definition
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'commit_privileged_session_rotation';
    SELECT proc.oid, pg_get_functiondef(proc.oid)
    INTO wrapper_oid, wrapper_definition
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'commit_hil_policy_decision_with_session_rotation';
    SELECT proc.oid INTO old_coordinator_oid
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'commit_hil_policy_decision';
    SELECT proc.oid, pg_get_functiondef(proc.oid)
    INTO pre_evidence_wrapper_oid, pre_evidence_wrapper_definition
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname =
          'commit_hil_policy_decision_with_session_rotation_pre_000019';
    SELECT count(*) = 1
    INTO evidence_fence_applied
    FROM sentinelflow.schema_migrations
    WHERE version = 19 AND name = 'evidence_bound_validation_hil';

    IF rotation_oid IS NULL OR wrapper_oid IS NULL OR old_coordinator_oid IS NULL THEN
        RAISE EXCEPTION 'privileged session rotation coordinators are missing';
    END IF;
    IF NOT (
        SELECT proc.prosecdef AND
               proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
        FROM pg_proc proc WHERE proc.oid = rotation_oid
    ) THEN
        RAISE EXCEPTION 'privileged session rotation must be SECURITY DEFINER with a fixed search_path';
    END IF;
    IF NOT (
        SELECT proc.prosecdef AND
               proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
        FROM pg_proc proc WHERE proc.oid = wrapper_oid
    ) THEN
        RAISE EXCEPTION 'combined HIL/session coordinator must be SECURITY DEFINER with a fixed search_path';
    END IF;
    IF NOT has_function_privilege('sentinelflow_api', wrapper_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_api', rotation_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_api', old_coordinator_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_worker', wrapper_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_dispatcher', wrapper_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_read', wrapper_oid, 'EXECUTE') OR
       EXISTS (
           SELECT 1
           FROM aclexplode((SELECT proacl FROM pg_proc WHERE oid = wrapper_oid)) acl
           WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'privileged session rotation EXECUTE grants drifted';
    END IF;
    IF position('FOR UPDATE' IN rotation_definition) = 0 OR
       position('clock_timestamp()' IN rotation_definition) = 0 OR
       position('UPDATE sentinelflow.admin_sessions' IN rotation_definition) = 0 OR
       position('INSERT INTO sentinelflow.admin_sessions' IN rotation_definition) = 0 OR
       position('IF p_replayed THEN' IN rotation_definition) = 0 THEN
        RAISE EXCEPTION 'privileged session rotation locking, authoritative clock, or replay boundary drifted';
    END IF;

    IF evidence_fence_applied THEN
        IF pre_evidence_wrapper_oid IS NULL THEN
            RAISE EXCEPTION 'evidence-bound HIL predecessor coordinator is missing';
        END IF;
        IF NOT (
            SELECT proc.prosecdef AND
                   proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
            FROM pg_proc proc WHERE proc.oid = pre_evidence_wrapper_oid
        ) THEN
            RAISE EXCEPTION 'evidence-bound HIL predecessor must be SECURITY DEFINER with a fixed search_path';
        END IF;
        IF has_function_privilege('sentinelflow_api', pre_evidence_wrapper_oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_worker', pre_evidence_wrapper_oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_dispatcher', pre_evidence_wrapper_oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_read', pre_evidence_wrapper_oid, 'EXECUTE') OR
           EXISTS (
               SELECT 1
               FROM aclexplode((SELECT proacl FROM pg_proc WHERE oid = pre_evidence_wrapper_oid)) acl
               WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
           ) THEN
            RAISE EXCEPTION 'evidence-bound HIL predecessor EXECUTE grants drifted';
        END IF;
        IF position(
               'commit_hil_policy_decision_with_session_rotation_pre_000019('
               IN wrapper_definition
           ) = 0 OR
           position(
               'IF NOT result_replayed AND NOT sentinelflow.policy_evidence_is_current_000019('
               IN wrapper_definition
           ) = 0 OR
           position('commit_hil_policy_decision(' IN wrapper_definition) <> 0 OR
           position('commit_privileged_session_rotation(' IN wrapper_definition) <> 0 OR
           position('commit_hil_policy_decision(' IN pre_evidence_wrapper_definition) = 0 OR
           position('commit_privileged_session_rotation(' IN pre_evidence_wrapper_definition) = 0 THEN
            RAISE EXCEPTION 'evidence-bound HIL/session coordinator boundary drifted';
        END IF;
    ELSE
        IF pre_evidence_wrapper_oid IS NOT NULL OR
           position('commit_hil_policy_decision(' IN wrapper_definition) = 0 OR
           position('commit_privileged_session_rotation(' IN wrapper_definition) = 0 THEN
            RAISE EXCEPTION 'pre-evidence HIL/session coordinator boundary drifted';
        END IF;
    END IF;
END
$verify_privileged_session_rotation$;

SET LOCAL ROLE sentinelflow_api;
DO $verify_direct_coordinator_denials$
BEGIN
    BEGIN
        PERFORM sentinelflow.commit_privileged_session_rotation(
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL
        );
        RAISE EXCEPTION 'API directly executed inner session rotation';
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        PERFORM sentinelflow.commit_hil_policy_decision(
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL
        );
        RAISE EXCEPTION 'API directly executed rotation-free HIL coordinator';
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;
    END;
END
$verify_direct_coordinator_denials$;

RESET ROLE;
ROLLBACK;
