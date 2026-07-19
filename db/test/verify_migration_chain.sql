BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $migration_chain$
DECLARE
    function_names text[];
    function_record record;
BEGIN
    IF (SELECT count(*) FROM sentinelflow.schema_migrations) <> 33 OR
       (SELECT min(version) FROM sentinelflow.schema_migrations) <> 1 OR
       (SELECT max(version) FROM sentinelflow.schema_migrations) <> 33 OR
       NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 25 AND name = 'dispatch_started_recovery'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 26 AND name = 'enforcement_lifecycle'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 27 AND name = 'revocation_hil'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 28 AND name = 'lifecycle_observability'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 29 AND name = 'retention_action_tombstone'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 30 AND name = 'demo_history_runtime_activation'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 31 AND name = 'artifact_content_digest_identity'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 32 AND name = 'validation_attempt_api_projection'
       ) OR NOT EXISTS (
           SELECT 1 FROM sentinelflow.schema_migrations
           WHERE version = 33 AND name = 'analysis_stale_version_resolution'
       ) THEN
        RAISE EXCEPTION 'migration ledger is not the exact version-33 chain';
    END IF;

    IF to_regprocedure(
        'sentinelflow.resolve_queued_stale_analysis_000033(uuid,uuid)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_pre_000033(uuid,uuid)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.prepare_analysis_attempt_verified_demo_pre_000033(uuid,uuid,bytea,uuid,uuid,uuid,text,text,text,bigint,text,text,text,text,text,timestamptz,timestamptz,timestamptz,timestamptz,text,text)'
    ) IS NULL THEN
        RAISE EXCEPTION 'version-33 analysis stale-version wrappers differ';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc function_row
        JOIN pg_catalog.pg_roles owner
          ON owner.oid = function_row.proowner
        WHERE function_row.oid =
              'sentinelflow.prepare_analysis_attempt(uuid,uuid)'::regprocedure
          AND owner.rolname = 'sentinelflow_migration'
          AND function_row.prosecdef
          AND function_row.proconfig =
              ARRAY['search_path=pg_catalog, sentinelflow']::text[]
          AND has_function_privilege(
              'sentinelflow_worker', function_row.oid, 'EXECUTE'
          )
          AND NOT has_function_privilege(
              'sentinelflow_read', function_row.oid, 'EXECUTE'
          )
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.resolve_queued_stale_analysis_000033(uuid,uuid)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.prepare_analysis_attempt_pre_000033(uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'version-33 analysis wrapper ownership or ACL differs';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS projection_function
        JOIN pg_catalog.pg_roles AS owner
          ON owner.oid = projection_function.proowner
        WHERE projection_function.oid =
              'sentinelflow.read_policy_validation_attempt_000032(uuid)'::regprocedure
          AND owner.rolname = 'sentinelflow_migration'
          AND projection_function.prosecdef
          AND projection_function.provolatile = 's'
          AND projection_function.proretset
          AND projection_function.proconfig =
              ARRAY['search_path=pg_catalog, sentinelflow']::text[]
          AND has_function_privilege(
              'sentinelflow_api', projection_function.oid, 'EXECUTE'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM pg_catalog.aclexplode(COALESCE(
                  projection_function.proacl,
                  pg_catalog.acldefault('f', projection_function.proowner)
              )) AS privilege
              WHERE privilege.grantee = 0
                AND privilege.privilege_type = 'EXECUTE'
          )
    ) THEN
        RAISE EXCEPTION 'version-32 validation attempt projection differs';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint constraint_record
        WHERE (constraint_record.conrelid =
                   'sentinelflow.command_candidates'::regclass
               AND constraint_record.conname IN (
                   'command_candidates_generated_artifact_digest_key',
                   'command_candidates_canonical_artifact_digest_key'
               )) OR
              (constraint_record.conrelid =
                   'sentinelflow.enforcement_actions'::regclass
               AND constraint_record.conname =
                   'enforcement_actions_canonical_artifact_digest_key') OR
              (constraint_record.conrelid =
                   'sentinelflow.lifecycle_inspection_artifacts_000026'::regclass
               AND constraint_record.conname =
                   'lifecycle_inspection_artifacts_0000_inspect_artifact_digest_key')
    ) THEN
        RAISE EXCEPTION 'content digests remain global identities';
    END IF;

    IF to_regprocedure(
        'sentinelflow.pin_demo_history_runtime_capability_expectation_000030(text,text,timestamptz)'
    ) IS NULL OR NOT EXISTS (
        SELECT 1
        FROM pg_proc function
        JOIN pg_roles owner ON owner.oid = function.proowner
        WHERE function.oid =
            'sentinelflow.pin_demo_history_runtime_capability_expectation_000030(text,text,timestamptz)'::regprocedure
          AND owner.rolname = session_user
          AND NOT EXISTS (
              SELECT 1
              FROM aclexplode(
                  COALESCE(function.proacl, acldefault('f', function.proowner))
              ) AS privilege
              WHERE privilege.grantee = 0
                AND privilege.privilege_type = 'EXECUTE'
          )
    ) OR EXISTS (
        SELECT 1
        FROM unnest(ARRAY[
            'sentinelflow_migration', 'sentinelflow_api', 'sentinelflow_worker',
            'sentinelflow_read', 'sentinelflow_dispatcher',
            'sentinelflow_retention', 'sentinelflow_lifecycle',
            'sentinelflow_metrics', 'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        ]) AS denied(role_name)
        WHERE has_function_privilege(
            denied.role_name,
            'sentinelflow.pin_demo_history_runtime_capability_expectation_000030(text,text,timestamptz)',
            'EXECUTE'
        )
    ) THEN
        RAISE EXCEPTION 'demo capability pin owner-only ACL differs';
    END IF;

    SELECT array_agg(p.proname ORDER BY p.proname)
    INTO function_names
    FROM pg_proc p
    JOIN pg_namespace namespace ON namespace.oid = p.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND (
          p.proname LIKE 'claim_dispatch_job%' OR
          p.proname LIKE 'finish_dispatch_job%' OR
          p.proname LIKE 'record_execution_capability%' OR
          p.proname LIKE 'record_execution_result%'
      );
    IF function_names <> ARRAY[
        'claim_dispatch_job',
        'claim_dispatch_job_pre_000019',
        'claim_dispatch_job_pre_000025',
        'finish_dispatch_job',
        'finish_dispatch_job_pre_000025',
        'record_execution_capability',
        'record_execution_capability_pre_000019',
        'record_execution_capability_pre_000025',
        'record_execution_capability_pre_000026',
        'record_execution_capability_pre_000027',
        'record_execution_result',
        'record_execution_result_pre_000026',
        'record_execution_result_pre_000027'
    ]::text[] THEN
        RAISE EXCEPTION 'dispatch wrapper function set is not canonical: %', function_names;
    END IF;

    FOR function_record IN
        SELECT p.oid, p.proname, p.prosecdef, p.proconfig,
               owner.rolname AS owner_name
        FROM pg_proc p
        JOIN pg_namespace namespace ON namespace.oid = p.pronamespace
        JOIN pg_roles owner ON owner.oid = p.proowner
        WHERE namespace.nspname = 'sentinelflow'
          AND p.proname = ANY (function_names)
    LOOP
        IF function_record.owner_name <> 'sentinelflow_migration' OR
           NOT function_record.prosecdef OR
           function_record.proconfig IS DISTINCT FROM
               ARRAY['search_path=pg_catalog, sentinelflow']::text[] OR
           EXISTS (
               SELECT 1
               FROM aclexplode(
                   COALESCE(
                       (SELECT proacl FROM pg_proc WHERE oid = function_record.oid),
                       acldefault('f',
                           (SELECT proowner FROM pg_proc WHERE oid = function_record.oid))
                   )
               ) privilege
               WHERE privilege.grantee = 0
                 AND privilege.privilege_type = 'EXECUTE'
           ) OR
           has_function_privilege('sentinelflow_api', function_record.oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_worker', function_record.oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_read', function_record.oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_retention', function_record.oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_lifecycle', function_record.oid, 'EXECUTE') OR
           has_function_privilege('sentinelflow_metrics', function_record.oid, 'EXECUTE') OR
           (
               function_record.proname LIKE '%_pre_%' AND
               has_function_privilege('sentinelflow_dispatcher', function_record.oid, 'EXECUTE')
           ) OR (
               function_record.proname NOT LIKE '%_pre_%' AND
               NOT has_function_privilege('sentinelflow_dispatcher', function_record.oid, 'EXECUTE')
           ) THEN
            RAISE EXCEPTION 'dispatch wrapper owner/security/ACL mismatch: %',
                function_record.proname;
        END IF;
    END LOOP;

    IF position(
        'claim_dispatch_job_pre_000025' IN pg_get_functiondef(
            'sentinelflow.claim_dispatch_job(uuid,uuid,sentinelflow.ascii_id,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'claim_dispatch_job_pre_000019' IN pg_get_functiondef(
            'sentinelflow.claim_dispatch_job_pre_000025(uuid,uuid,sentinelflow.ascii_id,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'finish_dispatch_job_pre_000025' IN pg_get_functiondef(
            'sentinelflow.finish_dispatch_job(uuid,uuid,text,sentinelflow.ascii_id,sentinelflow.sha256_digest,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'record_execution_capability_pre_000027' IN pg_get_functiondef(
            'sentinelflow.record_execution_capability(uuid,uuid,uuid,text,uuid,uuid,integer,sentinelflow.canonical_ipv4,bytea,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.ascii_id,sentinelflow.sha256_digest,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,timestamptz,timestamptz,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'record_execution_capability_pre_000026' IN pg_get_functiondef(
            'sentinelflow.record_execution_capability_pre_000027(uuid,uuid,uuid,text,uuid,uuid,integer,sentinelflow.canonical_ipv4,bytea,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.ascii_id,sentinelflow.sha256_digest,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,timestamptz,timestamptz,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'record_execution_capability_pre_000025' IN pg_get_functiondef(
            'sentinelflow.record_execution_capability_pre_000026(uuid,uuid,uuid,text,uuid,uuid,integer,sentinelflow.canonical_ipv4,bytea,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.ascii_id,sentinelflow.sha256_digest,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,timestamptz,timestamptz,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'record_execution_capability_pre_000019' IN pg_get_functiondef(
            'sentinelflow.record_execution_capability_pre_000025(uuid,uuid,uuid,text,uuid,uuid,integer,sentinelflow.canonical_ipv4,bytea,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.sha256_digest,sentinelflow.ascii_id,sentinelflow.sha256_digest,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest,timestamptz,timestamptz,timestamptz)'::regprocedure
        )
    ) = 0 OR position(
        'record_execution_result_pre_000027' IN pg_get_functiondef(
            'sentinelflow.record_execution_result(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)'::regprocedure
        )
    ) = 0 OR position(
        'record_execution_result_pre_000026' IN pg_get_functiondef(
            'sentinelflow.record_execution_result_pre_000027(uuid,uuid,uuid,uuid,sentinelflow.sha256_digest,text,uuid,sentinelflow.sha256_digest,sentinelflow.canonical_ipv4,text,text,text,bigint,integer,sentinelflow.sha256_digest,timestamptz,timestamptz,bigint,text,bytea,sentinelflow.sha256_digest,bytea)'::regprocedure
        )
    ) = 0 THEN
        RAISE EXCEPTION 'dispatch wrapper dependency chain is not canonical';
    END IF;

    IF to_regprocedure('sentinelflow.control_observability_samples_000028()') IS NULL OR
       NOT has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.control_observability_samples_000028()', 'EXECUTE'
       ) OR has_function_privilege(
           'sentinelflow_metrics',
           'sentinelflow.control_observability_samples_000024()', 'EXECUTE'
       ) OR EXISTS (
           SELECT 1
           FROM pg_proc function
           CROSS JOIN LATERAL aclexplode(
               COALESCE(function.proacl, acldefault('f', function.proowner))
           ) privilege
           WHERE function.oid =
               'sentinelflow.control_observability_samples_000028()'::regprocedure
             AND privilege.grantee = 0
             AND privilege.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'version-28 observability function boundary is not canonical';
    END IF;

    IF to_regprocedure(
           'sentinelflow.enforce_action_transition_000026()'
       ) IS NULL OR
       to_regprocedure(
           'sentinelflow.enforce_action_transition_pre_000029()'
       ) IS NULL OR NOT EXISTS (
           SELECT 1
           FROM pg_proc function
           JOIN pg_roles owner ON owner.oid = function.proowner
           WHERE function.oid =
               'sentinelflow.enforce_action_transition_000026()'::regprocedure
             AND owner.rolname = 'sentinelflow_migration'
             AND function.prosecdef
             AND function.proconfig =
                 ARRAY['search_path=pg_catalog, sentinelflow']::text[]
             AND pg_get_functiondef(function.oid) LIKE
                 '%pg_trigger_depth() = 2%'
             AND pg_get_functiondef(function.oid) LIKE
                 '%current_setting(''sentinelflow.retention_delete'', true)%'
             AND pg_get_functiondef(function.oid) LIKE
                 '%(to_jsonb(NEW) - ''evidence_snapshot_id'')%'
             AND pg_get_functiondef(function.oid) LIKE
                 '%WHERE evidence.evidence_snapshot_id = OLD.evidence_snapshot_id%'
       ) OR NOT EXISTS (
           SELECT 1
           FROM pg_proc function
           JOIN pg_roles owner ON owner.oid = function.proowner
           WHERE function.oid =
               'sentinelflow.enforce_action_transition_pre_000029()'::regprocedure
             AND owner.rolname = 'sentinelflow_migration'
             AND function.prosecdef
             AND function.proconfig =
                 ARRAY['search_path=pg_catalog, sentinelflow']::text[]
             AND pg_get_functiondef(function.oid) LIKE
                 '%MESSAGE = ''enforcement action immutable fields changed'';%'
             AND pg_get_functiondef(function.oid) NOT LIKE
                 '%sentinelflow.retention_delete%'
       ) OR NOT EXISTS (
           SELECT 1 FROM pg_trigger trigger
           WHERE trigger.tgrelid =
               'sentinelflow.enforcement_actions'::regclass
             AND trigger.tgname = 'enforcement_actions_transition_000026'
             AND trigger.tgfoid =
               'sentinelflow.enforce_action_transition_000026()'::regprocedure
             AND NOT trigger.tgisinternal
             AND trigger.tgenabled = 'O'
       ) OR EXISTS (
           SELECT 1
           FROM pg_proc function
           CROSS JOIN LATERAL aclexplode(
               COALESCE(function.proacl, acldefault('f', function.proowner))
           ) privilege
           WHERE function.oid IN (
               'sentinelflow.enforce_action_transition_000026()'::regprocedure,
               'sentinelflow.enforce_action_transition_pre_000029()'::regprocedure
           )
             AND privilege.grantee = 0
             AND privilege.privilege_type = 'EXECUTE'
       ) OR has_function_privilege(
           'sentinelflow_api',
           'sentinelflow.enforce_action_transition_000026()', 'EXECUTE'
       ) OR has_function_privilege(
           'sentinelflow_worker',
           'sentinelflow.enforce_action_transition_000026()', 'EXECUTE'
       ) OR has_function_privilege(
           'sentinelflow_retention',
           'sentinelflow.enforce_action_transition_000026()', 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'version-29 retention action boundary is not canonical';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_proc function
        JOIN pg_roles owner ON owner.oid = function.proowner
        WHERE function.oid =
            'sentinelflow.run_retention_000023(uuid,timestamptz,integer)'::regprocedure
          AND owner.rolname = 'sentinelflow_migration'
          AND function.prosecdef
          AND function.proconfig =
              ARRAY['search_path=pg_catalog, sentinelflow']::text[]
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
        RAISE EXCEPTION 'version-29 retention caller boundary is not canonical';
    END IF;
END
$migration_chain$;

ROLLBACK;
