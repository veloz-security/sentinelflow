\set ON_ERROR_STOP on

BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $verify_dispatch_recovery_contract$
DECLARE
    recovery_oid oid;
    definition text;
BEGIN
    IF current_setting('server_version_num')::integer < 170000 THEN
        RAISE EXCEPTION 'PostgreSQL 17 or newer is required';
    END IF;
    IF (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 11) <> 1 THEN
        RAISE EXCEPTION 'dispatch recovery migration is not applied exactly once';
    END IF;

    SELECT proc.oid, pg_get_functiondef(proc.oid)
    INTO recovery_oid, definition
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'recover_dispatch_execution'
      AND proc.proargtypes = '2950 2950'::oidvector;
    IF recovery_oid IS NULL THEN
        RAISE EXCEPTION 'narrow dispatch recovery function is missing';
    END IF;
    IF NOT (
        SELECT proc.prosecdef AND
               proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
        FROM pg_proc proc WHERE proc.oid = recovery_oid
    ) OR position('FOR SHARE' IN definition) = 0 OR
       position('server_now := clock_timestamp()' IN definition) = 0 THEN
        RAISE EXCEPTION 'dispatch recovery locking or SECURITY DEFINER boundary drifted';
    END IF;

    IF NOT has_function_privilege('sentinelflow_dispatcher', recovery_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_api', recovery_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_worker', recovery_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_read', recovery_oid, 'EXECUTE') OR
       EXISTS (
           SELECT 1 FROM aclexplode((SELECT proacl FROM pg_proc WHERE oid = recovery_oid)) acl
           WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'dispatch recovery EXECUTE privilege is broader than dispatcher';
    END IF;

    IF has_table_privilege('sentinelflow_dispatcher', 'sentinelflow.outbox_jobs', 'SELECT') OR
       has_table_privilege('sentinelflow_dispatcher', 'sentinelflow.execution_capabilities', 'SELECT') OR
       has_table_privilege('sentinelflow_dispatcher', 'sentinelflow.execution_results', 'SELECT') THEN
        RAISE EXCEPTION 'dispatcher received direct recovery table visibility';
    END IF;
END
$verify_dispatch_recovery_contract$;

SET LOCAL ROLE sentinelflow_dispatcher;

DO $verify_wrong_job_fails_closed$
BEGIN
    BEGIN
        PERFORM * FROM sentinelflow.recover_dispatch_execution(
            '019b0000-0000-4000-8000-000000009701'::uuid,
            '019b0000-0000-4000-8000-000000009702'::uuid
        );
        RAISE EXCEPTION 'unknown recovery job unexpectedly returned artifacts';
    EXCEPTION
        WHEN SQLSTATE 'SF101' THEN NULL;
    END;
END
$verify_wrong_job_fails_closed$;

RESET ROLE;
SET LOCAL ROLE sentinelflow_api;

DO $verify_api_denial$
BEGIN
    BEGIN
        PERFORM * FROM sentinelflow.recover_dispatch_execution(
            '019b0000-0000-4000-8000-000000009701'::uuid,
            '019b0000-0000-4000-8000-000000009702'::uuid
        );
        RAISE EXCEPTION 'API unexpectedly executed dispatch recovery';
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;
    END;
END
$verify_api_denial$;

RESET ROLE;
ROLLBACK;
