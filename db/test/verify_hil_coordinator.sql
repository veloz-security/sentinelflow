\set ON_ERROR_STOP on

BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $verify_hil_coordinator$
DECLARE
    coordinator_oid oid;
    issue_oid oid;
    result_oid oid;
    relation_name text;
    canonical_reason bytea;
    expected_reason bytea := convert_to(
        '{"reason_code":"operator_request","reason_text":"Reviewed synthetic evidence","schema_version":"hil-reason-v1"}',
        'UTF8'
    );
BEGIN
    IF current_setting('server_version_num')::integer < 170000 THEN
        RAISE EXCEPTION 'PostgreSQL 17 or newer is required';
    END IF;

    IF (SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 10) <> 1 THEN
        RAISE EXCEPTION 'control-plane hardening migration is not applied exactly once';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'sentinelflow'
          AND (
              (table_name = 'decision_challenges' AND column_name IN ('challenge_jcs', 'challenge_digest')) OR
              (table_name = 'hil_reasons' AND column_name IN ('reason_code', 'reason_jcs')) OR
              (table_name = 'approval_decisions' AND column_name IN ('decision_jcs', 'decision_digest')) OR
              (table_name = 'enforcement_authorizations' AND column_name = 'authorization_jcs')
          )
          AND is_nullable <> 'NO'
    ) THEN
        RAISE EXCEPTION 'canonical HIL evidence columns must be NOT NULL';
    END IF;

    IF (
        SELECT count(*)
        FROM pg_constraint
        WHERE conname IN (
            'decision_challenge_jcs_evidence',
            'hil_reason_jcs_evidence',
            'approval_decision_jcs_evidence',
            'enforcement_authorization_jcs_evidence',
            'execution_result_list_set_has_no_handle',
            'enforcement_action_list_set_has_no_handle'
        ) AND convalidated
    ) <> 6 THEN
        RAISE EXCEPTION 'canonical evidence or list-set constraints are incomplete';
    END IF;

    canonical_reason := sentinelflow.hil_reason_jcs(
        'operator_request', 'Reviewed synthetic evidence'
    );
    IF canonical_reason <> expected_reason OR
       sentinelflow.hil_sha256(canonical_reason) <> (
           'sha256:' || encode(sha256(expected_reason), 'hex')
       )::sentinelflow.sha256_digest THEN
        RAISE EXCEPTION 'hil-reason-v1 JCS or digest construction drifted';
    END IF;
    IF NOT ('é' IS NFC NORMALIZED) OR (U&'e\0301' IS NFC NORMALIZED) THEN
        RAISE EXCEPTION 'PostgreSQL NFC normalization predicate is unavailable or incorrect';
    END IF;

    SELECT min(proc.oid)
    INTO coordinator_oid
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'commit_hil_policy_decision';
    SELECT min(proc.oid)
    INTO issue_oid
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'issue_hil_policy_challenge';
    SELECT min(proc.oid)
    INTO result_oid
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND proc.proname = 'record_execution_result';

    IF coordinator_oid IS NULL OR issue_oid IS NULL OR result_oid IS NULL THEN
        RAISE EXCEPTION 'required HIL coordinator functions are missing';
    END IF;
    IF NOT (
        SELECT proc.prosecdef AND
               proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
        FROM pg_proc proc WHERE proc.oid = coordinator_oid
    ) OR NOT (
        SELECT proc.prosecdef AND
               proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
        FROM pg_proc proc WHERE proc.oid = issue_oid
    ) OR NOT (
        SELECT proc.prosecdef AND
               proc.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow']::text[]
        FROM pg_proc proc WHERE proc.oid = result_oid
    ) THEN
        RAISE EXCEPTION 'coordinator functions must be SECURITY DEFINER with a fixed search_path';
    END IF;

    IF position(
        'mutation_invoked AND p_started_at >= capability.expires_at'
        IN pg_get_functiondef(result_oid)
    ) = 0 OR position(
        'NOT mutation_invoked AND p_started_at >= capability.expires_at'
        IN pg_get_functiondef(result_oid)
    ) = 0 THEN
        RAISE EXCEPTION 'execution-result freshness is not half-open at capability expiry';
    END IF;

    IF NOT has_function_privilege('sentinelflow_api', coordinator_oid, 'EXECUTE') OR
       NOT has_function_privilege('sentinelflow_api', issue_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_worker', coordinator_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_dispatcher', coordinator_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_worker', issue_oid, 'EXECUTE') OR
       has_function_privilege('sentinelflow_api', result_oid, 'EXECUTE') OR
       NOT has_function_privilege('sentinelflow_dispatcher', result_oid, 'EXECUTE') THEN
        RAISE EXCEPTION 'HIL function EXECUTE grants do not match the role boundary';
    END IF;

    FOREACH relation_name IN ARRAY ARRAY[
        'sentinelflow.decision_challenges',
        'sentinelflow.hil_reasons',
        'sentinelflow.approval_decisions',
        'sentinelflow.enforcement_authorizations',
        'sentinelflow.enforcement_actions',
        'sentinelflow.outbox_jobs',
        'sentinelflow.dispatch_operations'
    ]
    LOOP
        IF has_table_privilege('sentinelflow_api', relation_name, 'INSERT') OR
           has_table_privilege('sentinelflow_api', relation_name, 'UPDATE') OR
           has_table_privilege('sentinelflow_api', relation_name, 'DELETE') OR
           has_any_column_privilege('sentinelflow_api', relation_name, 'UPDATE') THEN
            RAISE EXCEPTION 'API role retains direct mutation privilege on %', relation_name;
        END IF;
    END LOOP;

    IF position('lease_expires_at' IN pg_get_viewdef(
        'sentinelflow.dispatcher_approved_outbox'::regclass, true
    )) = 0 OR position('leased' IN pg_get_viewdef(
        'sentinelflow.dispatcher_approved_outbox'::regclass, true
    )) = 0 THEN
        RAISE EXCEPTION 'dispatcher view does not expose expired leases for bounded recovery';
    END IF;
    IF position('FOR UPDATE OF job' IN pg_get_functiondef(
        'sentinelflow.claim_dispatch_job(uuid,uuid,sentinelflow.ascii_id,timestamptz)'::regprocedure
    )) = 0 OR position('lease_expires_at > server_now' IN pg_get_functiondef(
        'sentinelflow.finish_dispatch_job(uuid,uuid,text,sentinelflow.ascii_id,sentinelflow.sha256_digest,timestamptz)'::regprocedure
    )) = 0 THEN
        RAISE EXCEPTION 'dispatcher lease fencing or reclaim locking is missing';
    END IF;
END
$verify_hil_coordinator$;

SET LOCAL ROLE sentinelflow_api;

DO $verify_api_denial$
BEGIN
    BEGIN
        UPDATE sentinelflow.approval_decisions
        SET decision = decision
        WHERE false;
        RAISE EXCEPTION 'API direct HIL mutation unexpectedly succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;
    END;
END
$verify_api_denial$;

RESET ROLE;
SET LOCAL ROLE sentinelflow_dispatcher;

DO $verify_list_set_handle_rejection$
BEGIN
    BEGIN
        PERFORM sentinelflow.record_execution_result(
            '019b0000-0000-4000-8000-000000009101'::uuid,
            '019b0000-0000-4000-8000-000000009102'::uuid,
            '019b0000-0000-4000-8000-000000009103'::uuid,
            '019b0000-0000-4000-8000-000000009104'::uuid,
            ('sha256:' || repeat('1', 64))::sentinelflow.sha256_digest,
            'add',
            '019b0000-0000-4000-8000-000000009105'::uuid,
            ('sha256:' || repeat('2', 64))::sentinelflow.sha256_digest,
            '192.0.2.10'::sentinelflow.canonical_ipv4,
            'applied', 'success', 'active', 1, 60,
            ('sha256:' || repeat('3', 64))::sentinelflow.sha256_digest,
            date_trunc('milliseconds', clock_timestamp()),
            date_trunc('milliseconds', clock_timestamp()),
            1, 'none', convert_to('{}', 'UTF8'),
            ('sha256:' || repeat('4', 64))::sentinelflow.sha256_digest,
            decode(repeat('00', 64), 'hex')
        );
        RAISE EXCEPTION 'list-set element handle unexpectedly accepted';
    EXCEPTION
        WHEN SQLSTATE '22023' THEN NULL;
    END;
END
$verify_list_set_handle_rejection$;

RESET ROLE;
ROLLBACK;
