\set ON_ERROR_STOP on

BEGIN;

DO $verify_sse_metadata$
DECLARE
    actual_columns text[];
    function_count integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 13 AND name = 'sse_notification_ledger'
    ) THEN
        RAISE EXCEPTION 'missing SSE notification migration marker';
    END IF;

    SELECT array_agg(column_name::text ORDER BY ordinal_position)
    INTO actual_columns
    FROM information_schema.columns
    WHERE table_schema = 'sentinelflow'
      AND table_name = 'sse_notification_ledger';
    IF actual_columns IS DISTINCT FROM ARRAY[
        'cursor', 'event_type', 'resource_type', 'resource_id',
        'resource_version', 'state', 'summary_code', 'incident_id',
        'trace_id', 'occurred_at'
    ]::text[] THEN
        RAISE EXCEPTION 'unexpected SSE ledger columns: %', actual_columns;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'sentinelflow'
          AND table_name = 'sse_notification_ledger'
          AND data_type IN ('json', 'jsonb', 'bytea')
    ) THEN
        RAISE EXCEPTION 'SSE ledger contains an unrestricted payload column';
    END IF;

    SELECT count(*) INTO function_count
    FROM pg_proc procedure
    JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'sentinelflow'
      AND procedure.proname IN (
          'append_sse_notification', 'emit_sse_notification_from_domain',
          'read_sse_notification_window', 'read_sse_notification_page',
          'prune_sse_notification_ledger'
      )
      AND procedure.prosecdef
      AND procedure.proconfig @> ARRAY['search_path=pg_catalog, sentinelflow'];
    IF function_count <> 5 THEN
        RAISE EXCEPTION 'SSE functions are not all SECURITY DEFINER with fixed search_path';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM unnest(ARRAY[
            'sentinelflow_api', 'sentinelflow_worker',
            'sentinelflow_dispatcher', 'sentinelflow_read'
        ]) role_name
        WHERE has_table_privilege(
                  role_name,
                  'sentinelflow.sse_notification_ledger',
                  'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
              )
           OR has_table_privilege(
                  role_name,
                  'sentinelflow.sse_notification_replay_state',
                  'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
              )
           OR has_sequence_privilege(
                  role_name,
                  'sentinelflow.sse_notification_cursor_seq',
                  'USAGE,SELECT,UPDATE'
              )
    ) THEN
        RAISE EXCEPTION 'runtime role has direct SSE ledger or sequence authority';
    END IF;
    IF NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.read_sse_notification_window()', 'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.read_sse_notification_page(bigint,integer)', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.append_sse_notification(text,text,uuid,bigint,text,text,uuid,uuid)',
        'EXECUTE'
    ) OR NOT has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.prune_sse_notification_ledger(timestamptz,integer)',
        'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_dispatcher',
        'sentinelflow.read_sse_notification_window()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_read',
        'sentinelflow.read_sse_notification_window()', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_api',
        'sentinelflow.prune_sse_notification_ledger(timestamptz,integer)', 'EXECUTE'
    ) OR has_function_privilege(
        'sentinelflow_worker',
        'sentinelflow.append_sse_notification(text,text,uuid,bigint,text,text,uuid,uuid)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'SSE function grants do not match the role boundary';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_proc procedure
        JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
        CROSS JOIN LATERAL aclexplode(
            coalesce(procedure.proacl, acldefault('f', procedure.proowner))
        ) acl
        WHERE namespace.nspname = 'sentinelflow'
          AND procedure.proname IN (
              'append_sse_notification', 'emit_sse_notification_from_domain',
              'read_sse_notification_window', 'read_sse_notification_page',
              'prune_sse_notification_ledger'
          )
          AND acl.grantee = 0
          AND acl.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'PUBLIC retains SSE function execution';
    END IF;
END
$verify_sse_metadata$;

-- Create two retained events with a rolled-back allocation between them. The
-- cursor gap is intentional; committed cursors must remain strictly ordered.
SET LOCAL ROLE sentinelflow_migration;
DO $verify_sse_append$
DECLARE
    first_cursor bigint;
    second_cursor bigint;
BEGIN
    SELECT cursor INTO first_cursor
    FROM sentinelflow.append_sse_notification(
        'source.degraded', 'source_health',
        '019b0000-0000-7000-8000-00000000e001', 1,
        'degraded', 'source_degraded', NULL, NULL
    );

    BEGIN
        PERFORM sentinelflow.append_sse_notification(
            'source.recovered', 'source_health',
            '019b0000-0000-7000-8000-00000000e099', 1,
            'recovered', 'source_recovered', NULL, NULL
        );
        RAISE EXCEPTION 'force sequence allocation rollback';
    EXCEPTION WHEN raise_exception THEN
        NULL;
    END;

    SELECT cursor INTO second_cursor
    FROM sentinelflow.append_sse_notification(
        'source.recovered', 'source_health',
        '019b0000-0000-7000-8000-00000000e001', 1,
        'recovered', 'source_recovered', NULL, NULL
    );
    IF second_cursor <= first_cursor + 1 THEN
        RAISE EXCEPTION 'expected a stable sequence gap: first %, second %',
            first_cursor, second_cursor;
    END IF;

    BEGIN
        UPDATE sentinelflow.sse_notification_ledger
        SET state = state WHERE cursor = first_cursor;
        RAISE EXCEPTION 'direct SSE update unexpectedly succeeded';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    BEGIN
        DELETE FROM sentinelflow.sse_notification_ledger
        WHERE cursor = first_cursor;
        RAISE EXCEPTION 'direct SSE delete unexpectedly succeeded';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
    BEGIN
        PERFORM sentinelflow.append_sse_notification(
            'source.recovered', 'source_health',
            '019b0000-0000-7000-8000-00000000e002', 1,
            'recovered', 'wrong_summary', NULL, NULL
        );
        RAISE EXCEPTION 'invalid SSE append unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE 'SF201' THEN
        NULL;
    END;
END
$verify_sse_append$;
RESET ROLE;

SET LOCAL ROLE sentinelflow_api;
DO $verify_sse_api$
DECLARE
    floor_value bigint;
    watermark_value bigint;
    row_count integer;
BEGIN
    SELECT replay_floor, watermark INTO floor_value, watermark_value
    FROM sentinelflow.read_sse_notification_window();
    IF floor_value <> 0 OR watermark_value <= 0 THEN
        RAISE EXCEPTION 'unexpected initial replay window: %..%', floor_value, watermark_value;
    END IF;
    SELECT count(*) INTO row_count
    FROM sentinelflow.read_sse_notification_page(0, 64)
    WHERE cursor IS NOT NULL;
    IF row_count <> 2 THEN
        RAISE EXCEPTION 'expected two retained SSE events, got %', row_count;
    END IF;

    BEGIN
        PERFORM 1 FROM sentinelflow.sse_notification_ledger;
        RAISE EXCEPTION 'API direct SSE read unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
    BEGIN
        DELETE FROM sentinelflow.sse_notification_ledger WHERE false;
        RAISE EXCEPTION 'API direct SSE delete unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
    BEGIN
        INSERT INTO sentinelflow.sse_notification_ledger (
            cursor, event_type, resource_type, resource_id,
            resource_version, state, summary_code, occurred_at
        ) VALUES (
            999999, 'source.degraded', 'source_health',
            '019b0000-0000-7000-8000-00000000efff',
            1, 'degraded', 'source_degraded', clock_timestamp()
        );
        RAISE EXCEPTION 'API cursor spoof unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
    BEGIN
        PERFORM nextval('sentinelflow.sse_notification_cursor_seq');
        RAISE EXCEPTION 'API sequence use unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$verify_sse_api$;
RESET ROLE;

SELECT pg_sleep(0.01);
SET LOCAL ROLE sentinelflow_worker;
DO $verify_sse_prune$
DECLARE
    result record;
BEGIN
    SELECT * INTO result
    FROM sentinelflow.prune_sse_notification_ledger(clock_timestamp(), 1);
    IF result.pruned_count <> 1 OR result.replay_floor <= 0 OR
       result.watermark <= result.replay_floor THEN
        RAISE EXCEPTION 'bounded prefix prune did not atomically advance floor: %', result;
    END IF;
    BEGIN
        DELETE FROM sentinelflow.sse_notification_ledger WHERE false;
        RAISE EXCEPTION 'worker direct SSE delete unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$verify_sse_prune$;
RESET ROLE;

SET LOCAL ROLE sentinelflow_api;
DO $verify_sse_gap$
DECLARE
    result record;
BEGIN
    SELECT * INTO result
    FROM sentinelflow.read_sse_notification_page(0, 64);
    IF NOT result.replay_gap OR result.cursor IS NOT NULL OR result.replay_floor <= 0 THEN
        RAISE EXCEPTION 'pruned cursor did not return replay gap metadata: %', result;
    END IF;
END
$verify_sse_gap$;
RESET ROLE;

ROLLBACK;
