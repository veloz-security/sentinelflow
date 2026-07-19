BEGIN;

SET LOCAL search_path = sentinelflow, pg_catalog;

DO $schema_contract$
DECLARE
    projection_oid oid :=
        'sentinelflow.read_policy_validation_attempt_000032(uuid)'::regprocedure;
    projection record;
BEGIN
    SELECT function_record.prosecdef, function_record.provolatile,
           function_record.proretset, function_record.proconfig,
           function_record.proacl, function_record.proowner,
           owner.rolname AS owner_name, language.lanname AS language_name
    INTO projection
    FROM pg_catalog.pg_proc AS function_record
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_record.proowner
    JOIN pg_catalog.pg_language AS language
      ON language.oid = function_record.prolang
    WHERE function_record.oid = projection_oid;

    IF projection.owner_name <> 'sentinelflow_migration' OR
       projection.language_name <> 'plpgsql' OR
       NOT projection.prosecdef OR projection.provolatile <> 's' OR
       NOT projection.proretset OR
       projection.proconfig IS DISTINCT FROM
           ARRAY['search_path=pg_catalog, sentinelflow']::text[] OR
       EXISTS (
           SELECT 1
           FROM pg_catalog.aclexplode(COALESCE(
               projection.proacl,
               pg_catalog.acldefault('f', projection.proowner)
           )) AS privilege
           WHERE privilege.grantee = 0
             AND privilege.privilege_type = 'EXECUTE'
       ) OR NOT pg_catalog.has_function_privilege(
           'sentinelflow_api', projection_oid, 'EXECUTE'
       ) OR EXISTS (
           SELECT 1
           FROM pg_catalog.unnest(ARRAY[
               'sentinelflow_worker', 'sentinelflow_read',
               'sentinelflow_dispatcher', 'sentinelflow_retention',
               'sentinelflow_lifecycle', 'sentinelflow_metrics',
               'sentinelflow_demo_importer', 'sentinelflow_demo_activator'
           ]) AS denied(role_name)
           WHERE pg_catalog.has_function_privilege(
               denied.role_name, projection_oid, 'EXECUTE'
           )
       ) THEN
        RAISE EXCEPTION 'validation attempt projection owner/security/ACL differs';
    END IF;

    IF pg_catalog.has_table_privilege(
           'sentinelflow_api', 'sentinelflow.validation_attempt_claims', 'SELECT'
       ) OR pg_catalog.has_table_privilege(
           'sentinelflow_api', 'sentinelflow.validation_attempt_results', 'SELECT'
       ) OR pg_catalog.has_table_privilege(
           'sentinelflow_api', 'sentinelflow.validation_attempt_gates', 'SELECT'
       ) THEN
        RAISE EXCEPTION 'API received raw validation-attempt table access';
    END IF;

    IF pg_catalog.pg_get_function_result(projection_oid) LIKE
           '%prepared_snapshot jsonb%' OR
       pg_catalog.pg_get_function_result(projection_oid) LIKE
           '%terminal_mutation jsonb%' OR
       pg_catalog.pg_get_function_result(projection_oid) NOT LIKE
           '%prepared_snapshot_digest sha256_digest%' OR
       pg_catalog.pg_get_function_result(projection_oid) NOT LIKE
           '%terminal_mutation_digest sha256_digest%' THEN
        RAISE EXCEPTION 'projection return contract leaks raw JSON or omits digests: %',
            pg_catalog.pg_get_function_result(projection_oid);
    END IF;
END
$schema_contract$;

-- Foreign-key behavior is covered by validation-worker tests. Disabling FK
-- triggers keeps this fixture focused on policy scoping and data minimization.
SET LOCAL session_replication_role = replica;

INSERT INTO validation_attempt_claims (
    validation_attempt_id, job_id, analysis_id, incident_id,
    incident_version, evidence_snapshot_id, evidence_snapshot_digest,
    policy_id, command_candidate_id, validation_snapshot_id,
    outbox_attempt, state, failure_code, prepared_snapshot,
    prepared_snapshot_digest, generated_at, terminal_at
) VALUES
    (
        '019b0000-0000-7000-8000-00000000a411',
        '019b0000-0000-7000-8000-00000000a421',
        '019b0000-0000-7000-8000-00000000a431',
        '019b0000-0000-7000-8000-00000000a441', 7,
        '019b0000-0000-7000-8000-00000000a451',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '019b0000-0000-7000-8000-00000000a401',
        '019b0000-0000-7000-8000-00000000a461',
        '019b0000-0000-7000-8000-00000000a471', 1,
        'invalid', 'history_demo_binding_mismatch',
        '{"private":"must-not-leak"}'::jsonb,
        'sha256:abababababababababababababababababababababababababababababababab',
        '2026-07-19 07:00:00+00', '2026-07-19 07:00:01+00'
    ),
    (
        '019b0000-0000-7000-8000-00000000b411',
        '019b0000-0000-7000-8000-00000000b421',
        '019b0000-0000-7000-8000-00000000b431',
        '019b0000-0000-7000-8000-00000000b441', 3,
        '019b0000-0000-7000-8000-00000000b451',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        '019b0000-0000-7000-8000-00000000b401',
        '019b0000-0000-7000-8000-00000000b461',
        '019b0000-0000-7000-8000-00000000b471', 1,
        'interrupted', 'validation_attempt_timeout',
        '{"other_private":"must-not-leak"}'::jsonb,
        'sha256:babababababababababababababababababababababababababababababababa',
        '2026-07-19 07:01:00+00', '2026-07-19 07:01:01+00'
    ),
    (
        '019b0000-0000-7000-8000-00000000c411',
        '019b0000-0000-7000-8000-00000000c421',
        '019b0000-0000-7000-8000-00000000c431',
        '019b0000-0000-7000-8000-00000000c441', 1,
        '019b0000-0000-7000-8000-00000000c451',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        '019b0000-0000-7000-8000-00000000c401',
        '019b0000-0000-7000-8000-00000000c461',
        '019b0000-0000-7000-8000-00000000c471', 1,
        'started', NULL, '{"started_private":"must-not-leak"}'::jsonb,
        'sha256:cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca',
        '2026-07-19 07:02:00+00', NULL
    );

INSERT INTO validation_attempt_results (
    validation_attempt_id, result_state, failure_code, failed_gate,
    prepared_snapshot_digest, terminal_mutation, terminal_mutation_digest,
    completed_at
) VALUES
    (
        '019b0000-0000-7000-8000-00000000a411', 'invalid',
        'history_demo_binding_mismatch', 'historical_impact',
        'sha256:abababababababababababababababababababababababababababababababab',
        '{"terminal_private":"must-not-leak"}'::jsonb,
        'sha256:adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad',
        '2026-07-19 07:00:01+00'
    ),
    (
        '019b0000-0000-7000-8000-00000000b411', 'interrupted',
        'validation_attempt_timeout', NULL,
        'sha256:babababababababababababababababababababababababababababababababa',
        NULL, NULL, '2026-07-19 07:01:01+00'
    );

INSERT INTO validation_attempt_gates (
    validation_attempt_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
)
SELECT
    '019b0000-0000-7000-8000-00000000a411', gate_order, gate_name,
    gate_order < 6,
    CASE WHEN gate_order < 6 THEN 'ok'
         ELSE 'history_demo_binding_mismatch'
    END::ascii_id,
    ('sha256:' || pg_catalog.repeat(
        pg_catalog.substr('abcdef', gate_order, 1), 64
    ))::sha256_digest,
    ('sha256:' || pg_catalog.repeat(gate_order::text, 64))::sha256_digest,
    '2026-07-19 07:00:00+00'::timestamptz +
        pg_catalog.make_interval(secs => gate_order)
FROM (VALUES
    (1::smallint, 'structured_output'),
    (2::smallint, 'command_grammar'),
    (3::smallint, 'policy_evidence_command_consistency'),
    (4::smallint, 'protected_network'),
    (5::smallint, 'owned_schema_syntax'),
    (6::smallint, 'historical_impact')
) AS expected(gate_order, gate_name);

INSERT INTO validation_attempt_gates (
    validation_attempt_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
) VALUES (
    '019b0000-0000-7000-8000-00000000b411', 1, 'structured_output',
    true, 'ok',
    'sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1',
    'sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2',
    '2026-07-19 07:01:00+00'
);

-- The definer projection must fail closed if the immutable terminal claim and
-- result ever diverge. Exercise each cross-table binding independently and
-- through the API role, then restore the valid fixture before positive reads.
DO $terminal_binding$
DECLARE
    policy_a constant uuid := '019b0000-0000-7000-8000-00000000a401';
BEGIN
    DELETE FROM validation_attempt_results
    WHERE validation_attempt_id =
        '019b0000-0000-7000-8000-00000000a411';
    EXECUTE 'SET LOCAL ROLE sentinelflow_api';
    BEGIN
        PERFORM *
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_a);
        RAISE EXCEPTION 'projection accepted a missing terminal result';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        IF SQLERRM <> 'validation attempt terminal binding mismatch' OR
           position('private' IN lower(SQLERRM)) <> 0 THEN
            RAISE EXCEPTION 'missing-result error was not generic: %', SQLERRM;
        END IF;
    END;
    EXECUTE 'RESET ROLE';
    INSERT INTO validation_attempt_results (
        validation_attempt_id, result_state, failure_code, failed_gate,
        prepared_snapshot_digest, terminal_mutation,
        terminal_mutation_digest, completed_at
    ) VALUES (
        '019b0000-0000-7000-8000-00000000a411', 'invalid',
        'history_demo_binding_mismatch', 'historical_impact',
        'sha256:abababababababababababababababababababababababababababababababab',
        '{"terminal_private":"must-not-leak"}'::jsonb,
        'sha256:adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad',
        '2026-07-19 07:00:01+00'
    );

    UPDATE validation_attempt_claims
    SET state = 'interrupted'
    WHERE policy_id = policy_a;
    EXECUTE 'SET LOCAL ROLE sentinelflow_api';
    BEGIN
        PERFORM *
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_a);
        RAISE EXCEPTION 'projection accepted claim/result state divergence';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        IF SQLERRM <> 'validation attempt terminal binding mismatch' OR
           position('private' IN lower(SQLERRM)) <> 0 THEN
            RAISE EXCEPTION 'state-divergence error was not generic: %', SQLERRM;
        END IF;
    END;
    EXECUTE 'RESET ROLE';
    UPDATE validation_attempt_claims
    SET state = 'invalid'
    WHERE policy_id = policy_a;

    UPDATE validation_attempt_claims
    SET failure_code = 'different_terminal_failure'
    WHERE policy_id = policy_a;
    EXECUTE 'SET LOCAL ROLE sentinelflow_api';
    BEGIN
        PERFORM *
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_a);
        RAISE EXCEPTION 'projection accepted claim/result failure divergence';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        IF SQLERRM <> 'validation attempt terminal binding mismatch' OR
           position('private' IN lower(SQLERRM)) <> 0 THEN
            RAISE EXCEPTION 'failure-divergence error was not generic: %', SQLERRM;
        END IF;
    END;
    EXECUTE 'RESET ROLE';
    UPDATE validation_attempt_claims
    SET failure_code = 'history_demo_binding_mismatch'
    WHERE policy_id = policy_a;

    UPDATE validation_attempt_claims
    SET prepared_snapshot_digest =
        'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
    WHERE policy_id = policy_a;
    EXECUTE 'SET LOCAL ROLE sentinelflow_api';
    BEGIN
        PERFORM *
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_a);
        RAISE EXCEPTION 'projection accepted prepared snapshot digest divergence';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        IF SQLERRM <> 'validation attempt terminal binding mismatch' OR
           position('private' IN lower(SQLERRM)) <> 0 THEN
            RAISE EXCEPTION 'digest-divergence error was not generic: %', SQLERRM;
        END IF;
    END;
    EXECUTE 'RESET ROLE';
    UPDATE validation_attempt_claims
    SET prepared_snapshot_digest =
        'sha256:abababababababababababababababababababababababababababababababab'
    WHERE policy_id = policy_a;

    UPDATE validation_attempt_claims
    SET terminal_at = terminal_at + interval '1 microsecond'
    WHERE policy_id = policy_a;
    EXECUTE 'SET LOCAL ROLE sentinelflow_api';
    BEGIN
        PERFORM *
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_a);
        RAISE EXCEPTION 'projection accepted terminal timestamp divergence';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        IF SQLERRM <> 'validation attempt terminal binding mismatch' OR
           position('private' IN lower(SQLERRM)) <> 0 THEN
            RAISE EXCEPTION 'timestamp-divergence error was not generic: %', SQLERRM;
        END IF;
    END;
    EXECUTE 'RESET ROLE';
    UPDATE validation_attempt_claims
    SET terminal_at = terminal_at - interval '1 microsecond'
    WHERE policy_id = policy_a;
END
$terminal_binding$;

SET LOCAL session_replication_role = origin;

SET LOCAL ROLE sentinelflow_api;

DO $api_projection$
DECLARE
    policy_a constant uuid := '019b0000-0000-7000-8000-00000000a401';
    policy_b constant uuid := '019b0000-0000-7000-8000-00000000b401';
    row_count integer;
    gate_orders smallint[];
    gate_names text[];
    gate_states text[];
    gate_codes text[];
    gate_digests text[];
    projected_keys text[];
BEGIN
    BEGIN
        PERFORM *
        FROM sentinelflow.read_policy_validation_attempt_000032(
            '019b0000-0000-7000-8000-00000000c401'
        );
        RAISE EXCEPTION 'projection accepted a nonterminal claim without a result';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        IF SQLERRM <> 'validation attempt terminal binding mismatch' OR
           position('private' IN lower(SQLERRM)) <> 0 THEN
            RAISE EXCEPTION 'nonterminal-result error was not generic: %', SQLERRM;
        END IF;
    END;

    SELECT count(*),
           array_agg(projection.gate_order ORDER BY projection.gate_order),
           array_agg(projection.gate_name ORDER BY projection.gate_order),
           array_agg(projection.gate_state ORDER BY projection.gate_order),
           array_agg(projection.gate_result_code::text ORDER BY projection.gate_order),
           array_agg(projection.gate_artifact_digest::text ORDER BY projection.gate_order)
    INTO row_count, gate_orders, gate_names, gate_states, gate_codes, gate_digests
    FROM sentinelflow.read_policy_validation_attempt_000032(policy_a) AS projection;

    IF row_count <> 6 OR
       gate_orders <> ARRAY[1, 2, 3, 4, 5, 6]::smallint[] OR
       gate_names <> ARRAY[
           'structured_output', 'command_grammar',
           'policy_evidence_command_consistency', 'protected_network',
           'owned_schema_syntax', 'historical_impact'
       ]::text[] OR
       gate_states <> ARRAY[
           'passed', 'passed', 'passed', 'passed', 'passed', 'failed'
       ]::text[] OR
       gate_codes <> ARRAY[
           'ok', 'ok', 'ok', 'ok', 'ok', 'history_demo_binding_mismatch'
       ]::text[] OR
       gate_digests <> ARRAY[
           'sha256:' || repeat('1', 64), 'sha256:' || repeat('2', 64),
           'sha256:' || repeat('3', 64), 'sha256:' || repeat('4', 64),
           'sha256:' || repeat('5', 64), 'sha256:' || repeat('6', 64)
       ]::text[] THEN
        RAISE EXCEPTION 'API gate projection differs';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_a) AS projection
        WHERE projection.validation_attempt_id <>
                  '019b0000-0000-7000-8000-00000000a411' OR
              projection.policy_id <> policy_a OR
              projection.analysis_id <>
                  '019b0000-0000-7000-8000-00000000a431' OR
              projection.incident_id <>
                  '019b0000-0000-7000-8000-00000000a441' OR
              projection.incident_version <> 7 OR
              projection.state <> 'invalid' OR
              projection.failure_code <> 'history_demo_binding_mismatch' OR
              projection.failed_gate <> 'historical_impact' OR
              projection.prepared_snapshot_digest <>
                  'sha256:abababababababababababababababababababababababababababababababab' OR
              projection.terminal_mutation_digest <>
                  'sha256:adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad' OR
              projection.completed_at <> '2026-07-19 07:00:01+00'
    ) THEN
        RAISE EXCEPTION 'API attempt binding or terminal digest differs';
    END IF;

    SELECT array_agg(key ORDER BY key)
    INTO projected_keys
    FROM sentinelflow.read_policy_validation_attempt_000032(policy_a) AS projection
    CROSS JOIN LATERAL jsonb_object_keys(to_jsonb(projection)) AS key
    WHERE projection.gate_order = 1;
    IF projected_keys && ARRAY[
        'prepared_snapshot', 'terminal_mutation', 'input_digest', 'checked_at'
    ]::text[] THEN
        RAISE EXCEPTION 'raw or unnecessary validation data leaked: %', projected_keys;
    END IF;

    IF (SELECT count(*)
        FROM sentinelflow.read_policy_validation_attempt_000032(policy_b)) <> 1 OR
       EXISTS (
           SELECT 1
           FROM sentinelflow.read_policy_validation_attempt_000032(policy_b) AS projection
           WHERE projection.policy_id <> policy_b OR
                 projection.validation_attempt_id <>
                     '019b0000-0000-7000-8000-00000000b411' OR
                 projection.state <> 'interrupted' OR
                 projection.gate_artifact_digest <>
                     'sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2'
       ) OR EXISTS (
           SELECT 1 FROM sentinelflow.read_policy_validation_attempt_000032(
               '019b0000-0000-7000-8000-00000000d401'
           )
       ) OR EXISTS (
           SELECT 1 FROM sentinelflow.read_policy_validation_attempt_000032(NULL)
       ) THEN
        RAISE EXCEPTION 'policy boundary, terminal-only filter, or unknown lookup differs';
    END IF;
END
$api_projection$;

RESET ROLE;

ROLLBACK;
