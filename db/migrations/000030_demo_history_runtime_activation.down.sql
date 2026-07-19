BEGIN;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = 30 AND name = 'demo_history_runtime_activation'
    ) OR pg_catalog.to_regrole('sentinelflow_demo_importer') IS NULL OR
       pg_catalog.to_regrole('sentinelflow_demo_activator') IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history runtime activation downgrade preflight failed';
    END IF;
END
$preflight$;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DO $evidence_guard$
BEGIN
    IF EXISTS (SELECT 1 FROM sentinelflow.demo_history_runtime_uses) OR
       EXISTS (SELECT 1 FROM sentinelflow.demo_history_runtime_activations) OR
       EXISTS (
           SELECT 1
           FROM sentinelflow.demo_history_runtime_capability_expectation
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history activation or capability evidence prevents downgrade';
    END IF;
END
$evidence_guard$;

RESET ROLE;
DROP FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_and_fence_000030(
    bytea, bytea, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz,
    text, text
);
DROP FUNCTION sentinelflow.finalize_demo_history_bootstrap_role_fence_000030();
DROP FUNCTION sentinelflow.fence_demo_history_bootstrap_roles_000030();
DROP FUNCTION sentinelflow.finalize_demo_history_importer_role_fence_000030();
DROP FUNCTION sentinelflow.fence_demo_history_importer_role_000030();
DROP FUNCTION sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
    text, text, timestamptz
);
SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

DROP FUNCTION sentinelflow.read_demo_history_import_recovery_leased_000030(uuid);
DROP FUNCTION sentinelflow.read_demo_history_import_leased_000030(uuid);
DROP FUNCTION sentinelflow.record_demo_history_import_failure_leased_000030(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.complete_demo_history_import_leased_000030(uuid);
DROP FUNCTION sentinelflow.append_demo_history_source_coverage_leased_000030(
    uuid, text, text, text, timestamptz, timestamptz, bigint, bigint
);
DROP FUNCTION sentinelflow.append_demo_history_auth_leased_000030(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, text, text, text, text, text
);
DROP FUNCTION sentinelflow.append_demo_history_gateway_leased_000030(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, timestamptz, text, text, text, text, text, text, text,
    text, integer, bigint, bigint, integer
);
DROP FUNCTION sentinelflow.begin_demo_history_import_leased_000030(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz
);
DROP FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000030(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
);
DROP FUNCTION sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    uuid, uuid, bytea, uuid, uuid, uuid, text, text, text, bigint, text,
    text, text, text, text, timestamptz, timestamptz, timestamptz,
    timestamptz, text, text
);
DROP FUNCTION sentinelflow.prepare_analysis_attempt_demo_exact_000030(
    uuid, uuid, uuid, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.prepare_analysis_attempt_demo_legacy_000030(
    uuid, uuid, uuid, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.demo_history_impact_digest_000030(
    uuid, inet, text, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.attach_demo_history_runtime_activation_000030(
    bytea, text, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz,
    text, text
);
DROP FUNCTION sentinelflow.create_demo_history_runtime_activation_pair_000030(
    bytea, bytea, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz,
    text, text
);
DROP FUNCTION sentinelflow.record_demo_history_runtime_use_000030(
    bytea, text, uuid, uuid, integer
);
DROP FUNCTION sentinelflow.verify_demo_history_runtime_activation_000030(
    bytea, text, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz,
    text, text
);
DROP FUNCTION sentinelflow.verify_demo_history_immutable_binding_000030(
    uuid, uuid, uuid, text, text, text, bigint, text, text, text, text,
    text, timestamptz, timestamptz, timestamptz, timestamptz, text
);
DROP FUNCTION sentinelflow.read_demo_history_import_recovery_000030(uuid);
DROP FUNCTION sentinelflow.assert_demo_history_importer_lease_000030();
DROP FUNCTION sentinelflow.demo_history_importer_lease_valid_000030();
DROP FUNCTION sentinelflow.demo_history_bootstrap_timeouts_exact_000030(text);

DROP TRIGGER demo_history_runtime_use_append_only
    ON sentinelflow.demo_history_runtime_uses;
DROP TRIGGER demo_history_runtime_activation_append_only
    ON sentinelflow.demo_history_runtime_activations;
DROP TRIGGER demo_history_runtime_capability_expectation_append_only
    ON sentinelflow.demo_history_runtime_capability_expectation;
DROP TABLE sentinelflow.demo_history_runtime_uses;
DROP TABLE sentinelflow.demo_history_runtime_activations;
DROP TABLE sentinelflow.demo_history_runtime_capability_expectation;

GRANT EXECUTE ON FUNCTION sentinelflow.begin_demo_history_import(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_gateway(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, timestamptz, text, text, text, text, text, text, text,
    text, integer, bigint, bigint, integer
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_auth(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, text, text, text, text, text
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.append_demo_history_source_coverage(
    uuid, text, text, text, timestamptz, timestamptz, bigint, bigint
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.complete_demo_history_import(uuid)
    TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.record_demo_history_import_failure(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz, text
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.read_demo_history_import(uuid)
    TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.verify_demo_history_validation_binding_000022(
    uuid, uuid, uuid, text, text, text, bigint, text, text, text, text,
    text, timestamptz, timestamptz, timestamptz, timestamptz, text
) TO sentinelflow_worker;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt_verified_demo_000022(
    uuid, uuid, uuid, uuid, uuid, text, text, text, bigint, text, text,
    text, text, text, timestamptz, timestamptz, timestamptz, timestamptz,
    text
) TO sentinelflow_worker;

REVOKE EXECUTE ON FUNCTION sentinelflow.begin_demo_history_import(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz
) FROM sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.append_demo_history_gateway(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, timestamptz, text, text, text, text, text, text, text,
    text, integer, bigint, bigint, integer
) FROM sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.append_demo_history_auth(
    uuid, text, bigint, uuid, text, integer, uuid, text, uuid, uuid,
    timestamptz, text, text, text, text, text
) FROM sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.append_demo_history_source_coverage(
    uuid, text, text, text, timestamptz, timestamptz, bigint, bigint
) FROM sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.complete_demo_history_import(uuid)
    FROM sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.record_demo_history_import_failure(
    uuid, uuid, text, text, text, bigint, text, text, text, text, text,
    timestamptz, timestamptz, timestamptz, timestamptz, text
) FROM sentinelflow_demo_importer;
REVOKE EXECUTE ON FUNCTION sentinelflow.read_demo_history_import(uuid)
    FROM sentinelflow_demo_importer;

REVOKE USAGE ON SCHEMA sentinelflow
    FROM sentinelflow_demo_importer, sentinelflow_demo_activator;

DELETE FROM sentinelflow.schema_migrations
WHERE version = 30 AND name = 'demo_history_runtime_activation';

RESET ROLE;

DO $database_authority_cleanup$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'sentinelflow_demo_importer',
        'sentinelflow_demo_activator'
    ]
    LOOP
        EXECUTE format(
            'ALTER ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB '
            'NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 '
            'PASSWORD NULL VALID UNTIL ''1970-01-01 00:00:00+00''',
            role_name
        );
        EXECUTE format(
            'ALTER ROLE %I IN DATABASE %I RESET ALL',
            role_name,
            current_database()
        );
        EXECUTE format(
            'REVOKE CONNECT ON DATABASE %I FROM %I',
            current_database(),
            role_name
        );
    END LOOP;

    PERFORM pg_catalog.pg_terminate_backend(activity.pid, 5000)
    FROM pg_catalog.pg_stat_activity AS activity
    WHERE activity.usename IN (
        'sentinelflow_demo_importer',
        'sentinelflow_demo_activator'
    )
      AND activity.pid <> pg_catalog.pg_backend_pid();
    PERFORM pg_catalog.pg_stat_clear_snapshot();
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND activity.pid <> pg_catalog.pg_backend_pid()
    ) OR (
        SELECT count(*)
        FROM pg_catalog.pg_authid AS role
        WHERE role.rolname IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND NOT role.rolcanlogin AND role.rolpassword IS NULL
          AND NOT role.rolinherit AND NOT role.rolsuper
          AND NOT role.rolcreatedb AND NOT role.rolcreaterole
          AND NOT role.rolreplication AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
          AND role.rolvaliduntil =
              '1970-01-01 00:00:00+00'::timestamptz
    ) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'demo history downgrade authority cleanup failed';
    END IF;
END
$database_authority_cleanup$;

COMMIT;
