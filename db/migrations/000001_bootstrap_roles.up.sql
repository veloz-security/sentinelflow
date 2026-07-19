BEGIN;

DO $roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'sentinelflow_migration',
        'sentinelflow_api',
        'sentinelflow_worker',
        'sentinelflow_read',
        'sentinelflow_dispatcher'
    ]
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                role_name
            );
        ELSE
            EXECUTE format(
                'ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                role_name
            );
        END IF;
    END LOOP;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS sentinelflow AUTHORIZATION sentinelflow_migration;
ALTER SCHEMA sentinelflow OWNER TO sentinelflow_migration;
REVOKE ALL ON SCHEMA sentinelflow FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

DO $database_grants$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'sentinelflow_migration',
        'sentinelflow_api',
        'sentinelflow_worker',
        'sentinelflow_read',
        'sentinelflow_dispatcher'
    ]
    LOOP
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), role_name);
        EXECUTE format(
            'ALTER ROLE %I IN DATABASE %I SET search_path = sentinelflow, pg_catalog',
            role_name,
            current_database()
        );
    END LOOP;
END
$database_grants$;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_]+$'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO schema_migrations (version, name)
VALUES (1, 'bootstrap_roles')
ON CONFLICT (version) DO NOTHING;

COMMIT;
