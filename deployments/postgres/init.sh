#!/usr/bin/env sh

set -eu

export LC_ALL=C
export PGCONNECT_TIMEOUT=5

make_demo_roles_inert_after_failure() {
  [ -n "${POSTGRES_USER:-}" ] && [ -n "${POSTGRES_DB:-}" ] || return 0
  command -v psql >/dev/null 2>&1 || return 0
  PGOPTIONS='-c statement_timeout=15s -c lock_timeout=2s' \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 --quiet \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" >/dev/null 2>&1 <<'PSQL' || true
\set ON_ERROR_STOP on
SELECT pg_catalog.format(
    'ALTER ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL '
    'VALID UNTIL ''1970-01-01 00:00:00+00''',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname IN (
    'sentinelflow_demo_importer',
    'sentinelflow_demo_activator'
)
ORDER BY role.rolname
\gexec
DO $sentinelflow_runner_failure_fence$
DECLARE
    target_pid integer;
BEGIN
    FOR target_pid IN
        SELECT activity.pid
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND activity.pid <> pg_catalog.pg_backend_pid()
        ORDER BY activity.pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(target_pid, 5000) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'could not terminate demo authority after migration failure';
        END IF;
    END LOOP;
    PERFORM pg_catalog.pg_stat_clear_snapshot();
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo authority session survived migration failure fence';
    END IF;
END
$sentinelflow_runner_failure_fence$;
PSQL
}

fail() {
  trap - HUP INT TERM
  make_demo_roles_inert_after_failure
  echo "SentinelFlow migration runner: $*" >&2
  exit 1
}

[ -n "${POSTGRES_DB:-}" ] || fail 'POSTGRES_DB is required'
[ -n "${POSTGRES_USER:-}" ] || fail 'POSTGRES_USER is required'
[ -n "${DATABASE_API_PASSWORD:-}" ] || fail 'DATABASE_API_PASSWORD is required'
[ -n "${DATABASE_WORKER_PASSWORD:-}" ] || fail 'DATABASE_WORKER_PASSWORD is required'
[ -n "${DATABASE_READ_PASSWORD:-}" ] || fail 'DATABASE_READ_PASSWORD is required'
[ -n "${DATABASE_DISPATCHER_PASSWORD:-}" ] || fail 'DATABASE_DISPATCHER_PASSWORD is required'
[ -n "${DATABASE_RETENTION_PASSWORD:-}" ] || fail 'DATABASE_RETENTION_PASSWORD is required'
[ -n "${DATABASE_LIFECYCLE_PASSWORD:-}" ] || fail 'DATABASE_LIFECYCLE_PASSWORD is required'
[ -n "${DATABASE_METRICS_PASSWORD:-}" ] || fail 'DATABASE_METRICS_PASSWORD is required'

sentinelflow_environment=${SENTINELFLOW_ENV:-production}
demo_analysis_digest=
demo_validation_digest=

read_demo_capability_receipt() {
  receipt=$1
  [ -f "$receipt" ] || fail "demo capability receipt is unavailable"
  [ ! -L "$receipt" ] || fail "demo capability receipt symlinks are forbidden"
  [ "$(stat -c '%u:%g:%a:%s' "$receipt")" = '0:70:440:72' ] ||
    fail "demo capability receipt metadata differs"
  digest=$(cat "$receipt")
  printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
    fail "demo capability receipt is malformed"
  printf '%s\n' "$digest"
}

case "$sentinelflow_environment" in
demo)
  [ -n "${DATABASE_DEMO_IMPORTER_PASSWORD:-}" ] ||
    fail 'DATABASE_DEMO_IMPORTER_PASSWORD is required in demo mode'
  demo_receipt_directory=/run/sentinelflow-demo-history-capability-receipts
  demo_analysis_digest=$(read_demo_capability_receipt "$demo_receipt_directory/analysis.sha256")
  demo_validation_digest=$(read_demo_capability_receipt "$demo_receipt_directory/validation.sha256")
  [ "$demo_analysis_digest" != "$demo_validation_digest" ] ||
    fail 'demo analysis and validation capability receipts must be distinct'
  demo_role_login=true
  ;;
development|production)
  [ -z "${DATABASE_DEMO_IMPORTER_PASSWORD:-}" ] ||
    fail 'DATABASE_DEMO_IMPORTER_PASSWORD is forbidden outside demo mode'
  demo_role_login=false
  ;;
*)
  fail 'SENTINELFLOW_ENV must be demo, development, or production'
  ;;
esac

set -- /migrations/*.up.sql
if [ "$1" = '/migrations/*.up.sql' ] || [ ! -f "$1" ]; then
  fail 'migrations are unavailable'
fi

# The six-digit prefix makes the C-locale glob order identical to numeric order.
# Validate the complete chain before opening a database connection so malformed,
# duplicate, missing, or out-of-order files cannot partially mutate the database.
expected_version=1
for migration in "$@"; do
  [ -f "$migration" ] || fail "migration is not a regular file: $migration"
  [ ! -L "$migration" ] || fail "migration symlinks are not allowed: $migration"

  filename=${migration##*/}
  case "$filename" in
    *[!0-9a-z_.]*) fail "invalid migration filename: $filename" ;;
  esac
  if ! printf '%s\n' "$filename" |
    grep -Eq '^[0-9]{6}_[a-z0-9_]+[.]up[.]sql$'; then
    fail "invalid migration filename: $filename"
  fi

  version_text=${filename%%_*}
  version_decimal=$(printf '%s\n' "$version_text" | sed 's/^0*//')
  [ -n "$version_decimal" ] || version_decimal=0
  [ "$version_decimal" -eq "$expected_version" ] ||
    fail "migration chain expected version $(printf '%06d' "$expected_version") but found $version_text"

  expected_version=$((expected_version + 1))
done

psql_script=$(mktemp /tmp/sentinelflow-migrate.XXXXXX)
chmod 600 "$psql_script"
trap 'rm -f "$psql_script"' 0
trap 'fail "migration interrupted"' HUP INT TERM

{
  cat <<'PSQL'
\set ON_ERROR_STOP on
\set QUIET on

-- This session-scoped lock covers ledger validation, every migration-owned
-- transaction, postconditions, and role credential hardening. PostgreSQL
-- releases it automatically if this client exits or loses its connection.
SELECT pg_catalog.pg_advisory_lock(1936618841, 1986813295);

-- Demo authority roles are cluster-global. A retained database or a second
-- database in the same dedicated demo cluster can therefore encounter roles
-- that a previous run left LOGIN-enabled. Disable those roles and remove their
-- credentials before any migration can grant database-local authority.
SELECT pg_catalog.format(
    'ALTER ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL '
    'VALID UNTIL ''1970-01-01 00:00:00+00''',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname IN (
    'sentinelflow_demo_importer',
    'sentinelflow_demo_activator'
)
ORDER BY role.rolname
\gexec

DO $sentinelflow_demo_session_fence$
DECLARE
    target_pid integer;
BEGIN
    FOR target_pid IN
        SELECT activity.pid
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND activity.pid <> pg_catalog.pg_backend_pid()
        ORDER BY activity.pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(target_pid, 5000) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'could not terminate an existing demo authority session';
        END IF;
    END LOOP;

    -- pg_stat_activity can reuse a transaction-local statistics snapshot.
    -- Discard the cursor snapshot before proving that every terminated backend
    -- has actually disappeared.
    PERFORM pg_catalog.pg_stat_clear_snapshot();

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS role
        WHERE role.rolname IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
          AND (role.rolcanlogin OR role.rolpassword IS NOT NULL OR
               role.rolvaliduntil IS DISTINCT FROM
                   timestamptz '1970-01-01 00:00:00+00' OR
               role.rolinherit OR role.rolsuper OR role.rolcreatedb OR
               role.rolcreaterole OR role.rolreplication OR
               role.rolbypassrls OR role.rolconnlimit <> 2)
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  SELECT role.oid
                  FROM pg_catalog.pg_roles AS role
                  WHERE role.rolname IN (
                      'sentinelflow_demo_importer',
                      'sentinelflow_demo_activator'
                  )
              )
           OR membership.member IN (
                  SELECT role.oid
                  FROM pg_catalog.pg_roles AS role
                  WHERE role.rolname IN (
                      'sentinelflow_demo_importer',
                      'sentinelflow_demo_activator'
                  )
              )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo authority roles failed the pre-migration inert-session contract';
    END IF;
END
$sentinelflow_demo_session_fence$;

CREATE TEMPORARY TABLE sentinelflow_expected_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL UNIQUE
) ON COMMIT PRESERVE ROWS;
PSQL

  for migration in "$@"; do
    filename=${migration##*/}
    version_text=${filename%%_*}
    version_decimal=$(printf '%s\n' "$version_text" | sed 's/^0*//')
    name=${filename#*_}
    name=${name%.up.sql}
    # filename validation above makes both interpolated values SQL-safe here.
    printf "INSERT INTO sentinelflow_expected_migrations (version, name) VALUES (%s, '%s');\n" \
      "$version_decimal" "$name"
  done

  first_migration=${1##*/}
  first_name=${first_migration#*_}
  first_name=${first_name%.up.sql}
  cat <<PSQL

SELECT CASE
    WHEN pg_catalog.to_regclass('sentinelflow.schema_migrations') IS NULL THEN 'false'
    ELSE 'true'
END AS ledger_exists
\gset
\if :ledger_exists
\else
\echo 'bootstrapping migration 000001_$first_name'
\ir /migrations/$first_migration
\endif

DO \$sentinelflow_migration_preflight\$
DECLARE
    ledger_count bigint;
    ledger_min bigint;
    ledger_max bigint;
    expected_max bigint;
BEGIN
    IF pg_catalog.to_regclass('sentinelflow.schema_migrations') IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'bootstrap migration did not create sentinelflow.schema_migrations';
    END IF;

    -- Referencing the explicit columns also fails closed if an object with an
    -- incompatible ledger shape was placed at the canonical name.
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.schema_migrations AS applied
        JOIN sentinelflow_expected_migrations AS expected
          ON expected.version = applied.version
        WHERE applied.name <> expected.name
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema migration version/name identity conflict';
    END IF;

    SELECT count(*), min(version), max(version)
      INTO ledger_count, ledger_min, ledger_max
      FROM sentinelflow.schema_migrations;
    SELECT max(version) INTO expected_max
      FROM sentinelflow_expected_migrations;

    IF ledger_count = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema migration ledger exists but is empty';
    END IF;
    IF ledger_min <> 1 OR ledger_count <> ledger_max THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema migration ledger is not a contiguous prefix';
    END IF;
    IF ledger_max > expected_max THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema migration ledger contains an unknown future or missing-file version';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.schema_migrations AS applied
        LEFT JOIN sentinelflow_expected_migrations AS expected
          ON expected.version = applied.version
         AND expected.name = applied.name
        WHERE expected.version IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema migration ledger does not match the checked-in migration chain';
    END IF;
END
\$sentinelflow_migration_preflight\$;
PSQL

  for migration in "$@"; do
    filename=${migration##*/}
    version_text=${filename%%_*}
    version_decimal=$(printf '%s\n' "$version_text" | sed 's/^0*//')
    name=${filename#*_}
    name=${name%.up.sql}

    # Migration 000001 was either already validated or was applied in the
    # bootstrap branch above. Every later migration is an exact prefix step.
    [ "$version_decimal" -eq 1 ] && continue

    cat <<PSQL

SELECT CASE WHEN EXISTS (
    SELECT 1 FROM sentinelflow.schema_migrations
    WHERE version = $version_decimal AND name = '$name'
) THEN 'false' ELSE 'true' END AS apply_migration
\gset
\if :apply_migration
\echo 'applying migration $filename'
DO \$sentinelflow_migration_step\$
BEGIN
    IF (SELECT max(version) FROM sentinelflow.schema_migrations) <> $((version_decimal - 1)) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'schema migration prefix changed before version $version_decimal';
    END IF;
END
\$sentinelflow_migration_step\$;
\ir /migrations/$filename
DO \$sentinelflow_migration_postcondition\$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.schema_migrations
        WHERE version = $version_decimal AND name = '$name'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration $filename did not record its exact ledger identity';
    END IF;
END
\$sentinelflow_migration_postcondition\$;
\else
\echo 'skipping applied migration $filename'
\endif
PSQL
  done

  cat <<'PSQL'

DO $sentinelflow_migration_final$
BEGIN
    IF EXISTS (
        SELECT version, name FROM sentinelflow_expected_migrations
        EXCEPT
        SELECT version, name FROM sentinelflow.schema_migrations
    ) OR EXISTS (
        SELECT version, name FROM sentinelflow.schema_migrations
        EXCEPT
        SELECT version, name FROM sentinelflow_expected_migrations
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'final schema migration ledger differs from the migration chain';
    END IF;
END
$sentinelflow_migration_final$;

\getenv api_password DATABASE_API_PASSWORD
\getenv worker_password DATABASE_WORKER_PASSWORD
\getenv read_password DATABASE_READ_PASSWORD
\getenv dispatcher_password DATABASE_DISPATCHER_PASSWORD
\getenv retention_password DATABASE_RETENTION_PASSWORD
\getenv lifecycle_password DATABASE_LIFECYCLE_PASSWORD
\getenv metrics_password DATABASE_METRICS_PASSWORD
\if :sentinelflow_demo_mode
\getenv demo_importer_password DATABASE_DEMO_IMPORTER_PASSWORD
\endif
PSQL

  if [ "$demo_role_login" = true ]; then
    printf "\\set demo_analysis_digest '%s'\n" "$demo_analysis_digest"
    printf "\\set demo_validation_digest '%s'\n" "$demo_validation_digest"
  fi

  cat <<'PSQL'

BEGIN;
SET password_encryption = 'scram-sha-256';

SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_api', :'api_password') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_worker', :'worker_password') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_read', :'read_password') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_dispatcher', :'dispatcher_password') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_retention', :'retention_password') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_lifecycle', :'lifecycle_password') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', 'sentinelflow_metrics', :'metrics_password') \gexec

ALTER ROLE sentinelflow_api NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinelflow_worker NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinelflow_read NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinelflow_dispatcher NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinelflow_retention NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinelflow_lifecycle LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
ALTER ROLE sentinelflow_metrics NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE sentinelflow_demo_importer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL
    VALID UNTIL '1970-01-01 00:00:00+00';
ALTER ROLE sentinelflow_demo_activator NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL
    VALID UNTIL '1970-01-01 00:00:00+00';

SELECT format(
    'ALTER ROLE sentinelflow_demo_importer IN DATABASE %I '
    'SET search_path = sentinelflow, pg_catalog',
    current_database()
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_importer IN DATABASE %I SET statement_timeout = %L',
    current_database(), '30s'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_importer IN DATABASE %I SET transaction_timeout = %L',
    current_database(), '2min'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_importer IN DATABASE %I SET idle_in_transaction_session_timeout = %L',
    current_database(), '5s'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_importer IN DATABASE %I SET idle_session_timeout = %L',
    current_database(), '30s'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_activator IN DATABASE %I '
    'SET search_path = sentinelflow, pg_catalog',
    current_database()
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_activator IN DATABASE %I SET statement_timeout = %L',
    current_database(), '15s'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_activator IN DATABASE %I SET transaction_timeout = %L',
    current_database(), '30s'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_activator IN DATABASE %I SET idle_in_transaction_session_timeout = %L',
    current_database(), '5s'
) \gexec
SELECT format(
    'ALTER ROLE sentinelflow_demo_activator IN DATABASE %I SET idle_session_timeout = %L',
    current_database(), '30s'
) \gexec

DO $sentinelflow_demo_role_precondition$
BEGIN
    IF (
        SELECT count(*)
        FROM pg_catalog.pg_authid
        WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
          AND NOT rolcanlogin
          AND rolpassword IS NULL
          AND rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
          AND NOT rolsuper
          AND NOT rolinherit
          AND NOT rolcreaterole
          AND NOT rolcreatedb
          AND NOT rolreplication
          AND NOT rolbypassrls
          AND rolconnlimit = 2
    ) <> 2 OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members membership
        WHERE membership.roleid IN (
                  SELECT oid FROM pg_catalog.pg_roles
                  WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  SELECT oid FROM pg_catalog.pg_roles
                  WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
              )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo authority roles failed the pre-login isolation contract';
    END IF;
END
$sentinelflow_demo_role_precondition$;

DO $sentinelflow_demo_role_timeout_contract$
BEGIN
    IF (
        SELECT count(*)
        FROM pg_catalog.pg_db_role_setting AS setting
        JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole
        JOIN pg_catalog.pg_database AS database ON database.oid = setting.setdatabase
        WHERE database.datname = current_database()
          AND (
              (
                  role.rolname = 'sentinelflow_demo_importer'
                  AND cardinality(setting.setconfig) = 5
                  AND setting.setconfig @> ARRAY[
                      'search_path=sentinelflow, pg_catalog',
                      'statement_timeout=30s',
                      'transaction_timeout=2min',
                      'idle_in_transaction_session_timeout=5s',
                      'idle_session_timeout=30s'
                  ]::text[]
              ) OR (
                  role.rolname = 'sentinelflow_demo_activator'
                  AND cardinality(setting.setconfig) = 5
                  AND setting.setconfig @> ARRAY[
                      'search_path=sentinelflow, pg_catalog',
                      'statement_timeout=15s',
                      'transaction_timeout=30s',
                      'idle_in_transaction_session_timeout=5s',
                      'idle_session_timeout=30s'
                  ]::text[]
              )
          )
    ) <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo authority role timeout contract differs';
    END IF;
END
$sentinelflow_demo_role_timeout_contract$;

\if :sentinelflow_demo_mode
CREATE TEMPORARY TABLE sentinelflow_demo_importer_deadline (
    expires_at timestamptz NOT NULL
) ON COMMIT DROP;
INSERT INTO sentinelflow_demo_importer_deadline (expires_at)
SELECT COALESCE(
    (
        SELECT expectation.importer_lease_expires_at
        FROM sentinelflow.demo_history_runtime_capability_expectation AS expectation
        WHERE expectation.bootstrap_id = 1
          AND expectation.analysis_secret_digest::text = :'demo_analysis_digest'
          AND expectation.validation_secret_digest::text = :'demo_validation_digest'
          AND expectation.importer_lease_expires_at > clock_timestamp()
    ),
    clock_timestamp() + interval '5 minutes'
);
CREATE TEMPORARY TABLE sentinelflow_expected_demo_capabilities (
    analysis_digest text NOT NULL,
    validation_digest text NOT NULL,
    CHECK (analysis_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (validation_digest ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (analysis_digest <> validation_digest)
) ON COMMIT DROP;
INSERT INTO sentinelflow_expected_demo_capabilities (
    analysis_digest,
    validation_digest
) VALUES (:'demo_analysis_digest', :'demo_validation_digest');
SELECT format(
    'ALTER ROLE %I LOGIN PASSWORD %L VALID UNTIL %L',
    'sentinelflow_demo_importer', :'demo_importer_password',
    (SELECT deadline.expires_at FROM sentinelflow_demo_importer_deadline AS deadline)
) \gexec
CREATE TEMPORARY TABLE sentinelflow_demo_capability_pin_result (
    pinned boolean NOT NULL CHECK (pinned)
) ON COMMIT DROP;
INSERT INTO sentinelflow_demo_capability_pin_result (pinned)
SELECT sentinelflow.pin_demo_history_runtime_capability_expectation_000030(
    expected.analysis_digest,
    expected.validation_digest,
    (SELECT deadline.expires_at FROM sentinelflow_demo_importer_deadline AS deadline)
)
FROM sentinelflow_expected_demo_capabilities AS expected;
\else
ALTER ROLE sentinelflow_demo_importer NOLOGIN PASSWORD NULL
    VALID UNTIL '1970-01-01 00:00:00+00';
ALTER ROLE sentinelflow_demo_activator NOLOGIN PASSWORD NULL
    VALID UNTIL '1970-01-01 00:00:00+00';
\endif

\if :sentinelflow_demo_mode
DO $sentinelflow_demo_role_postcondition$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS role
        CROSS JOIN sentinelflow_demo_importer_deadline AS deadline
        WHERE role.rolname = 'sentinelflow_demo_importer'
          AND role.rolcanlogin
          AND role.rolpassword IS NOT NULL
          AND role.rolvaliduntil = deadline.expires_at
          AND deadline.expires_at > clock_timestamp()
          AND deadline.expires_at <= clock_timestamp() + interval '5 minutes'
          AND role.rolpassword ~ '^SCRAM-SHA-256[$][1-9][0-9]*:[A-Za-z0-9+/]+={0,2}[$][A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$'
          AND NOT role.rolsuper
          AND NOT role.rolinherit
          AND NOT role.rolcreaterole
          AND NOT role.rolcreatedb
          AND NOT role.rolreplication
          AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS role
        WHERE role.rolname = 'sentinelflow_demo_activator'
          AND NOT role.rolcanlogin
          AND role.rolpassword IS NULL
          AND role.rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
          AND NOT role.rolsuper
          AND NOT role.rolinherit
          AND NOT role.rolcreaterole
          AND NOT role.rolcreatedb
          AND NOT role.rolreplication
          AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
    ) OR (
        SELECT count(*)
        FROM sentinelflow.demo_history_runtime_capability_expectation AS pin
        CROSS JOIN sentinelflow_demo_importer_deadline AS deadline
        CROSS JOIN sentinelflow_expected_demo_capabilities AS expected
        WHERE pin.bootstrap_id = 1
          AND pin.analysis_secret_digest::text = expected.analysis_digest
          AND pin.validation_secret_digest::text = expected.validation_digest
          AND pin.importer_lease_expires_at = deadline.expires_at
    ) <> 1 OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members membership
        WHERE membership.roleid IN (
                  SELECT oid FROM pg_catalog.pg_roles
                  WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  SELECT oid FROM pg_catalog.pg_roles
                  WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
              )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo authority roles failed the enabled isolation contract';
    END IF;
END
$sentinelflow_demo_role_postcondition$;
\else
DO $sentinelflow_non_demo_role_postcondition$
BEGIN
    IF (
        SELECT count(*)
        FROM pg_catalog.pg_authid
        WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
          AND NOT rolcanlogin
          AND rolpassword IS NULL
          AND rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
          AND NOT rolsuper
          AND NOT rolinherit
          AND NOT rolcreaterole
          AND NOT rolcreatedb
          AND NOT rolreplication
          AND NOT rolbypassrls
          AND rolconnlimit = 2
    ) <> 2 OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members membership
        WHERE membership.roleid IN (
                  SELECT oid FROM pg_catalog.pg_roles
                  WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  SELECT oid FROM pg_catalog.pg_roles
                  WHERE rolname IN ('sentinelflow_demo_importer', 'sentinelflow_demo_activator')
              )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename IN (
            'sentinelflow_demo_importer',
            'sentinelflow_demo_activator'
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo authority roles failed the disabled isolation contract';
    END IF;
END
$sentinelflow_non_demo_role_postcondition$;
\endif
COMMIT;

SELECT pg_catalog.pg_advisory_unlock(1936618841, 1986813295);
PSQL
} >"$psql_script"

if ! psql --no-psqlrc --set=ON_ERROR_STOP=1 --set=sentinelflow_demo_mode="$demo_role_login" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --file "$psql_script"; then
  fail 'migration execution failed; demo authority was fenced where reachable'
fi
