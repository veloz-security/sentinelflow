#!/usr/bin/env sh

set -eu

test "${SENTINELFLOW_ENV:-}" = "demo"

export LC_ALL=C
export PGCONNECT_TIMEOUT=5
export PGOPTIONS='-c statement_timeout=15s -c lock_timeout=2s -c idle_in_transaction_session_timeout=5s'

: "${PGHOST:?PGHOST is required}"
: "${PGPORT:?PGPORT is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"

receipt_directory=/run/sentinelflow-demo-history-capability-receipts
analysis_receipt=$receipt_directory/analysis.sha256
validation_receipt=$receipt_directory/validation.sha256
completed=false
sql_file=

make_bootstrap_roles_inert() {
  psql --no-psqlrc --set=ON_ERROR_STOP=1 --quiet \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" >/dev/null 2>&1 <<'PSQL' || true
ALTER ROLE sentinelflow_demo_importer
    NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL
    VALID UNTIL '1970-01-01 00:00:00+00';
ALTER ROLE sentinelflow_demo_activator
    NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD NULL
    VALID UNTIL '1970-01-01 00:00:00+00';
SELECT pg_catalog.pg_terminate_backend(activity.pid, 5000)
FROM pg_catalog.pg_stat_activity AS activity
WHERE activity.usename IN (
    'sentinelflow_demo_importer',
    'sentinelflow_demo_activator'
)
  AND activity.pid <> pg_catalog.pg_backend_pid();
PSQL
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$sql_file" ]; then
    rm -f "$sql_file"
  fi
  if [ "$completed" != true ]; then
    make_bootstrap_roles_inert
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

: "${DATABASE_DEMO_ACTIVATOR_PASSWORD:?DATABASE_DEMO_ACTIVATOR_PASSWORD is required}"

read_receipt() {
  receipt=$1
  [ -f "$receipt" ]
  [ ! -L "$receipt" ]
  [ "$(stat -c '%u:%g:%a:%s' "$receipt")" = '0:70:440:72' ]
  digest=$(cat "$receipt")
  printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$'
  printf '%s\n' "$digest"
}

analysis_digest=$(read_receipt "$analysis_receipt")
validation_digest=$(read_receipt "$validation_receipt")
[ "$analysis_digest" != "$validation_digest" ]

sql_file=$(mktemp /tmp/sentinelflow-demo-activation-handoff.XXXXXX)
chmod 0600 "$sql_file"

cat >"$sql_file" <<PSQL
\\set ON_ERROR_STOP on
\\set QUIET on
\\getenv demo_activator_password DATABASE_DEMO_ACTIVATOR_PASSWORD

SELECT pg_catalog.pg_advisory_lock(1936618841, 1986813295);
BEGIN;

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
) VALUES ('$analysis_digest', '$validation_digest');

DO \$sentinelflow_demo_handoff_precondition\$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = SESSION_USER
          AND role.rolsuper
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'demo activation handoff requires the session superuser';
    END IF;

    IF (
        SELECT count(*)
        FROM sentinelflow.demo_history_runtime_capability_expectation AS pin
        CROSS JOIN sentinelflow_expected_demo_capabilities AS expected
        WHERE pin.bootstrap_id = 1
          AND pin.analysis_secret_digest::text = expected.analysis_digest
          AND pin.validation_secret_digest::text = expected.validation_digest
          AND pin.importer_lease_expires_at > clock_timestamp()
    ) <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'demo activation handoff capability pin is unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS role
        WHERE role.rolname = 'sentinelflow_demo_importer'
          AND NOT role.rolcanlogin
          AND role.rolpassword IS NULL
          AND role.rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
          AND NOT role.rolinherit
          AND NOT role.rolsuper
          AND NOT role.rolcreatedb
          AND NOT role.rolcreaterole
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
          AND NOT role.rolinherit
          AND NOT role.rolsuper
          AND NOT role.rolcreatedb
          AND NOT role.rolcreaterole
          AND NOT role.rolreplication
          AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
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
            MESSAGE = 'demo activation handoff role fence is unavailable';
    END IF;

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
            MESSAGE = 'demo activation handoff role timeout contract differs';
    END IF;
END
\$sentinelflow_demo_handoff_precondition\$;

CREATE TEMPORARY TABLE sentinelflow_demo_activator_deadline (
    expires_at timestamptz NOT NULL
) ON COMMIT DROP;
INSERT INTO sentinelflow_demo_activator_deadline (expires_at)
VALUES (clock_timestamp() + interval '5 minutes');

SELECT pg_catalog.format(
    'ALTER ROLE %I LOGIN PASSWORD %L VALID UNTIL %L',
    'sentinelflow_demo_activator',
    :'demo_activator_password',
    (SELECT deadline.expires_at FROM sentinelflow_demo_activator_deadline AS deadline)
) \gexec

DO \$sentinelflow_demo_handoff_postcondition\$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS role
        WHERE role.rolname = 'sentinelflow_demo_importer'
          AND NOT role.rolcanlogin
          AND role.rolpassword IS NULL
          AND role.rolvaliduntil = timestamptz '1970-01-01 00:00:00+00'
          AND NOT role.rolinherit
          AND NOT role.rolsuper
          AND NOT role.rolcreatedb
          AND NOT role.rolcreaterole
          AND NOT role.rolreplication
          AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS role
        CROSS JOIN sentinelflow_demo_activator_deadline AS deadline
        WHERE role.rolname = 'sentinelflow_demo_activator'
          AND role.rolcanlogin
          AND role.rolpassword IS NOT NULL
          AND role.rolpassword ~ '^SCRAM-SHA-256[$][1-9][0-9]*:[A-Za-z0-9+/]+={0,2}[$][A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$'
          AND role.rolvaliduntil = deadline.expires_at
          AND deadline.expires_at > clock_timestamp()
          AND deadline.expires_at <= clock_timestamp() + interval '5 minutes'
          AND NOT role.rolinherit
          AND NOT role.rolsuper
          AND NOT role.rolcreatedb
          AND NOT role.rolcreaterole
          AND NOT role.rolreplication
          AND NOT role.rolbypassrls
          AND role.rolconnlimit = 2
    ) OR (
        SELECT count(*)
        FROM sentinelflow.demo_history_runtime_capability_expectation AS pin
        CROSS JOIN sentinelflow_expected_demo_capabilities AS expected
        WHERE pin.bootstrap_id = 1
          AND pin.analysis_secret_digest::text = expected.analysis_digest
          AND pin.validation_secret_digest::text = expected.validation_digest
          AND pin.pinned_at <= clock_timestamp()
          AND pin.importer_lease_expires_at > clock_timestamp()
          AND pin.importer_lease_expires_at <= pin.pinned_at + interval '5 minutes'
    ) <> 1 OR (
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
    ) <> 2 OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
              )
           OR membership.member IN (
                  pg_catalog.to_regrole('sentinelflow_demo_importer'),
                  pg_catalog.to_regrole('sentinelflow_demo_activator')
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
            MESSAGE = 'demo activation handoff failed the enabled-role contract';
    END IF;
END
\$sentinelflow_demo_handoff_postcondition\$;

COMMIT;
SELECT pg_catalog.pg_advisory_unlock(1936618841, 1986813295);
PSQL

psql --no-psqlrc --set=ON_ERROR_STOP=1 --quiet \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --file "$sql_file"

completed=true
rm -f "$sql_file"
sql_file=
