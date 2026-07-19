#!/usr/bin/env bash
set -euo pipefail

umask 077

original_arguments=("$@")

database=""
bundle=""
journal_destination=""
verification_key=""
dispatch_public_key="${SENTINELFLOW_DISPATCH_PUBLIC_KEY:-}"
result_public_key="${SENTINELFLOW_RESULT_PUBLIC_KEY:-}"
recovery_tool="${RECOVERY_TOOL:-sentinelflow-recoverytool}"
fail_after_database_commit="${SENTINELFLOW_RECOVERY_FAIL_AFTER_DATABASE_COMMIT:-0}"
fail_after_journal_commit="${SENTINELFLOW_RECOVERY_FAIL_AFTER_JOURNAL_COMMIT:-0}"
fail_after_receipt_removal="${SENTINELFLOW_RECOVERY_FAIL_AFTER_RECEIPT_REMOVAL:-0}"
fail_after_data_load="${SENTINELFLOW_RECOVERY_FAIL_AFTER_DATA_LOAD:-0}"

usage() {
  printf '%s\n' \
    'usage: restore-state.sh --database NAME --bundle ABSOLUTE_DIRECTORY --journal-destination ABSOLUTE_PATH --verification-key ABSOLUTE_PATH --dispatch-public-key ABSOLUTE_PATH --result-public-key ABSOLUTE_PATH [--recovery-tool PATH]' >&2
}

while (($# > 0)); do
  case "$1" in
    --database)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      database="$2"
      shift 2
      ;;
    --bundle)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      bundle="$2"
      shift 2
      ;;
    --journal-destination)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      journal_destination="$2"
      shift 2
      ;;
    --verification-key)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      verification_key="$2"
      shift 2
      ;;
    --dispatch-public-key)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      dispatch_public_key="$2"
      shift 2
      ;;
    --result-public-key)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      result_public_key="$2"
      shift 2
      ;;
    --recovery-tool)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      recovery_tool="$2"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ "$database" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$ ]] || { printf '%s\n' 'ERROR: invalid database name' >&2; exit 2; }
[[ "$bundle" == /* && "$journal_destination" == /* && "$verification_key" == /* &&
   "$dispatch_public_key" == /* && "$result_public_key" == /* &&
   "$dispatch_public_key" != "$result_public_key" ]] || { printf '%s\n' 'ERROR: recovery paths must be absolute and role separated' >&2; exit 2; }

recovery_tool="$(command -v "$recovery_tool")" || { printf '%s\n' 'ERROR: recovery tool is unavailable' >&2; exit 1; }
pg_dump_bin="$(command -v "${PG_DUMP_BIN:-pg_dump}")" || { printf '%s\n' 'ERROR: pg_dump is unavailable' >&2; exit 1; }
pg_restore_bin="$(command -v "${PG_RESTORE_BIN:-pg_restore}")" || { printf '%s\n' 'ERROR: pg_restore is unavailable' >&2; exit 1; }
psql_bin="$(command -v "${PSQL_BIN:-psql}")" || { printf '%s\n' 'ERROR: psql is unavailable' >&2; exit 1; }
cmp_bin="$(command -v cmp)" || { printf '%s\n' 'ERROR: cmp is unavailable' >&2; exit 1; }

if [[ -z "${SENTINELFLOW_RECOVERY_FENCE_FD:-}" ]]; then
  script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  script_path="$script_directory/$(basename "${BASH_SOURCE[0]}")"
  exec "$recovery_tool" run-session --journal "$journal_destination" -- "$script_path" "${original_arguments[@]}"
fi
"$recovery_tool" validate-session --journal "$journal_destination"

session_database_exec() {
  "$recovery_tool" exec-session-child --journal "$journal_destination" -- "$@"
}

canonicalize_schema_dump() {
  local path="$1"
  local canonical="$path.canonical"
  [[ -f "$path" && ! -L "$path" && ! -e "$canonical" ]] || {
    printf '%s\n' 'ERROR: schema dump path is unsafe' >&2
    exit 1
  }
  LC_ALL=C awk '
    /^-- Dumped from database version / { next }
    /^-- Dumped by pg_dump version / { next }
    { print }
  ' "$path" > "$canonical"
  chmod 0600 "$canonical"
  mv "$canonical" "$path"
}

sanitize_restore_timeouts() {
  local path="$1"
  local bounded="$path.bounded"
  local setting exact_count all_count
  [[ -f "$path" && ! -L "$path" && ! -e "$bounded" ]] || {
    printf '%s\n' 'ERROR: restore SQL path is unsafe' >&2
    exit 1
  }
  for setting in statement_timeout lock_timeout idle_in_transaction_session_timeout transaction_timeout; do
    exact_count="$(LC_ALL=C grep -Ec "^SET ${setting} = 0;$" "$path" || true)"
    all_count="$(LC_ALL=C grep -Ec "^SET( LOCAL)? ${setting} = " "$path" || true)"
    [[ "$exact_count" == "1" && "$all_count" == "1" ]] || {
      printf '%s\n' 'ERROR: restore SQL timeout contract is invalid' >&2
      exit 1
    }
  done
  LC_ALL=C sed \
    -e '/^SET statement_timeout = 0;$/d' \
    -e '/^SET lock_timeout = 0;$/d' \
    -e '/^SET idle_in_transaction_session_timeout = 0;$/d' \
    -e '/^SET transaction_timeout = 0;$/d' \
    "$path" > "$bounded"
  chmod 0600 "$bounded"
  mv "$bounded" "$path"
}

parse_restore_status() {
  local status="$1"
  local digest='sha256:[0-9a-f]{64}'
  local pattern

  pattern="^(prepared|database_restored|journal_installed|finalized)"$'\t'"(${digest})"$'\t'"(staged|installed)"$'\t'"(${digest})"$'\t'"(${digest})"$'\t'"(${digest})$"
  [[ "$status" =~ $pattern ]] || {
    printf '%s\n' 'ERROR: invalid restore status' >&2
    exit 1
  }
  restore_phase="${BASH_REMATCH[1]}"
  receipt_digest="${BASH_REMATCH[2]}"
  journal_state="${BASH_REMATCH[3]}"
  manifest_digest="${BASH_REMATCH[4]}"
  database_digest="${BASH_REMATCH[5]}"
  journal_digest="${BASH_REMATCH[6]}"
}

require_same_restore_binding() {
  [[ "$receipt_digest" == "$expected_receipt_digest" &&
     "$manifest_digest" == "$expected_manifest_digest" &&
     "$database_digest" == "$expected_database_digest" &&
     "$journal_digest" == "$expected_journal_digest" ]] || {
    printf '%s\n' 'ERROR: restore binding changed' >&2
    exit 1
  }
}

[[ -d "$bundle" && ! -L "$bundle" ]] || { printf '%s\n' 'ERROR: bundle directory is unavailable' >&2; exit 1; }
journal_parent="$(dirname "$journal_destination")"
[[ -d "$journal_parent" && ! -L "$journal_destination" ]] || { printf '%s\n' 'ERROR: journal destination is unsafe' >&2; exit 1; }

metadata_check="$(mktemp -d "$journal_parent/.sentinelflow-restore-check.XXXXXX")"
restore_pid=""
stop_restore_transaction() {
  if [[ -n "${restore_pid:-}" ]]; then
    printf '%s\n' 'ROLLBACK;' '\q' >&7 2>/dev/null || true
    exec 7>&- || true
    exec 8<&- || true
    wait "$restore_pid" 2>/dev/null || true
    restore_pid=""
  fi
}
cleanup() {
  stop_restore_transaction
  if [[ -n "${metadata_check:-}" && -d "$metadata_check" && ! -L "$metadata_check" ]]; then
    find "$metadata_check" -depth -delete
  fi
}
trap cleanup EXIT INT TERM HUP

$recovery_tool verify --bundle "$bundle" --verification-key "$verification_key"
session_database_exec "$pg_restore_bin" --list "$bundle/postgres/data.dump" > /dev/null

server_version_num="$(session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" --command 'SHOW server_version_num')"
server_version_num="${server_version_num//[[:space:]]/}"
[[ "$server_version_num" =~ ^[0-9]+$ ]] || { printf '%s\n' 'ERROR: invalid PostgreSQL server version' >&2; exit 1; }
target_major="$((10#$server_version_num / 10000))"
bundle_major="$(tr -d '[:space:]' < "$bundle/metadata/postgres-major.txt")"
[[ "$target_major" == "17" && "$target_major" == "$bundle_major" ]] || { printf '%s\n' 'ERROR: PostgreSQL major version drift' >&2; exit 1; }

session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --dbname "$database" \
  --command "COPY (SELECT version, name FROM sentinelflow.schema_migrations ORDER BY version) TO STDOUT" \
  > "$metadata_check/migrations.tsv"
$cmp_bin -s "$bundle/metadata/migrations.tsv" "$metadata_check/migrations.tsv" || { printf '%s\n' 'ERROR: migration version drift' >&2; exit 1; }

session_database_exec "$pg_dump_bin" --dbname "$database" --schema-only --schema=sentinelflow --strict-names \
  --no-owner --no-privileges --no-comments --no-security-labels --no-publications \
  --no-subscriptions --no-tablespaces --no-table-access-method \
  --restrict-key=SENTINELFLOWRECOVERYV1 \
  --file "$metadata_check/schema.sql"
canonicalize_schema_dump "$metadata_check/schema.sql"
$cmp_bin -s "$bundle/metadata/schema.sql" "$metadata_check/schema.sql" || { printf '%s\n' 'ERROR: database schema drift' >&2; exit 1; }

database_identity="$(session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" --command "SELECT 'pg17:' || control.system_identifier::text || ':' || database.oid::text || ':' || current_database() FROM pg_catalog.pg_control_system() control JOIN pg_catalog.pg_database database ON database.datname = current_database()")"
[[ "$database_identity" =~ ^pg17:[0-9]+:[0-9]+:[A-Za-z0-9_.-]{1,63}$ ]] || { printf '%s\n' 'ERROR: database identity is invalid' >&2; exit 1; }

restore_status="$($recovery_tool prepare-restore \
  --bundle "$bundle" \
  --verification-key "$verification_key" \
  --destination "$journal_destination" \
  --database-identity "$database_identity")"
parse_restore_status "$restore_status"
expected_receipt_digest="$receipt_digest"
expected_manifest_digest="$manifest_digest"
expected_database_digest="$database_digest"
expected_journal_digest="$journal_digest"

receipt_table_exists="$(session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" --command "SELECT (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NOT NULL)::text")"
receipt_state="absent"
if [[ "$receipt_table_exists" == "true" ]]; then
  receipt_state="$(session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" \
    --command "SELECT CASE WHEN count(*) = 1 AND bool_and(singleton AND schema_version = 'sentinelflow-restore-receipt-v1' AND receipt_digest = '$receipt_digest' AND bundle_manifest_digest = '$manifest_digest' AND database_identity_digest = '$database_digest' AND journal_digest = '$journal_digest') THEN 'exact' ELSE 'mismatch' END FROM public.sentinelflow_recovery_receipt_v1")"
  [[ "$receipt_state" == "exact" ]] || { printf '%s\n' 'ERROR: database restore receipt mismatch' >&2; exit 1; }
elif [[ "$receipt_table_exists" != "false" ]]; then
  printf '%s\n' 'ERROR: database restore receipt state is invalid' >&2
  exit 1
fi

case "$restore_phase" in
  prepared)
    ;;
  database_restored)
    [[ "$receipt_state" == "exact" ]] || { printf '%s\n' 'ERROR: database receipt is missing before journal commit' >&2; exit 1; }
    ;;
  journal_installed)
    ;;
  finalized)
    [[ "$receipt_state" == "absent" && "$journal_state" == "installed" ]] || { printf '%s\n' 'ERROR: finalized restore state is inconsistent' >&2; exit 1; }
    ;;
esac

if [[ "$receipt_state" == "absent" && "$restore_phase" == "prepared" ]]; then
  # pg_restore must finish producing one complete restricted SQL file before
  # psql opens the only mutating transaction. A producer that emits valid SQL
  # and then fails cannot cause a partial commit.
  session_database_exec "$pg_restore_bin" --file="$metadata_check/data.sql" --data-only --schema=sentinelflow --strict-names \
    --exit-on-error --no-owner --no-privileges \
    --restrict-key=SENTINELFLOWRECOVERYV1 "$bundle/postgres/data.dump"
  [[ -f "$metadata_check/data.sql" && ! -L "$metadata_check/data.sql" ]] || { printf '%s\n' 'ERROR: restore SQL was not materialized safely' >&2; exit 1; }
  chmod 0600 "$metadata_check/data.sql"
  sanitize_restore_timeouts "$metadata_check/data.sql"

  backup_lock_sql="$("$recovery_tool" postgres-lock-sql --mode backup)"
  restore_lock_sql="$("$recovery_tool" postgres-lock-sql --mode restore)"
  relation_copy_sql="$("$recovery_tool" postgres-relation-copy-sql)"
  sequence_copy_sql="$("$recovery_tool" postgres-sequence-copy-sql)"
  artifact_copy_sql="$("$recovery_tool" postgres-artifact-copy-sql)"
  mkfifo "$metadata_check/restore.in" "$metadata_check/restore.out"
  session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" \
    --set=receipt_digest="$receipt_digest" \
    --set=manifest_digest="$manifest_digest" \
    --set=database_digest="$database_digest" \
    --set=journal_digest="$journal_digest" \
    <"$metadata_check/restore.in" >"$metadata_check/restore.out" &
  restore_pid="$!"
  exec 7>"$metadata_check/restore.in"
  exec 8<"$metadata_check/restore.out"

  # READ COMMITTED is deliberate. Each post-lock read must see the state after
  # every sequential lock acquisition; RR/SERIALIZABLE can retain a stale
  # sequence catalog snapshot while a later sequence writer commits.
  printf '%s\n' \
    'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE;' \
    "SET LOCAL lock_timeout = '5s';" \
    "SET LOCAL statement_timeout = '5min';" \
    "$backup_lock_sql" \
    'SELECT pg_backend_pid();' \
    "SELECT (EXISTS (SELECT 1 FROM pg_catalog.pg_locks held WHERE held.pid = pg_backend_pid() AND held.locktype = 'relation' AND held.relation = 'pg_catalog.pg_class'::regclass AND held.mode = 'ShareRowExclusiveLock' AND held.granted) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'sentinelflow' AND relation.relkind IN ('r','p') AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_locks held WHERE held.pid = pg_backend_pid() AND held.locktype = 'relation' AND held.relation = relation.oid AND held.mode = 'ShareLock' AND held.granted)) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'sentinelflow' AND relation.relkind = 'S' AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_locks held WHERE held.pid = pg_backend_pid() AND held.locktype = 'relation' AND held.relation = relation.oid AND held.mode = 'ShareRowExclusiveLock' AND held.granted)))::text;" \
    "$relation_copy_sql" \
    "SELECT 'SENTINELFLOW_RELATIONS_END_V1';" \
    "$sequence_copy_sql" \
    "SELECT 'SENTINELFLOW_SEQUENCES_END_V1';" \
    'SELECT pg_export_snapshot();' >&7

  if ! IFS= read -r restore_backend_pid <&8 || [[ ! "$restore_backend_pid" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' 'ERROR: restore database fence did not become ready' >&2
    exit 1
  fi
  if ! IFS= read -r restore_locks_valid <&8 || [[ "$restore_locks_valid" != "true" ]]; then
    printf '%s\n' 'ERROR: restore database fence is incomplete' >&2
    exit 1
  fi
  : > "$metadata_check/relations.tsv"
  relation_rows=0
  relation_marker=0
  while IFS= read -r relation_row <&8; do
    if [[ "$relation_row" == 'SENTINELFLOW_RELATIONS_END_V1' ]]; then
      relation_marker=1
      break
    fi
    relation_rows=$((relation_rows + 1))
    [[ "$relation_rows" -le 256 ]] || { printf '%s\n' 'ERROR: restore relation contract is oversized' >&2; exit 1; }
    printf '%s\n' "$relation_row" >> "$metadata_check/relations.tsv"
  done
  [[ "$relation_marker" == "1" ]] || { printf '%s\n' 'ERROR: restore relation contract was truncated' >&2; exit 1; }
  "$cmp_bin" -s "$bundle/metadata/relations.tsv" "$metadata_check/relations.tsv" || { printf '%s\n' 'ERROR: database relation contract drifted after fencing' >&2; exit 1; }

  : > "$metadata_check/sequences.initial.tsv"
  sequence_rows=0
  sequence_marker=0
  while IFS= read -r sequence_row <&8; do
    if [[ "$sequence_row" == 'SENTINELFLOW_SEQUENCES_END_V1' ]]; then
      sequence_marker=1
      break
    fi
    sequence_rows=$((sequence_rows + 1))
    [[ "$sequence_rows" -le 16 ]] || { printf '%s\n' 'ERROR: restore sequence contract is oversized' >&2; exit 1; }
    printf '%s\n' "$sequence_row" >> "$metadata_check/sequences.initial.tsv"
  done
  [[ "$sequence_marker" == "1" && "$sequence_rows" == "2" ]] || { printf '%s\n' 'ERROR: restore sequence contract was truncated' >&2; exit 1; }
  printf '%s\n' \
    $'sentinelflow.audit_events_sequence_seq\t1\tfalse' \
    $'sentinelflow.sse_notification_cursor_seq\t1\tfalse' > "$metadata_check/sequences.fresh.tsv"
  {
    IFS= read -r signed_sequence_one
    IFS= read -r signed_sequence_two
  } < "$bundle/metadata/sequences.tsv"
  {
    IFS= read -r current_sequence_one
    IFS= read -r current_sequence_two
  } < "$metadata_check/sequences.initial.tsv"
  fresh_sequence_one=$'sentinelflow.audit_events_sequence_seq\t1\tfalse'
  fresh_sequence_two=$'sentinelflow.sse_notification_cursor_seq\t1\tfalse'
  [[ ( "$current_sequence_one" == "$fresh_sequence_one" || "$current_sequence_one" == "$signed_sequence_one" ) &&
     ( "$current_sequence_two" == "$fresh_sequence_two" || "$current_sequence_two" == "$signed_sequence_two" ) ]] || { printf '%s\n' 'ERROR: restore destination sequence is neither fresh nor an exact resumable signed state' >&2; exit 1; }
  if ! IFS= read -r locked_snapshot_id <&8 || [[ ! "$locked_snapshot_id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9]+$ ]]; then
    printf '%s\n' 'ERROR: locked restore snapshot is invalid' >&2
    exit 1
  fi

  # The schema check is repeated from a snapshot exported only after all
  # table/catalog/sequence fences are held. The earlier preflight is merely a
  # fast rejection and is never authoritative for mutation.
  session_database_exec "$pg_dump_bin" --dbname "$database" --schema-only --schema=sentinelflow --strict-names \
    --snapshot="$locked_snapshot_id" \
    --no-owner --no-privileges --no-comments --no-security-labels --no-publications \
    --no-subscriptions --no-tablespaces --no-table-access-method \
    --restrict-key=SENTINELFLOWRECOVERYV1 \
    --file "$metadata_check/schema.locked.sql"
  canonicalize_schema_dump "$metadata_check/schema.locked.sql"
  "$cmp_bin" -s "$bundle/metadata/schema.sql" "$metadata_check/schema.locked.sql" || { printf '%s\n' 'ERROR: database schema drifted after recovery fencing' >&2; exit 1; }
  session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --dbname "$database" \
    --set=snapshot_id="$locked_snapshot_id" > "$metadata_check/migrations.locked.tsv" <<'SQL'
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET TRANSACTION SNAPSHOT :'snapshot_id';
COPY (SELECT version, name FROM sentinelflow.schema_migrations ORDER BY version) TO STDOUT;
ROLLBACK;
SQL
  "$cmp_bin" -s "$bundle/metadata/migrations.tsv" "$metadata_check/migrations.locked.tsv" || { printf '%s\n' 'ERROR: migration ledger drifted after recovery fencing' >&2; exit 1; }

  # Upgrade the same RC transaction to mutation-exclusive locks. The SHARE
  # and SRX fences above have prevented every table and sequence writer since
  # the authoritative schema snapshot was taken.
  printf '%s\n' \
    "$restore_lock_sql" \
    "$relation_copy_sql" \
    "SELECT 'SENTINELFLOW_RELATIONS_END_V1';" \
    "$sequence_copy_sql" \
    "SELECT 'SENTINELFLOW_SEQUENCES_END_V1';" >&7

  : > "$metadata_check/relations.exclusive.tsv"
  relation_rows=0
  relation_marker=0
  while IFS= read -r relation_row <&8; do
    if [[ "$relation_row" == 'SENTINELFLOW_RELATIONS_END_V1' ]]; then
      relation_marker=1
      break
    fi
    relation_rows=$((relation_rows + 1))
    [[ "$relation_rows" -le 256 ]] || { printf '%s\n' 'ERROR: exclusive relation contract is oversized' >&2; exit 1; }
    printf '%s\n' "$relation_row" >> "$metadata_check/relations.exclusive.tsv"
  done
  [[ "$relation_marker" == "1" ]] || { printf '%s\n' 'ERROR: exclusive relation contract was truncated' >&2; exit 1; }
  "$cmp_bin" -s "$bundle/metadata/relations.tsv" "$metadata_check/relations.exclusive.tsv" || { printf '%s\n' 'ERROR: relation contract changed before restore' >&2; exit 1; }
  : > "$metadata_check/sequences.exclusive.tsv"
  sequence_rows=0
  sequence_marker=0
  while IFS= read -r sequence_row <&8; do
    if [[ "$sequence_row" == 'SENTINELFLOW_SEQUENCES_END_V1' ]]; then
      sequence_marker=1
      break
    fi
    sequence_rows=$((sequence_rows + 1))
    [[ "$sequence_rows" -le 16 ]] || { printf '%s\n' 'ERROR: exclusive sequence contract is oversized' >&2; exit 1; }
    printf '%s\n' "$sequence_row" >> "$metadata_check/sequences.exclusive.tsv"
  done
  [[ "$sequence_marker" == "1" && "$sequence_rows" == "2" ]] || { printf '%s\n' 'ERROR: exclusive sequence contract was truncated' >&2; exit 1; }
  "$cmp_bin" -s "$metadata_check/sequences.initial.tsv" "$metadata_check/sequences.exclusive.tsv" || { printf '%s\n' 'ERROR: sequence state changed before restore' >&2; exit 1; }

  printf '%s\n' 'SET LOCAL session_replication_role = replica;' >&7
  cat >&7 <<'SQL'
DO $fresh_destination$
DECLARE
    relation record;
    row_count bigint;
BEGIN
    FOR relation IN
        SELECT n.nspname AS schema_name, c.relname AS relation_name
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'sentinelflow'
          AND c.relkind IN ('r', 'p')
          AND c.relname <> 'schema_migrations'
        ORDER BY c.relname
    LOOP
        IF relation.relation_name = 'sse_notification_replay_state' THEN
            SELECT count(*) INTO row_count
            FROM sentinelflow.sse_notification_replay_state
            WHERE singleton AND replay_floor = 0 AND watermark = 0;
            IF row_count <> 1 OR
               (SELECT count(*) FROM sentinelflow.sse_notification_replay_state) <> 1 THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'restore destination baseline is invalid';
            END IF;
        ELSE
            EXECUTE format('SELECT count(*) FROM %I.%I', relation.schema_name, relation.relation_name)
                INTO row_count;
            IF row_count <> 0 THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'restore destination is not fresh';
            END IF;
        END IF;
    END LOOP;
END
$fresh_destination$;

CREATE TEMP TABLE sentinelflow_expected_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL
) ON COMMIT DROP;
SQL
  migration_count=0
  while IFS=$'\t' read -r migration_version migration_name migration_extra; do
    [[ "$migration_version" =~ ^[0-9]+$ && "$migration_name" =~ ^[a-z0-9_]+$ && -z "$migration_extra" ]] || { printf '%s\n' 'ERROR: signed migration metadata is invalid' >&2; exit 1; }
    printf "INSERT INTO sentinelflow_expected_migrations(version,name) VALUES (%s,'%s');\n" \
      "$migration_version" "$migration_name" >&7
    migration_count=$((migration_count + 1))
  done < "$bundle/metadata/migrations.tsv"
  [[ "$migration_count" -gt 0 ]] || { printf '%s\n' 'ERROR: signed migration metadata is empty' >&2; exit 1; }
  cat >&7 <<'SQL'
DO $validate_migration_ledger$
BEGIN
    IF EXISTS (
        (SELECT version, name FROM sentinelflow.schema_migrations
         EXCEPT SELECT version, name FROM sentinelflow_expected_migrations)
        UNION ALL
        (SELECT version, name FROM sentinelflow_expected_migrations
         EXCEPT SELECT version, name FROM sentinelflow.schema_migrations)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration ledger changed after recovery fencing';
    END IF;
END
$validate_migration_ledger$;

DELETE FROM sentinelflow.sse_notification_replay_state WHERE singleton;
SQL
  # pg_restore emits SELECT setval statements. Keep their scalar output out of
  # the stdout marker protocol; ON_ERROR_STOP and stderr remain active.
  printf '%s\n' '\o /dev/null' >&7
  cat "$metadata_check/data.sql" >&7
  printf '%s\n' '\o' >&7
  cat >&7 <<'SQL'
SET LOCAL session_replication_role = origin;

DO $validate_restored_foreign_keys$
DECLARE
    constraint_row record;
    join_expression text;
    nonnull_expression text;
    allnull_expression text;
    violation boolean;
BEGIN
    FOR constraint_row IN
        SELECT constraint_def.oid, constraint_def.conname,
               constraint_def.conrelid, constraint_def.confrelid,
               constraint_def.conkey, constraint_def.confkey,
               constraint_def.confmatchtype
        FROM pg_catalog.pg_constraint constraint_def
        WHERE constraint_def.contype = 'f'
          AND constraint_def.connamespace = 'sentinelflow'::regnamespace
        ORDER BY constraint_def.oid
    LOOP
        SELECT
            string_agg(format('child.%I = parent.%I', child_attribute.attname, parent_attribute.attname), ' AND ' ORDER BY key_pair.ordinality),
            string_agg(format('child.%I IS NOT NULL', child_attribute.attname), ' AND ' ORDER BY key_pair.ordinality),
            string_agg(format('child.%I IS NULL', child_attribute.attname), ' AND ' ORDER BY key_pair.ordinality)
        INTO join_expression, nonnull_expression, allnull_expression
        FROM unnest(constraint_row.conkey, constraint_row.confkey)
             WITH ORDINALITY AS key_pair(child_number, parent_number, ordinality)
        JOIN pg_catalog.pg_attribute child_attribute
          ON child_attribute.attrelid = constraint_row.conrelid
         AND child_attribute.attnum = key_pair.child_number
        JOIN pg_catalog.pg_attribute parent_attribute
          ON parent_attribute.attrelid = constraint_row.confrelid
         AND parent_attribute.attnum = key_pair.parent_number;

        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %s child WHERE (%s) AND NOT EXISTS (SELECT 1 FROM %s parent WHERE %s))',
            constraint_row.conrelid::regclass, nonnull_expression,
            constraint_row.confrelid::regclass, join_expression
        ) INTO violation;
        IF violation THEN
            RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'restored foreign key is invalid';
        END IF;

        IF constraint_row.confmatchtype = 'f' THEN
            EXECUTE format(
                'SELECT EXISTS (SELECT 1 FROM %s child WHERE NOT (%s) AND NOT (%s))',
                constraint_row.conrelid::regclass, nonnull_expression, allnull_expression
            ) INTO violation;
            IF violation THEN
                RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'restored MATCH FULL foreign key is invalid';
            END IF;
        END IF;
    END LOOP;
END
$validate_restored_foreign_keys$;
SQL
  printf '%s\n' \
    "$sequence_copy_sql" \
    "SELECT 'SENTINELFLOW_RESTORED_SEQUENCES_END_V1';" \
    "$artifact_copy_sql" \
    "SELECT 'SENTINELFLOW_EXECUTION_ARTIFACTS_END_V1';" \
    "SELECT 'SENTINELFLOW_RESTORE_VALIDATION_READY_V1';" >&7

  : > "$metadata_check/sequences.restored.tsv"
  sequence_rows=0
  sequence_marker=0
  while IFS= read -r sequence_row <&8; do
    if [[ "$sequence_row" == 'SENTINELFLOW_RESTORED_SEQUENCES_END_V1' ]]; then
      sequence_marker=1
      break
    fi
    sequence_rows=$((sequence_rows + 1))
    [[ "$sequence_rows" -le 16 ]] || { printf '%s\n' 'ERROR: restored sequence contract is oversized' >&2; exit 1; }
    printf '%s\n' "$sequence_row" >> "$metadata_check/sequences.restored.tsv"
  done
  [[ "$sequence_marker" == "1" && "$sequence_rows" == "2" ]] || { printf '%s\n' 'ERROR: restored sequence contract was truncated' >&2; exit 1; }
  "$cmp_bin" -s "$bundle/metadata/sequences.tsv" "$metadata_check/sequences.restored.tsv" || { printf '%s\n' 'ERROR: restored sequence state does not match the signed bundle' >&2; exit 1; }

  : > "$metadata_check/execution-artifacts.ndjson"
  artifact_rows=0
  artifact_marker=0
  while IFS= read -r artifact_row <&8; do
    if [[ "$artifact_row" == 'SENTINELFLOW_EXECUTION_ARTIFACTS_END_V1' ]]; then
      artifact_marker=1
      break
    fi
    artifact_rows=$((artifact_rows + 1))
    [[ "$artifact_rows" -le 100000 ]] || { printf '%s\n' 'ERROR: execution artifact stream is oversized' >&2; exit 1; }
    printf '%s\n' "$artifact_row" >> "$metadata_check/execution-artifacts.ndjson"
  done
  [[ "$artifact_marker" == "1" ]] || { printf '%s\n' 'ERROR: execution artifact stream was truncated' >&2; exit 1; }
  if ! IFS= read -r validation_ready <&8 || [[ "$validation_ready" != 'SENTINELFLOW_RESTORE_VALIDATION_READY_V1' ]]; then
    printf '%s\n' 'ERROR: restore validation transaction exited early' >&2
    exit 1
  fi
  "$recovery_tool" validate-recovery-state \
    --journal "$journal_destination" \
    --replay-journal "$bundle/executor/replay.json" \
    --dispatch-public-key "$dispatch_public_key" \
    --result-public-key "$result_public_key" \
    < "$metadata_check/execution-artifacts.ndjson"

  # Only after the signed journal and every retained DB artifact match may a
  # dead started lifecycle become recovery-only work. The dedicated PG17
  # claim path cannot mint, does not consume ordinary attempts, and is not
  # eligible before the original capability has expired.
  cat >&7 <<'SQL'
CREATE TEMP TABLE sentinelflow_recovery_clock (
    server_now timestamptz NOT NULL
) ON COMMIT DROP;
INSERT INTO sentinelflow_recovery_clock(server_now) VALUES (clock_timestamp());

UPDATE sentinelflow.dead_letter_jobs dead
SET resolution_state = 'requeued',
    resolved_at = (SELECT server_now FROM sentinelflow_recovery_clock),
    resolution_actor = 'sentinelflow_recovery',
    resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
        dead.job_id, capability.capability_digest,
        dead.failure_code, dead.failure_digest
    )
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.execution_capabilities capability USING (job_id)
LEFT JOIN sentinelflow.execution_results result USING (capability_id)
WHERE dead.resolution_state = 'unresolved'
  AND job.job_id = dead.job_id
  AND job.state = 'dead'
  AND dead.kind = job.kind
  AND dead.aggregate_type = job.aggregate_type
  AND dead.aggregate_id = job.aggregate_id
  AND dead.aggregate_version = job.aggregate_version
  AND dead.attempts = job.attempts
  AND capability.consumed_at IS NULL
  AND result.result_id IS NULL;

DO $recovery_dead_letter$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM sentinelflow.outbox_jobs job
        JOIN sentinelflow.execution_capabilities capability USING (job_id)
        LEFT JOIN sentinelflow.execution_results result USING (capability_id)
        LEFT JOIN sentinelflow.dead_letter_jobs dead USING (job_id)
        WHERE job.state = 'dead'
          AND capability.consumed_at IS NULL
          AND result.result_id IS NULL
          AND (dead.job_id IS NULL OR dead.resolution_state <> 'requeued' OR
               dead.resolved_at IS DISTINCT FROM (SELECT server_now FROM sentinelflow_recovery_clock) OR
               NOT isfinite(dead.resolved_at) OR
               dead.resolution_actor IS DISTINCT FROM 'sentinelflow_recovery' OR
               dead.kind IS DISTINCT FROM job.kind OR
               dead.aggregate_type IS DISTINCT FROM job.aggregate_type OR
               dead.aggregate_id IS DISTINCT FROM job.aggregate_id OR
               dead.aggregate_version IS DISTINCT FROM job.aggregate_version OR
               dead.attempts IS DISTINCT FROM job.attempts OR
               dead.dead_at > dead.resolved_at OR
               dead.resolution_digest IS DISTINCT FROM sentinelflow.dispatch_recovery_marker_000025(
                   job.job_id, capability.capability_digest,
                   dead.failure_code, dead.failure_digest
               ))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'started recovery dead-letter binding is incomplete';
    END IF;
END
$recovery_dead_letter$;

UPDATE sentinelflow.outbox_jobs job
SET state = 'retry',
    available_at = greatest(
        (SELECT server_now FROM sentinelflow_recovery_clock),
        capability.expires_at
    ),
    lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
    last_error_code = 'recovery_started',
    last_error_digest = dead.resolution_digest,
    updated_at = (SELECT server_now FROM sentinelflow_recovery_clock)
FROM sentinelflow.execution_capabilities capability
LEFT JOIN sentinelflow.execution_results result USING (capability_id)
JOIN sentinelflow.dead_letter_jobs dead ON dead.job_id = capability.job_id
WHERE job.job_id = capability.job_id
  AND job.state = 'dead'
  AND dead.resolution_state = 'requeued'
  AND dead.resolved_at = (SELECT server_now FROM sentinelflow_recovery_clock)
  AND dead.resolution_actor = 'sentinelflow_recovery'
  AND dead.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
      job.job_id, capability.capability_digest,
      dead.failure_code, dead.failure_digest
  )
  AND capability.consumed_at IS NULL
  AND result.result_id IS NULL;
SELECT 'SENTINELFLOW_RECOVERY_REQUEUED_V1';
SQL
  if ! IFS= read -r recovery_marker <&8 || [[ "$recovery_marker" != 'SENTINELFLOW_RECOVERY_REQUEUED_V1' ]]; then
    printf '%s\n' 'ERROR: restore recovery-only transition failed' >&2
    exit 1
  fi
  if [[ "$fail_after_data_load" == "1" ]]; then
    printf '%s\n' 'ERROR: injected stop after data load and sequence setval but before commit' >&2
    exit 96
  fi
  "$recovery_tool" verify --bundle "$bundle" --verification-key "$verification_key"

  cat >&7 <<'SQL'
CREATE TABLE public.sentinelflow_recovery_receipt_v1 (
    singleton boolean PRIMARY KEY CHECK (singleton),
    schema_version text NOT NULL CHECK (schema_version = 'sentinelflow-restore-receipt-v1'),
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    bundle_manifest_digest text NOT NULL CHECK (bundle_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    database_identity_digest text NOT NULL CHECK (database_identity_digest ~ '^sha256:[0-9a-f]{64}$'),
    journal_digest text NOT NULL CHECK (journal_digest ~ '^sha256:[0-9a-f]{64}$')
);
REVOKE ALL ON public.sentinelflow_recovery_receipt_v1 FROM PUBLIC;
INSERT INTO public.sentinelflow_recovery_receipt_v1 (
    singleton, schema_version, receipt_digest, bundle_manifest_digest,
    database_identity_digest, journal_digest
) VALUES (
    true, 'sentinelflow-restore-receipt-v1', :'receipt_digest',
    :'manifest_digest', :'database_digest', :'journal_digest'
);
COMMIT;
SELECT 'SENTINELFLOW_RESTORE_COMMITTED_V1';
SQL
  if ! IFS= read -r commit_marker <&8 || [[ "$commit_marker" != 'SENTINELFLOW_RESTORE_COMMITTED_V1' ]]; then
    printf '%s\n' 'ERROR: restore transaction did not commit' >&2
    exit 1
  fi
  printf '%s\n' '\q' >&7
  exec 7>&-
  exec 8<&-
  if ! wait "$restore_pid"; then
    printf '%s\n' 'ERROR: restore database session failed' >&2
    exit 1
  fi
  restore_pid=""
  receipt_state="exact"
fi

if [[ "$receipt_state" == "exact" && "$restore_phase" == "prepared" ]]; then
  restore_status="$($recovery_tool mark-database-restored \
    --bundle "$bundle" \
    --verification-key "$verification_key" \
    --destination "$journal_destination" \
    --database-identity "$database_identity")"
  parse_restore_status "$restore_status"
  require_same_restore_binding
fi

[[ "$restore_phase" != "database_restored" || "$receipt_state" == "exact" ]] || { printf '%s\n' 'ERROR: restored database receipt is missing before journal commit' >&2; exit 1; }

if [[ "$fail_after_database_commit" == "1" && "$restore_phase" == "database_restored" ]]; then
  printf '%s\n' 'ERROR: injected stop after database commit and before journal commit' >&2
  exit 97
fi

if [[ "$restore_phase" == "database_restored" ]]; then
  restore_status="$($recovery_tool commit-prepared-journal \
    --bundle "$bundle" \
    --verification-key "$verification_key" \
    --destination "$journal_destination" \
    --database-identity "$database_identity")"
  parse_restore_status "$restore_status"
  require_same_restore_binding
fi
[[ "$restore_phase" == "journal_installed" || "$restore_phase" == "finalized" ]] || { printf '%s\n' 'ERROR: journal restore did not converge' >&2; exit 1; }
[[ "$journal_state" == "installed" ]] || { printf '%s\n' 'ERROR: journal is not installed' >&2; exit 1; }

if [[ "$fail_after_journal_commit" == "1" && "$restore_phase" == "journal_installed" ]]; then
  printf '%s\n' 'ERROR: injected stop after journal commit and before receipt cleanup' >&2
  exit 98
fi

if [[ "$receipt_state" == "exact" && "$restore_phase" == "journal_installed" ]]; then
  session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --single-transaction --quiet --dbname "$database" \
    --command "DO \$drop_receipt\$ BEGIN IF (SELECT count(*) FROM public.sentinelflow_recovery_receipt_v1 WHERE singleton AND receipt_digest = '$receipt_digest') <> 1 THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'restore receipt changed'; END IF; DROP TABLE public.sentinelflow_recovery_receipt_v1; END \$drop_receipt\$;" >/dev/null
  receipt_state="absent"
fi

if [[ "$fail_after_receipt_removal" == "1" && "$restore_phase" == "journal_installed" && "$receipt_state" == "absent" ]]; then
  printf '%s\n' 'ERROR: injected stop after receipt cleanup and before final marker' >&2
  exit 99
fi

if [[ "$restore_phase" == "journal_installed" ]]; then
  restore_status="$($recovery_tool finalize-restore \
    --bundle "$bundle" \
    --verification-key "$verification_key" \
    --destination "$journal_destination" \
    --database-identity "$database_identity")"
  parse_restore_status "$restore_status"
  require_same_restore_binding
fi
[[ "$restore_phase" == "finalized" && "$journal_state" == "installed" && "$receipt_state" == "absent" ]] || { printf '%s\n' 'ERROR: restore did not reach durable final state' >&2; exit 1; }

printf '%s\n' 'SentinelFlow database and opaque executor journal restored with durable finalized state. No executor or nftables operation was invoked.'
