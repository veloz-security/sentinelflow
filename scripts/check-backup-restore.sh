#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image='postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193'
container="sentinelflow-backup-restore-check-$$-${RANDOM}"
temporary="$(mktemp -d /tmp/sentinelflow-recovery-check.XXXXXX)"
chmod 0700 "$temporary"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [[ -d "$temporary" && ! -L "$temporary" ]]; then
    # Recovery fixtures deliberately create root-owned 0700 directories through
    # the PostgreSQL container. A Linux host runner cannot remove those after
    # the test, so use the same pinned disposable image to clear only this
    # controlled bind mount before the host-side no-follow cleanup.
    docker run --rm --volume "$temporary:/recovery" --entrypoint /bin/sh "$image" \
      -c 'find /recovery -mindepth 1 -depth -delete' >/dev/null 2>&1 || true
    find "$temporary" -depth -delete
  fi
}
trap cleanup EXIT INT TERM HUP

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

expect_tool_rejection() {
  if docker exec "$container" /recovery/sentinelflow-recoverytool "$@" >/dev/null 2>&1; then
    fail "recovery tool accepted an unsafe negative case"
  fi
}

wait_for_data_dump_marker() {
  local marker="$1"
  local application_name="$2"
  local log_file="$3"
  local holder_count=0
  local activity=''
  for _attempt in $(seq 1 300); do
    if docker exec "$container" test -f "$marker"; then
      holder_count="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name = '$application_name' AND state = 'idle in transaction'")"
      [[ "$holder_count" -ge 2 ]] || fail "data dump completed after the PostgreSQL fence was released"
      return
    fi
    sleep 0.05
  done
  activity="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT concat_ws(':', pid, state, coalesce(wait_event_type, ''), coalesce(wait_event, '')) FROM pg_catalog.pg_stat_activity WHERE application_name = '$application_name' ORDER BY pid" | tr '\n' ' ')"
  fail "data pg_dump ready marker timed out: activity=$activity log=$(tail -20 "$log_file" | tr '\n' ' ')"
}

wait_for_writable_postgres() {
  local writable=''
  for _attempt in $(seq 1 300); do
    writable="$(docker exec "$container" psql -U postgres -d postgres -Atc 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)"
    [[ "$writable" == 't' ]] && return
    sleep 0.05
  done
  fail 'disposable PostgreSQL did not return to writable state'
}

apply_migrations() {
  local database="$1"
  local migration
  local migration_log
  local migration_name
  docker exec "$container" createdb -U postgres "$database"
  for migration in "$repo_root"/db/migrations/*.up.sql; do
    migration_name="$(basename "$migration")"
    migration_log="$temporary/migration-${database}-${migration_name}.log"
    if ! docker exec -i "$container" psql --set=ON_ERROR_STOP=1 -U postgres -d "$database" \
      < "$migration" >"$migration_log" 2>&1; then
      fail "migration $migration_name failed for $database: $(tail -20 "$migration_log" | tr '\n' ' ')"
    fi
    rm -f "$migration_log"
  done
}

bash -n \
  "$repo_root/scripts/backup-state.sh" \
  "$repo_root/scripts/restore-state.sh" \
  "$repo_root/scripts/check-backup-restore.sh"
(
  cd "$repo_root"
  go test -race -count=1 \
    ./internal/recoverybundle/... \
    ./internal/enforcement/journal \
    ./internal/dispatchruntime \
    -run 'Test(Seal|Empty|Bundle|Wrong|Restore|Started|EveryFrameTruncation|StartupCrash|StartedOnlyRecovery|Runtime|Offline|FileSafety)' >/dev/null
)

docker pull "$image" >/dev/null
architecture="$(docker image inspect "$image" --format '{{.Architecture}}')"
(
  cd "$repo_root"
  GOOS=linux GOARCH="$architecture" CGO_ENABLED=0 \
    go build -o "$temporary/sentinelflow-recoverytool" ./cmd/recoverytool
  GOOS=linux GOARCH="$architecture" CGO_ENABLED=0 \
    go build -o "$temporary/sentinelflow-recovery-fixture" ./internal/recoverybundle/testfixture
)
chmod 0755 "$temporary/sentinelflow-recoverytool" "$temporary/sentinelflow-recovery-fixture"

cat > "$temporary/malformed-recoverytool" <<'SH'
#!/bin/sh
set -eu

if [ "${1:-}" = 'prepare-restore' ]; then
  output="$(/recovery/sentinelflow-recoverytool "$@")"
  tab="$(printf '\t')"
  old_ifs="$IFS"
  IFS="$tab"
  read -r phase receipt journal_state manifest database journal <<EOF
$output
EOF
  IFS="$old_ifs"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$phase" "${receipt}';SELECT 1;--" "$journal_state" "$manifest" "$database" "$journal"
  exit 0
fi
exec /recovery/sentinelflow-recoverytool "$@"
SH
chmod 0755 "$temporary/malformed-recoverytool"

cat > "$temporary/failing-pg-restore" <<'SH'
#!/bin/sh
set -eu

for argument in "$@"; do
  if [ "$argument" = '--list' ]; then
    exec /usr/local/bin/pg_restore "$@"
  fi
done
/usr/local/bin/pg_restore "$@"
exit 86
SH
chmod 0755 "$temporary/failing-pg-restore"

cat > "$temporary/slow-pg-dump" <<'SH'
#!/bin/sh
set -eu

/usr/local/bin/pg_dump "$@"
schema_only=0
data_only=0
output=''
expect_output=0
for argument in "$@"; do
  [ "$argument" = '--schema-only' ] && schema_only=1
  [ "$argument" = '--data-only' ] && data_only=1
  if [ "$expect_output" = '1' ]; then
    output="$argument"
    expect_output=0
    continue
  fi
  case "$argument" in
    --file) expect_output=1 ;;
    --file=*) output="${argument#--file=}" ;;
  esac
done
[ "$expect_output" = '0' ] || exit 87
if [ "$schema_only" = '1' ] && [ -n "$output" ]; then
  sed -i \
    -e 's/^-- Dumped from database version .*/-- Dumped from database version 17.999-test/' \
    -e 's/^-- Dumped by pg_dump version .*/-- Dumped by pg_dump version 17.999-test/' \
    "$output"
fi
if [ "$data_only" = '1' ] && [ -n "${SENTINELFLOW_SLOW_PG_DUMP_READY_FILE:-}" ]; then
  case "$SENTINELFLOW_SLOW_PG_DUMP_READY_FILE" in
    /recovery/work/.*-data-ready) : > "$SENTINELFLOW_SLOW_PG_DUMP_READY_FILE" ;;
    *) exit 88 ;;
  esac
fi
sleep 2
SH
chmod 0755 "$temporary/slow-pg-dump"

cat > "$temporary/timeout-reset-pg-restore" <<'SH'
#!/bin/sh
set -eu

for argument in "$@"; do
  if [ "$argument" = '--list' ]; then
    exec /usr/local/bin/pg_restore "$@"
  fi
done
/usr/local/bin/pg_restore "$@"
for argument in "$@"; do
  case "$argument" in
    --file=*) printf '%s\n' 'SET statement_timeout = 0;' >> "${argument#--file=}" ;;
  esac
done
SH
chmod 0755 "$temporary/timeout-reset-pg-restore"

cat > "$temporary/canonicalize-column-inserts" <<'SH'
#!/bin/sh
set -eu

if [ "${1:-}" = '--self-test' ]; then
  [ "$#" -eq 2 ] || exit 64
  directory="$2"
  mkdir -m 0700 "$directory"
  cat > "$directory/order-a.sql" <<'SQL'
-- Dumped from database version 17.1
\restrict SENTINELFLOWRECOVERYV1

SET statement_timeout = 0;

INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
INSERT INTO public.synthetic (id, value) VALUES (1, 'beta');
SELECT pg_catalog.setval('public.synthetic_id_seq', 2, true);

\unrestrict SENTINELFLOWRECOVERYV1
SQL
  cat > "$directory/order-b.sql" <<'SQL'
-- Dumped from database version 17.999-test
\restrict SENTINELFLOWRECOVERYV1

SET statement_timeout = 0;

SELECT pg_catalog.setval('public.synthetic_id_seq', 2, true);
INSERT INTO public.synthetic (id, value) VALUES (1, 'beta');
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');

\unrestrict SENTINELFLOWRECOVERYV1
SQL
  cat > "$directory/duplicate.sql" <<'SQL'
\restrict SENTINELFLOWRECOVERYV1
SET statement_timeout = 0;
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
INSERT INTO public.synthetic (id, value) VALUES (1, 'beta');
SELECT pg_catalog.setval('public.synthetic_id_seq', 2, true);
\unrestrict SENTINELFLOWRECOVERYV1
SQL
  cat > "$directory/missing.sql" <<'SQL'
\restrict SENTINELFLOWRECOVERYV1
SET statement_timeout = 0;
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
SELECT pg_catalog.setval('public.synthetic_id_seq', 2, true);
\unrestrict SENTINELFLOWRECOVERYV1
SQL
  cat > "$directory/mutated.sql" <<'SQL'
\restrict SENTINELFLOWRECOVERYV1
SET statement_timeout = 0;
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
INSERT INTO public.synthetic (id, value) VALUES (1, 'gamma');
SELECT pg_catalog.setval('public.synthetic_id_seq', 2, true);
\unrestrict SENTINELFLOWRECOVERYV1
SQL
  cat > "$directory/setval-mutated.sql" <<'SQL'
\restrict SENTINELFLOWRECOVERYV1
SET statement_timeout = 0;
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
INSERT INTO public.synthetic (id, value) VALUES (1, 'beta');
SELECT pg_catalog.setval('public.synthetic_id_seq', 3, true);
\unrestrict SENTINELFLOWRECOVERYV1
SQL
  cat > "$directory/expected.canonical" <<'SQL'
SENTINELFLOW_PG_DUMP_FRAMING_V1
\restrict SENTINELFLOWRECOVERYV1
SET statement_timeout = 0;
\unrestrict SENTINELFLOWRECOVERYV1
SENTINELFLOW_PG_DUMP_RECORDS_V1
INSERT INTO public.synthetic (id, value) VALUES (1, 'alpha');
INSERT INTO public.synthetic (id, value) VALUES (1, 'beta');
SELECT pg_catalog.setval('public.synthetic_id_seq', 2, true);
SQL
  for fixture in order-a order-b duplicate missing mutated setval-mutated; do
    "$0" "$directory/$fixture.sql" "$directory/$fixture.canonical"
  done
  cmp -s "$directory/order-a.canonical" "$directory/expected.canonical" || {
    printf '%s\n' 'ERROR: canonical column-insert bytes changed' >&2
    exit 65
  }
  cmp -s "$directory/order-a.canonical" "$directory/order-b.canonical" || {
    printf '%s\n' 'ERROR: canonical column-insert ordering is unstable' >&2
    exit 66
  }
  for negative in duplicate missing mutated setval-mutated; do
    if cmp -s "$directory/order-a.canonical" "$directory/$negative.canonical"; then
      printf 'ERROR: canonical column-insert comparison missed %s\n' "$negative" >&2
      exit 67
    fi
  done
  exit 0
fi

[ "$#" -eq 2 ] || exit 64
input="$1"
output="$2"
[ -f "$input" ] && [ ! -L "$input" ] && [ ! -e "$output" ] && [ ! -L "$output" ] || exit 68
umask 077
framing="$output.framing.$$"
records="$output.records.$$"
sorted="$output.sorted.$$"
candidate="$output.candidate.$$"
trap 'rm -f "$framing" "$records" "$sorted" "$candidate"' EXIT INT TERM HUP
: > "$framing"
: > "$records"
LC_ALL=C awk -v framing="$framing" -v records="$records" '
  /^(INSERT INTO |SELECT pg_catalog[.]setval[(])/ {
    if ($0 !~ /;$/) {
      bad_record = 1
      next
    }
    print $0 >> records
    record_count++
    next
  }
  /^--/ || /^[[:space:]]*$/ { next }
  { print $0 >> framing }
  END {
    if (bad_record) exit 69
    if (record_count == 0) exit 70
  }
' "$input"
LC_ALL=C sort -s "$records" > "$sorted"
{
  printf '%s\n' 'SENTINELFLOW_PG_DUMP_FRAMING_V1'
  cat "$framing"
  printf '%s\n' 'SENTINELFLOW_PG_DUMP_RECORDS_V1'
  cat "$sorted"
} > "$candidate"
chmod 0600 "$candidate"
mv "$candidate" "$output"
SH
chmod 0755 "$temporary/canonicalize-column-inserts"

docker run -d --rm \
  --name "$container" \
  --env POSTGRES_PASSWORD=sentinelflow-recovery-test-only \
  --env SENTINELFLOW_DISPATCH_PUBLIC_KEY=/recovery/work/dispatcher-capability-public.pem \
  --env SENTINELFLOW_RESULT_PUBLIC_KEY=/recovery/work/executor-result-public.pem \
  --volume "$repo_root:/repo:ro" \
  --volume "$temporary:/recovery" \
  "$image" >/dev/null

ready=0
for _attempt in $(seq 1 60); do
  if docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres -d postgres \
    --command 'SELECT 1' >/dev/null 2>&1; then
    # The image starts and then stops a temporary bootstrap server before PID
    # 1 launches the durable server. Do not mistake that short window for
    # readiness or the first migration can race shutdown.
    sleep 1
    if docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres -d postgres \
      --command 'SELECT 1' >/dev/null 2>&1; then
      ready=1
      break
    fi
  fi
  sleep 0.25
done
[[ "$ready" == "1" ]] || fail 'disposable PostgreSQL 17 did not become ready'

docker exec "$container" mkdir -m 0700 \
  /recovery/work \
  /recovery/journal-destination \
  /recovery/ddl-journal-destination \
  /recovery/drift-journal-destination \
  /recovery/sequence-extra-journal-destination \
  /recovery/sequence-missing-journal-destination \
  /recovery/existing-journal-destination \
  /recovery/started-journal-destination \
  /recovery/terminal-ahead-journal-destination
docker exec "$container" /recovery/canonicalize-column-inserts \
  --self-test /recovery/work/canonicalizer-self-test
docker exec "$container" find /recovery/work/canonicalizer-self-test -depth -delete

docker exec "$container" /recovery/sentinelflow-recoverytool keygen \
  --private /recovery/work/backup-signing-private.pem \
  --public /recovery/work/backup-signing-public.pem
docker exec "$container" /recovery/sentinelflow-recoverytool keygen \
  --private /recovery/work/wrong-private.pem \
  --public /recovery/work/wrong-public.pem
docker exec "$container" /recovery/sentinelflow-recoverytool keygen \
  --private /recovery/work/dispatcher-capability-private.pem \
  --public /recovery/work/dispatcher-capability-public.pem
docker exec "$container" /recovery/sentinelflow-recoverytool keygen \
  --private /recovery/work/executor-result-private.pem \
  --public /recovery/work/executor-result-public.pem

apply_migrations sentinelflow_recovery_source
apply_migrations sentinelflow_recovery_target
apply_migrations sentinelflow_recovery_ddl
apply_migrations sentinelflow_recovery_drift
apply_migrations sentinelflow_recovery_existing
apply_migrations sentinelflow_recovery_started_source
apply_migrations sentinelflow_recovery_started_target
apply_migrations sentinelflow_recovery_terminal_ahead_source
apply_migrations sentinelflow_recovery_terminal_ahead_target

# These existing transactional fixtures provide gateway events plus a complete
# incident/policy/approval/action/audit graph. Only the final test rollback is
# changed to commit inside this disposable database.
fixture_artifact_digest='sha256:edee1b44bed122f25694e10a0284834f9b120a103a38ceb2e94f1d98c9d0319f'
fixture_owned_schema_digest='sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997'
sed '$s/^ROLLBACK;$/COMMIT;/' "$repo_root/db/test/verify_ingest.sql" | \
  docker exec -i "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
    -d sentinelflow_recovery_source >/dev/null
{
  sed \
    -e "s/sha256:3333333333333333333333333333333333333333333333333333333333333333/$fixture_artifact_digest/g" \
    -e "s/sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/$fixture_owned_schema_digest/g" \
    -e '/^DO \$approved_dispatch_view\$$/,$d' "$repo_root/db/test/verify_hil.sql"
  printf '%s\n' 'COMMIT;'
} | \
  docker exec -i "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
    -d sentinelflow_recovery_source >/dev/null
for fixture_database in \
  sentinelflow_recovery_started_source \
  sentinelflow_recovery_terminal_ahead_source; do
  {
    sed \
      -e "s/sha256:3333333333333333333333333333333333333333333333333333333333333333/$fixture_artifact_digest/g" \
      -e "s/sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/$fixture_owned_schema_digest/g" \
      -e '/^DO \$approved_dispatch_view\$$/,$d' "$repo_root/db/test/verify_hil.sql"
    printf '%s\n' 'COMMIT;'
  } | \
    docker exec -i "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
      -d "$fixture_database" >/dev/null
done

docker exec "$container" /recovery/sentinelflow-recovery-fixture init \
  --journal /recovery/work/replay.json \
  --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
  --result-private-key /recovery/work/executor-result-private.pem \
  --result-public-key /recovery/work/executor-result-public.pem

# A short-lived recovery helper inherits but does not own the session. Its exit
# must leave both the stable fence and existing-journal flock held by the shell.
docker exec "$container" /recovery/sentinelflow-recoverytool run-session \
  --journal /recovery/work/replay.json -- /bin/sh -eu -c \
  '/recovery/sentinelflow-recoverytool validate-session --journal /recovery/work/replay.json; : > /recovery/work/helper-exited.ready; sleep 2' &
helper_session_pid=$!
helper_ready=0
for _attempt in $(seq 1 60); do
  if docker exec "$container" test -f /recovery/work/helper-exited.ready >/dev/null 2>&1; then
    helper_ready=1
    break
  fi
  sleep 0.05
done
[[ "$helper_ready" == "1" ]] || fail 'inherited-fence helper session did not become ready'
if docker exec "$container" /recovery/sentinelflow-recoverytool run-session \
  --journal /recovery/work/replay.json -- /bin/true >/dev/null 2>&1; then
  fail 'helper exit released the recovery session fence'
fi
wait "$helper_session_pid"

# SIGKILL of the session shell must not release either lock while an orphaned
# PostgreSQL child is still alive with the inherited descriptors.
set +e
docker exec "$container" /recovery/sentinelflow-recoverytool run-session \
  --journal /recovery/work/replay.json -- /bin/sh -eu -c \
  'PGAPPNAME=sentinelflow_recovery_orphan /recovery/sentinelflow-recoverytool exec-session-child --journal /recovery/work/replay.json -- /usr/local/bin/psql -U postgres -d sentinelflow_recovery_source -c "SELECT pg_sleep(4)" >/dev/null & child=$!; printf "%s\n" "$child" > /recovery/work/orphan.pid; sleep 0.5; kill -KILL $$' >/dev/null 2>&1 &
orphan_session_pid=$!
set -e
orphan_ready=0
for _attempt in $(seq 1 120); do
  orphan_count="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name = 'sentinelflow_recovery_orphan'")"
  if [[ "$orphan_count" == "1" ]]; then
    orphan_ready=1
    break
  fi
  sleep 0.05
done
[[ "$orphan_ready" == "1" ]] || fail 'orphaned PostgreSQL child did not become ready'
set +e
wait "$orphan_session_pid"
set -e
if docker exec "$container" /recovery/sentinelflow-recoverytool run-session \
  --journal /recovery/work/replay.json -- /bin/true >/dev/null 2>&1; then
  fail 'shell SIGKILL released a fence still inherited by PostgreSQL'
fi
for _attempt in $(seq 1 120); do
  orphan_count="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name = 'sentinelflow_recovery_orphan'")"
  [[ "$orphan_count" == "0" ]] && break
  sleep 0.05
done
[[ "$orphan_count" == "0" ]] || fail 'orphaned PostgreSQL child did not terminate'
docker exec "$container" /recovery/sentinelflow-recoverytool run-session \
  --journal /recovery/work/replay.json -- /bin/true

# Backup refuses dispatch work that is still pending, leased, or retrying. The
# HIL fixture intentionally creates a pending dispatch job for this negative.
inflight_dispatch="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM sentinelflow.outbox_jobs WHERE kind IN ('dispatch_add','dispatch_revoke','dispatch_inspect') AND state IN ('pending','leased','retry')")"
[[ "$inflight_dispatch" -gt 0 ]] || fail 'dispatch quiescence fixture is missing'
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/backup-state.sh \
    --database sentinelflow_recovery_source \
    --journal /recovery/work/replay.json \
    --output /recovery/work/inflight-rejected-bundle \
    --signing-key /recovery/work/backup-signing-private.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'backup accepted in-flight dispatch authority'
fi
docker exec "$container" test ! -e /recovery/work/inflight-rejected-bundle

# Complete the real HIL fixture through dispatcher -> executor -> signed result.
# The resulting database rows are an exact subset of the authenticated journal.
docker exec "$container" /recovery/sentinelflow-recovery-fixture terminal \
  --database sentinelflow_recovery_source \
  --journal /recovery/work/replay.json \
  --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
  --result-private-key /recovery/work/executor-result-private.pem \
  --result-public-key /recovery/work/executor-result-public.pem

# Sequence values are non-MVCC state. The dedicated sequence fence must block
# direct nextval until the hidden bundle is sealed and atomically published.
sequence_state_before="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT last_value::text || '|' || is_called::text FROM sentinelflow.audit_events_sequence_seq")"
[[ "$sequence_state_before" =~ ^[0-9]+\|(true|false)$ ]] || fail 'source sequence state is invalid'
later_sequence_state_before="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT last_value::text || '|' || is_called::text FROM sentinelflow.sse_notification_cursor_seq")"
[[ "$later_sequence_state_before" =~ ^[0-9]+\|(true|false)$ ]] || fail 'later source sequence state is invalid'
docker exec "$container" test ! -e /recovery/work/.sequence-data-ready
docker exec \
  --env PGUSER=postgres \
  --env PGAPPNAME=sentinelflow_recovery_sequence_test \
  --env PG_DUMP_BIN=/recovery/slow-pg-dump \
  --env SENTINELFLOW_SLOW_PG_DUMP_READY_FILE=/recovery/work/.sequence-data-ready \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/backup-state.sh \
    --database sentinelflow_recovery_source \
    --journal /recovery/work/replay.json \
    --output /recovery/work/sequence-race-bundle \
    --signing-key /recovery/work/backup-signing-private.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >"$temporary/sequence-race.log" 2>&1 &
sequence_backup_pid=$!
sequence_holder_ready=0
for _attempt in $(seq 1 60); do
  sequence_holder="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name = 'sentinelflow_recovery_sequence_test' AND state = 'idle in transaction'")"
  if [[ "$sequence_holder" -ge 2 ]]; then
    sequence_holder_ready=1
    break
  fi
  sleep 0.05
done
if [[ "$sequence_holder_ready" != "1" ]]; then
  fail "sequence-safety snapshot holder did not become ready: $(tail -20 "$temporary/sequence-race.log" | tr '\n' ' ')"
fi
wait_for_data_dump_marker \
  /recovery/work/.sequence-data-ready \
  sentinelflow_recovery_sequence_test \
  "$temporary/sequence-race.log"
docker exec \
  --env PGAPPNAME=sentinelflow_recovery_blocked_sequence_writer \
  "$container" psql -U postgres -d sentinelflow_recovery_source \
  --set=ON_ERROR_STOP=1 --command "SELECT nextval(pg_get_serial_sequence('sentinelflow.audit_events','sequence'))" >/dev/null &
sequence_writer_pid=$!
docker exec \
  --env PGAPPNAME=sentinelflow_recovery_blocked_sequence_restart \
  "$container" psql -U postgres -d sentinelflow_recovery_source \
  --set=ON_ERROR_STOP=1 --command "ALTER SEQUENCE sentinelflow.sse_notification_cursor_seq RESTART WITH 42" >/dev/null &
sequence_restart_pid=$!
sequence_writer_blocked=0
for _attempt in $(seq 1 60); do
  blocked_state="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name IN ('sentinelflow_recovery_blocked_sequence_writer','sentinelflow_recovery_blocked_sequence_restart') AND wait_event_type = 'Lock'")"
  if [[ "$blocked_state" == "2" ]]; then
    sequence_writer_blocked=1
    break
  fi
  sleep 0.05
done
[[ "$sequence_writer_blocked" == "1" ]] || fail 'backup sequence fence did not block nextval and later-sequence restart'
docker exec "$container" test ! -e /recovery/work/sequence-race-bundle
if ! wait "$sequence_backup_pid"; then
  fail "sequence-fenced backup failed: $(tail -20 "$temporary/sequence-race.log" | tr '\n' ' ')"
fi
wait "$sequence_writer_pid" "$sequence_restart_pid"
docker exec "$container" find /recovery/work/.sequence-data-ready -delete
docker exec "$container" find /recovery/work/sequence-race-bundle -depth -delete
sequence_value_before="${sequence_state_before%%|*}"
sequence_called_before="${sequence_state_before##*|}"
docker exec "$container" psql -U postgres -d sentinelflow_recovery_source --set=ON_ERROR_STOP=1 \
  --command "SELECT setval('sentinelflow.audit_events_sequence_seq', $sequence_value_before, $sequence_called_before)" >/dev/null
later_sequence_value_before="${later_sequence_state_before%%|*}"
later_sequence_called_before="${later_sequence_state_before##*|}"
docker exec "$container" psql -U postgres -d sentinelflow_recovery_source --set=ON_ERROR_STOP=1 \
  --command "SELECT setval('sentinelflow.sse_notification_cursor_seq', $later_sequence_value_before, $later_sequence_called_before)" >/dev/null

# A normal writer that starts after the deterministic SHARE locks must wait
# until the snapshot and signed bundle are both complete.
source_watermark_before="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT watermark FROM sentinelflow.sse_notification_replay_state WHERE singleton")"
[[ "$source_watermark_before" =~ ^[0-9]+$ ]] || fail 'source replay watermark is invalid'
docker exec "$container" test ! -e /recovery/work/.locked-data-ready
docker exec \
  --env PGUSER=postgres \
  --env PGAPPNAME=sentinelflow_recovery_locked_snapshot \
  --env PG_DUMP_BIN=/recovery/slow-pg-dump \
  --env SENTINELFLOW_SLOW_PG_DUMP_READY_FILE=/recovery/work/.locked-data-ready \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/backup-state.sh \
    --database sentinelflow_recovery_source \
    --journal /recovery/work/replay.json \
    --output /recovery/work/bundle \
    --signing-key /recovery/work/backup-signing-private.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >"$temporary/locked-snapshot.log" 2>&1 &
backup_pid=$!
backup_holder_ready=0
for _attempt in $(seq 1 60); do
  backup_holder="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name = 'sentinelflow_recovery_locked_snapshot' AND state = 'idle in transaction'")"
  if [[ "$backup_holder" -ge 2 ]]; then
    backup_holder_ready=1
    break
  fi
  sleep 0.05
done
if [[ "$backup_holder_ready" != "1" ]]; then
  fail "locked snapshot holder did not become ready: $(tail -20 "$temporary/locked-snapshot.log" | tr '\n' ' ')"
fi
wait_for_data_dump_marker \
  /recovery/work/.locked-data-ready \
  sentinelflow_recovery_locked_snapshot \
  "$temporary/locked-snapshot.log"
docker exec \
  --env PGAPPNAME=sentinelflow_recovery_blocked_writer \
  "$container" psql --set=ON_ERROR_STOP=1 -U postgres -d sentinelflow_recovery_source \
  --command "BEGIN; UPDATE sentinelflow.sse_notification_replay_state SET watermark = watermark + 1 WHERE singleton; UPDATE sentinelflow.gateway_events SET status_code = status_code WHERE event_id = (SELECT event_id FROM sentinelflow.gateway_events ORDER BY event_id LIMIT 1); COMMIT;" >/dev/null &
blocked_writer_pid=$!
docker exec \
  --env PGAPPNAME=sentinelflow_recovery_blocked_truncate \
  "$container" psql --set=ON_ERROR_STOP=1 -U postgres -d sentinelflow_recovery_source \
  --command "BEGIN; TRUNCATE sentinelflow.ai_budget_reservations, sentinelflow.ai_budget_ledger; ROLLBACK;" >/dev/null &
blocked_truncate_pid=$!
writer_blocked=0
for _attempt in $(seq 1 60); do
  blocked_state="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name IN ('sentinelflow_recovery_blocked_writer','sentinelflow_recovery_blocked_truncate') AND wait_event_type = 'Lock'")"
  if [[ "$blocked_state" == "2" ]]; then
    writer_blocked=1
    break
  fi
  sleep 0.05
done
[[ "$writer_blocked" == "1" ]] || fail 'backup SHARE locks did not fence multi-table UPDATE/TRUNCATE writers'
if ! wait "$backup_pid"; then
  fail "locked snapshot backup failed: $(tail -20 "$temporary/locked-snapshot.log" | tr '\n' ' ')"
fi
wait "$blocked_writer_pid" "$blocked_truncate_pid"
docker exec "$container" find /recovery/work/.locked-data-ready -delete
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres -d sentinelflow_recovery_source \
  --command "UPDATE sentinelflow.sse_notification_replay_state SET watermark = $source_watermark_before WHERE singleton" >/dev/null

docker exec "$container" /recovery/sentinelflow-recoverytool verify \
  --bundle /recovery/work/bundle \
  --verification-key /recovery/work/backup-signing-public.pem

actual_files="$(docker exec "$container" find /recovery/work/bundle -type f | sed 's#^/recovery/work/bundle/##' | sort)"
expected_files=$'executor/replay.json\nmanifest.ed25519\nmanifest.json\nmetadata/migrations.tsv\nmetadata/postgres-major.txt\nmetadata/relations.tsv\nmetadata/schema.sql\nmetadata/sequences.tsv\npostgres/data.dump'
[[ "$actual_files" == "$expected_files" ]] || fail 'backup contains a missing or unlisted file'
private_key_marker='BEGIN '"PRIVATE KEY"
runtime_secret_pattern="${private_key_marker}|OPENAI_API_KEY|POSTGRES_PASSWORD|dispatcher-capability-private|executor-result-private"
if docker exec "$container" grep -aR -E \
  "$runtime_secret_pattern" \
  /recovery/work/bundle >/dev/null 2>&1; then
  fail 'backup contains key material or a runtime secret marker'
fi

# Authentication, completeness, file-type, and allowlist negatives.
expect_tool_rejection verify \
  --bundle /recovery/work/bundle \
  --verification-key /recovery/work/wrong-public.pem

docker exec "$container" cp -a /recovery/work/bundle /recovery/work/tampered
docker exec "$container" sh -c "printf x >> /recovery/work/tampered/executor/replay.json"
expect_tool_rejection verify --bundle /recovery/work/tampered --verification-key /recovery/work/backup-signing-public.pem
docker exec "$container" find /recovery/work/tampered -depth -delete

docker exec "$container" cp -a /recovery/work/bundle /recovery/work/torn
docker exec "$container" sh -eu -c \
  'dd if=/recovery/work/torn/executor/replay.json of=/recovery/work/torn/executor/replay.json.next bs=1 count=3 2>/dev/null; chmod 0600 /recovery/work/torn/executor/replay.json.next; mv /recovery/work/torn/executor/replay.json.next /recovery/work/torn/executor/replay.json'
expect_tool_rejection verify --bundle /recovery/work/torn --verification-key /recovery/work/backup-signing-public.pem
docker exec "$container" find /recovery/work/torn -depth -delete

docker exec "$container" cp -a /recovery/work/bundle /recovery/work/missing
docker exec "$container" find /recovery/work/missing/metadata/schema.sql -delete
expect_tool_rejection verify --bundle /recovery/work/missing --verification-key /recovery/work/backup-signing-public.pem
docker exec "$container" find /recovery/work/missing -depth -delete

docker exec "$container" cp -a /recovery/work/bundle /recovery/work/extra
docker exec "$container" sh -c "printf 'OPENAI_API_KEY=must-not-be-bundled' > /recovery/work/extra/.env; chmod 0600 /recovery/work/extra/.env"
expect_tool_rejection verify --bundle /recovery/work/extra --verification-key /recovery/work/backup-signing-public.pem
docker exec "$container" find /recovery/work/extra -depth -delete

docker exec "$container" cp -a /recovery/work/bundle /recovery/work/key-material
docker exec "$container" cp /recovery/work/backup-signing-private.pem /recovery/work/key-material/executor/backup-private.pem
docker exec "$container" chmod 0600 /recovery/work/key-material/executor/backup-private.pem
expect_tool_rejection verify --bundle /recovery/work/key-material --verification-key /recovery/work/backup-signing-public.pem
docker exec "$container" find /recovery/work/key-material -depth -delete

docker exec "$container" cp -a /recovery/work/bundle /recovery/work/symlink
docker exec "$container" find /recovery/work/symlink/executor/replay.json -delete
docker exec "$container" ln -s /recovery/work/replay.json /recovery/work/symlink/executor/replay.json
expect_tool_rejection verify --bundle /recovery/work/symlink --verification-key /recovery/work/backup-signing-public.pem
docker exec "$container" find /recovery/work/symlink -depth -delete

# The locked schema comparison must remain exact through the restore
# transaction. Relation, function, and type DDL all wait behind the static
# application/catalog fences; none can commit in the comparison/load gap.
set +e
docker exec \
  --env PGUSER=postgres \
  --env PGAPPNAME=sentinelflow_recovery_ddl_restore \
  --env PG_DUMP_BIN=/recovery/slow-pg-dump \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env SENTINELFLOW_RECOVERY_FAIL_AFTER_DATA_LOAD=1 \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_ddl \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/ddl-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >"$temporary/ddl-restore.log" 2>&1 &
ddl_restore_pid=$!
set -e
ddl_fence_ready=0
for _attempt in $(seq 1 160); do
  ddl_catalog_locks="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_ddl -Atc "SELECT count(DISTINCT held.relation) FROM pg_catalog.pg_stat_activity activity JOIN pg_catalog.pg_locks held ON held.pid = activity.pid WHERE activity.application_name = 'sentinelflow_recovery_ddl_restore' AND activity.state = 'idle in transaction' AND held.granted AND held.mode = 'ShareRowExclusiveLock' AND held.relation IN ('pg_catalog.pg_class'::regclass,'pg_catalog.pg_proc'::regclass,'pg_catalog.pg_type'::regclass)")"
  if [[ "$ddl_catalog_locks" == "3" ]]; then
    ddl_fence_ready=1
    break
  fi
  sleep 0.05
done
if [[ "$ddl_fence_ready" != "1" ]]; then
  schema_drift=''
  if docker exec "$container" pg_dump -U postgres -d sentinelflow_recovery_ddl \
      --schema-only --schema=sentinelflow --strict-names --no-owner --no-privileges \
      --no-comments --no-security-labels --no-publications --no-subscriptions \
      --no-tablespaces --no-table-access-method --restrict-key=SENTINELFLOWRECOVERYV1 \
      --file=/recovery/work/ddl-schema-diagnostic.sql; then
    docker exec "$container" sh -c \
      "sed '/^-- Dumped from database version /d;/^-- Dumped by pg_dump version /d' /recovery/work/ddl-schema-diagnostic.sql > /recovery/work/ddl-schema-diagnostic.canonical.sql"
    schema_drift="$(docker exec "$container" sh -c "diff -u /recovery/work/bundle/metadata/schema.sql /recovery/work/ddl-schema-diagnostic.canonical.sql | head -40" 2>/dev/null || true)"
  fi
  fail "restore DDL fences did not become ready: $(tail -20 "$temporary/ddl-restore.log" | tr '\n' ' ') schema=${schema_drift//$'\n'/ }"
fi
docker exec --env PGAPPNAME=sentinelflow_recovery_ddl_create_table \
  "$container" psql -U postgres -d sentinelflow_recovery_ddl --set=ON_ERROR_STOP=1 \
  --command "CREATE TABLE sentinelflow.concurrent_empty(id bigint)" >/dev/null &
ddl_table_pid=$!
docker exec --env PGAPPNAME=sentinelflow_recovery_ddl_alter_table \
  "$container" psql -U postgres -d sentinelflow_recovery_ddl --set=ON_ERROR_STOP=1 \
  --command "ALTER TABLE sentinelflow.gateway_events ADD COLUMN recovery_nullable text" >/dev/null &
ddl_alter_pid=$!
docker exec --env PGAPPNAME=sentinelflow_recovery_ddl_function \
  "$container" psql -U postgres -d sentinelflow_recovery_ddl --set=ON_ERROR_STOP=1 \
  --command "CREATE FUNCTION sentinelflow.concurrent_function() RETURNS integer LANGUAGE sql AS \$\$ SELECT 1 \$\$" >/dev/null &
ddl_function_pid=$!
docker exec --env PGAPPNAME=sentinelflow_recovery_ddl_type \
  "$container" psql -U postgres -d sentinelflow_recovery_ddl --set=ON_ERROR_STOP=1 \
  --command "CREATE TYPE sentinelflow.concurrent_type AS ENUM ('one')" >/dev/null &
ddl_type_pid=$!
ddl_writers_blocked=0
for _attempt in $(seq 1 80); do
  blocked_ddl="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_ddl -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name LIKE 'sentinelflow_recovery_ddl_%' AND application_name <> 'sentinelflow_recovery_ddl_restore' AND wait_event_type = 'Lock'")"
  if [[ "$blocked_ddl" == "4" ]]; then
    ddl_writers_blocked=1
    break
  fi
  sleep 0.05
done
[[ "$ddl_writers_blocked" == "1" ]] || fail 'restore did not fence concurrent table/function/type DDL'
set +e
wait "$ddl_restore_pid"
ddl_restore_status=$?
set -e
[[ "$ddl_restore_status" == "96" ]] || fail "DDL-fenced restore did not reach injected boundary: $(tail -20 "$temporary/ddl-restore.log" | tr '\n' ' ')"
wait "$ddl_table_pid" "$ddl_alter_pid" "$ddl_function_pid" "$ddl_type_pid"
ddl_after_release="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_ddl -Atc "SELECT (to_regclass('sentinelflow.concurrent_empty') IS NOT NULL)::text, (EXISTS (SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid = 'sentinelflow.gateway_events'::regclass AND attname = 'recovery_nullable' AND NOT attisdropped))::text, (to_regprocedure('sentinelflow.concurrent_function()') IS NOT NULL)::text, (to_regtype('sentinelflow.concurrent_type') IS NOT NULL)::text, (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$ddl_after_release" == "true|true|true|true|true" ]] || fail "fenced DDL did not remain external to the rolled-back restore: state=$ddl_after_release"
docker exec "$container" test ! -e /recovery/ddl-journal-destination/replay.json

# The static relation contract rejects both an additional SentinelFlow
# sequence and a required sequence moved outside the owned schema. Neither
# negative may reach table data, a receipt, or an installed journal.
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_drift \
  --command "CREATE SEQUENCE sentinelflow.unexpected_recovery_sequence AS bigint" >/dev/null
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_drift \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/sequence-extra-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'restore accepted an additional SentinelFlow sequence'
fi
docker exec "$container" test ! -e /recovery/sequence-extra-journal-destination/replay.json
sequence_negative_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_drift -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$sequence_negative_rows" == "0|true" ]] || fail 'extra sequence rejection mutated table data or receipt'
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_drift \
  --command "DROP SEQUENCE sentinelflow.unexpected_recovery_sequence; ALTER SEQUENCE sentinelflow.sse_notification_cursor_seq SET SCHEMA public" >/dev/null
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_drift \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/sequence-missing-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'restore accepted a missing owned sequence'
fi
docker exec "$container" test ! -e /recovery/sequence-missing-journal-destination/replay.json
sequence_negative_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_drift -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$sequence_negative_rows" == "0|true" ]] || fail 'missing sequence rejection mutated table data or receipt'
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_drift \
  --command "ALTER SEQUENCE public.sse_notification_cursor_seq SET SCHEMA sentinelflow" >/dev/null

# A target with a different migration ledger must fail before creating restore
# state or mutating data.
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_drift \
  --command "INSERT INTO sentinelflow.schema_migrations(version,name) SELECT max(version) + 1,'recovery_test_drift' FROM sentinelflow.schema_migrations" >/dev/null
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_drift \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/drift-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'migration version drift was restored'
fi
docker exec "$container" test ! -e /recovery/drift-journal-destination/replay.json

# A fresh restore must not infer authorization from an exact pre-existing
# journal. Only an authenticated prior restore phase may accept that inode.
docker exec "$container" cp /recovery/work/replay.json /recovery/existing-journal-destination/replay.json
docker exec "$container" chmod 0600 /recovery/existing-journal-destination/replay.json
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_existing \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/existing-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'fresh restore adopted a pre-existing journal'
fi
docker exec "$container" cmp /recovery/work/replay.json /recovery/existing-journal-destination/replay.json
docker exec "$container" test ! -e /recovery/existing-journal-destination/.replay.json.sentinelflow-restore-v1.state

# A compromised or buggy wrapper must not be able to smuggle tool output into
# SQL. The shell boundary independently requires six exact fields and lowercase
# sha256 digests before any interpolated query is issued.
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/malformed-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'malformed recovery-tool output crossed the shell trust boundary'
fi
injection_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$injection_rows" == "0|true" ]] || fail 'malformed tool output reached database mutation'

# A pg_restore producer may emit a complete valid SQL stream and still report a
# terminal failure. Because restore materializes and checks the producer first,
# psql must never see that file and no row may commit.
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env PG_RESTORE_BIN=/recovery/failing-pg-restore \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'failed pg_restore producer reached database commit'
fi
producer_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$producer_rows" == "0|true" ]] || fail 'failed pg_restore producer mutated the target'

# A valid pg_restore stream may not weaken the transaction's bounded timeout
# contract. Duplicate or non-exact timeout directives fail before psql reads
# any data bytes.
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env PG_RESTORE_BIN=/recovery/timeout-reset-pg-restore \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'pg_restore timeout reset reached the restore transaction'
fi
timeout_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$timeout_rows" == "0|true" ]] || fail 'timeout-reset producer mutated the target'

# A crash after the complete data stream must leave rows/receipt rolled back
# and each sequence in one of the two states accepted by the retry contract:
# the fresh target value or the exact signed bundle value.
set +e
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env SENTINELFLOW_RECOVERY_FAIL_AFTER_DATA_LOAD=1 \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
post_setval_status=$?
set -e
[[ "$post_setval_status" == "96" ]] || fail 'post-setval recovery interruption did not stop at the exact boundary'
wait_for_writable_postgres
post_setval_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$post_setval_rows" == "0|true" ]] || fail 'post-setval recovery interruption committed table data or receipt'
expected_sequence_state="$(docker exec "$container" cat /recovery/work/bundle/metadata/sequences.tsv)"
expected_sequence_one="${expected_sequence_state%%$'\n'*}"
expected_sequence_two="${expected_sequence_state#*$'\n'}"
fresh_sequence_one=$'sentinelflow.audit_events_sequence_seq\t1\tfalse'
fresh_sequence_two=$'sentinelflow.sse_notification_cursor_seq\t1\tfalse'
IFS=$'\t' read -r expected_sequence_one_name expected_sequence_one_value expected_sequence_one_called expected_sequence_one_extra <<< "$expected_sequence_one"
IFS=$'\t' read -r expected_sequence_two_name expected_sequence_two_value expected_sequence_two_called expected_sequence_two_extra <<< "$expected_sequence_two"
[[ "$expected_sequence_one_name" == 'sentinelflow.audit_events_sequence_seq' &&
   "$expected_sequence_two_name" == 'sentinelflow.sse_notification_cursor_seq' &&
   "$expected_sequence_one_value" =~ ^[0-9]+$ && "$expected_sequence_two_value" =~ ^[0-9]+$ &&
   "$expected_sequence_one_called" =~ ^(true|false)$ && "$expected_sequence_two_called" =~ ^(true|false)$ &&
   -z "$expected_sequence_one_extra" && -z "$expected_sequence_two_extra" &&
   "$expected_sequence_one" != "$fresh_sequence_one" && "$expected_sequence_two" != "$fresh_sequence_two" ]] ||
  fail 'signed sequence fixture is invalid or does not exercise non-fresh recovery'

read_target_sequence_state() {
  docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -F $'\t' -Atc "SELECT 'sentinelflow.audit_events_sequence_seq', last_value::text, is_called::text FROM sentinelflow.audit_events_sequence_seq UNION ALL SELECT 'sentinelflow.sse_notification_cursor_seq', last_value::text, is_called::text FROM sentinelflow.sse_notification_cursor_seq ORDER BY 1"
}

assert_retryable_sequence_state() {
  local label="$1"
  local state="$2"
  local actual_sequence_one="${state%%$'\n'*}"
  local actual_sequence_two="${state#*$'\n'}"
  [[ ( "$actual_sequence_one" == "$expected_sequence_one" || "$actual_sequence_one" == "$fresh_sequence_one" ) &&
     ( "$actual_sequence_two" == "$expected_sequence_two" || "$actual_sequence_two" == "$fresh_sequence_two" ) ]] ||
    fail "$label sequence state is neither independently fresh nor exact signed: expected=${expected_sequence_state//$'\n'/;} actual=${state//$'\n'/;}"
}

actual_sequence_state="$(read_target_sequence_state)"
assert_retryable_sequence_state 'post-setval' "$actual_sequence_state"

# An arbitrary third value is neither a fresh target nor signed backup state
# and must fail before any table row or durable receipt can be restored.
third_sequence_value=$((10#$expected_sequence_one_value + 1))
docker exec "$container" psql -U postgres -d sentinelflow_recovery_target --set=ON_ERROR_STOP=1 \
  --command "SELECT setval('sentinelflow.audit_events_sequence_seq', $third_sequence_value, true), setval('sentinelflow.sse_notification_cursor_seq', 1, false)" >/dev/null
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'restore accepted an arbitrary third sequence state'
fi
third_state_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$third_state_rows" == "0|true" ]] || fail 'third sequence state rejection mutated table data or receipt'

# A mixed crash state is valid independently per named sequence. Prove the
# preflight accepts signed audit state plus fresh SSE state and still rolls all
# table data and the receipt back at the injected boundary.
docker exec "$container" psql -U postgres -d sentinelflow_recovery_target --set=ON_ERROR_STOP=1 \
  --command "SELECT setval('sentinelflow.audit_events_sequence_seq', $expected_sequence_one_value, $expected_sequence_one_called), setval('sentinelflow.sse_notification_cursor_seq', 1, false)" >/dev/null
hybrid_sequence_state="$(read_target_sequence_state)"
[[ "$hybrid_sequence_state" == "$expected_sequence_one"$'\n'"$fresh_sequence_two" ]] ||
  fail "hybrid sequence fixture was not established: state=${hybrid_sequence_state//$'\n'/;}"
set +e
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env SENTINELFLOW_RECOVERY_FAIL_AFTER_DATA_LOAD=1 \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
hybrid_status=$?
set -e
[[ "$hybrid_status" == "96" ]] || fail "hybrid sequence retry did not reach the injected boundary: status=$hybrid_status"
wait_for_writable_postgres
hybrid_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text")"
[[ "$hybrid_rows" == "0|true" ]] || fail 'hybrid sequence retry committed table data or receipt'
assert_retryable_sequence_state 'hybrid retry rollback' "$(read_target_sequence_state)"

# A writer that begins before the restore transaction must complete before the
# ACCESS EXCLUSIVE fence, then make the freshness assertion fail. Restore may
# neither delete the competing row nor commit any backup row.
docker exec \
  --env PGAPPNAME=sentinelflow_recovery_race_writer \
  "$container" psql -U postgres -d sentinelflow_recovery_target \
    --set=ON_ERROR_STOP=1 \
    --command "BEGIN; UPDATE sentinelflow.sse_notification_replay_state SET watermark = 1 WHERE singleton; UPDATE sentinelflow.gateway_events SET status_code = status_code WHERE false; TRUNCATE sentinelflow.ai_budget_reservations, sentinelflow.ai_budget_ledger; SELECT pg_sleep(2); COMMIT;" >/dev/null &
writer_pid=$!
writer_ready=0
for _attempt in $(seq 1 40); do
  active_writer="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name = 'sentinelflow_recovery_race_writer' AND state = 'active'")"
  if [[ "$active_writer" == "1" ]]; then
    writer_ready=1
    break
  fi
  sleep 0.05
done
[[ "$writer_ready" == "1" ]] || fail 'concurrent restore writer did not start'
if docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'restore raced and overwrote a concurrent writer'
fi
wait "$writer_pid"
race_rows="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT watermark, (SELECT count(*) FROM sentinelflow.gateway_events), (to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL)::text FROM sentinelflow.sse_notification_replay_state WHERE singleton")"
[[ "$race_rows" == "1|0|true" ]] || fail 'restore transaction partially committed around concurrent writer'
docker exec "$container" psql -U postgres -d sentinelflow_recovery_target \
  --set=ON_ERROR_STOP=1 \
  --command "UPDATE sentinelflow.sse_notification_replay_state SET watermark = 0 WHERE singleton" >/dev/null

# Inject the exact DB-commit/journal-commit boundary. The database receipt,
# external marker, and staged journal must remain durable, while no installed
# journal exists yet.
set +e
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env SENTINELFLOW_RECOVERY_FAIL_AFTER_DATABASE_COMMIT=1 \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
injected_status=$?
set -e
[[ "$injected_status" == "97" ]] || fail "post-database/pre-journal failure injection did not stop at the boundary: status=$injected_status"
docker exec "$container" test ! -e /recovery/journal-destination/replay.json
docker exec "$container" test -f /recovery/journal-destination/.replay.json.sentinelflow-recovery-v1.partial
docker exec "$container" test -f /recovery/journal-destination/.replay.json.sentinelflow-restore-v1.state
receipt_count="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc 'SELECT count(*) FROM public.sentinelflow_recovery_receipt_v1')"
[[ "$receipt_count" == "1" ]] || fail 'transaction-bound restore receipt is missing'
committed_sequence_state="$(read_target_sequence_state)"
[[ "$committed_sequence_state" == "$expected_sequence_state" ]] ||
  fail "committed retry did not converge both sequences to exact signed state: expected=${expected_sequence_state//$'\n'/;} actual=${committed_sequence_state//$'\n'/;}"

# The next retry commits the exact staged journal and durable journal_installed
# state, then stops before receipt cleanup.
set +e
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env SENTINELFLOW_RECOVERY_FAIL_AFTER_JOURNAL_COMMIT=1 \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
journal_injected_status=$?
set -e
[[ "$journal_injected_status" == "98" ]] || fail "journal-installed failure injection did not stop at the boundary: status=$journal_injected_status"
docker exec "$container" test -f /recovery/journal-destination/replay.json
docker exec "$container" test ! -e /recovery/journal-destination/.replay.json.sentinelflow-recovery-v1.partial
docker exec "$container" grep -q '"phase":"journal_installed"' /recovery/journal-destination/.replay.json.sentinelflow-restore-v1.state
receipt_count="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc 'SELECT count(*) FROM public.sentinelflow_recovery_receipt_v1')"
[[ "$receipt_count" == "1" ]] || fail 'journal-installed phase lost the database receipt'

# Receipt cleanup is another durable retry boundary. The permanent marker must
# still say journal_installed until the next exact retry finalizes it.
set +e
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  --env SENTINELFLOW_RECOVERY_FAIL_AFTER_RECEIPT_REMOVAL=1 \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
receipt_injected_status=$?
set -e
[[ "$receipt_injected_status" == "99" ]] || fail "receipt-removal failure injection did not stop at the boundary: status=$receipt_injected_status"
receipt_absent="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL")"
[[ "$receipt_absent" == "t" ]] || fail 'receipt cleanup did not commit'
docker exec "$container" grep -q '"phase":"journal_installed"' /recovery/journal-destination/.replay.json.sentinelflow-restore-v1.state

# Exact retry now advances only the permanent final marker. A second completed
# retry is idempotent and never replays database data or the journal.
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
docker exec \
  --env PGUSER=postgres \
  --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_target \
    --bundle /recovery/work/bundle \
    --journal-destination /recovery/journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null

source_counts="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_source -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events),(SELECT count(*) FROM sentinelflow.incidents),(SELECT count(*) FROM sentinelflow.policy_proposals),(SELECT count(*) FROM sentinelflow.approval_decisions),(SELECT count(*) FROM sentinelflow.enforcement_actions),(SELECT count(*) FROM sentinelflow.audit_events),(SELECT count(*) FROM sentinelflow.sse_notification_ledger)")"
target_counts="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT (SELECT count(*) FROM sentinelflow.gateway_events),(SELECT count(*) FROM sentinelflow.incidents),(SELECT count(*) FROM sentinelflow.policy_proposals),(SELECT count(*) FROM sentinelflow.approval_decisions),(SELECT count(*) FROM sentinelflow.enforcement_actions),(SELECT count(*) FROM sentinelflow.audit_events),(SELECT count(*) FROM sentinelflow.sse_notification_ledger)")"
[[ "$target_counts" == "$source_counts" ]] || fail "representative database graph changed: source=$source_counts target=$target_counts"

docker exec "$container" pg_dump -U postgres -d sentinelflow_recovery_source \
  --data-only --schema=sentinelflow --strict-names \
  --exclude-table-data=sentinelflow.schema_migrations --column-inserts \
  --no-owner --no-privileges --restrict-key=SENTINELFLOWRECOVERYV1 \
  --file=/recovery/work/source-restored-data.sql
docker exec "$container" pg_dump -U postgres -d sentinelflow_recovery_target \
  --data-only --schema=sentinelflow --strict-names \
  --exclude-table-data=sentinelflow.schema_migrations --column-inserts \
  --no-owner --no-privileges --restrict-key=SENTINELFLOWRECOVERYV1 \
  --file=/recovery/work/target-restored-data.sql
docker exec "$container" /recovery/canonicalize-column-inserts \
  /recovery/work/source-restored-data.sql /recovery/work/source-restored-data.canonical
docker exec "$container" /recovery/canonicalize-column-inserts \
  /recovery/work/target-restored-data.sql /recovery/work/target-restored-data.canonical
if ! docker exec "$container" cmp /recovery/work/source-restored-data.canonical /recovery/work/target-restored-data.canonical; then
  data_difference="$(docker exec "$container" sh -c "diff -u /recovery/work/source-restored-data.canonical /recovery/work/target-restored-data.canonical | head -40" 2>/dev/null || true)"
  fail "restored logical dump changed: ${data_difference//$'\n'/ }"
fi

docker exec "$container" cmp /recovery/work/replay.json /recovery/journal-destination/replay.json
journal_mode="$(docker exec "$container" stat -c %a /recovery/journal-destination/replay.json)"
[[ "$journal_mode" == "600" ]] || fail 'restored journal mode changed'
docker exec "$container" test ! -e /recovery/journal-destination/.replay.json.sentinelflow-recovery-v1.partial
docker exec "$container" test ! -e /recovery/journal-destination/.replay.json.sentinelflow-restore-v1.state.next
docker exec "$container" grep -q '"phase":"finalized"' /recovery/journal-destination/.replay.json.sentinelflow-restore-v1.state
fence_mode="$(docker exec "$container" stat -c %a /recovery/journal-destination/.replay.json.sentinelflow-offline-v1.fence)"
[[ "$fence_mode" == "600" ]] || fail 'persistent executor recovery fence mode changed'
fence_size="$(docker exec "$container" stat -c %s /recovery/journal-destination/.replay.json.sentinelflow-offline-v1.fence)"
[[ "$fence_size" == "0" ]] || fail 'persistent executor recovery fence contains data'
receipt_absent="$(docker exec "$container" psql -U postgres -d sentinelflow_recovery_target -Atc "SELECT to_regclass('public.sentinelflow_recovery_receipt_v1') IS NULL")"
[[ "$receipt_absent" == "t" ]] || fail 'restore receipt was not finalized'

# Prove the only started-frame recovery path end to end. No mutation is
# permitted after restore: a started journal is resolved by one read-back,
# while a terminal-ahead journal is replayed without even an inspection.
docker exec "$container" /recovery/sentinelflow-recovery-fixture init \
  --journal /recovery/work/started-replay.json \
  --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
  --result-private-key /recovery/work/executor-result-private.pem \
  --result-public-key /recovery/work/executor-result-public.pem
docker exec "$container" /recovery/sentinelflow-recovery-fixture started \
  --database sentinelflow_recovery_started_source \
  --journal /recovery/work/started-replay.json \
  --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
  --result-private-key /recovery/work/executor-result-private.pem \
  --result-public-key /recovery/work/executor-result-public.pem

# Corrupting original dead-letter provenance must fail before publication and
# must not leak signed bytes or SQL details to ordinary output.
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_started_source --command \
  "UPDATE sentinelflow.dead_letter_jobs SET failure_code = 'forged_failure', failure_digest = sentinelflow.hil_sha256(convert_to('forged_failure','UTF8'))" >/dev/null
if docker exec --env PGUSER=postgres --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/backup-state.sh \
    --database sentinelflow_recovery_started_source \
    --journal /recovery/work/started-replay.json \
    --output /recovery/work/forged-dead-letter-bundle \
    --signing-key /recovery/work/backup-signing-private.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null 2>&1; then
  fail 'backup accepted forged dead-letter provenance'
fi
docker exec "$container" test ! -e /recovery/work/forged-dead-letter-bundle
docker exec "$container" psql --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_started_source --command \
  "UPDATE sentinelflow.dead_letter_jobs dead SET failure_code = job.last_error_code, failure_digest = job.last_error_digest FROM sentinelflow.outbox_jobs job WHERE job.job_id = dead.job_id" >/dev/null

docker exec --env PGUSER=postgres --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/backup-state.sh \
    --database sentinelflow_recovery_started_source \
    --journal /recovery/work/started-replay.json \
    --output /recovery/work/started-bundle \
    --signing-key /recovery/work/backup-signing-private.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
docker exec --env PGUSER=postgres --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_started_target \
    --bundle /recovery/work/started-bundle \
    --journal-destination /recovery/started-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null

# Actor, digest, and time corruption each make the dedicated claim false.
for provenance_mutation in \
  "resolution_actor = 'forged_recovery'" \
  "resolution_digest = sentinelflow.hil_sha256(convert_to('forged_recovery','UTF8'))" \
  "resolved_at = resolved_at - interval '1 microsecond'"; do
  claim_state="$(docker exec "$container" psql -qAt --set=ON_ERROR_STOP=1 -U postgres \
    -d sentinelflow_recovery_started_target --command \
    "BEGIN; UPDATE sentinelflow.dead_letter_jobs SET ${provenance_mutation}; SELECT sentinelflow.claim_dispatch_recovery_job_000025(job.job_id, gen_random_uuid(), 'forged-recovery', clock_timestamp() + interval '10 seconds') FROM sentinelflow.outbox_jobs job JOIN sentinelflow.execution_capabilities capability USING (job_id); ROLLBACK;")"
  [[ "$claim_state" == "f" ]] || fail 'forged dead-letter provenance became recovery eligible'
done

# The finish function independently revalidates provenance under row locks.
if docker exec "$container" psql -q --set=ON_ERROR_STOP=1 -U postgres \
  -d sentinelflow_recovery_started_target --command \
  "BEGIN; SELECT sentinelflow.claim_dispatch_recovery_job_000025(job.job_id, '019b0000-0000-4000-8000-00000000f001', 'finish-negative', clock_timestamp() + interval '10 seconds') FROM sentinelflow.outbox_jobs job JOIN sentinelflow.execution_capabilities capability USING (job_id); UPDATE sentinelflow.dead_letter_jobs SET resolution_actor = 'forged_recovery'; SELECT sentinelflow.finish_dispatch_recovery_job_000025(job.job_id, '019b0000-0000-4000-8000-00000000f001') FROM sentinelflow.outbox_jobs job JOIN sentinelflow.execution_capabilities capability USING (job_id); ROLLBACK;" >/dev/null 2>&1; then
  fail 'recovery finish accepted forged dead-letter provenance'
fi

sleep 1
if ! docker exec "$container" /recovery/sentinelflow-recovery-fixture recover-started \
    --database sentinelflow_recovery_started_target \
    --journal /recovery/started-journal-destination/replay.json \
    --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
    --result-private-key /recovery/work/executor-result-private.pem \
    --result-public-key /recovery/work/executor-result-public.pem \
    >"$temporary/recover-started.log" 2>&1; then
  fail "started-frame recovery fixture failed: $(tail -20 "$temporary/recover-started.log" | tr '\n' ' ') postgres=$(docker logs "$container" 2>&1 | tail -20 | tr '\n' ' ')"
fi

docker exec "$container" /recovery/sentinelflow-recovery-fixture init \
  --journal /recovery/work/terminal-ahead-replay.json \
  --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
  --result-private-key /recovery/work/executor-result-private.pem \
  --result-public-key /recovery/work/executor-result-public.pem
docker exec "$container" /recovery/sentinelflow-recovery-fixture terminal-ahead \
  --database sentinelflow_recovery_terminal_ahead_source \
  --journal /recovery/work/terminal-ahead-replay.json \
  --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
  --result-private-key /recovery/work/executor-result-private.pem \
  --result-public-key /recovery/work/executor-result-public.pem
docker exec --env PGUSER=postgres --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/backup-state.sh \
    --database sentinelflow_recovery_terminal_ahead_source \
    --journal /recovery/work/terminal-ahead-replay.json \
    --output /recovery/work/terminal-ahead-bundle \
    --signing-key /recovery/work/backup-signing-private.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
docker exec --env PGUSER=postgres --env RECOVERY_TOOL=/recovery/sentinelflow-recoverytool \
  "$container" /repo/scripts/restore-state.sh \
    --database sentinelflow_recovery_terminal_ahead_target \
    --bundle /recovery/work/terminal-ahead-bundle \
    --journal-destination /recovery/terminal-ahead-journal-destination/replay.json \
    --verification-key /recovery/work/backup-signing-public.pem \
    --dispatch-public-key /recovery/work/dispatcher-capability-public.pem \
    --result-public-key /recovery/work/executor-result-public.pem >/dev/null
sleep 1
if ! docker exec "$container" /recovery/sentinelflow-recovery-fixture recover-terminal \
    --database sentinelflow_recovery_terminal_ahead_target \
    --journal /recovery/terminal-ahead-journal-destination/replay.json \
    --dispatch-private-key /recovery/work/dispatcher-capability-private.pem \
    --result-private-key /recovery/work/executor-result-private.pem \
    --result-public-key /recovery/work/executor-result-public.pem \
    >"$temporary/recover-terminal.log" 2>&1; then
  fail "terminal-ahead recovery fixture failed: $(tail -20 "$temporary/recover-terminal.log" | tr '\n' ' ') postgres=$(docker logs "$container" 2>&1 | tail -20 | tr '\n' ' ')"
fi

printf '%s\n' 'SentinelFlow PostgreSQL 17 backup/restore and resumable journal recovery checks passed.'
