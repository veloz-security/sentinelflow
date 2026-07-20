#!/usr/bin/env bash
set -euo pipefail

umask 077

original_arguments=("$@")

database=""
journal=""
output=""
signing_key=""
dispatch_public_key="${SENTINELFLOW_DISPATCH_PUBLIC_KEY:-}"
result_public_key="${SENTINELFLOW_RESULT_PUBLIC_KEY:-}"
recovery_tool="${RECOVERY_TOOL:-sentinelflow-recoverytool}"

usage() {
  printf '%s\n' \
    'usage: backup-state.sh --database NAME --journal ABSOLUTE_PATH --output ABSOLUTE_DIRECTORY --signing-key ABSOLUTE_PATH --dispatch-public-key ABSOLUTE_PATH --result-public-key ABSOLUTE_PATH [--recovery-tool PATH]' >&2
}

while (($# > 0)); do
  case "$1" in
    --database)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      database="$2"
      shift 2
      ;;
    --journal)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      journal="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      output="$2"
      shift 2
      ;;
    --signing-key)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      signing_key="$2"
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
[[ "$journal" == /* && "$output" == /* && "$signing_key" == /* &&
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
  exec "$recovery_tool" run-session --journal "$journal" -- "$script_path" "${original_arguments[@]}"
fi
"$recovery_tool" validate-session --journal "$journal"

session_database_exec() {
  "$recovery_tool" exec-session-child --journal "$journal" -- "$@"
}

canonicalize_schema_dump() {
  local path="$1"
  local canonical="$path.canonical"
  [[ -f "$path" && ! -L "$path" && ! -e "$canonical" ]] || {
    printf '%s\n' 'ERROR: schema dump path is unsafe' >&2
    exit 1
  }
  # These two pg_dump producer headers are comments and vary across compatible
  # PostgreSQL 17 patch releases. All executable schema bytes remain exact.
  LC_ALL=C awk '
    /^-- Dumped from database version / { next }
    /^-- Dumped by pg_dump version / { next }
    { print }
  ' "$path" > "$canonical"
  chmod 0600 "$canonical"
  mv "$canonical" "$path"
}

output_parent="$(dirname "$output")"
[[ -d "$output_parent" && ! -e "$output" && ! -L "$output" ]] || { printf '%s\n' 'ERROR: output must be a fresh directory path' >&2; exit 1; }

staging="$(mktemp -d "$output_parent/.sentinelflow-recovery-v1.XXXXXX")"
candidate="$output_parent/.sentinelflow-recovery-v1.candidate.$(basename "$staging")"
[[ ! -e "$candidate" && ! -L "$candidate" ]] || { printf '%s\n' 'ERROR: sealed candidate path is not fresh' >&2; exit 1; }
session_directory="$(mktemp -d "$output_parent/.sentinelflow-recovery-session.XXXXXX")"
fence_input="$session_directory/fence.in"
fence_output="$session_directory/fence.out"
snapshot_input="$session_directory/snapshot.in"
snapshot_output="$session_directory/snapshot.out"
sequence_scratch="$session_directory/sequences.current.tsv"
mkfifo "$fence_input" "$fence_output" "$snapshot_input" "$snapshot_output"
fence_pid=""
snapshot_pid=""

stop_snapshot() {
  if [[ -n "${snapshot_pid:-}" ]]; then
    printf '%s\n' 'ROLLBACK;' '\q' >&9 2>/dev/null || true
    exec 9>&- || true
    exec 10<&- || true
    wait "$snapshot_pid" 2>/dev/null || true
    snapshot_pid=""
  fi
}

stop_fence() {
  if [[ -n "${fence_pid:-}" ]]; then
    printf '%s\n' 'ROLLBACK;' '\q' >&7 2>/dev/null || true
    exec 7>&- || true
    exec 8<&- || true
    wait "$fence_pid" 2>/dev/null || true
    fence_pid=""
  fi
}

cleanup() {
  stop_snapshot
  stop_fence
  if [[ -n "${staging:-}" && -d "$staging" && ! -L "$staging" ]]; then
    find "$staging" -depth -delete
  fi
  if [[ -n "${candidate:-}" && -d "$candidate" && ! -L "$candidate" ]]; then
    find "$candidate" -depth -delete
  fi
  if [[ -n "${session_directory:-}" && -d "$session_directory" && ! -L "$session_directory" ]]; then
    find "$session_directory" -depth -delete
  fi
}
trap cleanup EXIT INT TERM HUP

mkdir -m 0700 "$staging/postgres" "$staging/metadata"

server_version_num="$(session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" --command 'SHOW server_version_num')"
server_version_num="${server_version_num//[[:space:]]/}"
[[ "$server_version_num" =~ ^[0-9]+$ ]] || { printf '%s\n' 'ERROR: invalid PostgreSQL server version' >&2; exit 1; }
postgres_major="$((10#$server_version_num / 10000))"
[[ "$postgres_major" == "17" ]] || { printf '%s\n' 'ERROR: SentinelFlow recovery requires PostgreSQL 17' >&2; exit 1; }
printf '%s\n' "$postgres_major" > "$staging/metadata/postgres-major.txt"

"$recovery_tool" postgres-relation-contract > "$staging/metadata/relations.tsv"
backup_lock_sql="$("$recovery_tool" postgres-lock-sql --mode backup)"
relation_copy_sql="$("$recovery_tool" postgres-relation-copy-sql)"
sequence_copy_sql="$("$recovery_tool" postgres-sequence-copy-sql)"
artifact_copy_sql="$("$recovery_tool" postgres-artifact-copy-sql)"

# Keep the snapshot quiescence contract readable: terminal lifecycle rows are
# immutable history. A later inspect or revoke may advance the current action,
# so an old application is bound to its own signed result and dispatch job,
# while the current action is checked only as a monotonic descendant.
dispatch_quiescence_sql="$(cat <<'SQL'
DO $dispatch_quiescence$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM sentinelflow.outbox_jobs job
    WHERE job.kind IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
      AND (
        job.state IN ('pending', 'leased') OR
        (
          job.state = 'retry' AND NOT EXISTS (
            SELECT 1
            FROM sentinelflow.execution_capabilities capability
            LEFT JOIN sentinelflow.execution_results result USING (capability_id)
            JOIN sentinelflow.dead_letter_jobs dead ON dead.job_id = capability.job_id
            WHERE capability.job_id = job.job_id
              AND capability.consumed_at IS NULL
              AND result.result_id IS NULL
              AND job.last_error_code = 'recovery_started'
              AND job.last_error_digest = dead.resolution_digest
              AND job.available_at >= capability.expires_at
              AND dead.resolution_state = 'requeued'
              AND isfinite(dead.dead_at)
              AND isfinite(dead.resolved_at)
              AND dead.dead_at <= dead.resolved_at
              AND dead.resolved_at = job.updated_at
              AND dead.resolution_actor = 'sentinelflow_recovery'
              AND dead.kind = job.kind
              AND dead.aggregate_type = job.aggregate_type
              AND dead.aggregate_id = job.aggregate_id
              AND dead.aggregate_version = job.aggregate_version
              AND dead.attempts = job.attempts
              AND dead.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
                job.job_id, capability.capability_digest,
                dead.failure_code, dead.failure_digest
              )
          )
        )
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'dispatch work is not quiescent or recovery-only';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM sentinelflow.outbox_jobs job
    LEFT JOIN sentinelflow.execution_capabilities capability USING (job_id)
    LEFT JOIN sentinelflow.execution_results result USING (capability_id)
    LEFT JOIN sentinelflow.dispatch_operations operation ON operation.job_id = job.job_id
    LEFT JOIN sentinelflow.lifecycle_result_applications_000026 application
      ON application.result_id = result.result_id
    WHERE job.kind IN ('dispatch_add', 'dispatch_revoke', 'dispatch_inspect')
      AND job.state = 'completed'
      AND (
        capability.capability_id IS NULL OR result.result_id IS NULL OR
        operation.job_id IS NULL OR application.result_id IS NULL
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'completed dispatch lacks exact execution artifacts';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM sentinelflow.execution_capabilities capability
    LEFT JOIN sentinelflow.execution_results result USING (capability_id)
    LEFT JOIN sentinelflow.dispatch_operations operation ON operation.job_id = capability.job_id
    LEFT JOIN sentinelflow.outbox_jobs job ON job.job_id = capability.job_id
    LEFT JOIN sentinelflow.dead_letter_jobs dead ON dead.job_id = capability.job_id
    WHERE operation.job_id IS NULL OR
      (
        result.result_id IS NULL AND (
          job.job_id IS NULL OR job.state NOT IN ('dead', 'retry') OR
          capability.consumed_at IS NOT NULL OR
          (
            job.state = 'dead' AND (
              dead.job_id IS NULL OR dead.resolution_state <> 'unresolved' OR
              dead.resolved_at IS NOT NULL OR dead.resolution_actor IS NOT NULL OR
              dead.resolution_digest IS NOT NULL OR dead.kind <> job.kind OR
              dead.aggregate_type <> job.aggregate_type OR
              dead.aggregate_id <> job.aggregate_id OR
              dead.aggregate_version <> job.aggregate_version OR
              dead.attempts <> job.attempts OR
              dead.failure_code <> job.last_error_code OR
              dead.failure_digest <> job.last_error_digest OR
              NOT isfinite(dead.dead_at)
            )
          ) OR
          (
            job.state = 'retry' AND (
              job.last_error_code IS DISTINCT FROM 'recovery_started' OR
              job.last_error_digest IS DISTINCT FROM dead.resolution_digest OR
              job.available_at < capability.expires_at OR
              dead.resolution_state IS DISTINCT FROM 'requeued' OR
              NOT isfinite(dead.dead_at) OR NOT isfinite(dead.resolved_at) OR
              dead.dead_at > dead.resolved_at OR
              dead.resolved_at IS DISTINCT FROM job.updated_at OR
              dead.resolution_actor IS DISTINCT FROM 'sentinelflow_recovery' OR
              dead.kind IS DISTINCT FROM job.kind OR
              dead.aggregate_type IS DISTINCT FROM job.aggregate_type OR
              dead.aggregate_id IS DISTINCT FROM job.aggregate_id OR
              dead.aggregate_version IS DISTINCT FROM job.aggregate_version OR
              dead.attempts IS DISTINCT FROM job.attempts OR
              dead.resolution_digest IS DISTINCT FROM
                sentinelflow.dispatch_recovery_marker_000025(
                  job.job_id, capability.capability_digest,
                  dead.failure_code, dead.failure_digest
                )
            )
          )
        )
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'persisted capability lacks an exact terminal or recoverable-started binding';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM sentinelflow.execution_capabilities capability
    JOIN sentinelflow.execution_results result USING (capability_id)
    LEFT JOIN sentinelflow.outbox_jobs job ON job.job_id = capability.job_id
    LEFT JOIN sentinelflow.dispatch_operations operation ON operation.job_id = capability.job_id
    LEFT JOIN sentinelflow.lifecycle_result_applications_000026 application
      ON application.result_id = result.result_id
    LEFT JOIN sentinelflow.enforcement_actions action
      ON action.action_id = application.action_id
    LEFT JOIN sentinelflow.policy_proposals policy
      ON policy.policy_id = action.policy_id AND policy.version = action.policy_version
    LEFT JOIN sentinelflow.dead_letter_jobs dead ON dead.job_id = capability.job_id
    WHERE job.job_id IS NULL OR operation.job_id IS NULL OR
      application.result_id IS NULL OR action.action_id IS NULL OR policy.policy_id IS NULL OR
      job.state <> 'completed' OR
      job.operation IS DISTINCT FROM capability.operation OR
      job.kind IS DISTINCT FROM 'dispatch_' || capability.operation OR
      job.aggregate_type IS DISTINCT FROM 'enforcement_action' OR
      job.aggregate_id IS DISTINCT FROM capability.action_id OR
      job.aggregate_version IS DISTINCT FROM application.resulting_action_version OR
      operation.operation IS DISTINCT FROM capability.operation OR
      operation.action_id IS DISTINCT FROM capability.action_id OR
      operation.policy_id IS DISTINCT FROM capability.policy_id OR
      operation.policy_version IS DISTINCT FROM capability.policy_version OR
      operation.target_ipv4 IS DISTINCT FROM capability.target_ipv4 OR
      operation.artifact IS DISTINCT FROM capability.artifact OR
      operation.artifact_digest IS DISTINCT FROM capability.artifact_digest OR
      operation.original_add_digest IS DISTINCT FROM capability.original_add_digest OR
      operation.evidence_snapshot_digest IS DISTINCT FROM capability.evidence_snapshot_digest OR
      operation.validation_snapshot_digest IS DISTINCT FROM capability.validation_snapshot_digest OR
      operation.authorization_digest IS DISTINCT FROM capability.authorization_digest OR
      operation.actor_id IS DISTINCT FROM capability.actor_id OR
      operation.reason_digest IS DISTINCT FROM capability.reason_digest OR
      operation.owned_schema_digest IS DISTINCT FROM capability.owned_schema_digest OR
      capability.schema_version <> 'execution-capability-v1' OR
      capability.artifact_digest <> sentinelflow.hil_sha256(capability.artifact) OR
      capability.capability_digest <> sentinelflow.hil_sha256(capability.capability_jcs) OR
      capability.consumed_at IS DISTINCT FROM result.completed_at OR
      result.schema_version NOT IN ('execution-result-v1', 'execution-result-v2') OR
      result.capability_digest IS DISTINCT FROM capability.capability_digest OR
      result.operation IS DISTINCT FROM capability.operation OR
      result.action_id IS DISTINCT FROM capability.action_id OR
      result.artifact_digest IS DISTINCT FROM capability.artifact_digest OR
      result.target_ipv4 IS DISTINCT FROM capability.target_ipv4 OR
      result.owned_schema_digest IS DISTINCT FROM capability.owned_schema_digest OR
      result.result_digest <> sentinelflow.hil_sha256(result.result_jcs) OR
      result.element_handle IS NOT NULL OR
      job.updated_at < result.completed_at OR
      application.result_digest IS DISTINCT FROM result.result_digest OR
      application.action_id IS DISTINCT FROM result.action_id OR
      application.operation IS DISTINCT FROM result.operation OR
      application.classification IS DISTINCT FROM result.classification OR
      application.resulting_action_version < 1 OR
      application.resulting_action_version IS DISTINCT FROM job.aggregate_version OR
      application.processed_at < result.completed_at OR
      application.processed_at > job.updated_at OR
      NOT isfinite(application.processed_at) OR
      action.action_id IS DISTINCT FROM application.action_id OR
      action.policy_id IS DISTINCT FROM capability.policy_id OR
      action.policy_version IS DISTINCT FROM capability.policy_version OR
      action.version < application.resulting_action_version OR
      policy.state IS DISTINCT FROM action.state OR
      NOT (
        (
          application.operation = 'add' AND (
            application.classification IN ('applied', 'recovered_active') AND
              application.resulting_state = 'active' OR
            application.classification = 'failed' AND application.resulting_state = 'failed' OR
            application.classification = 'indeterminate' AND
              application.resulting_state = 'indeterminate'
          )
        ) OR
        (
          application.operation = 'revoke' AND (
            application.classification = 'revoked' AND
              application.resulting_state IN ('revoked', 'expired') OR
            application.classification = 'failed' AND application.resulting_state = 'failed' OR
            application.classification = 'indeterminate' AND
              application.resulting_state = 'indeterminate'
          )
        ) OR
        (
          application.operation = 'inspect' AND (
            application.classification = 'inspect_active' AND
              application.resulting_state IN ('active', 'failed') OR
            application.classification = 'inspect_absent' AND
              application.resulting_state IN ('expired', 'failed') OR
            application.classification IN ('inspect_mismatch', 'failed', 'indeterminate') AND
              application.resulting_state = 'indeterminate'
          )
        )
      ) OR
      (
        dead.job_id IS NOT NULL AND (
          dead.resolution_state <> 'resolved' OR
          NOT isfinite(dead.dead_at) OR NOT isfinite(dead.resolved_at) OR
          dead.dead_at > dead.resolved_at OR dead.resolved_at > job.updated_at OR
          dead.resolution_actor <> 'sentinelflow_recovery' OR
          dead.kind <> job.kind OR dead.aggregate_type <> job.aggregate_type OR
          dead.aggregate_id <> job.aggregate_id OR
          dead.aggregate_version NOT IN (
            job.aggregate_version, job.aggregate_version - 1
          ) OR
          dead.attempts <> job.attempts OR
          dead.resolution_digest <>
            sentinelflow.dispatch_recovery_marker_000025(
              job.job_id, capability.capability_digest,
              dead.failure_code, dead.failure_digest
            )
        )
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'dispatch execution bindings are inconsistent';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM sentinelflow.enforcement_expiry_bounds_000034 action_bounds
    JOIN sentinelflow.enforcement_actions action
      ON action.action_id = action_bounds.action_id
    JOIN sentinelflow.execution_results source_result
      ON source_result.result_id = action_bounds.source_result_id
    LEFT JOIN sentinelflow.execution_result_readback_bounds_000034 source_bounds
      ON source_bounds.result_id = source_result.result_id
    WHERE source_result.schema_version <> 'execution-result-v2' OR
      source_result.operation <> 'add' OR
      source_result.action_id <> action_bounds.action_id OR
      source_result.classification NOT IN ('applied', 'recovered_active') OR
      source_bounds.result_id IS NULL OR
      source_bounds.remaining_ttl_seconds IS NULL OR
      source_bounds.remaining_ttl_seconds IS DISTINCT FROM source_result.remaining_ttl_seconds OR
      source_bounds.expires_not_before IS NULL OR source_bounds.expires_not_after IS NULL OR
      action_bounds.expires_not_before IS DISTINCT FROM source_bounds.expires_not_before OR
      action_bounds.expires_not_after IS DISTINCT FROM source_bounds.expires_not_after OR
      action.applied_at IS DISTINCT FROM source_bounds.readback_started_at OR
      action.expected_expires_at IS DISTINCT FROM source_bounds.expires_not_before
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'expiry bounds are detached from their signed active result';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM sentinelflow.execution_capabilities capability
    CROSS JOIN LATERAL (
      SELECT convert_from(capability.capability_jcs, 'UTF8')::jsonb AS value
    ) document
    WHERE jsonb_typeof(document.value) <> 'object' OR
      (SELECT count(*) FROM jsonb_object_keys(document.value)) <> 20 OR
      document.value->>'schema_version' <> capability.schema_version OR
      document.value->>'capability_id' <> capability.capability_id::text OR
      document.value->>'job_id' <> capability.job_id::text OR
      document.value->>'operation' <> capability.operation OR
      document.value->>'action_id' <> capability.action_id::text OR
      document.value->>'policy_id' <> capability.policy_id::text OR
      (document.value->>'policy_version')::integer <> capability.policy_version OR
      document.value->>'target_ipv4' <> host(capability.target_ipv4) OR
      document.value->>'artifact_digest' <> capability.artifact_digest::text OR
      document.value->'original_add_digest' <>
        coalesce(to_jsonb(capability.original_add_digest::text), 'null'::jsonb) OR
      document.value->>'evidence_snapshot_digest' <> capability.evidence_snapshot_digest::text OR
      document.value->>'validation_snapshot_digest' <> capability.validation_snapshot_digest::text OR
      document.value->>'authorization_digest' <> capability.authorization_digest::text OR
      document.value->>'actor_id' <> capability.actor_id::text OR
      document.value->>'reason_digest' <> capability.reason_digest::text OR
      document.value->>'owned_schema_digest' <> capability.owned_schema_digest::text OR
      (document.value->>'issued_at')::timestamptz <> capability.issued_at OR
      (document.value->>'not_before')::timestamptz <> capability.not_before OR
      (document.value->>'expires_at')::timestamptz <> capability.expires_at
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'capability JCS binding is inconsistent';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM sentinelflow.execution_results result
    CROSS JOIN LATERAL (
      SELECT convert_from(result.result_jcs, 'UTF8')::jsonb AS value
    ) document
    LEFT JOIN sentinelflow.execution_result_readback_bounds_000034 result_readback_bounds
      ON result_readback_bounds.result_id = result.result_id
    WHERE jsonb_typeof(document.value) <> 'object' OR
      (SELECT count(*) FROM jsonb_object_keys(document.value)) <>
        CASE result.schema_version
          WHEN 'execution-result-v1' THEN 18
          WHEN 'execution-result-v2' THEN 20
          ELSE -1
        END OR
      document.value->>'schema_version' <> result.schema_version OR
      document.value->>'result_id' <> result.result_id::text OR
      document.value->>'capability_id' <> result.capability_id::text OR
      document.value->>'capability_digest' <> result.capability_digest::text OR
      document.value->>'operation' <> result.operation OR
      document.value->>'action_id' <> result.action_id::text OR
      document.value->>'artifact_digest' <> result.artifact_digest::text OR
      document.value->>'target_ipv4' <> host(result.target_ipv4) OR
      document.value->>'classification' <> result.classification OR
      document.value->'nft_exit_class' <>
        coalesce(to_jsonb(result.nft_exit_class), 'null'::jsonb) OR
      document.value->>'readback_state' <> result.readback_state OR
      document.value->'element_handle' <> 'null'::jsonb OR
      document.value->'remaining_ttl_seconds' <>
        coalesce(to_jsonb(result.remaining_ttl_seconds), 'null'::jsonb) OR
      document.value->>'owned_schema_digest' <> result.owned_schema_digest::text OR
      (document.value->>'started_at')::timestamptz <> result.started_at OR
      CASE result.schema_version
        WHEN 'execution-result-v1' THEN
          document.value ? 'readback_started_at' OR document.value ? 'readback_completed_at' OR
          result_readback_bounds.result_id IS NOT NULL
        WHEN 'execution-result-v2' THEN
          result_readback_bounds.result_id IS NULL OR
          result_readback_bounds.remaining_ttl_seconds IS DISTINCT FROM result.remaining_ttl_seconds OR
          (document.value->>'readback_started_at')::timestamptz <>
            result_readback_bounds.readback_started_at OR
          (document.value->>'readback_completed_at')::timestamptz <>
            result_readback_bounds.readback_completed_at
        ELSE true
      END OR
      (document.value->>'completed_at')::timestamptz <> result.completed_at OR
      (document.value->>'journal_sequence')::bigint <> result.journal_sequence OR
      document.value->>'error_code' <> result.error_code
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = 'result JCS binding is inconsistent';
  END IF;
END
$dispatch_quiescence$;
SQL
)"

# A separate READ COMMITTED read/write transaction owns every table, schema,
# and sequence fence before the clean repeatable-read exporter starts. Its
# uncommitted no-op sequence/catalog writes are invisible to the exporter.
session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" \
  <"$fence_input" >"$fence_output" &
fence_pid="$!"
exec 7>"$fence_input"
exec 8<"$fence_output"
printf '%s\n' \
  'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE;' \
  "SET LOCAL lock_timeout = '5s';" \
  "SET LOCAL statement_timeout = '15s';" \
  "$backup_lock_sql" \
  'SELECT pg_backend_pid();' >&7
if ! IFS= read -r fence_backend_pid <&8; then
  printf '%s\n' 'ERROR: PostgreSQL recovery fence exited before lock acquisition' >&2
  exit 1
fi
[[ "$fence_backend_pid" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' 'ERROR: PostgreSQL recovery fence did not become ready' >&2; exit 1; }

session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" \
  <"$snapshot_input" >"$snapshot_output" &
snapshot_pid="$!"
exec 9>"$snapshot_input"
exec 10<"$snapshot_output"
printf '%s\n' \
  'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;' \
  "SET LOCAL lock_timeout = '5s';" \
  "SET LOCAL statement_timeout = '15s';" \
  "$relation_copy_sql" \
  "SELECT 'SENTINELFLOW_RELATIONS_END_V1';" \
  "DO \$capability_nonce_binding\$ BEGIN IF EXISTS (SELECT 1 FROM sentinelflow.execution_capabilities capability CROSS JOIN LATERAL (SELECT convert_from(capability.capability_jcs, 'UTF8')::jsonb AS value) document WHERE CASE WHEN document.value->>'nonce' ~ '^[A-Za-z0-9_-]{22}$' THEN capability.nonce_digest <> sentinelflow.hil_sha256(decode(translate(document.value->>'nonce', '-_', '+/') || '==', 'base64')) ELSE true END) THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'capability nonce binding is inconsistent'; END IF; END \$capability_nonce_binding\$;" \
  "SELECT (EXISTS (SELECT 1 FROM pg_catalog.pg_locks held WHERE held.pid = $fence_backend_pid AND held.locktype = 'relation' AND held.relation = 'pg_catalog.pg_class'::regclass AND held.mode = 'ShareRowExclusiveLock' AND held.granted) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'sentinelflow' AND relation.relkind IN ('r','p') AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_locks held WHERE held.pid = $fence_backend_pid AND held.locktype = 'relation' AND held.relation = relation.oid AND held.mode = 'ShareLock' AND held.granted)) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'sentinelflow' AND relation.relkind = 'S' AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_locks held WHERE held.pid = $fence_backend_pid AND held.locktype = 'relation' AND held.relation = relation.oid AND held.mode = 'ShareRowExclusiveLock' AND held.granted)))::text;" \
  "$dispatch_quiescence_sql" \
  'SELECT pg_export_snapshot();' \
  "$sequence_copy_sql" \
  "SELECT 'SENTINELFLOW_SEQUENCES_END_V1';" >&9

: > "$staging/metadata/relations.actual.tsv"
relation_rows=0
while IFS= read -r relation_row <&10; do
  [[ "$relation_row" == 'SENTINELFLOW_RELATIONS_END_V1' ]] && break
  relation_rows=$((relation_rows + 1))
  [[ "$relation_rows" -le 256 ]] || { printf '%s\n' 'ERROR: PostgreSQL relation contract is oversized' >&2; exit 1; }
  printf '%s\n' "$relation_row" >> "$staging/metadata/relations.actual.tsv"
done
"$cmp_bin" -s "$staging/metadata/relations.tsv" "$staging/metadata/relations.actual.tsv" || { printf '%s\n' 'ERROR: PostgreSQL relation contract drifted' >&2; exit 1; }
rm "$staging/metadata/relations.actual.tsv"
IFS= read -r fence_locks_valid <&10
[[ "$fence_locks_valid" == "true" ]] || { printf '%s\n' 'ERROR: PostgreSQL recovery lock contract is incomplete' >&2; exit 1; }
IFS= read -r snapshot_id <&10
[[ "$snapshot_id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9]+$ ]] || { printf '%s\n' 'ERROR: PostgreSQL snapshot identifier is invalid' >&2; exit 1; }
: > "$staging/metadata/sequences.tsv"
sequence_rows=0
while IFS= read -r sequence_row <&10; do
  [[ "$sequence_row" == 'SENTINELFLOW_SEQUENCES_END_V1' ]] && break
  sequence_rows=$((sequence_rows + 1))
  [[ "$sequence_rows" -le 16 ]] || { printf '%s\n' 'ERROR: PostgreSQL sequence contract is oversized' >&2; exit 1; }
  printf '%s\n' "$sequence_row" >> "$staging/metadata/sequences.tsv"
done
[[ "$sequence_rows" == "2" ]] || { printf '%s\n' 'ERROR: PostgreSQL sequence snapshot is invalid' >&2; exit 1; }
validation_root="$staging"

validate_held_sequence_state() {
  local current="$sequence_scratch"
  local row
  local rows=0
  : > "$current"
  printf '%s\n' "$sequence_copy_sql" "SELECT 'SENTINELFLOW_SEQUENCES_END_V1';" >&9
  while IFS= read -r row <&10; do
    [[ "$row" == 'SENTINELFLOW_SEQUENCES_END_V1' ]] && break
    rows=$((rows + 1))
    [[ "$rows" -le 16 ]] || return 1
    printf '%s\n' "$row" >> "$current"
  done
  if [[ "$rows" == "2" ]] && "$cmp_bin" -s "$validation_root/metadata/sequences.tsv" "$current"; then
    return 0
  fi
  return 1
}

session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" \
  --set=snapshot_id="$snapshot_id" <<SQL | \
  "$recovery_tool" validate-execution-artifacts \
    --journal "$journal" \
    --dispatch-public-key "$dispatch_public_key" \
    --result-public-key "$result_public_key"
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET TRANSACTION SNAPSHOT :'snapshot_id';
$artifact_copy_sql
ROLLBACK;
SQL

session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --dbname "$database" \
  --set=snapshot_id="$snapshot_id" > "$staging/metadata/migrations.tsv" <<'SQL'
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET TRANSACTION SNAPSHOT :'snapshot_id';
COPY (SELECT version, name FROM sentinelflow.schema_migrations ORDER BY version) TO STDOUT;
ROLLBACK;
SQL
[[ -s "$staging/metadata/migrations.tsv" ]] || { printf '%s\n' 'ERROR: migration ledger is empty' >&2; exit 1; }

session_database_exec "$pg_dump_bin" --dbname "$database" --schema-only --schema=sentinelflow --strict-names \
  --snapshot="$snapshot_id" \
  --no-owner --no-privileges --no-comments --no-security-labels --no-publications \
  --no-subscriptions --no-tablespaces --no-table-access-method \
  --restrict-key=SENTINELFLOWRECOVERYV1 \
  --file "$staging/metadata/schema.sql"
canonicalize_schema_dump "$staging/metadata/schema.sql"

session_database_exec "$pg_dump_bin" --dbname "$database" --format=custom --data-only --schema=sentinelflow --strict-names \
  --snapshot="$snapshot_id" \
  --no-owner --no-privileges --exclude-table-data=sentinelflow.schema_migrations \
  --file "$staging/postgres/data.dump"

session_database_exec "$pg_restore_bin" --list "$staging/postgres/data.dump" >/dev/null

validate_held_sequence_state || { printf '%s\n' 'ERROR: SentinelFlow sequence state changed during database dump' >&2; exit 1; }

"$recovery_tool" seal \
  --staging "$staging" \
  --output "$candidate" \
  --journal "$journal" \
  --signing-key "$signing_key"
staging=""
validation_root="$candidate"

validate_held_sequence_state || { printf '%s\n' 'ERROR: SentinelFlow sequence state changed before bundle seal completed' >&2; exit 1; }

# Re-run strict signed-artifact verification under the still-held snapshot and
# database/sequence fences. No database or artifact check follows publication.
session_database_exec "$psql_bin" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --dbname "$database" \
  --set=snapshot_id="$snapshot_id" <<SQL | \
  "$recovery_tool" validate-recovery-state \
    --journal "$journal" \
    --replay-journal "$candidate/executor/replay.json" \
    --dispatch-public-key "$dispatch_public_key" \
    --result-public-key "$result_public_key"
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET TRANSACTION SNAPSHOT :'snapshot_id';
$artifact_copy_sql
ROLLBACK;
SQL

"$recovery_tool" publish --candidate "$candidate" --output "$output" --journal "$journal"
candidate=""

stop_snapshot
stop_fence
printf '%s\n' 'SentinelFlow recovery bundle created and authenticated.'
