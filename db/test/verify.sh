#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
db_root="$repo_root/db"
container="sentinelflow-db-verify-$$"
postgres_password="sentinelflow-test-only"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

docker run -d --rm \
  --name "$container" \
  --env POSTGRES_PASSWORD="$postgres_password" \
  --publish 127.0.0.1::5432 \
  postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193 >/dev/null

ready=0
for _attempt in $(seq 1 60); do
  if docker exec "$container" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" != "1" ]]; then
  printf '%s\n' 'ERROR: disposable PostgreSQL did not become ready' >&2
  exit 1
fi

apply_migrations() {
  local database="$1"
  local expected_applied="${2:-}"
  local applied=0
  local expected_version=1
  local migration
  local migration_filename
  local migration_name
  local migration_version
  local migration_version_decimal
  local ledger_exists
  local ledger_name
  local ledger_count
  local ledger_max

  # The checked-in up files are ordered one-shot transitions. Production uses
  # deployments/postgres/init.sh to validate the exact ledger and skip an
  # already-applied prefix; replaying every raw SQL file is not a supported
  # restart model and corrupts versioned wrapper stacks before later files can
  # attest them. Keep this test harness ledger-aware as well, while still
  # failing closed on filename, gap, identity, and suffix-application errors.
  for migration in "$db_root"/migrations/*.up.sql; do
    migration_filename="$(basename "$migration")"
    if [[ ! "$migration_filename" =~ ^([0-9]{6})_([a-z0-9_]+)\.up\.sql$ ]]; then
      printf 'ERROR: invalid migration filename: %s\n' "$migration_filename" >&2
      exit 1
    fi
    migration_version="${BASH_REMATCH[1]}"
    migration_name="${BASH_REMATCH[2]}"
    migration_version_decimal=$((10#$migration_version))
    if (( migration_version_decimal != expected_version )); then
      printf 'ERROR: migration chain expected version %06d but found %s\n' \
        "$expected_version" "$migration_version" >&2
      exit 1
    fi
    expected_version=$((expected_version + 1))

    ledger_exists="$(docker exec "$container" \
      psql --no-psqlrc --tuples-only --no-align --username postgres \
        --dbname "$database" \
        --command "SELECT (to_regclass('sentinelflow.schema_migrations') IS NOT NULL)::text;")"
    if [[ "$ledger_exists" == "f" || "$ledger_exists" == "false" ]]; then
      if (( migration_version_decimal != 1 )); then
        printf 'ERROR: migration ledger is absent before version %s\n' \
          "$migration_version" >&2
        exit 1
      fi
      docker exec -i "$container" \
        psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
          --dbname "$database" < "$migration" >/dev/null
      applied=$((applied + 1))
      continue
    fi

    ledger_name="$(docker exec "$container" \
      psql --no-psqlrc --tuples-only --no-align --username postgres \
        --dbname "$database" \
        --command "SELECT COALESCE((SELECT name FROM sentinelflow.schema_migrations WHERE version = $migration_version_decimal), '');")"
    if [[ -n "$ledger_name" ]]; then
      if [[ "$ledger_name" != "$migration_name" ]]; then
        printf 'ERROR: migration %s identity conflict: ledger name=%s expected=%s\n' \
          "$migration_version" "$ledger_name" "$migration_name" >&2
        exit 1
      fi
      continue
    fi

    ledger_max="$(docker exec "$container" \
      psql --no-psqlrc --tuples-only --no-align --username postgres \
        --dbname "$database" \
        --command 'SELECT COALESCE(max(version), 0) FROM sentinelflow.schema_migrations;')"
    if (( ledger_max != migration_version_decimal - 1 )); then
      printf 'ERROR: migration ledger is not an exact prefix before %s: max=%s\n' \
        "$migration_version" "$ledger_max" >&2
      exit 1
    fi
    docker exec -i "$container" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
      < "$migration" >/dev/null
    ledger_name="$(docker exec "$container" \
      psql --no-psqlrc --tuples-only --no-align --username postgres \
        --dbname "$database" \
        --command "SELECT COALESCE((SELECT name FROM sentinelflow.schema_migrations WHERE version = $migration_version_decimal), '');")"
    if [[ "$ledger_name" != "$migration_name" ]]; then
      printf 'ERROR: migration %s did not record exact ledger identity %s\n' \
        "$migration_version" "$migration_name" >&2
      exit 1
    fi
    applied=$((applied + 1))
  done

  ledger_count="$(docker exec "$container" \
    psql --no-psqlrc --tuples-only --no-align --username postgres \
      --dbname "$database" \
      --command 'SELECT count(*) FROM sentinelflow.schema_migrations;')"
  ledger_max="$(docker exec "$container" \
    psql --no-psqlrc --tuples-only --no-align --username postgres \
      --dbname "$database" \
      --command 'SELECT max(version) FROM sentinelflow.schema_migrations;')"
  if (( ledger_count != expected_version - 1 || ledger_max != expected_version - 1 )); then
    printf 'ERROR: final migration ledger is not the complete checked-in chain: count=%s max=%s expected=%s\n' \
      "$ledger_count" "$ledger_max" "$((expected_version - 1))" >&2
    exit 1
  fi
  if [[ -n "$expected_applied" ]] && (( applied != expected_applied )); then
    printf 'ERROR: migration application count=%s expected=%s for %s\n' \
      "$applied" "$expected_applied" "$database" >&2
    exit 1
  fi
}

migration_wrapper_snapshot() {
  local database="$1"
  docker exec "$container" \
    psql --no-psqlrc --tuples-only --no-align --username postgres \
      --dbname "$database" --command "
WITH wrapper_state AS (
    SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' ||
           E'\\nowner=' || owner.rolname ||
           E'\\nsecurity_definer=' || p.prosecdef::text ||
           E'\\nconfig=' || COALESCE(p.proconfig::text, '') ||
           E'\\nacl=' || COALESCE(p.proacl::text, '') ||
           E'\\ndefinition=' || pg_get_functiondef(p.oid) AS state
    FROM pg_proc p
    JOIN pg_namespace namespace ON namespace.oid = p.pronamespace
    JOIN pg_roles owner ON owner.oid = p.proowner
    WHERE namespace.nspname = 'sentinelflow'
      AND (
          p.proname LIKE 'claim_dispatch_job%' OR
          p.proname LIKE 'enforce_action_transition%' OR
          p.proname LIKE 'finish_dispatch_job%' OR
          p.proname LIKE 'record_execution_capability%' OR
          p.proname LIKE 'record_execution_result%'
      )
)
SELECT md5(string_agg(state, E'\\n--wrapper--\\n' ORDER BY state))
FROM wrapper_state;"
}

verify_dispatch_lifecycle_migration_lifecycle() {
  local database="$1"
  local before
  local after
  local migration

  before="$(migration_wrapper_snapshot "$database")"
  if [[ ! "$before" =~ ^[0-9a-f]{32}$ ]]; then
    printf 'ERROR: could not fingerprint canonical dispatch wrapper stack\n' >&2
    exit 1
  fi

  for migration in \
    000034_execution_result_v2_expiry_bounds.down.sql \
    000033_analysis_stale_version_resolution.down.sql \
    000032_validation_attempt_api_projection.down.sql \
    000031_artifact_content_digest_identity.down.sql \
    000030_demo_history_runtime_activation.down.sql \
    000029_retention_action_tombstone.down.sql \
    000028_lifecycle_observability.down.sql \
    000027_revocation_hil.down.sql \
    000026_enforcement_lifecycle.down.sql \
    000025_dispatch_started_recovery.down.sql; do
    docker exec -i "$container" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
        --dbname "$database" < "$db_root/migrations/$migration" >/dev/null
  done

  docker exec "$container" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
      --dbname "$database" --command "
DO \$rollback_state\$
BEGIN
    IF (SELECT count(*) FROM sentinelflow.schema_migrations) <> 24 OR
       (SELECT max(version) FROM sentinelflow.schema_migrations) <> 24 THEN
        RAISE EXCEPTION 'latest-first rollback did not restore the exact version-24 prefix';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'sentinelflow'
          AND p.proname ~ '_pre_00002[567]\$'
    ) THEN
        RAISE EXCEPTION 'latest-first rollback retained a version-25/26/27 wrapper alias';
    END IF;
    IF to_regprocedure(
        'sentinelflow.claim_dispatch_job(uuid,uuid,sentinelflow.ascii_id,timestamptz)'
    ) IS NULL OR to_regprocedure(
        'sentinelflow.finish_dispatch_job(uuid,uuid,text,sentinelflow.ascii_id,sentinelflow.sha256_digest,timestamptz)'
    ) IS NULL THEN
        RAISE EXCEPTION 'latest-first rollback did not restore the version-24 dispatcher API';
    END IF;
END
\$rollback_state\$;" >/dev/null

  # Applying the exact pending suffix, rather than replaying the already-
  # applied prefix, is the supported forward recovery from a clean rollback.
  apply_migrations "$database" 10
  after="$(migration_wrapper_snapshot "$database")"
  if [[ "$after" != "$before" ]]; then
    printf 'ERROR: dispatch wrapper definitions, ownership, configuration, or ACLs changed after rollback/reapply\n' >&2
    exit 1
  fi
  docker exec -i "$container" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
      --dbname "$database" < "$db_root/test/verify_migration_chain.sql" >/dev/null
  docker exec -i "$container" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
      --dbname "$database" \
      < "$db_root/test/verify_validation_attempt_api_projection.sql" >/dev/null
}

apply_migrations_before_privileged_rotation() {
  local database="$1"
  local migration
  local migration_version
  for migration in "$db_root"/migrations/*.up.sql; do
    migration_version="$(basename "$migration")"
    migration_version="${migration_version%%_*}"
    if (( 10#$migration_version >= 12 )); then
      continue
    fi
    docker exec -i "$container" \
      psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
      < "$migration" >/dev/null
  done
}

apply_migrations_before_exact_artifacts() {
  local database="$1"
  local migration
  local migration_version
  for migration in "$db_root"/migrations/*.up.sql; do
    migration_version="$(basename "$migration")"
    migration_version="${migration_version%%_*}"
    if (( 10#$migration_version >= 14 )); then
      continue
    fi
    docker exec -i "$container" \
      psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
      < "$migration" >/dev/null
  done
}

apply_migrations_through() {
  local database="$1"
  local maximum_version="$2"
  local migration
  local migration_version
  for migration in "$db_root"/migrations/*.up.sql; do
    migration_version="$(basename "$migration")"
    migration_version="${migration_version%%_*}"
    if (( 10#$migration_version > maximum_version )); then
      continue
    fi
    docker exec -i "$container" \
      psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
        --dbname "$database" < "$migration" >/dev/null
  done
}

verify_database() {
  local database="$1"
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_artifact_content_digest_identity.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_validation_attempt_api_projection.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_ingest.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_outbox.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_ai_budget.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_hil.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_privileged_session_rotation.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_dispatch_recovery.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_sse_notification_ledger.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_exact_hil_artifacts.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_retention.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_control_observability.sql" >/dev/null
}

verify_artifact_content_digest_down_failstop() {
  local database="$1"
  local down_output
  local down_status

  # Commit the synthetic shared-content fixtures only in this disposable
  # database, then prove downgrade refuses to discard their valid multiplicity.
  sed '$s/^ROLLBACK;$/COMMIT;/' \
    "$db_root/test/verify_artifact_content_digest_identity.sql" | \
    docker exec -i "$container" \
      psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
      >/dev/null
  set +e
  down_output="$(docker exec -i "$container" \
    psql --no-psqlrc --set ON_ERROR_STOP=1 --set VERBOSITY=verbose \
      --username postgres --dbname "$database" \
    < "$db_root/migrations/000031_artifact_content_digest_identity.down.sql" \
    2>&1)"
  down_status=$?
  set -e
  if (( down_status == 0 )); then
    printf '%s\n' 'ERROR: 000031 down migration discarded shared content identity' >&2
    exit 1
  fi
  if [[ "$down_output" != *'ERROR:  55000: shared artifact content digests prevent downgrade'* ]]; then
    printf '%s\n' 'ERROR: 000031 down migration did not fail with the expected 55000 guard' >&2
    exit 1
  fi
  docker exec "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    --command "DO \$\$ BEGIN
      IF NOT EXISTS (
          SELECT 1 FROM sentinelflow.schema_migrations
          WHERE version = 31 AND name = 'artifact_content_digest_identity'
      ) OR to_regclass(
          'sentinelflow.command_candidates_generated_artifact_digest_idx'
      ) IS NULL OR to_regclass(
          'sentinelflow.command_candidates_canonical_artifact_digest_idx'
      ) IS NULL OR to_regclass(
          'sentinelflow.enforcement_actions_canonical_artifact_digest_idx'
      ) IS NULL OR to_regclass(
          'sentinelflow.lifecycle_inspection_artifact_digest_000031_idx'
      ) IS NULL THEN
          RAISE EXCEPTION 'failed 000031 downgrade changed canonical state';
      END IF;
    END \$\$;" >/dev/null
}

verify_exact_hil_migration_lifecycle() {
  local database="$1"
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000014_exact_hil_artifacts.down.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000014_exact_hil_artifacts.up.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000014_exact_hil_artifacts.up.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_exact_hil_artifacts.sql" >/dev/null
}

verify_exact_hil_down_failstop() {
  local database="$1"
  docker exec "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    --command "SET ROLE sentinelflow_migration;
      INSERT INTO sentinelflow.incidents (
        incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
        deterministic_score, version
      ) VALUES (
        '019b0000-0000-7000-8000-00000000ef01', 'path_scan', 'open',
        '8.8.8.8', 'gateway', clock_timestamp(), clock_timestamp(), 0.9, 1
      );
      INSERT INTO sentinelflow.evidence_snapshots (
        evidence_snapshot_id, schema_version, incident_id, incident_version,
        source_ip, service_label, window_start, window_end, source_health_status,
        signal_count, expanded_event_count, snapshot_digest, expires_at
      ) VALUES (
        '019b0000-0000-7000-8000-00000000ef02', 'evidence-snapshot-v1',
        '019b0000-0000-7000-8000-00000000ef01', 1, '8.8.8.8', 'gateway',
        clock_timestamp(), clock_timestamp(), 'complete', 1, 1,
        sentinelflow.validation_sha256(convert_to('{}', 'UTF8')),
        clock_timestamp() + interval '1 day'
      );
      INSERT INTO sentinelflow.evidence_snapshot_artifacts (
        evidence_snapshot_id, schema_version, source_health_digest,
        canonical_bytes, canonical_digest, created_at
      ) VALUES (
        '019b0000-0000-7000-8000-00000000ef02', 'evidence-snapshot-v1',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        convert_to('{}', 'UTF8'),
        sentinelflow.validation_sha256(convert_to('{}', 'UTF8')),
        clock_timestamp()
      );" >/dev/null
  if docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000014_exact_hil_artifacts.down.sql" >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: 000014 down migration discarded canonical authority' >&2
    exit 1
  fi
}

verify_sse_notification_migration_lifecycle() {
  local database="$1"
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000013_sse_notification_ledger.down.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000013_sse_notification_ledger.up.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000013_sse_notification_ledger.up.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_sse_notification_ledger.sql" >/dev/null
}

verify_sse_notification_down_failstop() {
  local database="$1"
  docker exec "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    --command "SET ROLE sentinelflow_migration; SELECT * FROM sentinelflow.append_sse_notification('source.degraded', 'source_health', '019b0000-0000-7000-8000-00000000e100', 1, 'degraded', 'source_degraded', NULL, NULL);" \
    >/dev/null
  if docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000013_sse_notification_ledger.down.sql" >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: 000013 down migration discarded live SSE evidence' >&2
    exit 1
  fi
}

verify_privileged_rotation_migration_lifecycle() {
  local database="$1"
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000012_privileged_session_rotation.down.sql" >/dev/null
  docker exec "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    --command "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'sentinelflow' AND p.proname IN ('commit_privileged_session_rotation', 'commit_hil_policy_decision_with_session_rotation')) OR EXISTS (SELECT 1 FROM sentinelflow.schema_migrations WHERE version = 12) OR has_function_privilege('sentinelflow_api', (SELECT min(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'sentinelflow' AND p.proname = 'commit_hil_policy_decision'), 'EXECUTE') THEN RAISE EXCEPTION '000012 down migration incomplete or restored unsafe coordinator authority'; END IF; END \$\$;" \
    >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000012_privileged_session_rotation.up.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/migrations/000012_privileged_session_rotation.up.sql" >/dev/null
  docker exec -i "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
    < "$db_root/test/verify_privileged_session_rotation.sql" >/dev/null
}

expect_denied() {
  local database="$1"
  local statement="$2"
  if docker exec "$container" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "$database" \
      --command "$statement" >/dev/null 2>&1; then
    printf 'ERROR: expected denial for: %s\n' "$statement" >&2
    exit 1
  fi
}

create_database() {
  local database="$1"
  local created=0
  for _attempt in $(seq 1 60); do
    if docker exec "$container" createdb --username postgres "$database" >/dev/null 2>&1; then
      created=1
      break
    fi
    sleep 0.25
  done
  if [[ "$created" != "1" ]]; then
    printf 'ERROR: could not create disposable database %s\n' "$database" >&2
    exit 1
  fi
}

create_database sentinelflow_verify_one
create_database sentinelflow_verify_two
create_database sentinelflow_verify_pre_rotation
create_database sentinelflow_verify_pre_exact
create_database sentinelflow_verify_sse_lifecycle
create_database sentinelflow_verify_exact_lifecycle
create_database sentinelflow_verify_sse_live
create_database sentinelflow_verify_exact_live
create_database sentinelflow_verify_migration_chain
create_database sentinelflow_verify_expiry_bounds
create_database sentinelflow_verify_content_down
create_database sentinelflow_verify_stale_repair

# Exercise the latest-first rollback while the cluster-global lifecycle role is
# owned only by this database. PostgreSQL correctly refuses to drop that role
# after later fixture databases have granted it CONNECT/USAGE privileges.
apply_migrations sentinelflow_verify_migration_chain
verify_dispatch_lifecycle_migration_lifecycle sentinelflow_verify_migration_chain
apply_migrations sentinelflow_verify_expiry_bounds
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_expiry_bounds \
    < "$db_root/test/verify_execution_result_v2_expiry_bounds.sql" >/dev/null
apply_migrations sentinelflow_verify_one
apply_migrations sentinelflow_verify_one 0
apply_migrations sentinelflow_verify_two
apply_migrations sentinelflow_verify_content_down
apply_migrations_through sentinelflow_verify_stale_repair 32
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_stale_repair \
    < "$db_root/test/prepare_analysis_stale_version_repair.sql" >/dev/null
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_stale_repair \
    < "$db_root/migrations/000033_analysis_stale_version_resolution.up.sql" >/dev/null
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_stale_repair \
    < "$db_root/test/verify_analysis_stale_version_repair.sql" >/dev/null
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_stale_repair \
    < "$db_root/test/verify_analysis_stale_version_runtime.sql" >/dev/null
apply_migrations_before_privileged_rotation sentinelflow_verify_pre_rotation
apply_migrations_before_exact_artifacts sentinelflow_verify_pre_exact
apply_migrations_before_exact_artifacts sentinelflow_verify_sse_lifecycle
apply_migrations_before_exact_artifacts sentinelflow_verify_exact_lifecycle
apply_migrations_before_exact_artifacts sentinelflow_verify_sse_live
apply_migrations_before_exact_artifacts sentinelflow_verify_exact_live
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_exact_lifecycle \
    < "$db_root/migrations/000014_exact_hil_artifacts.up.sql" >/dev/null
docker exec -i "$container" \
  psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres \
    --dbname sentinelflow_verify_exact_live \
    < "$db_root/migrations/000014_exact_hil_artifacts.up.sql" >/dev/null

docker exec -i "$container" \
  psql --set ON_ERROR_STOP=1 --username postgres --dbname sentinelflow_verify_pre_rotation \
  < "$db_root/test/verify_hil_coordinator.sql" >/dev/null
docker exec -i "$container" \
  psql --set ON_ERROR_STOP=1 --username postgres --dbname sentinelflow_verify_pre_exact \
  < "$db_root/test/verify_analysis_worker.sql" >/dev/null

verify_database sentinelflow_verify_one
verify_database sentinelflow_verify_two
verify_artifact_content_digest_down_failstop sentinelflow_verify_content_down
verify_sse_notification_migration_lifecycle sentinelflow_verify_sse_lifecycle
verify_exact_hil_migration_lifecycle sentinelflow_verify_exact_lifecycle
verify_privileged_rotation_migration_lifecycle sentinelflow_verify_pre_rotation
verify_sse_notification_down_failstop sentinelflow_verify_sse_live
verify_exact_hil_down_failstop sentinelflow_verify_exact_live

host_port="$(docker port "$container" 5432/tcp | awk -F: 'END { print $NF }')"
if [[ -z "$host_port" ]]; then
  printf '%s\n' 'ERROR: could not determine disposable PostgreSQL host port' >&2
  exit 1
fi
if ! command -v sqlc >/dev/null 2>&1; then
  printf '%s\n' 'ERROR: sqlc is required for database query-contract verification' >&2
  exit 1
fi
SENTINELFLOW_SQLC_DATABASE_URI="postgresql://postgres:${postgres_password}@127.0.0.1:${host_port}/sentinelflow_verify_one?sslmode=disable" \
  sqlc -f "$db_root/sqlc.yaml" compile

docker exec "$container" \
  psql --set ON_ERROR_STOP=1 --username postgres --dbname sentinelflow_verify_one \
  --command 'SET ROLE sentinelflow_dispatcher; SELECT * FROM sentinelflow.dispatcher_approved_outbox;' \
  >/dev/null

expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_dispatcher; SELECT * FROM sentinelflow.outbox_jobs;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_dispatcher; SELECT * FROM sentinelflow.incidents;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_dispatcher; SELECT * FROM sentinelflow.admin_sessions;'
expect_denied sentinelflow_verify_one \
  "SET ROLE sentinelflow_dispatcher; INSERT INTO sentinelflow.audit_events (event_id, actor_type, actor_id, action, object_type, outcome, occurred_at) VALUES ('019b0000-0000-7000-8000-000000009099', 'dispatcher', 'dispatcher-test', 'forged', 'audit', 'succeeded', clock_timestamp());"
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_read; SELECT * FROM sentinelflow.admin_sessions;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_worker; SELECT * FROM sentinelflow.ingest_replay_nonces;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_read; SELECT * FROM sentinelflow.ingest_replay_nonces;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; DELETE FROM sentinelflow.ingest_replay_nonces WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; UPDATE sentinelflow.sender_checkpoints SET sender_id = sender_id WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; UPDATE sentinelflow.sender_checkpoints SET last_acknowledged_sequence = last_acknowledged_sequence WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; UPDATE sentinelflow.outbox_jobs SET state = state WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_worker; UPDATE sentinelflow.outbox_jobs SET state = state WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_worker; UPDATE sentinelflow.ai_budget_ledger SET reserved_micro_usd = reserved_micro_usd WHERE false;'
expect_denied sentinelflow_verify_one \
  "SET ROLE sentinelflow_worker; INSERT INTO sentinelflow.ai_budget_reservations (reservation_id, budget_date, model, rate_card_version, reserved_micro_usd, state, created_at, expires_at) VALUES ('019b0000-0000-4000-8000-000000008099', current_date, 'gpt-5.6-sol', 'operator-v1', 1, 'active', clock_timestamp(), clock_timestamp() + interval '1 minute');"
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; DELETE FROM sentinelflow.ingest_sequence_gaps WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; INSERT INTO sentinelflow.ingest_sequence_gap_resolutions DEFAULT VALUES;'
expect_denied sentinelflow_verify_one \
  "SET ROLE sentinelflow_worker; SELECT sentinelflow.register_ingest_sequence('sender','gateway','AAAAAAAAAAAAAAAAAAAAAA',1,'019b0000-0000-7000-8000-000000000001','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',clock_timestamp());"
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; TRUNCATE sentinelflow.audit_events;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; UPDATE sentinelflow.gateway_events SET status_code = status_code WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; UPDATE sentinelflow.approval_decisions SET decision = decision WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; UPDATE sentinelflow.enforcement_actions SET state = state WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; SELECT * FROM sentinelflow.validation_attempt_claims;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; SELECT * FROM sentinelflow.validation_attempt_results;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_api; SELECT * FROM sentinelflow.validation_attempt_gates;'
expect_denied sentinelflow_verify_one \
  "SET ROLE sentinelflow_worker; SELECT * FROM sentinelflow.read_policy_validation_attempt_000032('019b0000-0000-7000-8000-00000000a401');"
expect_denied sentinelflow_verify_one \
  "SET ROLE sentinelflow_read; SELECT * FROM sentinelflow.read_policy_validation_attempt_000032('019b0000-0000-7000-8000-00000000a401');"
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_worker; UPDATE sentinelflow.signals SET observed_count = observed_count WHERE false;'
expect_denied sentinelflow_verify_one \
  'SET ROLE sentinelflow_worker; UPDATE sentinelflow.policy_proposals SET state_revision = state_revision WHERE false;'

version="$(docker exec "$container" psql --username postgres --dbname sentinelflow_verify_one --tuples-only --no-align --command 'SHOW server_version;')"
migration_count="$(docker exec "$container" psql --username postgres --dbname sentinelflow_verify_one --tuples-only --no-align --command 'SELECT count(*) FROM sentinelflow.schema_migrations;')"
table_count="$(docker exec "$container" psql --username postgres --dbname sentinelflow_verify_one --tuples-only --no-align --command "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'sentinelflow';")"

printf 'PASS: PostgreSQL %s migrations=%s tables=%s fresh_apply=ok runner_restart_noop=ok latest_first_rollback_reapply=ok wrapper_owner_body_acl=ok artifact_content_digest_identity=ok validation_attempt_api_projection=ok content_digest_down_failstop=ok retention_fk_tombstone=ok sse_ledger=ok sse_down_failstop=ok exact_hil_artifacts=ok exact_hil_down_failstop=ok retention=ok control_observability=ok sqlc=ok role_negatives=ok replay_nonce=ok atomic_ingest=ok outbox_fencing=ok ai_budget=ok analysis_worker=ok audit_append_only=ok policy_state_cas=ok hil_exact=ok hil_coordinator=ok privileged_session_rotation=ok dispatch_recovery=ok dispatcher=ok cleanup=armed\n' \
  "$version" "$migration_count" "$table_count"
