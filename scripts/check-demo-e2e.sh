#!/usr/bin/env bash

set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/lib/demo-e2e.mjs"
compose_file="$repo_root/deployments/compose.yaml"
nft_structure_digest="$repo_root/deployments/tests/nft-structure-digest.mjs"
backend_image=""
postgres_image=""
web_image=""
release_mode=true
e2e_mode="release_expiry"
release_qualified=true
release_unverified_reason=""
browser_qa_hold_seconds=0
browser_qa_hold_seen=false
browser_qa_runner=false
browser_qa_runner_seen=false
# The management API consumes every login attempt from the direct peer before
# Argon2 verification.  The fast E2E flow performs five independent
# management logins before the revoked browser proof, so an automatic sixth
# browser login must wait until the one-minute rolling window has expired.
# Keep a one-second scheduling margin; this is a fixed wait, never a
# credential retry or a relaxation of the production limiter.
browser_qa_revoked_login_window_seconds=61
coverage_readiness_detector_window_seconds=300
coverage_readiness_margin_seconds=5
coverage_readiness_required_seconds=305
coverage_readiness_timeout_seconds=420
coverage_readiness_poll_seconds=2
detection_stability_timeout_seconds=300
detection_stability_poll_seconds=2

usage() {
  printf '%s\n' \
    "Usage: scripts/check-demo-e2e.sh [--fast] [--browser-qa-hold-seconds N] [--run-browser-qa]" \
    "" \
    "Both modes approve exactly one signed-history-authorized 203.0.113.20 action," \
    "prove a signed read-only inspection, and verify outage/restart non-replay." \
    "Default leaves that action active for native kernel expiry." \
    "--fast: non-release developer smoke; revokes the single action instead." \
    "--browser-qa-hold-seconds N: per-phase browser QA hold, N=60..900." \
    "--run-browser-qa: consume each private locator with the local Compose browser QA runner; without it the hold remains available for manual QA."
}

while (($# > 0)); do
  case "$1" in
    --fast)
      release_mode=false
      shift
      ;;
    --browser-qa-hold-seconds)
      if [[ "$browser_qa_hold_seen" == true || $# -lt 2 ]]; then
        usage >&2
        exit 2
      fi
      browser_qa_hold_seen=true
      browser_qa_hold_seconds="$2"
      shift 2
      ;;
    --run-browser-qa)
      if [[ "$browser_qa_runner_seen" == true ]]; then
        usage >&2
        exit 2
      fi
      browser_qa_runner_seen=true
      browser_qa_runner=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$release_mode" == false ]]; then
  e2e_mode="fast_revoke"
fi

if [[ "$browser_qa_hold_seen" == true ]]; then
  if [[ ! "$browser_qa_hold_seconds" =~ ^[0-9]+$ ]] ||
    ((browser_qa_hold_seconds < 60 || browser_qa_hold_seconds > 900)); then
    printf 'ERROR: --browser-qa-hold-seconds must be an integer from 60 through 900.\n' >&2
    exit 2
  fi
fi
if [[ "$browser_qa_runner" == true && "$browser_qa_hold_seen" != true ]]; then
  printf 'ERROR: --run-browser-qa requires --browser-qa-hold-seconds.\n' >&2
  exit 2
fi

for command in docker go node curl mktemp cmp install cat mv uname; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'ERROR: required command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done
test -f "$helper"
test -f "$compose_file"
test -f "$nft_structure_digest"
if [[ "$browser_qa_runner" == true ]]; then
  test -f "$repo_root/web/scripts/compose-browser-qa.mjs"
fi

run_bounded() {
  local timeout_seconds="$1"
  shift
  node "$helper" run-bounded --timeout-seconds "$timeout_seconds" -- "$@"
}

# BSD and GNU stat both return success for options intended for the other
# implementation, but produce incompatible output. Select the format from the
# operating-system family rather than relying on an exit-status fallback.
file_mode() {
  local path="$1"
  local mode=""
  case "$(uname -s)" in
    Darwin)
      mode="$(stat -f '%Lp' "$path")"
      ;;
    Linux)
      mode="$(stat -c '%a' "$path")"
      ;;
    *)
      printf 'ERROR: unsupported operating system for permission verification: %s\n' "$(uname -s)" >&2
      return 1
      ;;
  esac
  if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf 'ERROR: unable to read a numeric permission mode for %s\n' "$path" >&2
    return 1
  fi
  printf '%s\n' "$mode"
}

run_bounded 30 docker info >/dev/null
run_bounded 30 docker compose version >/dev/null

host_nft_policy="${SENTINELFLOW_DEMO_E2E_HOST_NFT_POLICY:-auto}"
case "$host_nft_policy" in
  auto | require | skip) ;;
  *)
    printf 'ERROR: SENTINELFLOW_DEMO_E2E_HOST_NFT_POLICY must be auto, require, or skip.\n' >&2
    exit 2
    ;;
esac
expiry_grace_seconds="${SENTINELFLOW_DEMO_E2E_EXPIRY_GRACE_SECONDS:-30}"
if [[ ! "$expiry_grace_seconds" =~ ^[0-9]+$ ]] ||
  ((expiry_grace_seconds < 10 || expiry_grace_seconds > 300)); then
  printf 'ERROR: SENTINELFLOW_DEMO_E2E_EXPIRY_GRACE_SECONDS must be 10..300.\n' >&2
  exit 2
fi

temp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
temp_root="$(mktemp -d "$temp_parent/sentinelflow-demo-e2e.XXXXXX")"
chmod 0700 "$temp_root"
project_suffix="$(basename "$temp_root" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | tail -c 13)"
project="sf-demo-e2e-${project_suffix}-$$"
image_suffix="${project_suffix}-$$"
backend_image="sentinelflow/backend:e2e-$image_suffix"
postgres_image="sentinelflow/postgres:e2e-$image_suffix"
web_image="sentinelflow/web:e2e-$image_suffix"
environment_file="$temp_root/compose.env"
compose_override_file="$temp_root/compose-override.json"
base_service_list_file="$temp_root/base-services.txt"
secrets_directory="$temp_root/secrets"
history_directory="$temp_root/history"
credentials_file="$secrets_directory/admin-credentials.json"
compose_config_file="$temp_root/compose-config.json"
runtime_inspect_file="$temp_root/runtime-inspect.json"
none_network_id_file="$temp_root/none-network-id.txt"
none_network_inspection_file="$temp_root/none-network-inspection.json"
e2e_state_file="$temp_root/e2e-state.json"
browser_qa_active_locator_file="$temp_root/browser-qa-active-locator.json"
browser_qa_active_stop_file="$temp_root/browser-qa-active.stop"
browser_qa_revoked_locator_file="$temp_root/browser-qa-revoked-locator.json"
browser_qa_revoked_stop_file="$temp_root/browser-qa-revoked.stop"
journal_before_snapshot="$temp_root/journal-before.json"
journal_after_snapshot="$temp_root/journal-after.json"
journal_before_raw="$temp_root/journal-before.bin"
journal_after_raw="$temp_root/journal-after.bin"
evidence_sql_file="$temp_root/evidence-chain.sql"
evidence_sql_preflight_file="$temp_root/evidence-chain-preflight.ndjson"
detection_diagnostic_sql_file="$temp_root/detection-diagnostic.sql"
detection_diagnostic_db_file="$temp_root/detection-diagnostic-db.json"
detection_diagnostic_detector_file="$temp_root/detection-diagnostic-detector.json"
detection_diagnostic_validationworker_file="$temp_root/detection-diagnostic-validationworker.json"
expiry_diagnostic_sql_file="$temp_root/expiry-diagnostic.sql"
expiry_diagnostic_db_file="$temp_root/expiry-diagnostic-db.json"
expiry_diagnostic_runtime_file="$temp_root/expiry-diagnostic-runtime.json"
detection_stability_sql_file="$temp_root/detection-stability.sql"
detection_stability_db_file="$temp_root/detection-stability-db.json"
detection_stability_candidate_file="$temp_root/detection-stability-candidate.json"
detection_stability_last_file="$temp_root/detection-stability-last.json"
detection_stability_first_ready_file="$temp_root/detection-stability-first-ready.json"
coverage_readiness_sql_file="$temp_root/coverage-readiness.sql"
coverage_readiness_db_file="$temp_root/coverage-readiness-db.json"
coverage_readiness_candidate_file="$temp_root/coverage-readiness-candidate.json"
coverage_readiness_last_file="$temp_root/coverage-readiness-last.json"
coverage_readiness_first_ready_file="$temp_root/coverage-readiness-first-ready.json"
evidence_before_file="$temp_root/evidence-before.ndjson"
evidence_after_file="$temp_root/evidence-after.ndjson"
evidence_terminal_file="$temp_root/evidence-terminal.ndjson"
artifact_copy_sql_file="$temp_root/artifact-copy.sql"
artifact_query_file="$temp_root/artifact-query.sql"
artifact_rows_file="$temp_root/artifact-rows.ndjson"
recovery_tool="$temp_root/sentinelflow-recoverytool"
validation_before_journal="$temp_root/validation-before.lock"
validation_after_journal="$temp_root/validation-after.lock"
validation_terminal_journal="$temp_root/validation-terminal.lock"
terminal_journal_snapshot="$temp_root/journal-terminal.json"
terminal_journal_raw="$temp_root/journal-terminal.bin"
dispatch_public_key="$temp_root/dispatcher-capability-public.pem"
result_public_key="$temp_root/executor-result-public.pem"
host_before_digest=""
host_nft_active=false
host_nft_checked=false
compose_may_exist=false
images_may_exist=false
diagnostic_ready=false
diagnostic_sequence=0
current_stage="bootstrap"
detector_id=""
validationworker_id=""
transient_names=()
legacy_name="sf-legacy-hil-test-14377"
legacy_id="$(run_bounded 15 docker inspect --format '{{.Id}}' "$legacy_name" 2>/dev/null || true)"
legacy_running="$(run_bounded 15 docker inspect --format '{{.State.Running}}' "$legacy_name" 2>/dev/null || true)"

# Current shell values must not override the generated, mode-restricted env
# file. Docker transport/context variables are intentionally left untouched.
unset COMPOSE_FILE COMPOSE_ENV_FILES COMPOSE_PROFILES COMPOSE_PROJECT_NAME
unset OPENAI_API_KEY OPENAI_MODEL OPENAI_REASONING_EFFORT OPENAI_STORE
unset POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
unset DATABASE_API_PASSWORD DATABASE_WORKER_PASSWORD DATABASE_READ_PASSWORD
unset DATABASE_DISPATCHER_PASSWORD DATABASE_RETENTION_PASSWORD DATABASE_LIFECYCLE_PASSWORD
unset DATABASE_METRICS_PASSWORD DATABASE_DEMO_IMPORTER_PASSWORD DATABASE_DEMO_ACTIVATOR_PASSWORD
unset DATABASE_API_URL DATABASE_WORKER_URL DATABASE_READ_URL DATABASE_DISPATCHER_URL
unset DATABASE_RETENTION_URL DATABASE_LIFECYCLE_URL DATABASE_METRICS_URL
unset DATABASE_DEMO_IMPORTER_URL DATABASE_DEMO_ACTIVATOR_URL
unset GATEWAY_EVENT_HMAC_KEY AUTH_EVENT_HMAC_KEY AUTH_ACCOUNT_HASH_KEY SESSION_HMAC_KEY
unset ADMIN_USERNAME ADMIN_PASSWORD_ARGON2ID_HASH ADMIN_ALLOWED_ORIGINS
unset NFT_BINARY_EXPECTED_SHA256 NFT_EXPECTED_VERSION
unset DEMO_SECRETS_SOURCE DEMO_HISTORY_SOURCE
unset DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE
unset API_MANAGEMENT_PUBLISHED_PORT GATEWAY_PUBLISHED_PORT WEB_PUBLISHED_PORT GATEWAY_PUBLIC_HOST

compose() {
  local timeout_seconds="$1"
  shift
  run_bounded "$timeout_seconds" env COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
    --project-name "$project" \
    --env-file "$environment_file" \
    --file "$compose_file" \
    --file "$compose_override_file" \
    --profile stub-ai \
    "$@"
}

remove_exact_project() {
  local status=0
  if [[ -f "$environment_file" && -f "$compose_override_file" ]]; then
    compose 90 down --volumes --remove-orphans --timeout 15 >/dev/null 2>&1 || status=1
  fi
  return "$status"
}

remove_exact_images() {
  local status=0 image
  for image in "$backend_image" "$postgres_image" "$web_image"; do
    run_bounded 60 docker image rm --force "$image" >/dev/null 2>&1 || true
    if run_bounded 15 docker image inspect "$image" >/dev/null 2>&1; then
      status=1
    fi
  done
  return "$status"
}

project_resources_absent() {
  local container network volume
  container="$(run_bounded 15 docker ps --all --quiet --filter "label=com.docker.compose.project=$project")"
  network="$(run_bounded 15 docker network ls --quiet --filter "label=com.docker.compose.project=$project")"
  volume="$(run_bounded 15 docker volume ls --quiet --filter "label=com.docker.compose.project=$project")"
  [[ -z "$container" && -z "$network" && -z "$volume" ]]
}

capture_host_nft_digest() {
  local phase="$1"
  local output_file="$temp_root/host-nft-$phase.json"
  local container_name="$project-host-nft-$phase"
  run_bounded 15 docker rm --force "$container_name" >/dev/null 2>&1 || true
  if ! run_bounded 30 docker run --rm \
    --name "$container_name" \
    --network host \
    --user 0:0 \
    --read-only \
    --cap-drop ALL \
    --cap-add NET_ADMIN \
    --security-opt no-new-privileges:true \
    --entrypoint /usr/sbin/nft \
    "$backend_image" \
    -j list ruleset >"$output_file" 2>/dev/null; then
    rm -f "$output_file"
    return 1
  fi
  node "$nft_structure_digest" <"$output_file"
}

initialize_host_nft_evidence() {
  if [[ "$host_nft_policy" == "skip" ]]; then
    printf 'SKIP: host nftables comparison disabled by explicit policy.\n'
    release_qualified=false
    release_unverified_reason="host nftables comparison was explicitly skipped"
    return
  fi
  if [[ "$(uname -s)" != "Linux" ]]; then
    if [[ "$host_nft_policy" == "require" ]]; then
      printf 'ERROR: required host-network nftables evidence is unsupported on this non-Linux host.\n' >&2
      exit 1
    fi
    printf 'SKIP: host nftables comparison is unsupported on this non-Linux host (policy=auto).\n'
    release_qualified=false
    release_unverified_reason="host nftables comparison is unsupported on this host"
    return
  fi
  if ! host_before_digest="$(capture_host_nft_digest before)"; then
    if [[ "$host_nft_policy" == "require" ]]; then
      printf 'ERROR: required read-only host-network nftables probe failed.\n' >&2
      exit 1
    fi
    printf 'SKIP: read-only host-network nftables probe was unavailable (policy=auto).\n'
    release_qualified=false
    release_unverified_reason="host nftables comparison probe was unavailable"
    return
  fi
  if [[ ! "$host_before_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'ERROR: host nftables structure digest is invalid.\n' >&2
    exit 1
  fi
  host_nft_active=true
  printf 'PASS: captured semantic host nftables structure before Compose network creation.\n'
}

finish_host_nft_evidence() {
  local after_digest
  if [[ "$host_nft_active" != true ]]; then
    host_nft_checked=true
    return
  fi
  if ! after_digest="$(capture_host_nft_digest after)"; then
    printf 'ERROR: post-cleanup host nftables probe failed.\n' >&2
    return 1
  fi
  if [[ "$after_digest" != "$host_before_digest" ]]; then
    printf 'ERROR: semantic host nftables structure changed across the isolated demo.\n' >&2
    return 1
  fi
  host_nft_checked=true
  printf 'PASS: semantic host nftables structure is unchanged after exact Compose cleanup.\n'
}

cleanup() {
  local status="$?"
  local name current_id current_running
  trap - EXIT INT TERM HUP
  set +e
  if ((status != 0)) && [[ "$diagnostic_ready" == true ]]; then
    if ! capture_detection_diagnostics "failure-$current_stage"; then
      printf 'DEMO_E2E_DIAGNOSTIC_UNAVAILABLE stage=%s\n' "failure-$current_stage" >&2
    fi
  fi
  # Bash 3.2 treats an empty declared array as unbound under `set -u`.
  for name in "${transient_names[@]-}" "$project-host-nft-before" "$project-host-nft-after"; do
    [[ -z "$name" ]] || run_bounded 15 docker rm --force "$name" >/dev/null 2>&1 || true
  done
  if [[ "$compose_may_exist" == true ]]; then
    remove_exact_project || status=1
    compose_may_exist=false
  fi
  if ! project_resources_absent; then
    printf 'ERROR: exact project cleanup left labeled Docker resources.\n' >&2
    status=1
  fi
  if [[ "$host_nft_active" == true && "$host_nft_checked" != true ]]; then
    finish_host_nft_evidence || status=1
  fi
  if [[ "$images_may_exist" == true ]]; then
    if ! remove_exact_images; then
      printf 'ERROR: unique E2E image remained after cleanup.\n' >&2
      status=1
    fi
    images_may_exist=false
  fi
  if [[ -n "$legacy_id" ]]; then
    current_id="$(run_bounded 15 docker inspect --format '{{.Id}}' "$legacy_name" 2>/dev/null || true)"
    current_running="$(run_bounded 15 docker inspect --format '{{.State.Running}}' "$legacy_name" 2>/dev/null || true)"
    if [[ "$current_id" != "$legacy_id" || "$current_running" != "$legacy_running" ]]; then
      printf 'ERROR: pre-existing legacy HIL test container was changed.\n' >&2
      status=1
    fi
  fi
  case "$temp_root" in
    "$temp_parent"/sentinelflow-demo-e2e.*)
      if [[ -d "$temp_root" && ! -L "$temp_root" ]]; then
        rm -rf -- "$temp_root"
      else
        printf 'ERROR: refusing unsafe temporary cleanup.\n' >&2
        status=1
      fi
      ;;
    *)
      printf 'ERROR: refusing out-of-scope temporary cleanup.\n' >&2
      status=1
      ;;
  esac
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

run_bounded 30 docker network inspect none --format '{{.Id}}' >"$none_network_id_file"
chmod 0600 "$none_network_id_file"
none_network_id="$(node "$helper" check-none-network-id "$none_network_id_file")"

node "$helper" write-compose-override \
  --output "$compose_override_file" \
  --backend-image "$backend_image" \
  --postgres-image "$postgres_image" \
  --web-image "$web_image"

run_transient() {
  local name="$1"
  shift
  transient_names+=("$name")
  run_bounded 90 docker run --rm --name "$name" "$@"
}

read_nft_state() {
  local target="$1"
  local readback_file
  readback_file="$(mktemp "$temp_root/nft-readback.XXXXXX")"
  run_bounded 15 docker exec "$executor_id" /usr/sbin/nft -j list set inet sentinelflow blacklist_ipv4 >"$readback_file"
  node "$helper" nft-state "$readback_file" "$target"
  rm -f "$readback_file"
}

capture_journal_snapshot() {
  local output_file="$1"
  local retained_raw_file="$2"
  local phase="$3"
  local raw_file attempt
  for attempt in 1 2 3 4 5; do
    raw_file="$(mktemp "$temp_root/executor-journal.XXXXXX")"
    rm -f "$raw_file"
    rm -f "$output_file"
    if run_bounded 30 docker cp \
      "$executor_id:/var/lib/sentinelflow-executor/replay.json" "$raw_file" >/dev/null 2>&1; then
      chmod 0600 "$raw_file"
      if node "$helper" journal-snapshot "$raw_file" \
        --state "$e2e_state_file" --phase "$phase" --output "$output_file"; then
        mv "$raw_file" "$retained_raw_file"
        chmod 0600 "$retained_raw_file"
        return 0
      fi
    fi
    rm -f "$raw_file"
    sleep 1
  done
  rm -f "$output_file" "$retained_raw_file"
  return 1
}

deadline_slice_seconds() {
  local deadline_seconds="${1:-}"
  local maximum_seconds="${2:-}"
  local remaining_seconds
  if [[ ! "$deadline_seconds" =~ ^[0-9]+$ || ! "$maximum_seconds" =~ ^[0-9]+$ ]] ||
    ((maximum_seconds < 1 || maximum_seconds > 1800)); then
    return 2
  fi
  remaining_seconds=$((deadline_seconds - SECONDS))
  if ((remaining_seconds <= 0)); then
    return 1
  fi
  if ((remaining_seconds < maximum_seconds)); then
    printf '%s\n' "$remaining_seconds"
  else
    printf '%s\n' "$maximum_seconds"
  fi
}

postgres_query_bounded() {
  if (($# < 3)); then
    return 2
  fi
  local timeout_seconds="$1"
  local input_file="$2"
  local output_file="$3"
  shift 3
  if [[ ! "$timeout_seconds" =~ ^[0-9]+$ ]] ||
    ((timeout_seconds < 1 || timeout_seconds > 30)); then
    return 2
  fi
  : >"$output_file"
  chmod 0600 "$output_file"
  run_bounded "$timeout_seconds" docker exec --interactive "$postgres_id" /bin/sh -eu -c \
    'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql --no-psqlrc --set=ON_ERROR_STOP=1 --quiet --tuples-only --no-align --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" "$@"' \
    sentinelflow-e2e "$@" <"$input_file" >"$output_file"
}

postgres_query() {
  postgres_query_bounded 30 "$@"
}

preflight_evidence_chain_sql() {
  local zero_job_id="00000000-0000-0000-0000-000000000000"
  current_stage="evidence-sql-preflight"
  if [[ -z "$postgres_id" || ! -f "$evidence_sql_file" ]]; then
    printf 'ERROR: evidence-chain SQL preflight prerequisites are unavailable.\n' >&2
    return 1
  fi
  rm -f "$evidence_sql_preflight_file"
  if ! postgres_query "$evidence_sql_file" "$evidence_sql_preflight_file" \
    --set="add_job=$zero_job_id" --set="revoke_job="; then
    printf 'ERROR: evidence-chain SQL failed its migrated PostgreSQL parse preflight.\n' >&2
    rm -f "$evidence_sql_preflight_file"
    return 1
  fi
  if [[ -s "$evidence_sql_preflight_file" ]]; then
    printf 'ERROR: evidence-chain SQL preflight unexpectedly returned rows.\n' >&2
    rm -f "$evidence_sql_preflight_file"
    return 1
  fi
  rm -f "$evidence_sql_preflight_file"
  printf 'PASS: evidence-chain SQL parsed on migrated PostgreSQL and returned zero rows.\n'
}

capture_detection_diagnostics() {
  local stage="$1"
  diagnostic_sequence=$((diagnostic_sequence + 1))
  if [[ ! "$stage" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ || "$diagnostic_ready" != true ||
    -z "$postgres_id" || -z "$detector_id" || -z "$validationworker_id" ||
    ! -f "$detection_diagnostic_sql_file" ]]; then
    return 1
  fi
  rm -f "$detection_diagnostic_db_file" "$detection_diagnostic_detector_file" \
    "$detection_diagnostic_validationworker_file"
  if ! postgres_query "$detection_diagnostic_sql_file" "$detection_diagnostic_db_file"; then
    rm -f "$detection_diagnostic_db_file" "$detection_diagnostic_detector_file" \
      "$detection_diagnostic_validationworker_file"
    return 1
  fi
  if ! run_bounded 15 docker inspect \
    --format '{"running":{{json .State.Running}},"restart_count":{{json .RestartCount}}}' \
    "$detector_id" >"$detection_diagnostic_detector_file"; then
    rm -f "$detection_diagnostic_db_file" "$detection_diagnostic_detector_file" \
      "$detection_diagnostic_validationworker_file"
    return 1
  fi
  if ! run_bounded 15 docker inspect \
    --format '{"running":{{json .State.Running}},"restart_count":{{json .RestartCount}}}' \
    "$validationworker_id" >"$detection_diagnostic_validationworker_file"; then
    rm -f "$detection_diagnostic_db_file" "$detection_diagnostic_detector_file" \
      "$detection_diagnostic_validationworker_file"
    return 1
  fi
  chmod 0600 "$detection_diagnostic_detector_file" "$detection_diagnostic_validationworker_file"
  if ! node "$helper" print-detection-diagnostic "$detection_diagnostic_db_file" \
    --detector "$detection_diagnostic_detector_file" \
    --validationworker "$detection_diagnostic_validationworker_file" --stage "$stage"; then
    rm -f "$detection_diagnostic_db_file" "$detection_diagnostic_detector_file" \
      "$detection_diagnostic_validationworker_file"
    return 1
  fi
  rm -f "$detection_diagnostic_db_file" "$detection_diagnostic_detector_file" \
    "$detection_diagnostic_validationworker_file"
}

# This is called only when the release expiry convergence assertion fails.
# It emits the bounded, redacted lifecycle projection needed to separate an
# early, late, and boundary-overlap result.  It deliberately does not inspect
# logs, environment, JCS, signatures, capabilities, or request data.
capture_expiry_diagnostics() {
  local action_id dispatcher_id executor_runtime_id lifecycleworker_id
  if [[ "$diagnostic_ready" != true || -z "$postgres_id" || ! -f "$expiry_diagnostic_sql_file" ]]; then
    return 1
  fi
  if ! action_id="$(node "$helper" print-expiry-action-id --state "$e2e_state_file")" ||
    [[ ! "$action_id" =~ ^[0-9a-f-]{36}$ ]]; then
    return 1
  fi
  dispatcher_id="$(compose 30 ps --quiet dispatcher)"
  executor_runtime_id="$(compose 30 ps --quiet executor)"
  lifecycleworker_id="$(compose 30 ps --quiet lifecycleworker)"
  if [[ -z "$dispatcher_id" || -z "$executor_runtime_id" || -z "$lifecycleworker_id" ]]; then
    return 1
  fi
  rm -f "$expiry_diagnostic_db_file" "$expiry_diagnostic_runtime_file"
  if ! postgres_query "$expiry_diagnostic_sql_file" "$expiry_diagnostic_db_file" --set="action_id=$action_id"; then
    rm -f "$expiry_diagnostic_db_file" "$expiry_diagnostic_runtime_file"
    return 1
  fi
  if ! {
    printf '{"dispatcher":'
    run_bounded 15 docker inspect --format '{"running":{{json .State.Running}},"restart_count":{{json .RestartCount}}}' "$dispatcher_id"
    printf ',"executor":'
    run_bounded 15 docker inspect --format '{"running":{{json .State.Running}},"restart_count":{{json .RestartCount}}}' "$executor_runtime_id"
    printf ',"lifecycleworker":'
    run_bounded 15 docker inspect --format '{"running":{{json .State.Running}},"restart_count":{{json .RestartCount}}}' "$lifecycleworker_id"
    printf '}\n'
  } >"$expiry_diagnostic_runtime_file"; then
    rm -f "$expiry_diagnostic_db_file" "$expiry_diagnostic_runtime_file"
    return 1
  fi
  chmod 0600 "$expiry_diagnostic_db_file" "$expiry_diagnostic_runtime_file"
  if ! node "$helper" print-expiry-diagnostic "$expiry_diagnostic_db_file" \
    --runtime "$expiry_diagnostic_runtime_file"; then
    rm -f "$expiry_diagnostic_db_file" "$expiry_diagnostic_runtime_file"
    return 1
  fi
  rm -f "$expiry_diagnostic_db_file" "$expiry_diagnostic_runtime_file"
}

wait_for_cold_start_coverage() {
  local advance_state deadline query_timeout_seconds readiness_state readiness_summary sleep_seconds
  current_stage="coverage-readiness"
  deadline=$((SECONDS + coverage_readiness_timeout_seconds))
  rm -f "$coverage_readiness_db_file" "$coverage_readiness_candidate_file" \
    "$coverage_readiness_last_file" "$coverage_readiness_first_ready_file"
  while :; do
    if ! query_timeout_seconds="$(deadline_slice_seconds "$deadline" 30)"; then
      break
    fi
    if postgres_query_bounded "$query_timeout_seconds" \
      "$coverage_readiness_sql_file" "$coverage_readiness_db_file"; then
      # A query may finish at the timeout boundary; never accept or parse its
      # result once the advertised readiness deadline has elapsed.
      if ((SECONDS >= deadline)); then
        break
      fi
      rm -f "$coverage_readiness_candidate_file"
      if ! node "$helper" print-coverage-readiness "$coverage_readiness_db_file" \
        >"$coverage_readiness_candidate_file"; then
        printf 'ERROR: malformed coverage readiness snapshot failed closed.\n' >&2
        return 1
      fi
      chmod 0600 "$coverage_readiness_candidate_file"
      if ! readiness_state="$(node "$helper" coverage-readiness-state \
        "$coverage_readiness_candidate_file")" ||
        [[ "$readiness_state" != "ready" && "$readiness_state" != "waiting" ]]; then
        printf 'ERROR: canonical coverage readiness state failed closed.\n' >&2
        return 1
      fi
      rm -f "$coverage_readiness_last_file"
      mv "$coverage_readiness_candidate_file" "$coverage_readiness_last_file"
      if [[ "$readiness_state" == "waiting" ]]; then
        rm -f "$coverage_readiness_first_ready_file"
      elif [[ ! -e "$coverage_readiness_first_ready_file" && \
        ! -L "$coverage_readiness_first_ready_file" ]]; then
        install -m 0600 "$coverage_readiness_last_file" "$coverage_readiness_first_ready_file"
      elif [[ -f "$coverage_readiness_first_ready_file" && \
        ! -L "$coverage_readiness_first_ready_file" ]]; then
        if ! advance_state="$(node "$helper" coverage-readiness-advance \
          "$coverage_readiness_first_ready_file" "$coverage_readiness_last_file")"; then
          printf 'ERROR: coverage readiness freshness comparison failed closed.\n' >&2
          return 1
        fi
        case "$advance_state" in
          advanced)
            if ((SECONDS >= deadline)); then
              break
            fi
            IFS= read -r readiness_summary <"$coverage_readiness_last_file"
            printf 'DEMO_E2E_COVERAGE_READINESS %s\n' "$readiness_summary"
            printf 'PASS: two trusted gateway/auth watermarks advance across the fixed %ss readiness window (%ss detector + %ss margin).\n' \
              "$coverage_readiness_required_seconds" "$coverage_readiness_detector_window_seconds" \
              "$coverage_readiness_margin_seconds"
            current_stage="post-coverage-readiness"
            if ((SECONDS >= deadline)); then
              current_stage="coverage-readiness"
              break
            fi
            return 0
            ;;
          not-advanced)
            rm -f "$coverage_readiness_first_ready_file"
            ;;
          *)
            printf 'ERROR: coverage readiness freshness state failed closed.\n' >&2
            return 1
            ;;
        esac
      else
        printf 'ERROR: unsafe coverage readiness candidate failed closed.\n' >&2
        return 1
      fi
    fi
    if ! sleep_seconds="$(deadline_slice_seconds \
      "$deadline" "$coverage_readiness_poll_seconds")"; then
      break
    fi
    sleep "$sleep_seconds"
  done
  if [[ -f "$coverage_readiness_last_file" && ! -L "$coverage_readiness_last_file" ]]; then
    IFS= read -r readiness_summary <"$coverage_readiness_last_file"
    printf 'DEMO_E2E_COVERAGE_READINESS_TIMEOUT %s\n' "$readiness_summary" >&2
  else
    printf 'DEMO_E2E_COVERAGE_READINESS_TIMEOUT unavailable\n' >&2
  fi
  printf 'ERROR: trusted gateway/auth coverage did not span the fixed %ss readiness window.\n' \
    "$coverage_readiness_required_seconds" >&2
  return 1
}

wait_for_detection_stability() {
  local advance_state deadline query_timeout_seconds sleep_seconds stability_state stability_summary
  current_stage="detection-stability"
  deadline=$((SECONDS + detection_stability_timeout_seconds))
  rm -f "$detection_stability_db_file" "$detection_stability_candidate_file" \
    "$detection_stability_last_file" "$detection_stability_first_ready_file"
  while :; do
    if ! query_timeout_seconds="$(deadline_slice_seconds "$deadline" 30)"; then
      break
    fi
    if postgres_query_bounded "$query_timeout_seconds" \
      "$detection_stability_sql_file" "$detection_stability_db_file"; then
      if ((SECONDS >= deadline)); then
        break
      fi
      rm -f "$detection_stability_candidate_file"
      if ! node "$helper" print-detection-stability "$detection_stability_db_file" \
        >"$detection_stability_candidate_file"; then
        printf 'ERROR: malformed detection stability snapshot failed closed.\n' >&2
        capture_detection_diagnostics "detection-stability-malformed" || true
        return 1
      fi
      chmod 0600 "$detection_stability_candidate_file"
      if ! stability_state="$(node "$helper" detection-stability-state \
        "$detection_stability_candidate_file")"; then
        printf 'ERROR: detection stability state failed closed.\n' >&2
        capture_detection_diagnostics "detection-stability-invalid" || true
        return 1
      fi
      rm -f "$detection_stability_last_file"
      mv "$detection_stability_candidate_file" "$detection_stability_last_file"
      case "$stability_state" in
        failed)
          IFS= read -r stability_summary <"$detection_stability_last_file"
          printf 'DEMO_E2E_DETECTION_STABILITY_FAILED %s\n' "$stability_summary" >&2
          capture_detection_diagnostics "detection-stability-dead" || true
          printf 'ERROR: a scenario-scoped detect job dead-lettered.\n' >&2
          return 1
          ;;
        waiting)
          rm -f "$detection_stability_first_ready_file"
          ;;
        ready)
          if [[ ! -e "$detection_stability_first_ready_file" && \
            ! -L "$detection_stability_first_ready_file" ]]; then
            install -m 0600 "$detection_stability_last_file" "$detection_stability_first_ready_file"
          elif [[ -f "$detection_stability_first_ready_file" && \
            ! -L "$detection_stability_first_ready_file" ]]; then
            if ! advance_state="$(node "$helper" detection-stability-advance \
              "$detection_stability_first_ready_file" "$detection_stability_last_file")"; then
              printf 'ERROR: detection stability comparison failed closed.\n' >&2
              capture_detection_diagnostics "detection-stability-invalid" || true
              return 1
            fi
            case "$advance_state" in
              stable)
                if ((SECONDS >= deadline)); then
                  break
                fi
                IFS= read -r stability_summary <"$detection_stability_last_file"
                printf 'DEMO_E2E_DETECTION_STABILITY %s\n' "$stability_summary"
                printf 'PASS: scenario detect jobs drained and incident/evidence/policy bindings stayed stable across two observations.\n'
                current_stage="post-detection-stability"
                return 0
                ;;
              changed)
                rm -f "$detection_stability_first_ready_file"
                install -m 0600 "$detection_stability_last_file" "$detection_stability_first_ready_file"
                ;;
              *)
                printf 'ERROR: detection stability comparison state failed closed.\n' >&2
                capture_detection_diagnostics "detection-stability-invalid" || true
                return 1
                ;;
            esac
          else
            printf 'ERROR: unsafe detection stability baseline failed closed.\n' >&2
            capture_detection_diagnostics "detection-stability-invalid" || true
            return 1
          fi
          ;;
        *)
          printf 'ERROR: unknown detection stability state failed closed.\n' >&2
          capture_detection_diagnostics "detection-stability-invalid" || true
          return 1
          ;;
      esac
    fi
    if ! sleep_seconds="$(deadline_slice_seconds \
      "$deadline" "$detection_stability_poll_seconds")"; then
      break
    fi
    sleep "$sleep_seconds"
  done
  if [[ -f "$detection_stability_last_file" && ! -L "$detection_stability_last_file" ]]; then
    IFS= read -r stability_summary <"$detection_stability_last_file"
    printf 'DEMO_E2E_DETECTION_STABILITY_TIMEOUT %s\n' "$stability_summary" >&2
  else
    printf 'DEMO_E2E_DETECTION_STABILITY_TIMEOUT unavailable\n' >&2
  fi
  capture_detection_diagnostics "detection-stability-timeout" || true
  printf 'ERROR: scenario detection and policy state did not stabilize within %ss.\n' \
    "$detection_stability_timeout_seconds" >&2
  return 1
}

hold_for_browser_qa() {
  local phase="$1"
  local deadline locator_file stop_file
  if [[ "$browser_qa_hold_seen" != true ]]; then
    return 0
  fi
  case "$phase" in
    active)
      locator_file="$browser_qa_active_locator_file"
      stop_file="$browser_qa_active_stop_file"
      ;;
    revoked)
      if [[ "$e2e_mode" != "fast_revoke" ]]; then
        printf 'ERROR: revoked browser QA is unavailable outside fast-revoke mode.\n' >&2
        return 1
      fi
      locator_file="$browser_qa_revoked_locator_file"
      stop_file="$browser_qa_revoked_stop_file"
      ;;
    *)
      printf 'ERROR: browser QA phase is invalid.\n' >&2
      return 1
      ;;
  esac
  if [[ "$phase" == "revoked" && "$browser_qa_runner" == true ]]; then
    wait_for_revoked_browser_qa_login_window
  fi
  current_stage="browser-qa-$phase-hold"
  node "$helper" write-browser-qa-locator \
    --output "$locator_file" \
    --root "$temp_root" \
    --project "$project" \
    --web-port "$web_port" \
    --credentials "$credentials_file" \
    --state "$e2e_state_file" \
    --phase "$phase" \
    --hold-seconds "$browser_qa_hold_seconds" \
    --stop-file "$stop_file"
  printf '%s\n' "$locator_file"
  if [[ "$browser_qa_runner" == true ]]; then
    run_bounded "$browser_qa_hold_seconds" \
      node "$repo_root/web/scripts/compose-browser-qa.mjs" --locator "$locator_file"
  fi
  deadline=$((SECONDS + browser_qa_hold_seconds))
  while ((SECONDS < deadline)); do
    if [[ -e "$stop_file" || -L "$stop_file" ]]; then
      if [[ -f "$stop_file" && ! -L "$stop_file" ]]; then
        printf 'PASS: browser QA %s stop marker received; continuing deterministic E2E.\n' "$phase"
        current_stage="post-browser-qa-$phase"
        return 0
      fi
      printf 'ERROR: browser QA %s stop marker must be a regular non-symlink file.\n' "$phase" >&2
      return 1
    fi
    sleep 1
  done
  printf 'ERROR: browser QA %s hold deadline elapsed without a regular stop marker.\n' "$phase" >&2
  return 1
}

wait_for_revoked_browser_qa_login_window() {
  # The web proxy deliberately strips forwarding headers and the API keys its
  # pre-hash five-per-minute limiter to the direct TCP peer.  The helper and
  # Chromium both traverse that proxy, so they share one source budget.  Do
  # not replace this bounded wait with a second login attempt: a rendered
  # authentication error is evidence, not a retry signal.
  local deadline
  current_stage="browser-qa-revoked-login-window"
  printf '==> Waiting %ss for the shared pre-hash login window before revoked browser QA\n' \
    "$browser_qa_revoked_login_window_seconds"
  deadline=$((SECONDS + browser_qa_revoked_login_window_seconds))
  while ((SECONDS < deadline)); do
    sleep 1
  done
}

validate_persisted_evidence() {
  local output_file="$1"
  local journal_snapshot="$2"
  local replay_journal="$3"
  local validation_journal="$4"
  local phase="$5"
  local selectors selector job_id action_id attempt
  local add_job="" revoke_job="" selected_action_id=""
  if [[ "$e2e_mode" == "fast_revoke" && "$phase" != "revoked" ]] ||
    [[ "$e2e_mode" == "release_expiry" && "$phase" != "active" && "$phase" != "expired" ]]; then
    return 1
  fi
  selectors="$(node "$helper" db-selectors "$e2e_state_file")"
  while read -r selector job_id action_id; do
    case "$selector" in
      add)
        [[ -z "$add_job" && -z "$selected_action_id" ]] || return 1
        add_job="$job_id"
        selected_action_id="$action_id"
        ;;
      revoke)
        [[ -z "$revoke_job" && -n "$selected_action_id" && "$action_id" == "$selected_action_id" ]] || return 1
        revoke_job="$job_id"
        ;;
      *) return 1 ;;
    esac
  done <<<"$selectors"
  if [[ ! "$add_job" =~ ^[0-9a-f-]{36}$ || ! "$selected_action_id" =~ ^[0-9a-f-]{36}$ ]] ||
    { [[ "$e2e_mode" == "fast_revoke" ]] && [[ ! "$revoke_job" =~ ^[0-9a-f-]{36}$ ]]; } ||
    { [[ "$e2e_mode" == "release_expiry" ]] && [[ -n "$revoke_job" ]]; }; then
    return 1
  fi

  for attempt in 1 2 3 4 5; do
    # The database view must precede the append-only executor journal copy.
    # If an inspect lands between these two snapshots, recovery reconciliation
    # rejects the pair and the next attempt refreshes both sides together.
    if ! postgres_query "$evidence_sql_file" "$output_file" \
      --set="add_job=$add_job" \
      --set="revoke_job=$revoke_job" ||
      ! node "$helper" check-evidence-chain "$output_file" \
        --state "$e2e_state_file" --phase "$phase" ||
      ! postgres_query "$artifact_query_file" "$artifact_rows_file" ||
      ! capture_journal_snapshot "$journal_snapshot" "$replay_journal" "$phase"; then
      sleep 1
      continue
    fi
    if run_bounded 60 "$recovery_tool" run-session --journal "$validation_journal" \
      "$recovery_tool" validate-execution-artifacts \
      --journal "$validation_journal" \
      --dispatch-public-key "$dispatch_public_key" \
      --result-public-key "$result_public_key" <"$artifact_rows_file" &&
      run_bounded 60 "$recovery_tool" run-session --journal "$validation_journal" \
        "$recovery_tool" validate-recovery-state \
        --journal "$validation_journal" \
        --replay-journal "$replay_journal" \
        --dispatch-public-key "$dispatch_public_key" \
        --result-public-key "$result_public_key" <"$artifact_rows_file"; then
      rm -f "$artifact_rows_file"
      return 0
    fi
    sleep 1
  done
  rm -f "$artifact_rows_file" "$output_file" "$journal_snapshot" "$replay_journal"
  return 1
}

wait_for_nft_active() {
  local target="$1"
  local deadline=$((SECONDS + 120))
  local state remaining digest
  while ((SECONDS < deadline)); do
    if read -r state remaining digest < <(read_nft_state "$target") && [[ "$state" == "active" ]]; then
      printf '%s %s %s\n' "$state" "$remaining" "$digest"
      return 0
    fi
    sleep 1
  done
  return 1
}

run_scenario() {
  local scenario="$1"
  local source_ip="$2"
  local seed="$3"
  local safe_name="${scenario//-/_}"
  local report_file="$temp_root/simulator-$safe_name.json"
  local container_name="$project-sim-$safe_name"
  current_stage="scenario-$safe_name"
  run_transient "$container_name" \
    --network "${project}_edge" \
    --ip "$source_ip" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint /usr/local/bin/simulator \
    "$backend_image" \
    -gateway-url http://gateway:8080 \
    -gateway-host localhost:8080 \
    -seed "$seed" \
    -concurrency 16 \
    -request-timeout 10s \
    "$scenario" >"$report_file"
  node "$helper" check-simulator "$report_file" "$scenario"
  printf 'PASS: scenario=%s source=%s\n' "$scenario" "$source_ip"
}

probe_gateway() {
  local source_ip="$1"
  local suffix="$2"
  run_transient "$project-probe-$suffix" \
    --network "${project}_edge" \
    --ip "$source_ip" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint /usr/bin/wget \
    "$backend_image" \
    -q -O /dev/null -T 5 \
    --header 'Host: localhost:8080' \
    http://gateway:8080/
}

printf '==> Building pinned demo images without credentials\n'
cd "$repo_root"
for image in "$backend_image" "$postgres_image" "$web_image"; do
  if run_bounded 15 docker image inspect "$image" >/dev/null 2>&1; then
    printf 'ERROR: unique E2E image tag already exists.\n' >&2
    exit 1
  fi
done
images_may_exist=true
run_bounded 900 docker build --load --progress plain --tag "$backend_image" \
  --file deployments/Dockerfile.backend --build-arg VERSION=local-demo .
run_bounded 900 docker build --load --progress plain --tag "$postgres_image" \
  --file deployments/Dockerfile.postgres .
run_bounded 900 docker build --load --progress plain --tag "$web_image" \
  --file deployments/Dockerfile.web .
run_bounded 300 go build -trimpath -o "$recovery_tool" ./cmd/recoverytool

attestation="$({
  run_bounded 30 docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --entrypoint /bin/sh \
    "$backend_image" \
    -eu -c 'sha256sum /usr/sbin/nft | cut -d " " -f 1; /usr/sbin/nft --version'
})"
if [[ "$(printf '%s\n' "$attestation" | wc -l | tr -d ' ')" != "2" ]]; then
  printf 'ERROR: unexpected nftables attestation output.\n' >&2
  exit 1
fi
nft_digest="$(printf '%s\n' "$attestation" | sed -n '1p')"
nft_version_output="$(printf '%s\n' "$attestation" | sed -n '2p')"
if [[ ! "$nft_digest" =~ ^[0-9a-f]{64}$ ]] ||
  [[ ! "$nft_version_output" =~ ^nftables\ v([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?)(\ \([\ -~]{1,128}\))?$ ]]; then
  printf 'ERROR: built nftables binary did not produce a canonical attestation.\n' >&2
  exit 1
fi
nft_version="nftables v${BASH_REMATCH[1]}"

printf '==> Generating an isolated temporary demo authority bundle\n'
env -u SENTINELFLOW_ADMIN_PASSWORD \
  SENTINELFLOW_NFT_BINARY_SHA256="$nft_digest" \
  SENTINELFLOW_NFT_VERSION="$nft_version" \
  node "$helper" run-bounded --timeout-seconds 120 -- go run ./cmd/democonfig \
    --output "$environment_file" \
    --secrets-dir "$secrets_directory" \
    --history-dir "$history_directory" >/dev/null
test "$(file_mode "$environment_file")" = "600"
test "$(file_mode "$secrets_directory")" = "700"
analysis_activation="$secrets_directory/demo-history-analysis-activation.capability"
validation_activation="$secrets_directory/demo-history-validation-activation.capability"
for capability in "$analysis_activation" "$validation_activation"; do
  test -f "$capability"
  test ! -L "$capability"
  test "$(file_mode "$capability")" = "400"
  test "$(wc -c <"$capability" | tr -d ' ')" = "32"
done
activation_comparison=0
cmp -s "$analysis_activation" "$validation_activation" || activation_comparison=$?
test "$activation_comparison" = "1"

read -r api_port gateway_port web_port < <(node "$helper" allocate-ports)
if [[ ! "$api_port" =~ ^[0-9]+$ || ! "$gateway_port" =~ ^[0-9]+$ || ! "$web_port" =~ ^[0-9]+$ ]]; then
  printf 'ERROR: loopback port allocation failed.\n' >&2
  exit 1
fi
{
  printf 'COMPOSE_PROJECT_NAME=%s\n' "$project"
  printf 'COMPOSE_PROFILES=stub-ai\n'
  printf 'DEMO_SECRETS_SOURCE=%s\n' "$secrets_directory"
  printf 'DEMO_HISTORY_SOURCE=%s\n' "$history_directory"
  printf 'API_MANAGEMENT_PUBLISHED_PORT=%s\n' "$api_port"
  printf 'GATEWAY_PUBLISHED_PORT=%s\n' "$gateway_port"
  printf 'WEB_PUBLISHED_PORT=%s\n' "$web_port"
  printf 'ADMIN_ALLOWED_ORIGINS=http://localhost:%s\n' "$web_port"
} >>"$environment_file"
chmod 0600 "$environment_file"

node "$helper" write-evidence-sql --output "$evidence_sql_file"
node "$helper" write-detection-diagnostic-sql --output "$detection_diagnostic_sql_file"
node "$helper" write-expiry-diagnostic-sql --output "$expiry_diagnostic_sql_file"
node "$helper" write-detection-stability-sql --output "$detection_stability_sql_file"
node "$helper" write-coverage-readiness-sql --output "$coverage_readiness_sql_file"
run_bounded 30 "$recovery_tool" postgres-artifact-copy-sql >"$artifact_copy_sql_file"
chmod 0600 "$artifact_copy_sql_file"
{
  printf '%s\n' "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;"
  printf '%s\n' "SET LOCAL statement_timeout = '15s';"
  printf '%s\n' "SET LOCAL lock_timeout = '2s';"
  cat "$artifact_copy_sql_file"
  printf '%s\n' "COMMIT;"
} >"$artifact_query_file"
chmod 0600 "$artifact_query_file"
run_bounded 15 install -m 0600 \
  "$secrets_directory/dispatcher-capability-public.pem" "$dispatch_public_key"
run_bounded 15 install -m 0600 \
  "$secrets_directory/executor-result-public.pem" "$result_public_key"

printf '==> Validating stub-only Compose resolution and temporary bind sources\n'
run_bounded 60 env COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
  --project-name "$project" --env-file "$environment_file" --file "$compose_file" \
  --profile '*' config --services >"$base_service_list_file"
node "$helper" check-service-list "$base_service_list_file"
compose 60 config --format json >"$compose_config_file"
node "$helper" check-compose "$compose_config_file" \
  --project "$project" \
  --secrets "$secrets_directory" \
  --history "$history_directory" \
  --api-port "$api_port" \
  --gateway-port "$gateway_port" \
  --web-port "$web_port" \
  --backend-image "$backend_image" \
  --postgres-image "$postgres_image" \
  --web-image "$web_image"
rm -f "$compose_config_file" "$base_service_list_file"

# This evidence point is deliberately after all image builds and before the
# first Compose operation that may create a project network.
initialize_host_nft_evidence

printf '==> Starting the unique stub-ai Compose project\n'
compose_may_exist=true
compose 360 up --detach --wait --wait-timeout 240 --no-build

container_ids=()
while IFS= read -r container_id; do
  [[ -z "$container_id" ]] || container_ids+=("$container_id")
done < <(compose 30 ps --all --quiet)
if ((${#container_ids[@]} == 0)); then
  printf 'ERROR: Compose project has no containers.\n' >&2
  exit 1
fi
run_bounded 30 docker inspect "${container_ids[@]}" >"$runtime_inspect_file"
chmod 0600 "$runtime_inspect_file"
run_bounded 30 docker network inspect none \
  --format '{"Id":{{json .Id}},"Name":{{json .Name}},"Driver":{{json .Driver}},"Containers":{{json .Containers}}}' \
  >"$none_network_inspection_file"
chmod 0600 "$none_network_inspection_file"
node "$helper" check-runtime "$runtime_inspect_file" \
  --project "$project" \
  --backend-image "$backend_image" \
  --postgres-image "$postgres_image" \
  --web-image "$web_image" \
  --none-network-id "$none_network_id" \
  --none-network-inspection "$none_network_inspection_file"
rm -f "$runtime_inspect_file" "$none_network_inspection_file"
executor_id="$(compose 30 ps --quiet executor)"
gateway_id="$(compose 30 ps --quiet gateway)"
postgres_id="$(compose 30 ps --quiet postgres)"
detector_id="$(compose 30 ps --quiet detector)"
validationworker_id="$(compose 30 ps --quiet validationworker)"
test -n "$executor_id"
test -n "$gateway_id"
test -n "$postgres_id"
test -n "$detector_id"
test -n "$validationworker_id"
diagnostic_ready=true
printf 'PASS: core services are healthy; Gateway is unprivileged and executor owns NET_ADMIN.\n'

curl --connect-timeout 3 --max-time 10 --fail --silent --show-error --output /dev/null \
  "http://127.0.0.1:$api_port/health/ready"
curl --connect-timeout 3 --max-time 10 --fail --silent --show-error --output /dev/null \
  "http://127.0.0.1:$web_port/health/live"
curl --connect-timeout 3 --max-time 10 --fail --silent --show-error --output /dev/null \
  --header 'Host: localhost:8080' "http://127.0.0.1:$gateway_port/health/ready"

printf '==> Proving the origin network is unreachable from an edge-only client\n'
if run_transient "$project-origin-isolation" \
  --network "${project}_edge" \
  --ip 203.0.113.250 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --entrypoint /usr/bin/wget \
  "$backend_image" \
  -q -O /dev/null -T 3 http://172.30.0.10:8081/; then
  printf 'ERROR: edge-only client reached the private origin network.\n' >&2
  exit 1
fi
printf 'PASS: private origin is not directly reachable from edge.\n'

printf '==> Parsing the evidence-chain SQL against migrated PostgreSQL\n'
preflight_evidence_chain_sql

printf '==> Waiting for actual trusted cold-start coverage across the fixed detector window\n'
wait_for_cold_start_coverage

printf '==> Running every frozen scenario from a distinct direct peer\n'
run_scenario normal 203.0.113.21 2026072101
run_scenario path-scan 203.0.113.22 2026072102
run_scenario request-burst 203.0.113.23 2026072103
run_scenario brute-force 203.0.113.24 2026072104
run_scenario credential-stuffing 203.0.113.20 2026072105
if ! capture_detection_diagnostics "after-scenarios"; then
  printf 'DEMO_E2E_DIAGNOSTIC_UNAVAILABLE stage=after-scenarios\n' >&2
fi

printf '==> Waiting for scenario detect drain and stable incident/policy bindings\n'
wait_for_detection_stability

printf '==> Exercising web-proxied session, cookie, CSRF, exact HIL, action, and audit\n'
current_stage="approve"
run_bounded 900 node "$helper" approve \
  --base-url "http://127.0.0.1:$web_port/" \
  --origin "http://localhost:$web_port" \
  --credentials "$credentials_file" \
  --output "$e2e_state_file" \
  --mode "$e2e_mode" \
  --timeout-seconds 300
current_stage="post-approve"
read -r persisted_mode action_target_ipv4 approved_ttl < <(node "$helper" state-summary "$e2e_state_file")
if [[ "$persisted_mode" != "$e2e_mode" || "$action_target_ipv4" != "203.0.113.20" ||
  "$approved_ttl" != "1800" ]]; then
  printf 'ERROR: approved E2E state is invalid.\n' >&2
  exit 1
fi
if ! read -r active_state active_remaining _active_digest < <(wait_for_nft_active "$action_target_ipv4"); then
  printf 'ERROR: the exact approved artifact was not added to the Gateway namespace nft set.\n' >&2
  exit 1
fi
if [[ "$active_state" != "active" ]] || ((active_remaining > approved_ttl)); then
  printf 'ERROR: initial nft read-back exceeded the approved TTL.\n' >&2
  exit 1
fi
if probe_gateway "$action_target_ipv4" blocked-approved-target; then
  printf 'ERROR: the approved source still reached the protected Gateway port.\n' >&2
  exit 1
fi
probe_gateway 203.0.113.26 unblocked-control
run_bounded 420 node "$helper" verify-inspected \
  --base-url "http://127.0.0.1:$web_port/" \
  --origin "http://localhost:$web_port" \
  --credentials "$credentials_file" \
  --state "$e2e_state_file" \
  --timeout-seconds 300
printf 'PASS: one exact HIL artifact is active, source-scoped, and independently inspected.\n'
hold_for_browser_qa active

if [[ "$e2e_mode" == "fast_revoke" ]]; then
  printf '==> Proving a digest-mismatched revoke decision fails closed\n'
  run_bounded 120 node "$helper" prove-revoke-negative \
    --base-url "http://127.0.0.1:$web_port/" \
    --origin "http://localhost:$web_port" \
    --credentials "$credentials_file" \
    --state "$e2e_state_file"
  read -r negative_state negative_remaining _negative_digest < <(read_nft_state "$action_target_ipv4")
  if [[ "$negative_state" != "active" ]] || ((negative_remaining > active_remaining)); then
    printf 'ERROR: rejected revoke changed kernel state or refreshed TTL.\n' >&2
    exit 1
  fi
  if probe_gateway "$action_target_ipv4" negative-revoke-still-blocked; then
    printf 'ERROR: rejected revoke removed the protected source.\n' >&2
    exit 1
  fi

  printf '==> Revoking the exact action through HIL and the isolated executor\n'
  run_bounded 420 node "$helper" revoke \
    --base-url "http://127.0.0.1:$web_port/" \
    --origin "http://localhost:$web_port" \
    --credentials "$credentials_file" \
    --state "$e2e_state_file" \
    --timeout-seconds 300
  read -r revoked_state _revoked_remaining _revoked_digest < <(read_nft_state "$action_target_ipv4")
  if [[ "$revoked_state" != "absent" ]]; then
    printf 'ERROR: exact revoke did not remove its bound target.\n' >&2
    exit 1
  fi
  probe_gateway "$action_target_ipv4" revoked-forwarding
  probe_gateway 203.0.113.26 unblocked-after-revoke
  if ! validate_persisted_evidence \
  "$evidence_before_file" "$journal_before_snapshot" "$journal_before_raw" \
  "$validation_before_journal" "revoked"; then
    printf 'ERROR: DB evidence and executor journal did not converge after revoke.\n' >&2
    exit 1
  fi
  printf 'PASS: exact add, inspection, revoke, signed results, and audits converged.\n'
  hold_for_browser_qa revoked
else
  if ! validate_persisted_evidence \
  "$evidence_before_file" "$journal_before_snapshot" "$journal_before_raw" \
  "$validation_before_journal" "active"; then
    printf 'ERROR: active DB evidence and executor journal did not converge.\n' >&2
    exit 1
  fi
fi

printf '==> Proving control-plane outage does not stop forwarding or create authority\n'
current_stage="control-plane-outage"
compose 60 stop --timeout 10 api detector validationworker lifecycleworker stubworker dispatcher >/dev/null
run_scenario path-scan 203.0.113.25 2026072199
if [[ "$e2e_mode" == "fast_revoke" ]]; then
  probe_gateway "$action_target_ipv4" outage-revoked-forwarding
else
  if probe_gateway "$action_target_ipv4" outage-active-still-blocked; then
    printf 'ERROR: control-plane outage removed the active block.\n' >&2
    exit 1
  fi
fi
read -r outage_state _outage_ttl _outage_digest < <(read_nft_state 203.0.113.25)
if [[ "$outage_state" != "absent" ]]; then
  printf 'ERROR: control-plane outage created a new adaptive block.\n' >&2
  exit 1
fi
# Recover only the long-running control-plane services. Do not ask Compose to
# reconcile the whole project here: that would re-run one-shot services such
# as migrate/history-importer and can turn a restart probe into a migration
# bootstrap attempt.
compose 360 up --no-deps --detach --wait --wait-timeout 240 --no-build \
  api detector validationworker lifecycleworker stubworker dispatcher
printf 'PASS: Gateway behavior continued while the control plane was stopped; no new block appeared.\n'

printf '==> Restarting dispatcher and executor for journal/DB reconciliation\n'
# The executor shares the live Gateway network namespace. Restarting Gateway
# would intentionally discard that namespace and the native timeout element;
# the lifecycle contract treats that early disappearance as failed rather than
# silently re-adding it. This reconciliation probe therefore restarts only the
# dispatcher and executor, proving persisted-journal recovery preserves the
# existing element and cannot refresh its TTL.
compose 60 restart --timeout 10 dispatcher >/dev/null
compose 60 restart --timeout 10 executor >/dev/null
compose 360 up --no-deps --detach --wait --wait-timeout 240 --no-build \
  dispatcher executor
executor_id="$(compose 30 ps --quiet executor)"
postgres_id="$(compose 30 ps --quiet postgres)"
sleep 3
read -r restart_state restart_remaining _restart_digest < <(read_nft_state "$action_target_ipv4")
if [[ "$e2e_mode" == "fast_revoke" ]]; then
  if [[ "$restart_state" != "absent" ]]; then
    printf 'ERROR: restart replayed the revoked add.\n' >&2
    exit 1
  fi
else
  if [[ "$restart_state" != "active" ]] || ((restart_remaining > active_remaining)); then
    printf 'ERROR: restart removed the active block or refreshed its TTL.\n' >&2
    exit 1
  fi
fi
restart_evidence_phase="active"
if [[ "$e2e_mode" == "fast_revoke" ]]; then
  restart_evidence_phase="revoked"
fi
if ! validate_persisted_evidence \
  "$evidence_after_file" "$journal_after_snapshot" "$journal_after_raw" \
  "$validation_after_journal" "$restart_evidence_phase"; then
  printf 'ERROR: DB evidence and executor journal did not converge after restart.\n' >&2
  exit 1
fi
node "$helper" journal-compare "$journal_before_snapshot" "$journal_after_snapshot" \
  --before-raw "$journal_before_raw" --after-raw "$journal_after_raw" \
  --state "$e2e_state_file" --phase "$restart_evidence_phase"
if ! cmp -s "$evidence_before_file" "$evidence_after_file"; then
  printf 'ERROR: selected immutable DB evidence changed across restart.\n' >&2
  exit 1
fi
run_bounded 180 node "$helper" verify-restart \
  --base-url "http://127.0.0.1:$web_port/" \
  --origin "http://localhost:$web_port" \
  --credentials "$credentials_file" \
  --state "$e2e_state_file"
read -r outage_after_state _outage_after_ttl _outage_after_digest < <(read_nft_state 203.0.113.25)
if [[ "$outage_after_state" != "absent" ]]; then
  printf 'ERROR: restored control plane enforced an unapproved outage incident.\n' >&2
  exit 1
fi
if [[ "$e2e_mode" == "fast_revoke" ]]; then
  probe_gateway "$action_target_ipv4" restart-revoked-forwarding
  printf 'NON-RELEASE PASS: --fast preserved exact revoke evidence across outage and restart.\n'
  printf 'NON-RELEASE: native TTL expiry is covered only by the default release gate.\n'
else
  if probe_gateway "$action_target_ipv4" restart-active-still-blocked; then
    printf 'ERROR: restart removed the active block.\n' >&2
    exit 1
  fi
  printf 'PASS: restart preserved the active action without re-adding or refreshing TTL.\n'
  printf '==> Release gate: waiting remaining kernel TTL<=%ss plus grace=%ss using shell monotonic time\n' \
    "$restart_remaining" "$expiry_grace_seconds"
  expiry_deadline=$((SECONDS + restart_remaining + expiry_grace_seconds))
  next_progress=$((SECONDS + 60))
  while ((SECONDS < expiry_deadline)); do
    remaining_wait=$((expiry_deadline - SECONDS))
    sleep_for=15
    if ((remaining_wait < sleep_for)); then
      sleep_for="$remaining_wait"
    fi
    sleep "$sleep_for"
    if ((SECONDS >= next_progress && SECONDS < expiry_deadline)); then
      printf '... TTL expiry gate remaining <= %ss\n' "$((expiry_deadline - SECONDS))"
      next_progress=$((SECONDS + 60))
    fi
  done
  read -r expired_state _expired_ttl _expired_digest < <(read_nft_state "$action_target_ipv4")
  if [[ "$expired_state" != "absent" ]]; then
    printf 'ERROR: approved nft element did not expire natively within bounded grace.\n' >&2
    exit 1
  fi
  probe_gateway "$action_target_ipv4" expired-forwarding
  current_stage="verify-expired"
  if ! run_bounded 180 node "$helper" verify-expired \
    --base-url "http://127.0.0.1:$web_port/" \
    --origin "http://localhost:$web_port" \
    --credentials "$credentials_file" \
    --state "$e2e_state_file" \
    --timeout-seconds 120; then
    if ! capture_expiry_diagnostics; then
      printf 'DEMO_E2E_EXPIRY_DIAGNOSTIC_UNAVAILABLE stage=verify-expired\n' >&2
    fi
    exit 1
  fi
  if ! validate_persisted_evidence \
    "$evidence_terminal_file" "$terminal_journal_snapshot" "$terminal_journal_raw" \
    "$validation_terminal_journal" "expired"; then
    printf 'ERROR: terminal expiry artifacts and recovery evidence did not converge.\n' >&2
    exit 1
  fi
  printf 'PASS: native TTL expiry, signed absent inspection, terminal action, forwarding, audit, and recovery converged.\n'
fi

printf '==> Removing only the exact Compose project and checking host nftables afterward\n'
remove_exact_project
compose_may_exist=false
if ! project_resources_absent; then
  printf 'ERROR: exact Compose cleanup left labeled resources.\n' >&2
  exit 1
fi
finish_host_nft_evidence
if ! remove_exact_images; then
  printf 'ERROR: unique E2E images remained after exact cleanup.\n' >&2
  exit 1
fi
images_may_exist=false

if [[ "$release_mode" == true ]]; then
  if [[ "$release_qualified" == true ]]; then
    printf 'PASS: SentinelFlow stub-ai Compose release E2E gate completed.\n'
  else
    printf 'UNVERIFIED: release qualification withheld because %s.\n' "$release_unverified_reason" >&2
    exit 1
  fi
else
  printf 'PASS: SentinelFlow stub-ai Compose developer smoke completed (non-release).\n'
fi
