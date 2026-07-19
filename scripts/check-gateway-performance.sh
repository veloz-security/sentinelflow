#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

mode="${SENTINELFLOW_GATEWAY_PERF_MODE:-release}"
case "$mode" in
  release)
    duration=5m
    warmup=10s
    outage_duration=10s
    expected_gate_mode=five-minute
    expected_result_duration=5m0s
    allow_short=0
    ;;
  smoke)
    duration=5s
    warmup=2s
    outage_duration=3s
    expected_gate_mode=development
    expected_result_duration=5s
    allow_short=1
    ;;
  *)
    printf '%s\n' 'ERROR: SENTINELFLOW_GATEWAY_PERF_MODE must be release or smoke' >&2
    exit 1
    ;;
esac

for forbidden in \
  SENTINELFLOW_GATEWAY_PERF_DURATION \
  SENTINELFLOW_GATEWAY_PERF_WARMUP \
  SENTINELFLOW_GATEWAY_PERF_OUTAGE_DURATION \
  SENTINELFLOW_GATEWAY_PERF_ALLOW_SHORT; do
  if [[ -n "${!forbidden:-}" ]]; then
    printf 'ERROR: %s is fixed by SENTINELFLOW_GATEWAY_PERF_MODE and cannot be overridden\n' "$forbidden" >&2
    exit 1
  fi
done

memory_bytes=unknown
if [[ -r /sys/fs/cgroup/memory.max ]]; then
  candidate="$(tr -d '[:space:]' </sys/fs/cgroup/memory.max)"
  if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
    memory_bytes="$candidate"
  fi
fi
if [[ "$memory_bytes" == unknown && -r /proc/meminfo ]]; then
  candidate="$(awk '/^MemTotal:/ { print $2 * 1024; exit }' /proc/meminfo)"
  if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
    memory_bytes="$candidate"
  fi
fi
if [[ "$memory_bytes" == unknown ]] && command -v sysctl >/dev/null 2>&1; then
  candidate="$(sysctl -n hw.memsize 2>/dev/null || true)"
  if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
    memory_bytes="$candidate"
  fi
fi

cpu_count=unknown
if command -v getconf >/dev/null 2>&1; then
  candidate="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
  if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
    cpu_count="$candidate"
  fi
fi
if [[ "$cpu_count" == unknown ]] && command -v sysctl >/dev/null 2>&1; then
  candidate="$(sysctl -n hw.ncpu 2>/dev/null || true)"
  if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
    cpu_count="$candidate"
  fi
fi

reference_memory=0
if [[ "$memory_bytes" =~ ^[1-9][0-9]*$ ]] &&
   (( memory_bytes >= 3758096384 && memory_bytes <= 4831838208 )); then
  reference_memory=1
fi
printf 'HOST_PROFILE os=%s arch=%s memory_bytes=%s cpu_count=%s reference_4gb=%s\n' \
  "$(uname -s)" "$(uname -m)" "$memory_bytes" "$cpu_count" "$reference_memory"
printf 'WORKLOAD mode=%s duration=%s warmup=%s outage=%s rps=500 added_p95_limit_us=5000\n' \
  "$mode" "$duration" "$warmup" "$outage_duration"

# These focused checks prove that a rejected or saturated EventSink cannot
# alter forwarding and that bounded queue overflow is surfaced in metrics.
# They are correctness prerequisites, not substitutes for the load run.
env -u GOFLAGS -u GOMAXPROCS go test -count=1 -timeout=2m \
  -run '^TestGatewayEventSinkFailureNeverBlocksForwarding$' ./internal/gateway
env -u GOFLAGS -u GOMAXPROCS go test -count=1 -timeout=2m \
  -run '^TestSenderMetricsExposeQueueOverflowWithoutBlocking$' ./internal/eventsender

result_file="$(mktemp "${TMPDIR:-/tmp}/sentinelflow-gateway-perf.XXXXXX")"
cleanup() {
  rm -f "$result_file"
}
trap cleanup EXIT INT TERM HUP

set +e
env -u GOFLAGS -u GOMAXPROCS \
  SENTINELFLOW_GATEWAY_PERF=1 \
  SENTINELFLOW_GATEWAY_PERF_DURATION="$duration" \
  SENTINELFLOW_GATEWAY_PERF_WARMUP="$warmup" \
  SENTINELFLOW_GATEWAY_PERF_OUTAGE_DURATION="$outage_duration" \
  SENTINELFLOW_GATEWAY_PERF_ALLOW_SHORT="$allow_short" \
  go test -count=1 -timeout=12m -run '^TestGatewayPerformanceGate$' -v ./internal/gateway \
  2>&1 | tee "$result_file"
test_status=${PIPESTATUS[0]}
set -e
if (( test_status != 0 )); then
  printf 'GATE_VERDICT=failed reason=load_test_exit_%d\n' "$test_status" >&2
  exit "$test_status"
fi

gate_count="$(grep -c 'GATE_RESULT ' "$result_file" || true)"
if [[ "$gate_count" != 1 ]]; then
  printf 'ERROR: expected exactly one GATE_RESULT line, got %s\n' "$gate_count" >&2
  exit 1
fi
gate_line="$(grep 'GATE_RESULT ' "$result_file")"
gate_line="${gate_line#*GATE_RESULT }"
mode_value= duration_value= rps_value= direct_p95_us_value=
gateway_p95_us_value= added_p95_us_value= outage_direct_p95_us_value=
outage_gateway_p95_us_value= outage_added_p95_us_value= accepted_value= dropped_value=
mode_seen= duration_seen= rps_seen= direct_p95_us_seen=
gateway_p95_us_seen= added_p95_us_seen= outage_direct_p95_us_seen=
outage_gateway_p95_us_seen= outage_added_p95_us_seen= accepted_seen= dropped_seen=
field_count=0
for field in $gate_line; do
  if [[ ! "$field" =~ ^([a-z][a-z0-9_]*)=([a-z0-9-]+)$ ]]; then
    printf 'ERROR: malformed GATE_RESULT field %q\n' "$field" >&2
    exit 1
  fi
  key="${BASH_REMATCH[1]}"
  value="${BASH_REMATCH[2]}"
  case "$key" in
    mode|duration|rps|direct_p95_us|gateway_p95_us|added_p95_us|outage_direct_p95_us|outage_gateway_p95_us|outage_added_p95_us|accepted|dropped) ;;
    *)
      printf 'ERROR: unreviewed GATE_RESULT field %s\n' "$key" >&2
      exit 1
      ;;
  esac
  eval "seen=\${${key}_seen}"
  if [[ "$seen" == 1 ]]; then
    printf 'ERROR: duplicate GATE_RESULT field %s\n' "$key" >&2
    exit 1
  fi
  printf -v "${key}_value" '%s' "$value"
  printf -v "${key}_seen" '%s' 1
  field_count=$((field_count + 1))
done

required=(mode duration rps direct_p95_us gateway_p95_us added_p95_us
  outage_direct_p95_us outage_gateway_p95_us outage_added_p95_us accepted dropped)
for key in "${required[@]}"; do
  eval "seen=\${${key}_seen}"
  if [[ "$seen" != 1 ]]; then
    printf 'ERROR: missing GATE_RESULT field %s\n' "$key" >&2
    exit 1
  fi
done
if (( field_count != ${#required[@]} )); then
  printf '%s\n' 'ERROR: GATE_RESULT contains an unreviewed field' >&2
  exit 1
fi
for key in rps direct_p95_us gateway_p95_us added_p95_us outage_direct_p95_us \
  outage_gateway_p95_us outage_added_p95_us accepted dropped; do
  eval "value=\${${key}_value}"
  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    printf 'ERROR: non-canonical numeric GATE_RESULT field %s\n' "$key" >&2
    exit 1
  fi
done
if [[ "$mode_value" != "$expected_gate_mode" ||
      "$duration_value" != "$expected_result_duration" ||
      "$rps_value" != 500 ]]; then
  printf '%s\n' 'ERROR: performance workload identity drifted from the fixed contract' >&2
  exit 1
fi
if (( added_p95_us_value > 5000 || outage_added_p95_us_value > 5000 )); then
  printf '%s\n' 'ERROR: independently parsed proxy-added p95 exceeds 5000 microseconds' >&2
  exit 1
fi
if (( accepted_value == 0 || dropped_value == 0 )); then
  printf '%s\n' 'ERROR: healthy acceptance or visible outage-drop evidence is missing' >&2
  exit 1
fi
if ! grep -q 'resources: heap_before=' "$result_file" ||
   ! grep -q 'errors=0 status=0 parity=0' "$result_file"; then
  printf '%s\n' 'ERROR: throughput, parity, error, or resource evidence is missing' >&2
  exit 1
fi

if [[ "$mode" == smoke ]]; then
  printf 'GATE_VERDICT=non_release_smoke added_p95_us=%s outage_added_p95_us=%s\n' \
    "$added_p95_us_value" "$outage_added_p95_us_value"
  exit 0
fi
if (( reference_memory != 1 )); then
  printf 'GATE_VERDICT=unverified reason=host_is_not_detected_4gb_reference added_p95_us=%s outage_added_p95_us=%s\n' \
    "$added_p95_us_value" "$outage_added_p95_us_value" >&2
  exit 3
fi
printf 'GATE_VERDICT=pass reference_4gb=1 added_p95_us=%s outage_added_p95_us=%s\n' \
  "$added_p95_us_value" "$outage_added_p95_us_value"
