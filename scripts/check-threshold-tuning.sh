#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d /tmp/sentinelflow-threshold-check.XXXXXX)"
chmod 0700 "$temporary"

cleanup() {
  if [[ -d "$temporary" && ! -L "$temporary" ]]; then
    find "$temporary" -depth -delete
  fi
}
trap cleanup EXIT INT TERM HUP

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

bash -n "$repo_root/scripts/check-threshold-tuning.sh"
before_digest="$(shasum -a 256 "$repo_root/internal/detection/config.go" | awk '{print $1}')"
(
  cd "$repo_root"
  go test -race -count=3 ./internal/tuning ./cmd/thresholdreport >/dev/null
  go vet ./internal/tuning ./cmd/thresholdreport
  go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./internal/tuning ./cmd/thresholdreport
  CGO_ENABLED=0 go build -o "$temporary/sentinelflow-thresholdreport" ./cmd/thresholdreport
)
chmod 0755 "$temporary/sentinelflow-thresholdreport"

"$temporary/sentinelflow-thresholdreport" compare \
  --input "$repo_root/samples/tuning/threshold_cases_v1.json" \
  --output "$temporary/report.json" \
  --author ops.qa \
  --evaluated-at 2026-07-18T05:00:00Z > "$temporary/compare-result.json"

"$temporary/sentinelflow-thresholdreport" verify \
  --input "$repo_root/samples/tuning/threshold_cases_v1.json" \
  --report "$temporary/report.json" > "$temporary/verify-result.json"

node - "$temporary/report.json" <<'NODE'
const fs = require("node:fs");
const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const byID = new Map(report.results.map((entry) => [entry.profile.profile_id, entry]));
const baseline = byID.get("baseline-v1");
const conservative = byID.get("conservative-v1");
const sensitive = byID.get("sensitive-v1");
if (!baseline || !conservative || !sensitive ||
    baseline.matrix.true_positive !== 8 || baseline.matrix.true_negative !== 8 ||
    baseline.matrix.false_positive !== 0 || baseline.matrix.false_negative !== 0 ||
    baseline.matrix.incomplete !== 4 || !baseline.activation_eligible ||
    conservative.matrix.false_negative !== 6 || conservative.activation_eligible ||
    conservative.activation_reason !== "attack_detection_regression" ||
    sensitive.matrix.false_positive !== 5 || sensitive.activation_eligible ||
    sensitive.activation_reason !== "false_positive_regression" ||
    report.recommendation !== "retain_frozen_baseline" ||
    report.selected_profile_id !== "baseline-v1" || report.activation_performed !== false) {
  process.exit(1);
}
for (const result of report.results) {
  for (const item of result.cases) {
    if (item.evidence_state !== "complete" &&
        (item.decision !== "incomplete" || item.explanation_code !== "evidence_guard_fail_closed")) {
      process.exit(1);
    }
  }
}
NODE

cp "$temporary/report.json" "$temporary/tampered.json"
perl -0pi -e 's/"false_positive": 5/"false_positive": 4/' "$temporary/tampered.json"
if "$temporary/sentinelflow-thresholdreport" verify \
  --input "$repo_root/samples/tuning/threshold_cases_v1.json" \
  --report "$temporary/tampered.json" >/dev/null 2>&1; then
  fail 'tampered threshold report passed verification'
fi

after_digest="$(shasum -a 256 "$repo_root/internal/detection/config.go" | awk '{print $1}')"
[[ "$before_digest" == "$after_digest" ]] || fail 'offline comparison mutated active detector configuration'

printf '%s\n' 'PASS: threshold baseline, candidate regressions, duplicate policy, evidence guards, and no-activation gate'
