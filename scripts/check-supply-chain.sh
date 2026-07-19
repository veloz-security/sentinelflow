#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C
export GOPROXY=https://proxy.golang.org
export GOSUMDB=sum.golang.org
export GONOSUMDB=
export NPM_CONFIG_AUDIT=false
export NPM_CONFIG_FUND=false
export NPM_CONFIG_IGNORE_SCRIPTS=true
export NPM_CONFIG_LOGLEVEL=warn
export NPM_CONFIG_REGISTRY=https://registry.npmjs.org/
export NPM_CONFIG_UPDATE_NOTIFIER=false
export NPM_CONFIG_USERCONFIG=/dev/null
export NO_COLOR=1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for command in cmp go mktemp node npm; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required supply-chain tool is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

required_go_version="$(awk '$1 == "go" { print $2 }' go.mod)"
export GOTOOLCHAIN="go${required_go_version}"
actual_go_version="$(go env GOVERSION)"
if [[ "$actual_go_version" != "go${required_go_version}" ]]; then
  printf 'Go toolchain mismatch: required go%s, found %s\n' "$required_go_version" "$actual_go_version" >&2
  exit 1
fi

temp_directory="$(mktemp -d "${TMPDIR:-/tmp}/sentinelflow-supply-chain.XXXXXX")"
exported_sbom_path=""
supply_chain_complete=false
cleanup() {
  if [[ -n "$exported_sbom_path" && "$supply_chain_complete" == false ]]; then
    find "$exported_sbom_path" -delete 2>/dev/null || true
  fi
  find "$temp_directory" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'supply-chain: static pin and dependency policy\n'
node --test scripts/supply-chain-policy.test.mjs
node scripts/supply-chain-policy.mjs check

printf 'supply-chain: Go module integrity\n'
go mod verify
go mod tidy -diff
go list -mod=readonly -deps ./cmd/... ./internal/... >/dev/null

printf 'supply-chain: npm lock and tarball integrity without lifecycle scripts\n'
npm_staging="$temp_directory/npm"
mkdir -m 0700 "$npm_staging"
install -m 0600 web/package.json web/package-lock.json "$npm_staging/"
NPM_CONFIG_CACHE="$temp_directory/npm-cache" npm --prefix "$npm_staging" ci --ignore-scripts --no-audit --no-fund

printf 'supply-chain: known-vulnerability policy\n'
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./cmd/... ./internal/...
NPM_CONFIG_CACHE="$temp_directory/npm-cache" npm --prefix "$npm_staging" audit --audit-level=critical --ignore-scripts --no-fund

printf 'supply-chain: reproducible SPDX 2.3 source-dependency SBOM\n'
first_sbom="$temp_directory/sentinelflow.first.spdx.json"
second_sbom="$temp_directory/sentinelflow.second.spdx.json"
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
SOURCE_DATE_EPOCH="$source_date_epoch" node scripts/supply-chain-policy.mjs sbom --output "$first_sbom"
SOURCE_DATE_EPOCH="$source_date_epoch" node scripts/supply-chain-policy.mjs sbom --output "$second_sbom"
if ! cmp -s "$first_sbom" "$second_sbom"; then
  printf 'SPDX SBOM generation is not reproducible\n' >&2
  exit 1
fi
node scripts/supply-chain-policy.mjs verify-sbom "$first_sbom"

if [[ -n "${SENTINELFLOW_SBOM_OUTPUT:-}" ]]; then
  output_directory="$(cd "$(dirname "$SENTINELFLOW_SBOM_OUTPUT")" && pwd)"
  output_path="$output_directory/$(basename "$SENTINELFLOW_SBOM_OUTPUT")"
  case "$output_path" in
    "$repo_root"/*)
      printf 'refusing to place generated SBOM inside the repository: %s\n' "$output_path" >&2
      exit 1
      ;;
  esac
  if [[ -e "$output_path" || -L "$output_path" ]]; then
    printf 'refusing to overwrite SBOM output: %s\n' "$output_path" >&2
    exit 1
  fi
  exported_sbom_path="$output_path"
  SOURCE_DATE_EPOCH="$source_date_epoch" node scripts/supply-chain-policy.mjs sbom --output "$output_path"
  if ! cmp -s "$first_sbom" "$output_path"; then
    printf 'exported SPDX SBOM differs from the verified artifact\n' >&2
    exit 1
  fi
  printf 'supply-chain: SPDX artifact copied to %s\n' "$(basename "$output_path")"
fi

printf 'supply-chain: reproducible runtime images, isolation, vulnerability policy, and image SBOMs\n'
./scripts/check-images.sh

printf '%s\n' \
  'supply-chain: passed' \
  'coverage note: govulncheck reports known reachable Go vulnerabilities; npm audit reports registry advisories for the complete lockfile.' \
  'coverage note: the source SPDX artifact covers Go build modules and npm lock packages; the separate image artifacts cover every shipped runtime image and its OS/package inventory.'
supply_chain_complete=true
