#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

patterns='(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|password[[:space:]]*[:=][[:space:]]*["'"'][^"'"']{8,}["'"'])'
violations=()
while IFS= read -r -d '' file; do
  if [[ -f "$file" ]] && rg -q --pcre2 "$patterns" "$file"; then
    violations+=("$file")
  fi
done < <(git ls-files -co --exclude-standard -z)

if (( ${#violations[@]} > 0 )); then
  printf 'possible committed secret material in:\n' >&2
  printf '  %s\n' "${violations[@]}" >&2
  exit 1
fi

go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./cmd/... ./internal/...
npm --prefix web audit --audit-level=high
