#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

unformatted="$(gofmt -l cmd internal)"
if [[ -n "$unformatted" ]]; then
  printf 'gofmt required:\n%s\n' "$unformatted" >&2
  exit 1
fi

go vet ./cmd/... ./internal/...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./cmd/... ./internal/...
go test ./cmd/... ./internal/...
go build ./cmd/...
