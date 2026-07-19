#!/usr/bin/env bash

set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
environment_file="$repo_root/.env.demo"
local_key_file="$repo_root/.env.local"
secrets_directory="$repo_root/secrets/demo"
history_directory="$repo_root/data/demo-history"
backend_image="sentinelflow/backend:demo"

command -v docker >/dev/null
command -v go >/dev/null
command -v node >/dev/null
docker info >/dev/null

if [[ -e "$environment_file" || -L "$environment_file" || -e "$secrets_directory" || -L "$secrets_directory" ||
  -e "$history_directory" || -L "$history_directory" ]]; then
  echo "Refusing to overwrite an existing .env.demo, secrets/demo, or data/demo-history bundle." >&2
  exit 1
fi

cd "$repo_root"
docker build --load \
  --progress plain \
  --tag "$backend_image" \
  --file deployments/Dockerfile.backend \
  --build-arg VERSION=local-demo \
  .

attestation="$({
  docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --entrypoint /bin/sh \
    "$backend_image" \
    -eu -c 'sha256sum /usr/sbin/nft | cut -d " " -f 1; /usr/sbin/nft --version'
})"

if [[ "$(printf '%s\n' "$attestation" | wc -l | tr -d ' ')" != "2" ]]; then
  echo "Unexpected nftables attestation output." >&2
  exit 1
fi
nft_digest="$(printf '%s\n' "$attestation" | sed -n '1p')"
nft_version_output="$(printf '%s\n' "$attestation" | sed -n '2p')"
if [[ ! "$nft_digest" =~ ^[0-9a-f]{64}$ ]] ||
  [[ ! "$nft_version_output" =~ ^nftables\ v([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?)(\ \([\ -~]{1,128}\))?$ ]]; then
  echo "The built nftables binary did not produce a canonical attestation." >&2
  exit 1
fi
nft_version="nftables v${BASH_REMATCH[1]}"

SENTINELFLOW_NFT_BINARY_SHA256="$nft_digest" \
SENTINELFLOW_NFT_VERSION="$nft_version" \
  go run ./cmd/democonfig \
    --output "$environment_file" \
    --secrets-dir "$secrets_directory" \
    --history-dir "$history_directory"

analysis_activation="$secrets_directory/demo-history-analysis-activation.capability"
validation_activation="$secrets_directory/demo-history-validation-activation.capability"
for capability in "$analysis_activation" "$validation_activation"; do
  if [[ ! -f "$capability" || -L "$capability" ]] ||
    [[ "$(wc -c <"$capability" | tr -d ' ')" != "32" ]]; then
    echo "Generated demo-history activation capability failed its file contract." >&2
    exit 1
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    capability_mode="$(stat -f '%Lp' "$capability")"
  else
    capability_mode="$(stat -c '%a' "$capability")"
  fi
  if [[ "$capability_mode" != "400" ]]; then
    echo "Generated demo-history activation capability has an unsafe mode." >&2
    exit 1
  fi
done
activation_comparison=0
cmp -s "$analysis_activation" "$validation_activation" || activation_comparison=$?
if [[ "$activation_comparison" != "1" ]]; then
  echo "Generated demo-history activation capabilities are not consumer-separated." >&2
  exit 1
fi

compose_environment=(--env-file "$environment_file")
if [[ -e "$local_key_file" ]]; then
  node scripts/import-openai-key.mjs --check
  compose_environment+=(--env-file "$local_key_file")
  docker compose \
    "${compose_environment[@]}" \
    --file deployments/compose.yaml \
    config --quiet
else
  # The core Gateway/detection profile is intentionally OpenAI-independent.
  # Supplying an empty interpolation value keeps Compose validation quiet; the
  # live-ai profile remains unusable until a checked local key and rate card
  # are supplied explicitly.
  OPENAI_API_KEY= docker compose \
    "${compose_environment[@]}" \
    --file deployments/compose.yaml \
    config --quiet
fi

echo "Demo bundle is ready. Add the operator-supplied rate card to .env.demo before enabling the live-ai profile."
