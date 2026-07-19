#!/usr/bin/env bash

set -euo pipefail

network="sf-preflight-net-$$"
gateway="sf-preflight-gateway-$$"
client_ip="203.0.113.20"
control_ip="203.0.113.21"
gateway_ip="203.0.113.10"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_chain_contract="$repo_root/contracts/enforcement/nft_base_chain_v1.nft"
base_chain_expected_sha256="2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488"
alpine_image="alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

cleanup() {
  docker rm -f "$gateway" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

command -v docker >/dev/null
docker info >/dev/null
test -f "$base_chain_contract"
test "$(sha256_file "$base_chain_contract")" = "$base_chain_expected_sha256"

docker network create --subnet 203.0.113.0/24 "$network" >/dev/null
docker run -d --rm \
  --name "$gateway" \
  --network "$network" \
  --ip "$gateway_ip" \
  "$alpine_image" \
  sh -ec \
  'apk add --no-cache busybox-extras=1.37.0-r31 >/dev/null && mkdir -p /www && printf sentinel-ok > /www/index.html && exec httpd -f -p 8080 -h /www' \
  >/dev/null

before=""
for _attempt in {1..15}; do
  if before="$(
    docker run --rm \
      --network "$network" \
      --ip "$client_ip" \
      "$alpine_image" \
      wget -qO- -T 2 "http://$gateway_ip:8080/" 2>/dev/null
  )"; then
    break
  fi
  sleep 0.2
done
test "$before" = "sentinel-ok"

docker run --rm \
  --network "container:$gateway" \
  --cap-add NET_ADMIN \
  --volume "$base_chain_contract:/contracts/nft_base_chain_v1.nft:ro" \
  "$alpine_image" \
  sh -ec '
    apk add --no-cache nftables=1.1.6-r1 >/dev/null
    nft -f /contracts/nft_base_chain_v1.nft
    printf "%s\n" "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }" | nft --check -f -
    printf "%s\n" "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }" | nft -f -
  ' \
  >/dev/null

if docker run --rm \
  --network "$network" \
  --ip "$client_ip" \
  "$alpine_image" \
  wget -qO- -T 2 "http://$gateway_ip:8080/" \
  >/dev/null 2>&1; then
  echo "ERROR: selected source was not blocked" >&2
  exit 1
fi

control="$(
  docker run --rm \
    --network "$network" \
    --ip "$control_ip" \
    "$alpine_image" \
    wget -qO- -T 3 "http://$gateway_ip:8080/"
)"
test "$control" = "sentinel-ok"

readback="$(
  docker run --rm \
    --network "container:$gateway" \
    --cap-add NET_ADMIN \
    "$alpine_image" \
    sh -ec 'apk add --no-cache nftables=1.1.6-r1 >/dev/null && nft list set inet sentinelflow blacklist_ipv4'
)"
printf '%s\n' "$readback" | grep -F "$client_ip timeout 1m" >/dev/null

docker run --rm \
  --network "container:$gateway" \
  --cap-add NET_ADMIN \
  "$alpine_image" \
  sh -ec '
    apk add --no-cache nftables=1.1.6-r1 >/dev/null
    printf "%s\n" "delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }" | nft -f -
  ' \
  >/dev/null

after="$(
  docker run --rm \
    --network "$network" \
    --ip "$client_ip" \
    "$alpine_image" \
    wget -qO- -T 3 "http://$gateway_ip:8080/"
)"
test "$after" = "sentinel-ok"

printf 'PASS: before=%s blocked_source=%s control=%s after_revoke=%s\n' \
  "$before" "$client_ip" "$control" "$after"
