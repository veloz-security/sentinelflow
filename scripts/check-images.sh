#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C
export NO_COLOR=1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
  printf 'container/image gate failed: %s\n' "$*" >&2
  exit 1
}

for command in awk docker find grep install mktemp node shasum tar; do
  command -v "$command" >/dev/null 2>&1 ||
    fail "required tool is unavailable: $command"
done
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
docker buildx version >/dev/null 2>&1 || fail "Docker Buildx is unavailable"
docker compose version >/dev/null 2>&1 || fail "Docker Compose is unavailable"

scanner_image="aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
buildkit_builder_image="moby/buildkit:v0.23.2@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e"
scanner_database="ghcr.io/aquasecurity/trivy-db:2@sha256:dfb24f192c02d06a1c467c87177b61e67bfb816d86b6d8d55d52e29329f83035"
prometheus_image="prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80"
# These are verification-only receipt digests, not activation capabilities or
# runtime authority. The migration runner validates only their strict receipt
# file contract and pins them in the disposable image-gate database.
demo_analysis_receipt="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
demo_validation_receipt="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

temporary="$(mktemp -d "${TMPDIR:-/tmp}/sentinelflow-images.XXXXXX")"
run_id="${temporary##*.}"
containers=()
images=()
networks=()
volumes=()
buildx_builder=""
scanner_preexisting=false
prometheus_preexisting=false
exported_report_directory=""
exported_reports_complete=false

if docker image inspect "$scanner_image" >/dev/null 2>&1; then
  scanner_preexisting=true
fi
if docker image inspect "$prometheus_image" >/dev/null 2>&1; then
  prometheus_preexisting=true
fi

cleanup() {
  local item
  if ((${#containers[@]} > 0)); then
    for item in "${containers[@]}"; do
      docker container rm --force "$item" >/dev/null 2>&1 || true
    done
  fi
  if ((${#networks[@]} > 0)); then
    for item in "${networks[@]}"; do
      docker network rm "$item" >/dev/null 2>&1 || true
    done
  fi
  if ((${#volumes[@]} > 0)); then
    for item in "${volumes[@]}"; do
      docker volume rm "$item" >/dev/null 2>&1 || true
    done
  fi
  if ((${#images[@]} > 0)); then
    for item in "${images[@]}"; do
      docker image rm "$item" >/dev/null 2>&1 || true
    done
  fi
  if [[ "$scanner_preexisting" == false ]]; then
    docker image rm "$scanner_image" >/dev/null 2>&1 || true
  fi
  if [[ "$prometheus_preexisting" == false ]]; then
    docker image rm "$prometheus_image" >/dev/null 2>&1 || true
  fi
  if [[ -n "$exported_report_directory" && "$exported_reports_complete" == false ]]; then
    find "$exported_report_directory" -depth -delete 2>/dev/null || true
  fi
  if [[ -n "$buildx_builder" ]]; then
    docker buildx rm --force "$buildx_builder" >/dev/null 2>&1 || true
  fi
  find "$temporary" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$temporary/cache" "$temporary/reports" "$temporary/work"

buildx_builder="sentinelflow-supply-chain-$run_id"
docker buildx create \
  --name "$buildx_builder" \
  --driver docker-container \
  --driver-opt "image=$buildkit_builder_image" \
  --use >/dev/null || fail "unable to create the pinned OCI-capable BuildKit builder"

context_snapshot="$temporary/context"
context_archive="$temporary/context.tar"
mkdir -m 0700 "$context_snapshot"
if find cmd contracts internal \
  deployments/Dockerfile.backend \
  deployments/Dockerfile.postgres \
  deployments/Dockerfile.web \
  deployments/nginx.conf \
  -type l -print -quit | grep -q .; then
  fail "container build inputs must not contain symbolic links"
fi
if find web \
  \( -path web/node_modules -o \
    -path web/dist -o \
    -path web/coverage -o \
    -path web/output -o \
    -path web/playwright-report -o \
    -path web/test-results \) -prune -o \
  -type l -print -quit | grep -q .; then
  fail "container build inputs must not contain symbolic links"
fi
tar -cf "$context_archive" \
  --exclude='web/coverage' \
  --exclude='web/dist' \
  --exclude='web/node_modules' \
  --exclude='web/output' \
  --exclude='web/playwright-report' \
  --exclude='web/test-results' \
  .dockerignore go.mod go.sum cmd contracts internal \
  deployments/Dockerfile.backend \
  deployments/Dockerfile.postgres \
  deployments/Dockerfile.web \
  deployments/nginx.conf \
  web
tar -xf "$context_archive" -C "$context_snapshot"
find "$context_archive" -delete

printf 'images: static image, action, and dependency pin policy\n'
node --test scripts/supply-chain-policy.test.mjs
node scripts/supply-chain-policy.mjs check

compose_config="$temporary/compose.json"
POSTGRES_DB=sentinelflow \
POSTGRES_USER=postgres \
POSTGRES_PASSWORD=synthetic-container-gate \
DATABASE_API_PASSWORD=synthetic-container-gate \
DATABASE_WORKER_PASSWORD=synthetic-container-gate \
DATABASE_READ_PASSWORD=synthetic-container-gate \
DATABASE_DISPATCHER_PASSWORD=synthetic-container-gate \
DATABASE_RETENTION_PASSWORD=synthetic-container-gate \
DATABASE_LIFECYCLE_PASSWORD=synthetic-container-gate \
DATABASE_METRICS_PASSWORD=synthetic-container-gate \
DATABASE_DEMO_IMPORTER_PASSWORD=synthetic-demo-importer-container-gate \
DATABASE_DEMO_ACTIVATOR_PASSWORD=synthetic-demo-activator-container-gate \
OPENAI_API_KEY= \
GATEWAY_EVENT_HMAC_KEY= \
AUTH_EVENT_HMAC_KEY= \
AUTH_ACCOUNT_HASH_KEY= \
SESSION_HMAC_KEY= \
docker compose --env-file .env.example --file deployments/compose.yaml \
  --profile '*' config --format json >"$compose_config"
node scripts/supply-chain-policy.mjs verify-compose-runtime "$compose_config"

build_image() {
  local kind="$1"
  local dockerfile="$2"
  local tag="$3"
  local oci_output="$temporary/work/$kind.$(basename "$tag").oci.tar"
  local -a build_arguments
  build_arguments=(
    --output "type=oci,dest=$oci_output,rewrite-timestamp=true"
    --pull
    --no-cache
    --provenance=false
    --sbom=false
    --build-arg SOURCE_DATE_EPOCH=0
    --tag "$tag"
    --file "$dockerfile"
  )
  if [[ "$kind" == backend ]]; then
    build_arguments+=(--build-arg VERSION=supply-chain-verification)
  fi
  docker buildx build "${build_arguments[@]}" "$context_snapshot"
  docker load --input "$oci_output" >/dev/null
  find "$oci_output" -delete
  docker image inspect "$tag" >"$temporary/work/$kind.$(basename "$tag").inspect.json"
  node scripts/supply-chain-policy.mjs verify-image-inspection \
    "$kind" "$temporary/work/$kind.$(basename "$tag").inspect.json"
}

printf 'images: reproducible no-cache application builds\n'
for kind in backend postgres web; do
  dockerfile="deployments/Dockerfile.$kind"
  first_tag="sentinelflow/$kind:supply-chain-$run_id-a"
  second_tag="sentinelflow/$kind:supply-chain-$run_id-b"
  images+=("$first_tag" "$second_tag")
  build_image "$kind" "$dockerfile" "$first_tag"
  build_image "$kind" "$dockerfile" "$second_tag"
  first_id="$(docker image inspect --format '{{.Id}}' "$first_tag")"
  second_id="$(docker image inspect --format '{{.Id}}' "$second_tag")"
  [[ "$first_id" == "$second_id" ]] ||
    fail "$kind no-cache builds are not byte-reproducible"
done

backend_image="sentinelflow/backend:supply-chain-$run_id-a"
postgres_image="sentinelflow/postgres:supply-chain-$run_id-a"
web_image="sentinelflow/web:supply-chain-$run_id-a"

printf 'images: unprivileged read-only runtime dependency probes\n'
backend_probe="sentinelflow-backend-probe-$run_id"
containers+=("$backend_probe")
if ! docker run --rm --name "$backend_probe" \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
  --entrypoint /bin/sh \
  "$backend_image" -eux -c '
    contract=/app/contracts/enforcement/nft_base_chain_v1.nft
    test "$(id -u):$(id -g)" = "65532:65532"
    test -s /etc/ssl/certs/ca-certificates.crt
    test -x /usr/sbin/nft
    nft --version >/dev/null
    test -r "$contract"
    find /app/contracts -type d -exec sh -eu -c '\''
      for path do
        test "$(stat -c "%a:%u:%g" "$path")" = "555:0:0"
      done
    '\'' sh {} +
    find /app/contracts -type f -exec sh -eu -c '\''
      for path do
        test "$(stat -c "%a:%u:%g" "$path")" = "444:0:0"
      done
    '\'' sh {} +
    root_options=
    while read -r _ mount_target _ mount_options _; do
      if test "$mount_target" = "/"; then
        root_options="$mount_options"
        break
      fi
    done </proc/mounts
    case ",$root_options," in
      *,ro,*) ;;
      *) echo "root filesystem mount is not read-only" >&2; exit 1 ;;
    esac
    if touch /sentinelflow-rootfs-write-probe; then
      echo "root filesystem accepted a write probe" >&2
      exit 1
    fi
    for field in CapInh CapPrm CapEff CapBnd CapAmb; do
      grep -Eq "^${field}:[[:space:]]*0000000000000000$" /proc/self/status
    done
  '; then
  fail "backend unprivileged read-only runtime dependency probe failed"
fi

web_probe="sentinelflow-web-probe-$run_id"
containers+=("$web_probe")
if ! docker run --rm --name "$web_probe" \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
  --entrypoint /bin/sh \
  "$web_image" -eux -c '
    config=/etc/nginx/conf.d/default.conf
    test "$(id -u):$(id -g)" = "101:101"
    test -r "$config"
    test "$(stat -c "%a:%u:%g" "$config")" = "444:0:0"
    find /usr/share/nginx/html -type d -exec sh -eu -c '\''
      for path do
        test "$(stat -c "%a:%u:%g" "$path")" = "555:0:0"
      done
    '\'' sh {} +
    find /usr/share/nginx/html -type f -exec sh -eu -c '\''
      for path do
        test "$(stat -c "%a:%u:%g" "$path")" = "444:0:0"
      done
    '\'' sh {} +
    root_options=
    while read -r _ mount_target _ mount_options _; do
      if test "$mount_target" = "/"; then
        root_options="$mount_options"
        break
      fi
    done </proc/mounts
    case ",$root_options," in
      *,ro,*) ;;
      *) echo "root filesystem mount is not read-only" >&2; exit 1 ;;
    esac
    if touch /sentinelflow-rootfs-write-probe; then
      echo "root filesystem accepted a write probe" >&2
      exit 1
    fi
    for field in CapInh CapPrm CapEff CapBnd CapAmb; do
      grep -Eq "^${field}:[[:space:]]*0000000000000000$" /proc/self/status
    done
    nginx -t >/dev/null
  '; then
  fail "web unprivileged read-only nginx probe failed"
fi

docker pull "$prometheus_image" >/dev/null
docker image inspect "$prometheus_image" >"$temporary/work/prometheus.inspect.json"
node scripts/supply-chain-policy.mjs verify-image-inspection \
  prometheus "$temporary/work/prometheus.inspect.json"

prometheus_probe="sentinelflow-prometheus-probe-$run_id"
containers+=("$prometheus_probe")
if ! docker run --rm --name "$prometheus_probe" \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
  "$prometheus_image" --version >/dev/null; then
  fail "Prometheus unprivileged read-only entrypoint probe failed"
fi

printf 'images: immutable scanner and vulnerability database acquisition\n'
docker pull "$scanner_image" >/dev/null
scanner_repo_digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$scanner_image")"
grep -Fxq \
  'aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e' \
  <<<"$scanner_repo_digest" || fail "Trivy image repo digest differs"

scanner_version_container="sentinelflow-trivy-version-$run_id"
containers+=("$scanner_version_container")
scanner_version="$(
  docker run --rm --name "$scanner_version_container" \
    --network none \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
    "$scanner_image" --version
)"
node scripts/supply-chain-policy.mjs verify-scanner-version "$scanner_version"

scanner_db_container="sentinelflow-trivy-db-$run_id"
containers+=("$scanner_db_container")
docker run --rm --name "$scanner_db_container" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  --mount "type=bind,source=$temporary/cache,target=/root/.cache/trivy" \
  "$scanner_image" image \
  --download-db-only \
  --db-repository "$scanner_database" \
  --no-progress
node scripts/supply-chain-policy.mjs verify-scanner-db "$temporary/cache/db"

scan_image() {
  local kind="$1"
  local reference="$2"
  local image_manifest_id
  local image_config_id
  local config_path
  local archive_binding
  local config_digest
  local scan_container
  local sbom_container
  local work_directory="$temporary/work/$kind"
  local report="$temporary/reports/$kind.vulnerabilities.json"
  local sbom="$temporary/reports/$kind.spdx.json"

  mkdir -m 0700 "$work_directory"
  image_manifest_id="$(docker image inspect --format '{{.Id}}' "$reference")"
  docker image save --output "$work_directory/image.tar" "$reference"
  tar -xOf "$work_directory/image.tar" index.json \
    >"$work_directory/index.json"
  tar -xOf "$work_directory/image.tar" manifest.json \
    >"$work_directory/manifest.json"
  archive_binding="$(
    node scripts/supply-chain-policy.mjs verify-image-archive \
      "$image_manifest_id" \
      "$work_directory/index.json" \
      "$work_directory/manifest.json"
  )"
  image_config_id="${archive_binding%%$'\t'*}"
  config_path="${archive_binding#*$'\t'}"
  [[ "$image_config_id" != "$archive_binding" && -n "$config_path" ]] ||
    fail "$kind image archive binding result is malformed"
  config_digest="$(
    tar -xOf "$work_directory/image.tar" "$config_path" |
      shasum -a 256 |
      awk '{print $1}'
  )"
  [[ "sha256:$config_digest" == "$image_config_id" ]] ||
    fail "$kind image archive config blob checksum differs"

  scan_container="sentinelflow-trivy-scan-$kind-$run_id"
  containers+=("$scan_container")
  docker run --rm --name "$scan_container" \
    --network none \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m \
    --mount "type=bind,source=$temporary/cache,target=/root/.cache/trivy" \
    --mount "type=bind,source=$work_directory,target=/work" \
    "$scanner_image" image \
    --input /work/image.tar \
    --skip-db-update \
    --skip-version-check \
    --offline-scan \
    --scanners vuln \
    --severity CRITICAL \
    --format json \
    --output /work/vulnerabilities.json \
    --timeout 5m \
    --no-progress
  install -m 0600 "$work_directory/vulnerabilities.json" "$report"
  node scripts/supply-chain-policy.mjs verify-vulnerability-report \
    "$reference" "$image_config_id" "$report"

  sbom_container="sentinelflow-trivy-sbom-$kind-$run_id"
  containers+=("$sbom_container")
  docker run --rm --name "$sbom_container" \
    --network none \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m \
    --mount "type=bind,source=$temporary/cache,target=/root/.cache/trivy" \
    --mount "type=bind,source=$work_directory,target=/work" \
    "$scanner_image" image \
    --input /work/image.tar \
    --skip-db-update \
    --skip-version-check \
    --offline-scan \
    --scanners vuln \
    --format spdx-json \
    --output /work/spdx.json \
    --timeout 5m \
    --no-progress
  install -m 0600 "$work_directory/spdx.json" "$sbom"
  node scripts/supply-chain-policy.mjs verify-image-sbom "$sbom"

  IMAGE_KIND="$kind" IMAGE_REFERENCE="$reference" \
    IMAGE_MANIFEST_ID="$image_manifest_id" IMAGE_CONFIG_ID="$image_config_id" \
    node -e '
      const fs = require("node:fs");
      const crypto = require("node:crypto");
      const output = process.argv[1];
      const record = {
        schema_version: "sentinelflow-image-evidence-v1",
        image_kind: process.env.IMAGE_KIND,
        image_reference: process.env.IMAGE_REFERENCE,
        image_manifest_id: process.env.IMAGE_MANIFEST_ID,
        image_config_id: process.env.IMAGE_CONFIG_ID,
        scanner_image: process.argv[2],
        scanner_database: process.argv[3],
        vulnerability_report_sha256: crypto.createHash("sha256").update(fs.readFileSync(process.argv[4])).digest("hex"),
        spdx_sha256: crypto.createHash("sha256").update(fs.readFileSync(process.argv[5])).digest("hex"),
      };
      fs.writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    ' \
    "$temporary/reports/$kind.evidence.json" \
    "$scanner_image" "$scanner_database" "$report" "$sbom"
}

printf 'images: offline CRITICAL vulnerability policy and runtime SPDX inventories\n'
scan_image backend "$backend_image"
scan_image postgres "$postgres_image"
scan_image web "$web_image"
scan_image prometheus "$prometheus_image"

printf 'images: non-root PostgreSQL fresh-volume, migration, restart, and ownership gates\n'
postgres_network="sentinelflow-postgres-network-$run_id"
postgres_volume="sentinelflow-postgres-volume-$run_id"
postgres_container="sentinelflow-postgres-runtime-$run_id"
demo_receipt_volume="sentinelflow-postgres-demo-receipts-$run_id"
demo_receipt_initializer="sentinelflow-postgres-demo-receipt-init-$run_id"
networks+=("$postgres_network")
volumes+=("$postgres_volume")
volumes+=("$demo_receipt_volume")
containers+=("$postgres_container")
containers+=("$demo_receipt_initializer")
docker network create --label sentinelflow.test=container-gate "$postgres_network" >/dev/null
docker volume create --label sentinelflow.test=container-gate "$postgres_volume" >/dev/null
docker volume create --label sentinelflow.test=container-gate "$demo_receipt_volume" >/dev/null
docker run --rm --name "$demo_receipt_initializer" \
  --network none \
  --user 0:0 \
  --read-only \
  --cap-drop ALL \
  --cap-add CHOWN \
  --security-opt no-new-privileges:true \
  --env "ANALYSIS_RECEIPT=$demo_analysis_receipt" \
  --env "VALIDATION_RECEIPT=$demo_validation_receipt" \
  --mount "type=volume,source=$demo_receipt_volume,target=/receipts" \
  "$postgres_image" /bin/sh -eu -c '
    test "$ANALYSIS_RECEIPT" != "$VALIDATION_RECEIPT"
    printf "%s\\n" "$ANALYSIS_RECEIPT" >/receipts/analysis.sha256
    printf "%s\\n" "$VALIDATION_RECEIPT" >/receipts/validation.sha256
    chown 0:70 /receipts /receipts/analysis.sha256 /receipts/validation.sha256
    chmod 0750 /receipts
    chmod 0440 /receipts/analysis.sha256 /receipts/validation.sha256
    test "$(stat -c "%u:%g:%a:%s" /receipts/analysis.sha256)" = "0:70:440:72"
    test "$(stat -c "%u:%g:%a:%s" /receipts/validation.sha256)" = "0:70:440:72"
    test "$(find /receipts -mindepth 1 -maxdepth 1 | wc -l)" -eq 2
  '
docker run --detach --name "$postgres_container" \
  --network "$postgres_network" \
  --network-alias postgres \
  --user 70:70 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777,uid=70,gid=70 \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,nodev,size=4m,mode=0750,uid=70,gid=70 \
  --env POSTGRES_DB=sentinelflow \
  --env POSTGRES_USER=postgres \
  --env POSTGRES_PASSWORD=synthetic-container-gate \
  --env POSTGRES_INITDB_ARGS='--auth-host=scram-sha-256 --auth-local=scram-sha-256' \
  --mount "type=volume,source=$postgres_volume,target=/var/lib/postgresql/data" \
  "$postgres_image" >/dev/null

wait_for_postgres() {
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "$postgres_container" pg_isready -q \
      --username postgres --dbname sentinelflow; then
      return
    fi
    if ! docker container inspect --format '{{.State.Running}}' \
      "$postgres_container" 2>/dev/null | grep -Fxq true; then
      docker logs "$postgres_container" >&2 || true
      fail "non-root PostgreSQL stopped before readiness"
    fi
    sleep 1
  done
  docker logs "$postgres_container" >&2 || true
  fail "non-root PostgreSQL did not become ready"
}
wait_for_postgres

docker exec "$postgres_container" sh -eu -c '
  test "$(id -u):$(id -g)" = "70:70"
  test ! -e /usr/local/bin/gosu
  test -w "$PGDATA"
  test -w /tmp
  test -w /var/run/postgresql
  ! touch /sentinelflow-rootfs-write-probe 2>/dev/null
  test "$(stat -c "%u:%g" "$PGDATA")" = "70:70"
  for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    grep -Eq "^${field}:[[:space:]]*0000000000000000$" /proc/self/status
  done
'

run_migrations() {
  local name="sentinelflow-postgres-migrate-$run_id-$1"
  containers+=("$name")
  docker run --rm --name "$name" \
    --network "$postgres_network" \
    --user 70:70 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 64 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
    --env PGHOST=postgres \
    --env PGPORT=5432 \
    --env PGPASSWORD=synthetic-container-gate \
    --env POSTGRES_DB=sentinelflow \
    --env POSTGRES_USER=postgres \
    --env SENTINELFLOW_ENV=demo \
    --env DATABASE_API_PASSWORD=synthetic-container-gate \
    --env DATABASE_WORKER_PASSWORD=synthetic-container-gate \
    --env DATABASE_READ_PASSWORD=synthetic-container-gate \
    --env DATABASE_DISPATCHER_PASSWORD=synthetic-container-gate \
    --env DATABASE_RETENTION_PASSWORD=synthetic-container-gate \
    --env DATABASE_LIFECYCLE_PASSWORD=synthetic-container-gate \
    --env DATABASE_METRICS_PASSWORD=synthetic-container-gate \
    --env DATABASE_DEMO_IMPORTER_PASSWORD=synthetic-demo-importer-container-gate \
    --env DATABASE_DEMO_ACTIVATOR_PASSWORD=synthetic-demo-activator-container-gate \
    --mount "type=bind,source=$repo_root/deployments/postgres/init.sh,target=/opt/sentinelflow/init.sh,readonly" \
    --mount "type=bind,source=$repo_root/db/migrations,target=/migrations,readonly" \
    --mount "type=volume,source=$demo_receipt_volume,target=/run/sentinelflow-demo-history-capability-receipts,readonly" \
    "$postgres_image" /opt/sentinelflow/init.sh
}

run_migrations initial
ledger_before="$(
  docker exec --env PGPASSWORD=synthetic-container-gate "$postgres_container" \
    psql --no-psqlrc -qAt --username postgres --dbname sentinelflow \
    --command 'SELECT count(*)::text || '"'"':'"'"' || max(version)::text FROM sentinelflow.schema_migrations'
)"
docker restart "$postgres_container" >/dev/null
wait_for_postgres
run_migrations restart
ledger_after="$(
  docker exec --env PGPASSWORD=synthetic-container-gate "$postgres_container" \
    psql --no-psqlrc -qAt --username postgres --dbname sentinelflow \
    --command 'SELECT count(*)::text || '"'"':'"'"' || max(version)::text FROM sentinelflow.schema_migrations'
)"
[[ "$ledger_before" == "$ledger_after" ]] ||
  fail "migration restart changed the exact migration ledger"

wrong_volume="sentinelflow-postgres-wrong-owner-$run_id"
wrong_container="sentinelflow-postgres-wrong-owner-$run_id"
volumes+=("$wrong_volume")
containers+=("$wrong_container")
docker volume create --label sentinelflow.test=container-gate "$wrong_volume" >/dev/null
set +e
docker run --name "$wrong_container" \
  --network none \
  --user 70:70 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777,uid=70,gid=70 \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,nodev,size=4m,mode=0750,uid=70,gid=70 \
  --env POSTGRES_DB=sentinelflow \
  --env POSTGRES_USER=postgres \
  --env POSTGRES_PASSWORD=synthetic-container-gate \
  --mount "type=volume,source=$wrong_volume,target=/var/lib/postgresql/data,volume-nocopy" \
  "$postgres_image" >"$temporary/work/wrong-owner.stdout" \
  2>"$temporary/work/wrong-owner.stderr"
wrong_status=$?
set -e
[[ "$wrong_status" -ne 0 ]] ||
  fail "PostgreSQL accepted a root-owned volume without an explicit ownership migration"
grep -Eqi 'permission denied|operation not permitted' \
  "$temporary/work/wrong-owner.stderr" "$temporary/work/wrong-owner.stdout" ||
  fail "wrong-owner PostgreSQL failure did not identify the permission boundary"

if [[ -n "${SENTINELFLOW_IMAGE_REPORT_DIR:-}" ]]; then
  output_parent="$(dirname "$SENTINELFLOW_IMAGE_REPORT_DIR")"
  output_parent="$(cd "$output_parent" && pwd)"
  output_directory="$output_parent/$(basename "$SENTINELFLOW_IMAGE_REPORT_DIR")"
  case "$output_directory" in
    "$repo_root" | "$repo_root"/*)
      fail "refusing to place image reports inside the repository"
      ;;
  esac
  [[ ! -e "$output_directory" && ! -L "$output_directory" ]] ||
    fail "refusing to overwrite image report directory"
  mkdir -m 0700 "$output_directory"
  exported_report_directory="$output_directory"
  for report in "$temporary/reports"/*.json; do
    install -m 0600 "$report" "$output_directory/$(basename "$report")"
  done
  exported_reports_complete=true
  printf 'images: verified reports copied to %s\n' "$(basename "$output_directory")"
fi

printf '%s\n' \
  'images: passed' \
  "scanner: $scanner_image" \
  "vulnerability database: $scanner_database" \
  'policy: every shipped runtime image has a validated OS-package SPDX inventory and zero unexcepted CRITICAL findings' \
  'PostgreSQL limitation: a pre-existing volume not owned by fixed UID/GID 70:70 fails closed and requires an explicit offline ownership migration'
