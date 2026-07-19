#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
observability_root="$repository_root/deployments/observability"
image="prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80"
probe_image="postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
network="sentinelflow-prometheus-verify-$$"
container="sentinelflow-prometheus-verify-$$"
probe_observability_network="sentinelflow-observability-probe-$$"
probe_edge_network="sentinelflow-edge-probe-$$"
probe_gateway="sentinelflow-gateway-probe-$$"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker rm -f "$probe_gateway" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker network rm "$probe_observability_network" >/dev/null 2>&1 || true
  docker network rm "$probe_edge_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

docker pull "$image" >/dev/null
image_contract="$(docker image inspect "$image" \
  --format '{{index .Config.Labels "io.prometheus.image.variant"}} {{.Config.User}} {{.Os}}')"
if [[ "$image_contract" != "distroless 65532 linux" ]]; then
  printf '%s\n' 'ERROR: reviewed Prometheus distroless image contract changed' >&2
  exit 1
fi

docker run --rm --entrypoint /bin/promtool \
  --volume "$observability_root:/etc/prometheus:ro" \
  "$image" check config /etc/prometheus/prometheus.yml
docker run --rm --entrypoint /bin/promtool \
  --volume "$observability_root:/etc/prometheus:ro" \
  "$image" check rules /etc/prometheus/control-plane-alerts.yaml
docker run --rm --entrypoint /bin/promtool \
  --volume "$observability_root:/etc/prometheus:ro" \
  "$image" test rules /etc/prometheus/control-plane-alerts.test.yaml

compose_json="$(docker compose -f "$repository_root/deployments/compose.yaml" \
  config --format json 2>/dev/null)"
jq -e --arg image "$image" '
  .services.prometheus.image == $image and
  .services.prometheus.user == "65532:65532" and
  .services.prometheus.read_only == true and
  .services.prometheus.cap_drop == ["ALL"] and
  .services.prometheus.cpus == 0.5 and
  .services.prometheus.mem_limit == "268435456" and
  ((.services.prometheus.ports // []) | length == 0) and
  (.services.prometheus.networks | keys == ["observability"]) and
  .services.prometheus.networks.observability.ipv4_address == "172.29.0.4" and
  .services.gateway.networks.observability.ipv4_address == "172.29.0.2" and
  .services.gateway.networks.edge.ipv4_address == "203.0.113.10" and
  .services.gateway.environment.GATEWAY_LISTEN_ADDR == "203.0.113.10:8080" and
  .services.gateway.environment.GATEWAY_METRICS_LISTEN_ADDR == "172.29.0.2:9090" and
  (.services.gateway.healthcheck.test[1] | contains("http://203.0.113.10:8080/health/ready")) and
  (.services.gateway.healthcheck.test[1] | contains("http://172.29.0.2:9090/metrics")) and
  (.services.gateway.ports | length == 1) and
  .services.gateway.ports[0].host_ip == "127.0.0.1" and
  .services.gateway.ports[0].target == 8080 and
  .services.controlmetricsexporter.networks.observability.ipv4_address == "172.29.0.3" and
  .networks.observability.internal == true
' >/dev/null <<<"$compose_json"

# Reproduce the production multi-interface bind shape in a disposable network
# namespace. An observability-only peer can reach the metrics listener but not
# the data listener, while an edge-only peer proves the data listener exists.
docker pull "$probe_image" >/dev/null
docker network create --internal --subnet 172.29.241.0/24 \
  "$probe_observability_network" >/dev/null
docker network create --internal --subnet 198.51.100.240/28 \
  "$probe_edge_network" >/dev/null
docker create --name "$probe_gateway" \
  --network "$probe_observability_network" --ip 172.29.241.2 \
  --entrypoint /bin/sh "$probe_image" -ec '
    nc -lk -s 172.29.241.2 -p 9090 -e /bin/cat &
    exec nc -lk -s 198.51.100.242 -p 8080 -e /bin/cat
  ' >/dev/null
docker network connect --ip 198.51.100.242 \
  "$probe_edge_network" "$probe_gateway"
docker start "$probe_gateway" >/dev/null
for _attempt in $(seq 1 20); do
  if docker run --rm --network "$probe_observability_network" \
      --entrypoint /usr/bin/nc "$probe_image" -z -w 1 172.29.241.2 9090 &&
     docker run --rm --network "$probe_edge_network" \
      --entrypoint /usr/bin/nc "$probe_image" -z -w 1 198.51.100.242 8080; then
    break
  fi
  if [[ "$_attempt" == "20" ]]; then
    printf '%s\n' 'ERROR: interface-isolation probe listeners did not become ready' >&2
    exit 1
  fi
  sleep 0.1
done
docker run --rm --network "$probe_observability_network" \
  --entrypoint /bin/sh "$probe_image" -ec '
    nc -z -w 1 172.29.241.2 9090
    ! nc -z -w 1 172.29.241.2 8080
  '

docker network create --internal --subnet 172.29.240.0/24 "$network" >/dev/null
docker run --detach --name "$container" \
  --network "$network" --ip 172.29.240.4 \
  --user 65532:65532 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --cpus 0.50 --memory 256m \
  --tmpfs /prometheus:rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=65532,gid=65532 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777 \
  --volume "$observability_root/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  --volume "$observability_root/control-plane-alerts.yaml:/etc/prometheus/control-plane-alerts.yaml:ro" \
  "$image" \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time=24h \
  --storage.tsdb.retention.size=48MB \
  --web.listen-address=172.29.240.4:9090 >/dev/null

for _attempt in $(seq 1 20); do
  if docker exec "$container" /bin/promtool check ready \
      --url=http://172.29.240.4:9090 >/dev/null 2>&1; then
    docker exec "$container" /bin/promtool query instant \
      http://172.29.240.4:9090 prometheus_build_info >/dev/null
    printf '%s\n' 'PASS: Prometheus config, alerts, image, resources, interface isolation, and runtime smoke verified'
    exit 0
  fi
  sleep 0.25
done

docker logs "$container" >&2
printf '%s\n' 'ERROR: Prometheus did not become ready' >&2
exit 1
