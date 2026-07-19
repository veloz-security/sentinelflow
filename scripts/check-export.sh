#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image='postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193'
container="sentinelflow-export-check-$$"
temporary="$(mktemp -d /tmp/sentinelflow-export-check.XXXXXX)"
chmod 0700 "$temporary"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [[ -d "$temporary" && ! -L "$temporary" ]]; then
    find "$temporary" -depth -delete
  fi
}
trap cleanup EXIT INT TERM HUP

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

bash -n "$repo_root/scripts/check-export.sh"
(
  cd "$repo_root"
  go test -race -count=3 ./internal/exportbundle ./cmd/exporttool >/dev/null
  go vet ./internal/exportbundle ./cmd/exporttool
  node --test scripts/contract-vectors.test.mjs >/dev/null
  CGO_ENABLED=0 go build -o "$temporary/sentinelflow-exporttool" ./cmd/exporttool
)
chmod 0755 "$temporary/sentinelflow-exporttool"

docker pull "$image" >/dev/null
docker run -d --rm \
  --name "$container" \
  --env POSTGRES_PASSWORD=sentinelflow-export-test-only \
  --publish 127.0.0.1::5432 \
  "$image" >/dev/null

published_port="$(docker port "$container" 5432/tcp)"
published_port="${published_port##*:}"
[[ "$published_port" =~ ^[0-9]+$ ]] || fail 'published PostgreSQL port was not canonical'

# The image entrypoint may expose a short-lived Unix-socket-only bootstrap
# postmaster before the final TCP listener. Require three consecutive queries
# through the final listener so createdb cannot race that handoff.
ready_streak=0
for _attempt in $(seq 1 120); do
  if docker exec --env PGPASSWORD=sentinelflow-export-test-only "$container" \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 --host 127.0.0.1 \
    --username postgres --dbname postgres --tuples-only --no-align \
    --command 'SELECT 1' >/dev/null 2>&1; then
    ready_streak="$((ready_streak + 1))"
  else
    ready_streak=0
  fi
  if [[ "$ready_streak" -ge 3 ]]; then
    break
  fi
  sleep 0.25
done
[[ "$ready_streak" -ge 3 ]] || fail 'disposable PostgreSQL 17 final TCP server did not become stable'

docker exec --env PGPASSWORD=sentinelflow-export-test-only "$container" \
  createdb --host 127.0.0.1 --username postgres sentinelflow
for migration in "$repo_root"/db/migrations/*.up.sql; do
  docker exec -i "$container" \
    psql --set=ON_ERROR_STOP=1 --username postgres --dbname sentinelflow \
    < "$migration" >/dev/null
done

docker exec -i "$container" \
  psql --set=ON_ERROR_STOP=1 --username postgres --dbname sentinelflow >/dev/null <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE sentinelflow_export_login LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'export-test-only';
GRANT sentinelflow_read TO sentinelflow_export_login
  WITH INHERIT FALSE, SET TRUE;
CREATE ROLE sentinelflow_export_wrong LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'wrong-test-only';
CREATE ROLE sentinelflow_export_aux NOLOGIN;
CREATE ROLE sentinelflow_export_extra LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'extra-test-only';
GRANT sentinelflow_read TO sentinelflow_export_extra
  WITH INHERIT FALSE, SET TRUE;
GRANT sentinelflow_export_aux TO sentinelflow_export_extra
  WITH INHERIT FALSE, SET TRUE;
CREATE ROLE sentinelflow_export_direct LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'direct-test-only';
GRANT sentinelflow_read TO sentinelflow_export_direct
  WITH INHERIT FALSE, SET TRUE;
GRANT SELECT ON sentinelflow.incidents TO sentinelflow_export_direct;
CREATE ROLE sentinelflow_export_admin LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'admin-test-only';
GRANT sentinelflow_read TO sentinelflow_export_admin
  WITH ADMIN TRUE, INHERIT FALSE, SET TRUE;
SQL

capability_login="$(docker exec "$container" psql --set=ON_ERROR_STOP=1 --username postgres \
  --dbname sentinelflow --tuples-only --no-align \
  --command "SELECT rolcanlogin::text FROM pg_catalog.pg_roles WHERE rolname = 'sentinelflow_read';")"
[[ "$capability_login" == "false" ]] || fail 'sentinelflow_read capability was weakened to LOGIN'

docker exec -i "$container" \
  psql --set=ON_ERROR_STOP=1 --username postgres --dbname sentinelflow >/dev/null <<'SQL'
SET search_path = sentinelflow, pg_catalog;
INSERT INTO sentinelflow.incidents (
  incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
  deterministic_score, version, created_at, updated_at
) VALUES (
  '019b0000-0000-4000-8000-00000000e101', 'path_scan', 'open',
  '198.51.100.42', 'demo_app', '2026-07-18T01:00:00Z',
  '2026-07-18T01:02:00Z', 0.9, 1,
  '2026-07-18T01:00:00Z', '2026-07-18T01:02:00Z'
);
INSERT INTO sentinelflow.incidents (
  incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
  deterministic_score, version, created_at, updated_at
) VALUES (
  '019b0000-0000-4000-8000-00000000e102', 'request_burst', 'open',
  '198.51.100.43', 'demo_app', '2026-06-01T01:00:00Z',
  '2026-06-01T01:02:00Z', 0.8, 1,
  '2026-06-01T01:00:00Z', '2026-06-01T01:02:00Z'
);
INSERT INTO sentinelflow.audit_events (
  event_id, actor_type, actor_id, action, object_type, object_id,
  incident_id, trace_id, primary_digest, outcome, occurred_at, recorded_at
) VALUES (
  '019b0000-0000-4000-8000-00000000e201', 'administrator', 'admin.alice',
  'incident_reviewed', 'incident', '019b0000-0000-4000-8000-00000000e101',
  '019b0000-0000-4000-8000-00000000e101',
  '019b0000-0000-4000-8000-00000000e301',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'accepted', '2026-07-18T01:03:00Z', '2026-07-18T01:03:01Z'
);
SQL

if docker exec "$container" psql --set=ON_ERROR_STOP=1 --username sentinelflow_export_login \
  --dbname sentinelflow --command \
  "BEGIN; SET LOCAL ROLE sentinelflow_read; UPDATE sentinelflow.incidents SET state = 'closed'; COMMIT;" \
  >/dev/null 2>&1; then
	fail 'delegated sentinelflow_read capability unexpectedly mutated incident state'
fi

database_url="postgresql://sentinelflow_export_login:export-test-only@127.0.0.1:${published_port}/sentinelflow?sslmode=disable"

printf '%s\n' 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY' > "$temporary/pseudonym.key"
chmod 0600 "$temporary/pseudonym.key"

env -i \
  PATH="$PATH" \
  SENTINELFLOW_ENV=test \
  DATABASE_READ_URL="$database_url" \
  "$temporary/sentinelflow-exporttool" create \
  --output "$temporary/export.json" \
  --pseudonym-key-file "$temporary/pseudonym.key" \
  --pseudonym-key-id export-test-v1 \
  --since 2026-07-18T00:00:00Z \
  --until 2026-07-18T23:59:59Z \
  --max-incidents 10 \
  --max-audit-events 10 > "$temporary/create-result.json"

env -i PATH="$PATH" "$temporary/sentinelflow-exporttool" verify \
  --input "$temporary/export.json" > "$temporary/verify-result.json"

env -i \
  PATH="$PATH" \
  SENTINELFLOW_ENV=test \
  DATABASE_READ_URL="$database_url" \
  "$temporary/sentinelflow-exporttool" create \
  --output "$temporary/outside-window.json" \
  --pseudonym-key-file "$temporary/pseudonym.key" \
  --pseudonym-key-id export-test-v1 \
  --since 2026-07-18T00:00:00Z \
  --until 2026-07-18T23:59:59Z \
  --incident-id 019b0000-0000-4000-8000-00000000e102 > "$temporary/outside-result.json"
grep -Fq '"incident_count":0' "$temporary/outside-result.json" ||
  fail 'exact incident filter escaped the manifest time window'

if grep -Fq '198.51.100.42' "$temporary/export.json" ||
   grep -Fq 'admin.alice' "$temporary/export.json" ||
   grep -Fq '019b0000-0000-4000-8000-00000000e301' "$temporary/export.json"; then
  fail 'export leaked a raw source, actor, or trace identifier'
fi
grep -Fq '019b0000-0000-4000-8000-00000000e101' "$temporary/export.json" ||
  fail 'export omitted the incident traceability identifier'
grep -Fq 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$temporary/export.json" || fail 'export omitted the source audit digest'

if [[ "$(uname -s)" == 'Darwin' ]]; then
  mode="$(stat -f '%Lp' "$temporary/export.json")"
else
  mode="$(stat -c '%a' "$temporary/export.json")"
fi
[[ "$mode" == "600" ]] || fail 'export file is not mode 0600'

cp "$temporary/export.json" "$temporary/tampered.json"
perl -0pi -e 's/"kind": "path_scan"/"kind": "request_burst"/' "$temporary/tampered.json"
if env -i PATH="$PATH" "$temporary/sentinelflow-exporttool" verify \
  --input "$temporary/tampered.json" >/dev/null 2>&1; then
  fail 'tampered export passed verification'
fi

wrong_database_url="postgresql://sentinelflow_export_wrong:wrong-test-only@127.0.0.1:${published_port}/sentinelflow?sslmode=disable"
if env -i \
  PATH="$PATH" \
  SENTINELFLOW_ENV=test \
	DATABASE_READ_URL="$wrong_database_url" \
  "$temporary/sentinelflow-exporttool" create \
  --output "$temporary/wrong-role.json" \
  --pseudonym-key-file "$temporary/pseudonym.key" \
  --pseudonym-key-id export-test-v1 \
  --since 2026-07-18T00:00:00Z \
  --until 2026-07-18T23:59:59Z >/dev/null 2>&1; then
  fail 'export accepted a non-reader database role'
fi

extra_database_url="postgresql://sentinelflow_export_extra:extra-test-only@127.0.0.1:${published_port}/sentinelflow?sslmode=disable"
if env -i \
  PATH="$PATH" \
  SENTINELFLOW_ENV=test \
	DATABASE_READ_URL="$extra_database_url" \
  "$temporary/sentinelflow-exporttool" create \
  --output "$temporary/extra-role.json" \
  --pseudonym-key-file "$temporary/pseudonym.key" \
  --pseudonym-key-id export-test-v1 \
  --since 2026-07-18T00:00:00Z \
  --until 2026-07-18T23:59:59Z >/dev/null 2>&1; then
  fail 'export accepted a login with more than one capability membership'
fi

direct_database_url="postgresql://sentinelflow_export_direct:direct-test-only@127.0.0.1:${published_port}/sentinelflow?sslmode=disable"
if env -i \
  PATH="$PATH" \
  SENTINELFLOW_ENV=test \
	DATABASE_READ_URL="$direct_database_url" \
  "$temporary/sentinelflow-exporttool" create \
  --output "$temporary/direct-role.json" \
  --pseudonym-key-file "$temporary/pseudonym.key" \
  --pseudonym-key-id export-test-v1 \
  --since 2026-07-18T00:00:00Z \
  --until 2026-07-18T23:59:59Z >/dev/null 2>&1; then
  fail 'export accepted a deployment login with direct table authority'
fi

admin_database_url="postgresql://sentinelflow_export_admin:admin-test-only@127.0.0.1:${published_port}/sentinelflow?sslmode=disable"
if env -i \
  PATH="$PATH" \
  SENTINELFLOW_ENV=test \
	DATABASE_READ_URL="$admin_database_url" \
  "$temporary/sentinelflow-exporttool" create \
  --output "$temporary/admin-role.json" \
  --pseudonym-key-file "$temporary/pseudonym.key" \
  --pseudonym-key-id export-test-v1 \
  --since 2026-07-18T00:00:00Z \
  --until 2026-07-18T23:59:59Z >/dev/null 2>&1; then
  fail 'export accepted an administrator-capable read membership'
fi

printf '%s\n' 'PASS: delegated read capability, privacy export scope, redaction, chain, file, and tamper gates'
