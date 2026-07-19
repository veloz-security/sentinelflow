#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const exactNpmVersionPattern =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u;
const exactGoVersionPattern =
  /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u;
const goPseudoVersionPattern =
  /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)-\d{14}-[0-9a-f]{12,}$/u;
const sha256DigestPattern = /@sha256:[0-9a-f]{64}$/u;
const fullCommitPattern = /^[0-9a-f]{40}$/u;
export const approvedPrometheusImage =
  "prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80";
export const approvedTrivyImage =
  "aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e";
export const approvedBuildkitImage =
  "moby/buildkit:v0.23.2@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e";
export const approvedTrivyDatabase =
  "ghcr.io/aquasecurity/trivy-db:2@sha256:dfb24f192c02d06a1c467c87177b61e67bfb816d86b6d8d55d52e29329f83035";
export const approvedTrivyDatabaseChecksums = Object.freeze({
  "trivy.db":
    "1b9e589f5b930a171f5c09399b7b47efb21425b6fe94cd41ebbfb2533bef34c1",
});
export const approvedTrivyDatabaseMetadata = Object.freeze({
  Version: 2,
  NextUpdate: "2026-07-19T18:43:59.213935938Z",
  UpdatedAt: "2026-07-18T18:43:59.213936274Z",
});

function commandScript(lines) {
  return `${lines.join("\n")}\n`;
}

function reviewedCommand(...argv) {
  return Object.freeze(argv);
}

// This is the reviewed, normalized Compose command contract. Keep the shell
// bodies byte-exact: checking only argv[0] would let a Compose-only change run
// arbitrary work with executor capabilities or mounted signing material before
// starting the expected healthy process.
export const reviewedComposeCommands = Object.freeze({
  api: reviewedCommand("/usr/local/bin/api"),
  controlmetricsexporter: reviewedCommand(
    "/usr/local/bin/controlmetricsexporter",
  ),
  "demo-activation-handoff": reviewedCommand(
    "/opt/sentinelflow/demo-activation-handoff.sh",
  ),
  "demo-activator": reviewedCommand("/usr/local/bin/demoactivator"),
  "demo-app": reviewedCommand("/usr/local/bin/demoapp"),
  detector: reviewedCommand("/usr/local/bin/detector"),
  dispatcher: reviewedCommand(
    "/bin/sh",
    "-eu",
    "-c",
    commandScript([
      "attempts=0",
      "while test ! -S /run/sentinelflow-executor/executor.sock; do",
      '  attempts="$$((attempts + 1))"',
      '  test "$$attempts" -lt 300 || exit 1',
      "  sleep 0.1",
      "done",
      "exec /usr/local/bin/dispatcher",
    ]),
  ),
  executor: reviewedCommand(
    "/bin/sh",
    "-eu",
    "-c",
    commandScript([
      "rm -f /run/sentinelflow-ready/executor-heartbeat",
      "/usr/local/bin/executor &",
      'child="$$!"',
      'heartbeat=""',
      "stop() {",
      '  test -z "$$heartbeat" || kill "$$heartbeat" 2>/dev/null || true',
      '  kill -TERM "$$child" 2>/dev/null || true',
      '  wait "$$child" 2>/dev/null || true',
      "  rm -f /run/sentinelflow-ready/executor-heartbeat",
      "}",
      "trap stop TERM INT EXIT",
      "attempts=0",
      "while test ! -S /run/sentinelflow-executor/executor.sock; do",
      '  kill -0 "$$child" 2>/dev/null || exit 1',
      '  attempts="$$((attempts + 1))"',
      '  test "$$attempts" -lt 300 || exit 1',
      "  sleep 0.1",
      "done",
      "(",
      '  while kill -0 "$$child" 2>/dev/null; do',
      "    touch /run/sentinelflow-ready/executor-heartbeat",
      "    sleep 1",
      "  done",
      ") &",
      'heartbeat="$$!"',
      'wait "$$child"',
    ]),
  ),
  gateway: reviewedCommand(
    "/bin/sh",
    "-eu",
    "-c",
    commandScript([
      "fresh_executor() {",
      "  test -f /run/sentinelflow-ready/executor-heartbeat || return 1",
      '  now="$$(date +%s)"',
      '  modified="$$(stat -c %Y /run/sentinelflow-ready/executor-heartbeat 2>/dev/null || echo 0)"',
      '  test "$$((now - modified))" -le 3',
      "}",
      "attempts=0",
      "until fresh_executor; do",
      '  attempts="$$((attempts + 1))"',
      '  test "$$attempts" -lt 300 || exit 1',
      "  sleep 0.1",
      "done",
      "exec /usr/local/bin/gateway",
    ]),
  ),
  "history-importer": reviewedCommand("/usr/local/bin/historyimporter"),
  lifecycleworker: reviewedCommand("/usr/local/bin/lifecycleworker"),
  migrate: reviewedCommand("/opt/sentinelflow/init.sh"),
  postgres: reviewedCommand(
    "postgres",
    "-c",
    "hba_file=/etc/postgresql/sentinelflow-pg_hba.conf",
    "-c",
    "listen_addresses=172.32.0.2",
  ),
  prometheus: reviewedCommand(
    "--config.file=/etc/prometheus/prometheus.yml",
    "--storage.tsdb.path=/prometheus",
    "--storage.tsdb.retention.time=24h",
    "--storage.tsdb.retention.size=48MB",
    "--web.listen-address=172.29.0.4:9090",
  ),
  retentionworker: reviewedCommand("/usr/local/bin/retentionworker"),
  "secret-init": reviewedCommand(
    "/bin/sh",
    "-eu",
    "-c",
    commandScript([
      "test -f /source/dispatcher-capability-private.pem",
      "test -f /source/dispatcher-capability-public.pem",
      "test -f /source/executor-result-private.pem",
      "test -f /source/executor-result-public.pem",
      "test -f /source/demo-history-analysis-activation.capability",
      "test -f /source/demo-history-validation-activation.capability",
      "test ! -L /source/demo-history-analysis-activation.capability",
      "test ! -L /source/demo-history-validation-activation.capability",
      "test \"$$(stat -c '%a' /source/demo-history-analysis-activation.capability)\" = '400'",
      "test \"$$(stat -c '%a' /source/demo-history-validation-activation.capability)\" = '400'",
      'test "$$(wc -c </source/demo-history-analysis-activation.capability)" -eq 32',
      'test "$$(wc -c </source/demo-history-validation-activation.capability)" -eq 32',
      "activation_comparison=0",
      "cmp -s /source/demo-history-analysis-activation.capability /source/demo-history-validation-activation.capability || activation_comparison=$$?",
      'test "$$activation_comparison" -eq 1',
      "chown 65532:65532 /volumes/gateway-state /volumes/auth-state",
      "chmod 0700 /volumes/gateway-state /volumes/auth-state",
      "chown 0:65532 /volumes/executor-state /volumes/executor-socket /volumes/validator-socket /volumes/readiness",
      "chmod 0750 /volumes/executor-state /volumes/executor-socket /volumes/validator-socket /volumes/readiness",
      "chown 65532:65532 /volumes/dispatcher-secrets",
      "chmod 0700 /volumes/dispatcher-secrets",
      "chown 0:65532 /volumes/executor-secrets",
      "chmod 0700 /volumes/executor-secrets",
      "chown 0:70 /volumes/demo-history-capability-receipts",
      "chmod 0750 /volumes/demo-history-capability-receipts",
      "chown 65532:65532 /volumes/demo-history-analysis-activation /volumes/demo-history-validation-activation",
      "chmod 0700 /volumes/demo-history-analysis-activation /volumes/demo-history-validation-activation",
      "install -o 65532 -g 65532 -m 0600 /source/dispatcher-capability-private.pem /volumes/dispatcher-secrets/dispatcher-capability-private.pem",
      "install -o 65532 -g 65532 -m 0644 /source/executor-result-public.pem /volumes/dispatcher-secrets/executor-result-public.pem",
      "install -o 0 -g 65532 -m 0644 /source/dispatcher-capability-public.pem /volumes/executor-secrets/dispatcher-capability-public.pem",
      "install -o 0 -g 65532 -m 0600 /source/executor-result-private.pem /volumes/executor-secrets/executor-result-private.pem",
      "analysis_digest=\"$$(sha256sum /source/demo-history-analysis-activation.capability | cut -d ' ' -f 1)\"",
      "validation_digest=\"$$(sha256sum /source/demo-history-validation-activation.capability | cut -d ' ' -f 1)\"",
      "case \"$$analysis_digest\" in *[!0-9a-f]*|'') exit 1 ;; esac",
      "case \"$$validation_digest\" in *[!0-9a-f]*|'') exit 1 ;; esac",
      'test "$${#analysis_digest}" -eq 64',
      'test "$${#validation_digest}" -eq 64',
      'test "$$analysis_digest" != "$$validation_digest"',
      "find /volumes/demo-history-capability-receipts -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +",
      "printf 'sha256:%s\\n' \"$$analysis_digest\" >/volumes/demo-history-capability-receipts/analysis.sha256",
      "printf 'sha256:%s\\n' \"$$validation_digest\" >/volumes/demo-history-capability-receipts/validation.sha256",
      "chown 0:70 /volumes/demo-history-capability-receipts/analysis.sha256 /volumes/demo-history-capability-receipts/validation.sha256",
      "chmod 0440 /volumes/demo-history-capability-receipts/analysis.sha256 /volumes/demo-history-capability-receipts/validation.sha256",
      "test \"$$(stat -c '%u:%g:%a:%s' /volumes/demo-history-capability-receipts/analysis.sha256)\" = '0:70:440:72'",
      "test \"$$(stat -c '%u:%g:%a:%s' /volumes/demo-history-capability-receipts/validation.sha256)\" = '0:70:440:72'",
      'test "$$(find /volumes/demo-history-capability-receipts -mindepth 1 -maxdepth 1 | wc -l)" -eq 2',
      "install -o 65532 -g 65532 -m 0400 /source/demo-history-analysis-activation.capability /volumes/demo-history-analysis-activation/activation-capability",
      "install -o 65532 -g 65532 -m 0400 /source/demo-history-validation-activation.capability /volumes/demo-history-validation-activation/activation-capability",
      "test \"$$(stat -c '%u:%g:%a:%s' /volumes/demo-history-analysis-activation/activation-capability)\" = '65532:65532:400:32'",
      "test \"$$(stat -c '%u:%g:%a:%s' /volumes/demo-history-validation-activation/activation-capability)\" = '65532:65532:400:32'",
      "cmp -s /source/demo-history-analysis-activation.capability /volumes/demo-history-analysis-activation/activation-capability",
      "cmp -s /source/demo-history-validation-activation.capability /volumes/demo-history-validation-activation/activation-capability",
    ]),
  ),
  simulator: reviewedCommand(
    "/usr/local/bin/simulator",
    "-gateway-url",
    "http://gateway:8080",
    "-gateway-host",
    "localhost:8080",
    "-seed",
    "20260718",
    "normal",
  ),
  stubworker: reviewedCommand("/usr/local/bin/stubworker"),
  validationworker: reviewedCommand("/usr/local/bin/validationworker"),
  validator: reviewedCommand("/usr/local/bin/validator"),
  web: null,
  worker: reviewedCommand("/usr/local/bin/worker"),
});

const expectedComposeServices = Object.freeze({
  api: {
    image: "sentinelflow/backend:demo",
    networks: ["control", "ingest", "management"],
    command: "/usr/local/bin/api",
  },
  controlmetricsexporter: {
    image: "sentinelflow/backend:demo",
    networks: ["control", "observability"],
    command: "/usr/local/bin/controlmetricsexporter",
  },
  "demo-activation-handoff": {
    image: "sentinelflow/postgres:demo",
    networks: ["control"],
    user: "70:70",
    command: "/opt/sentinelflow/demo-activation-handoff.sh",
  },
  "demo-activator": {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/demoactivator",
  },
  "demo-app": {
    image: "sentinelflow/backend:demo",
    networks: ["ingest", "origin"],
    command: "/usr/local/bin/demoapp",
  },
  detector: {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/detector",
  },
  dispatcher: {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/bin/sh",
  },
  executor: {
    image: "sentinelflow/backend:demo",
    networkMode: "service:gateway",
    user: "0:65532",
    capAdd: ["NET_ADMIN"],
    command: "/bin/sh",
  },
  gateway: {
    image: "sentinelflow/backend:demo",
    networks: ["edge", "ingest", "observability", "origin"],
    command: "/bin/sh",
  },
  "history-importer": {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/historyimporter",
  },
  lifecycleworker: {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/lifecycleworker",
  },
  migrate: {
    image: "sentinelflow/postgres:demo",
    networks: ["control"],
    user: "70:70",
    command: "/opt/sentinelflow/init.sh",
  },
  postgres: {
    image: "sentinelflow/postgres:demo",
    networks: ["control"],
    user: "70:70",
    command: "postgres",
  },
  prometheus: {
    image: approvedPrometheusImage,
    networks: ["observability"],
    user: "65532:65532",
    command: "--config.file=/etc/prometheus/prometheus.yml",
  },
  retentionworker: {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/retentionworker",
  },
  "secret-init": {
    image: "sentinelflow/backend:demo",
    networkMode: "none",
    user: "0:0",
    capAdd: ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
    command: "/bin/sh",
  },
  simulator: {
    image: "sentinelflow/backend:demo",
    networks: ["edge"],
    command: "/usr/local/bin/simulator",
  },
  stubworker: {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/stubworker",
  },
  validationworker: {
    image: "sentinelflow/backend:demo",
    networks: ["control"],
    command: "/usr/local/bin/validationworker",
  },
  validator: {
    image: "sentinelflow/backend:demo",
    networkMode: "none",
    user: "0:65532",
    capAdd: ["NET_ADMIN"],
    command: "/usr/local/bin/validator",
  },
  web: {
    image: "sentinelflow/web:demo",
    networks: ["management"],
    command: null,
  },
  worker: {
    image: "sentinelflow/backend:demo",
    networks: ["ai-egress", "control"],
    command: "/usr/local/bin/worker",
  },
});

function reviewedHealthcheck(test, interval, timeout, retries, startPeriod) {
  return Object.freeze({
    test: Object.freeze(test),
    interval,
    timeout,
    retries,
    start_period: startPeriod,
  });
}

// Healthchecks execute inside the service container and therefore form a
// second command channel. Freeze the complete normalized object for reviewed
// healthchecks and require every other service to remain healthcheck-free.
export const reviewedComposeHealthchecks = Object.freeze({
  api: reviewedHealthcheck(
    ["CMD-SHELL", "wget -q -O /dev/null http://172.34.0.10:8083/health/ready"],
    "2s",
    "2s",
    30,
    "5s",
  ),
  controlmetricsexporter: reviewedHealthcheck(
    ["CMD-SHELL", "wget -q -O /dev/null http://172.29.0.3:9091/health"],
    "5s",
    "3s",
    12,
    "5s",
  ),
  "demo-activation-handoff": null,
  "demo-activator": null,
  "demo-app": reviewedHealthcheck(
    ["CMD-SHELL", "nc -z -w 1 172.30.0.10 8081"],
    "2s",
    "2s",
    30,
    "5s",
  ),
  detector: null,
  dispatcher: null,
  executor: reviewedHealthcheck(
    ["CMD-SHELL", "test -S /run/sentinelflow-executor/executor.sock"],
    "2s",
    "2s",
    30,
    "5s",
  ),
  gateway: reviewedHealthcheck(
    [
      "CMD-SHELL",
      "wget -q -O /dev/null http://203.0.113.10:8080/health/ready && wget -q -O /dev/null http://172.29.0.2:9090/metrics",
    ],
    "2s",
    "2s",
    30,
    "5s",
  ),
  "history-importer": null,
  lifecycleworker: reviewedHealthcheck(
    ["CMD-SHELL", "pidof lifecycleworker >/dev/null"],
    "5s",
    "2s",
    12,
    "5s",
  ),
  migrate: null,
  postgres: reviewedHealthcheck(
    [
      "CMD-SHELL",
      'pg_isready -q -h 172.32.0.2 -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"',
    ],
    "2s",
    "2s",
    30,
    "5s",
  ),
  prometheus: reviewedHealthcheck(
    ["CMD", "/bin/promtool", "check", "ready", "--url=http://172.29.0.4:9090"],
    "5s",
    "3s",
    12,
    "5s",
  ),
  retentionworker: reviewedHealthcheck(
    ["CMD-SHELL", "pidof retentionworker >/dev/null"],
    "5s",
    "2s",
    12,
    "5s",
  ),
  "secret-init": null,
  simulator: null,
  stubworker: reviewedHealthcheck(
    ["CMD-SHELL", "pidof stubworker >/dev/null"],
    "5s",
    "2s",
    12,
    "5s",
  ),
  validationworker: null,
  validator: reviewedHealthcheck(
    ["CMD-SHELL", "test -S /run/sentinelflow-validator/validator.sock"],
    "2s",
    "2s",
    30,
    "5s",
  ),
  web: reviewedHealthcheck(
    ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8080/health/live"],
    "2s",
    "2s",
    30,
    "5s",
  ),
  worker: null,
});

const demoHistoryEnvironmentOwners = Object.freeze({
  DATABASE_DEMO_ACTIVATOR_PASSWORD: ["demo-activation-handoff"],
  DATABASE_DEMO_ACTIVATOR_URL: ["demo-activator"],
  DATABASE_DEMO_IMPORTER_PASSWORD: ["migrate"],
  DATABASE_DEMO_IMPORTER_URL: ["history-importer"],
  DEMO_HISTORY_FIXTURE_DATASET: ["history-importer"],
  DEMO_HISTORY_SIGNED_ENVELOPE_FILE: [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ],
  DEMO_HISTORY_PUBLIC_KEY_B64URL: [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ],
  DEMO_HISTORY_RUN_SCOPE: [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ],
  DEMO_HISTORY_IMPORT_ID: [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ],
  DEMO_HISTORY_CLOCK_AT: [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ],
  DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST: [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ],
  DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: [
    "demo-activator",
    "stubworker",
    "worker",
  ],
  DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE: [
    "demo-activator",
    "validationworker",
  ],
});

const fixedDemoHistoryEnvironmentValues = Object.freeze({
  DEMO_HISTORY_FIXTURE_DATASET:
    "/app/contracts/fixtures/demo_history_dataset_v1.json",
  DEMO_HISTORY_SIGNED_ENVELOPE_FILE:
    "/run/sentinelflow-demo-history/signed-manifest.json",
  DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE:
    "/run/secrets/sentinelflow-demo-history-analysis/activation-capability",
  DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE:
    "/run/secrets/sentinelflow-demo-history-validation/activation-capability",
});

function reviewedEnvironmentOwners(...services) {
  return Object.freeze(services);
}

// These values either grant access to credentials/authority material or bind a
// component to a privileged socket or database role. Ownership is exact across
// the normalized service inventory, so injecting a known sensitive variable
// into any additional service fails the static policy check.
export const reviewedSensitiveEnvironmentOwners = Object.freeze({
  ADMIN_PASSWORD_ARGON2ID_HASH: reviewedEnvironmentOwners("api"),
  AUTH_ACCOUNT_HASH_KEY: reviewedEnvironmentOwners("demo-app"),
  AUTH_EVENT_HMAC_KEY: reviewedEnvironmentOwners("api", "demo-app"),
  DATABASE_API_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_API_URL: reviewedEnvironmentOwners("api"),
  DATABASE_DISPATCHER_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_DISPATCHER_URL: reviewedEnvironmentOwners("dispatcher"),
  DATABASE_LIFECYCLE_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_LIFECYCLE_URL: reviewedEnvironmentOwners("lifecycleworker"),
  DATABASE_METRICS_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_METRICS_URL: reviewedEnvironmentOwners("controlmetricsexporter"),
  DATABASE_READ_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_RETENTION_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_RETENTION_URL: reviewedEnvironmentOwners("retentionworker"),
  DATABASE_WORKER_PASSWORD: reviewedEnvironmentOwners("migrate"),
  DATABASE_WORKER_URL: reviewedEnvironmentOwners(
    "detector",
    "stubworker",
    "validationworker",
    "worker",
  ),
  DEMO_ALLOW_RFC5737: reviewedEnvironmentOwners("executor", "validationworker"),
  DEMO_ENFORCEMENT_ISOLATION_VERIFIED: reviewedEnvironmentOwners(
    "executor",
    "validationworker",
  ),
  DEMO_HOST_RULESET_UNCHANGED: reviewedEnvironmentOwners(
    "executor",
    "validationworker",
  ),
  DISPATCHER_RESULT_PUBLIC_KEY_FILE: reviewedEnvironmentOwners("dispatcher"),
  DISPATCHER_SIGNING_PRIVATE_KEY_FILE: reviewedEnvironmentOwners("dispatcher"),
  EXECUTOR_DISPATCH_PUBLIC_KEY_FILE: reviewedEnvironmentOwners("executor"),
  EXECUTOR_REPLAY_JOURNAL: reviewedEnvironmentOwners("executor"),
  EXECUTOR_RESULT_PRIVATE_KEY_FILE: reviewedEnvironmentOwners("executor"),
  EXECUTOR_SOCKET: reviewedEnvironmentOwners("dispatcher", "executor"),
  EXECUTOR_STARTUP_MODE: reviewedEnvironmentOwners("executor"),
  GATEWAY_EVENT_HMAC_KEY: reviewedEnvironmentOwners("api", "gateway"),
  NFT_BINARY_EXPECTED_SHA256: reviewedEnvironmentOwners(
    "executor",
    "validationworker",
    "validator",
  ),
  NFT_EXPECTED_VERSION: reviewedEnvironmentOwners(
    "executor",
    "validationworker",
    "validator",
  ),
  NFT_VALIDATOR_SOCKET: reviewedEnvironmentOwners(
    "validationworker",
    "validator",
  ),
  OPENAI_API_KEY: reviewedEnvironmentOwners("worker"),
  PGPASSWORD: reviewedEnvironmentOwners("demo-activation-handoff", "migrate"),
  POSTGRES_PASSWORD: reviewedEnvironmentOwners("postgres"),
  PROTECTED_CURRENT_ADMIN_IPV4: reviewedEnvironmentOwners("validationworker"),
  PROTECTED_GATEWAY_IPV4: reviewedEnvironmentOwners("validationworker"),
  PROTECTED_MANAGEMENT_IPV4: reviewedEnvironmentOwners("validationworker"),
  PROTECTED_ORIGIN_IPV4: reviewedEnvironmentOwners("validationworker"),
  SESSION_HMAC_KEY: reviewedEnvironmentOwners("api"),
});

export const reviewedSensitiveEnvironmentFixedValues = Object.freeze({
  DEMO_ALLOW_RFC5737: "true",
  DEMO_ENFORCEMENT_ISOLATION_VERIFIED: "true",
  DEMO_HOST_RULESET_UNCHANGED: "true",
  DISPATCHER_RESULT_PUBLIC_KEY_FILE:
    "/run/secrets/sentinelflow/executor-result-public.pem",
  DISPATCHER_SIGNING_PRIVATE_KEY_FILE:
    "/run/secrets/sentinelflow/dispatcher-capability-private.pem",
  EXECUTOR_DISPATCH_PUBLIC_KEY_FILE:
    "/run/secrets/sentinelflow/dispatcher-capability-public.pem",
  EXECUTOR_REPLAY_JOURNAL: "/var/lib/sentinelflow-executor/replay.json",
  EXECUTOR_RESULT_PRIVATE_KEY_FILE:
    "/run/secrets/sentinelflow/executor-result-private.pem",
  EXECUTOR_SOCKET: "/run/sentinelflow-executor/executor.sock",
  EXECUTOR_STARTUP_MODE: "bootstrap",
  NFT_VALIDATOR_SOCKET: "/run/sentinelflow-validator/validator.sock",
  PROTECTED_CURRENT_ADMIN_IPV4: "172.34.0.6",
  PROTECTED_GATEWAY_IPV4: "172.30.0.2,172.31.0.2,203.0.113.10",
  PROTECTED_MANAGEMENT_IPV4: "172.34.0.10",
  PROTECTED_ORIGIN_IPV4: "172.30.0.10",
});

function reviewedDependencies(entries) {
  return Object.freeze(
    Object.fromEntries(
      entries.map(([dependency, condition, restart]) => [
        dependency,
        Object.freeze({
          condition,
          required: true,
          ...(restart === true ? { restart: true } : {}),
        }),
      ]),
    ),
  );
}

export const reviewedComposeDependencies = Object.freeze({
  api: reviewedDependencies([["migrate", "service_completed_successfully"]]),
  controlmetricsexporter: reviewedDependencies([
    ["migrate", "service_completed_successfully"],
  ]),
  "demo-activation-handoff": reviewedDependencies([
    ["history-importer", "service_completed_successfully"],
  ]),
  "demo-activator": reviewedDependencies([
    ["demo-activation-handoff", "service_completed_successfully"],
  ]),
  "demo-app": reviewedDependencies([
    ["api", "service_healthy"],
    ["secret-init", "service_completed_successfully"],
  ]),
  detector: reviewedDependencies([
    ["history-importer", "service_completed_successfully"],
  ]),
  dispatcher: reviewedDependencies([
    ["migrate", "service_completed_successfully"],
    ["secret-init", "service_completed_successfully"],
  ]),
  executor: reviewedDependencies([
    // Compose normalizes network_mode: service:gateway into this lifecycle
    // edge. It is required for the executor to share only the Gateway network
    // namespace and is checked as an exact dependency below.
    // Compose adds restart: true to the normalized service namespace owner
    // edge. It keeps executor lifecycle recovery coupled to the Gateway
    // namespace without granting the executor any broader dependency edge.
    ["gateway", "service_started", true],
    ["secret-init", "service_completed_successfully"],
  ]),
  gateway: reviewedDependencies([
    ["api", "service_healthy"],
    ["demo-app", "service_healthy"],
    ["secret-init", "service_completed_successfully"],
  ]),
  "history-importer": reviewedDependencies([
    ["migrate", "service_completed_successfully"],
  ]),
  lifecycleworker: reviewedDependencies([
    ["migrate", "service_completed_successfully"],
  ]),
  migrate: reviewedDependencies([
    ["postgres", "service_healthy"],
    ["secret-init", "service_completed_successfully"],
  ]),
  postgres: reviewedDependencies([]),
  prometheus: reviewedDependencies([
    ["controlmetricsexporter", "service_healthy"],
    ["gateway", "service_healthy"],
  ]),
  retentionworker: reviewedDependencies([
    ["history-importer", "service_completed_successfully"],
  ]),
  "secret-init": reviewedDependencies([]),
  simulator: reviewedDependencies([["gateway", "service_healthy"]]),
  stubworker: reviewedDependencies([
    ["postgres", "service_healthy"],
    ["migrate", "service_completed_successfully"],
    ["demo-activator", "service_completed_successfully"],
  ]),
  validationworker: reviewedDependencies([
    ["demo-activator", "service_completed_successfully"],
    ["validator", "service_healthy"],
  ]),
  worker: reviewedDependencies([
    ["demo-activator", "service_completed_successfully"],
  ]),
  validator: reviewedDependencies([
    ["history-importer", "service_completed_successfully"],
    ["secret-init", "service_completed_successfully"],
  ]),
  web: reviewedDependencies([["api", "service_healthy"]]),
});

// Retain the original export for callers that consumed the narrower contract
// before dependency ownership was expanded to the complete service inventory.
export const reviewedDemoActivationDependencies = reviewedComposeDependencies;

function reviewedMounts(...mounts) {
  return Object.freeze(mounts.map((mount) => Object.freeze(mount)));
}

function namedVolumeMount(source, target, readOnly = false) {
  return { type: "volume", source, target, readOnly };
}

function fixedBindMount(source, target, readOnly = true) {
  return {
    type: "bind",
    source,
    target,
    readOnly,
    bind: { create_host_path: false },
  };
}

// Compose implementations differ in whether their normalized `config --format
// json` output retains an explicitly configured false boolean. The source file
// policy below preserves the authoring requirement; the runtime policy accepts
// only the two lossless representations of that requirement: `{}` or
// `{ create_host_path: false }`. It never accepts an explicit true value.
const reviewedComposeSourceBinds = Object.freeze([
  Object.freeze({
    source: "./postgres/pg_hba.conf",
    target: "/etc/postgresql/sentinelflow-pg_hba.conf",
    count: 1,
  }),
  Object.freeze({
    source: "./postgres/init.sh",
    target: "/opt/sentinelflow/init.sh",
    count: 1,
  }),
  Object.freeze({
    source: "../db/migrations",
    target: "/migrations",
    count: 1,
  }),
  Object.freeze({
    source: "./postgres/demo-activation-handoff.sh",
    target: "/opt/sentinelflow/demo-activation-handoff.sh",
    count: 1,
  }),
  Object.freeze({
    source: "./observability/prometheus.yml",
    target: "/etc/prometheus/prometheus.yml",
    count: 1,
  }),
  Object.freeze({
    source: "./observability/control-plane-alerts.yaml",
    target: "/etc/prometheus/control-plane-alerts.yaml",
    count: 1,
  }),
  Object.freeze({
    source: "${DEMO_HISTORY_SOURCE:-../data/demo-history}",
    target: "/run/sentinelflow-demo-history",
    count: 5,
  }),
  Object.freeze({
    source: "${DEMO_SECRETS_SOURCE:-../secrets/demo}",
    target: "/source",
    count: 1,
  }),
]);

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export function validateComposeSourceBindPolicy(
  text,
  filename = "deployments/compose.yaml",
) {
  invariant(typeof text === "string", `${filename} must be text`);
  for (const { source, target, count } of reviewedComposeSourceBinds) {
    const expectedBlock = new RegExp(
      `^\\s*- type: bind\\s*\\r?\\n\\s*source: ${escapeRegularExpression(source)}\\s*\\r?\\n\\s*target: ${escapeRegularExpression(target)}\\s*\\r?\\n\\s*read_only: true\\s*\\r?\\n\\s*bind:\\s*\\r?\\n\\s*create_host_path: false\\s*$`,
      "gmu",
    );
    invariant(
      [...text.matchAll(expectedBlock)].length === count,
      `${filename} must explicitly set bind.create_host_path: false for ${target}`,
    );
  }
}

function dynamicBindMount(sourceGroup, target, readOnly = true) {
  return {
    type: "bind",
    sourceGroup,
    target,
    readOnly,
    bind: { create_host_path: false },
  };
}

// Every service mount is frozen, not only the known secret destinations. This
// makes an authority volume or the raw demo secret bind invalid at any
// alternate destination and prevents aliases from hiding behind an otherwise
// harmless-looking path.
export const reviewedComposeMounts = Object.freeze({
  api: reviewedMounts(),
  controlmetricsexporter: reviewedMounts(),
  "demo-activation-handoff": reviewedMounts(
    fixedBindMount(
      path.join(
        repositoryRoot,
        "deployments/postgres/demo-activation-handoff.sh",
      ),
      "/opt/sentinelflow/demo-activation-handoff.sh",
    ),
    namedVolumeMount(
      "demo-history-capability-receipts",
      "/run/sentinelflow-demo-history-capability-receipts",
      true,
    ),
  ),
  "demo-activator": reviewedMounts(
    dynamicBindMount("demo-history", "/run/sentinelflow-demo-history", true),
    namedVolumeMount(
      "demo-history-analysis-activation",
      "/run/secrets/sentinelflow-demo-history-analysis",
      true,
    ),
    namedVolumeMount(
      "demo-history-validation-activation",
      "/run/secrets/sentinelflow-demo-history-validation",
      true,
    ),
  ),
  "demo-app": reviewedMounts(
    namedVolumeMount("auth-state", "/var/lib/sentinelflow-auth-adapter"),
  ),
  detector: reviewedMounts(),
  dispatcher: reviewedMounts(
    namedVolumeMount("executor-socket", "/run/sentinelflow-executor", true),
    namedVolumeMount("dispatcher-secrets", "/run/secrets/sentinelflow", true),
  ),
  executor: reviewedMounts(
    namedVolumeMount("executor-state", "/var/lib/sentinelflow-executor"),
    namedVolumeMount("executor-socket", "/run/sentinelflow-executor"),
    namedVolumeMount("executor-readiness", "/run/sentinelflow-ready"),
    namedVolumeMount("executor-secrets", "/run/secrets/sentinelflow", true),
  ),
  gateway: reviewedMounts(
    namedVolumeMount("gateway-state", "/var/lib/sentinelflow-gateway"),
    namedVolumeMount("executor-readiness", "/run/sentinelflow-ready", true),
  ),
  "history-importer": reviewedMounts(
    dynamicBindMount("demo-history", "/run/sentinelflow-demo-history", true),
  ),
  lifecycleworker: reviewedMounts(),
  migrate: reviewedMounts(
    fixedBindMount(
      path.join(repositoryRoot, "deployments/postgres/init.sh"),
      "/opt/sentinelflow/init.sh",
    ),
    fixedBindMount(path.join(repositoryRoot, "db/migrations"), "/migrations"),
    namedVolumeMount(
      "demo-history-capability-receipts",
      "/run/sentinelflow-demo-history-capability-receipts",
      true,
    ),
  ),
  postgres: reviewedMounts(
    namedVolumeMount("postgres-data", "/var/lib/postgresql/data"),
    fixedBindMount(
      path.join(repositoryRoot, "deployments/postgres/pg_hba.conf"),
      "/etc/postgresql/sentinelflow-pg_hba.conf",
    ),
  ),
  prometheus: reviewedMounts(
    fixedBindMount(
      path.join(repositoryRoot, "deployments/observability/prometheus.yml"),
      "/etc/prometheus/prometheus.yml",
    ),
    fixedBindMount(
      path.join(
        repositoryRoot,
        "deployments/observability/control-plane-alerts.yaml",
      ),
      "/etc/prometheus/control-plane-alerts.yaml",
    ),
  ),
  retentionworker: reviewedMounts(),
  "secret-init": reviewedMounts(
    dynamicBindMount("demo-secrets", "/source", true),
    namedVolumeMount("gateway-state", "/volumes/gateway-state"),
    namedVolumeMount("auth-state", "/volumes/auth-state"),
    namedVolumeMount("executor-state", "/volumes/executor-state"),
    namedVolumeMount("executor-socket", "/volumes/executor-socket"),
    namedVolumeMount("validator-socket", "/volumes/validator-socket"),
    namedVolumeMount("executor-readiness", "/volumes/readiness"),
    namedVolumeMount("dispatcher-secrets", "/volumes/dispatcher-secrets"),
    namedVolumeMount("executor-secrets", "/volumes/executor-secrets"),
    namedVolumeMount(
      "demo-history-capability-receipts",
      "/volumes/demo-history-capability-receipts",
    ),
    namedVolumeMount(
      "demo-history-analysis-activation",
      "/volumes/demo-history-analysis-activation",
    ),
    namedVolumeMount(
      "demo-history-validation-activation",
      "/volumes/demo-history-validation-activation",
    ),
  ),
  simulator: reviewedMounts(),
  stubworker: reviewedMounts(
    dynamicBindMount("demo-history", "/run/sentinelflow-demo-history", true),
    namedVolumeMount(
      "demo-history-analysis-activation",
      "/run/secrets/sentinelflow-demo-history-analysis",
      true,
    ),
  ),
  validationworker: reviewedMounts(
    namedVolumeMount("validator-socket", "/run/sentinelflow-validator", true),
    dynamicBindMount("demo-history", "/run/sentinelflow-demo-history", true),
    namedVolumeMount(
      "demo-history-validation-activation",
      "/run/secrets/sentinelflow-demo-history-validation",
      true,
    ),
  ),
  validator: reviewedMounts(
    namedVolumeMount("validator-socket", "/run/sentinelflow-validator"),
  ),
  web: reviewedMounts(),
  worker: reviewedMounts(
    dynamicBindMount("demo-history", "/run/sentinelflow-demo-history", true),
    namedVolumeMount(
      "demo-history-analysis-activation",
      "/run/secrets/sentinelflow-demo-history-analysis",
      true,
    ),
  ),
});

export const reviewedComposeVolumeNames = Object.freeze({
  "auth-state": "sentinelflow_auth-state",
  "demo-history-capability-receipts":
    "sentinelflow_demo-history-capability-receipts",
  "demo-history-analysis-activation":
    "sentinelflow_demo-history-analysis-activation",
  "demo-history-validation-activation":
    "sentinelflow_demo-history-validation-activation",
  "dispatcher-secrets": "sentinelflow_dispatcher-secrets",
  "executor-readiness": "sentinelflow_executor-readiness",
  "executor-secrets": "sentinelflow_executor-secrets",
  "executor-socket": "sentinelflow_executor-socket",
  "executor-state": "sentinelflow_executor-state",
  "gateway-state": "sentinelflow_gateway-state",
  "postgres-data": "sentinelflow_postgres-data",
  "validator-socket": "sentinelflow_validator-socket",
});

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function exactSortedStrings(actual, expected, message) {
  const normalizedActual = [...(actual || [])].sort();
  const normalizedExpected = [...expected].sort();
  invariant(
    JSON.stringify(normalizedActual) === JSON.stringify(normalizedExpected),
    `${message}: expected ${normalizedExpected.join(",") || "none"}, got ${normalizedActual.join(",") || "none"}`,
  );
}

function exactStrings(actual, expected, message) {
  invariant(
    JSON.stringify(actual || []) === JSON.stringify(expected),
    `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual || [])}`,
  );
}

export function validateScannerVersionOutput(output) {
  invariant(
    typeof output === "string" && /^Version: 0\.70\.0\s*$/u.test(output),
    "Trivy scanner did not report exact version 0.70.0",
  );
}

export function validateScannerDatabaseChecksums(checksums) {
  invariant(
    checksums && typeof checksums === "object" && !Array.isArray(checksums),
    "Trivy database checksum result is invalid",
  );
  exactSortedStrings(
    Object.keys(checksums),
    Object.keys(approvedTrivyDatabaseChecksums),
    "Trivy database files differ from the frozen contract",
  );
  for (const [filename, expected] of Object.entries(
    approvedTrivyDatabaseChecksums,
  )) {
    invariant(
      checksums[filename] === expected,
      `Trivy database checksum mismatch for ${filename}`,
    );
  }
}

export function validateScannerDatabaseMetadata(metadata, now = new Date()) {
  invariant(
    metadata && typeof metadata === "object" && !Array.isArray(metadata),
    "Trivy database metadata is invalid",
  );
  for (const [field, expected] of Object.entries(
    approvedTrivyDatabaseMetadata,
  )) {
    invariant(
      metadata[field] === expected,
      `Trivy database metadata mismatch for ${field}`,
    );
  }
  const downloadedAt = Date.parse(metadata.DownloadedAt);
  invariant(
    Number.isFinite(downloadedAt),
    "Trivy database DownloadedAt is invalid",
  );
  invariant(
    downloadedAt >= Date.parse(metadata.UpdatedAt) &&
      downloadedAt <= now.getTime() + 5 * 60 * 1000,
    "Trivy database DownloadedAt is outside the acquisition window",
  );
  invariant(
    now.getTime() - Date.parse(metadata.UpdatedAt) <= 7 * 24 * 60 * 60 * 1000,
    "Trivy database snapshot is older than seven days",
  );
}

export function validateImageInspection(kind, inspection) {
  invariant(
    Array.isArray(inspection) && inspection.length === 1,
    `${kind} image inspection must contain exactly one image`,
  );
  const image = inspection[0];
  invariant(image && typeof image === "object", `${kind} image is invalid`);
  invariant(
    typeof image.Id === "string" && /^sha256:[0-9a-f]{64}$/u.test(image.Id),
    `${kind} image ID is invalid`,
  );
  invariant(
    image.Os === "linux" && ["amd64", "arm64"].includes(image.Architecture),
    `${kind} image platform must be linux/amd64 or linux/arm64`,
  );
  invariant(
    image.Config && typeof image.Config === "object",
    `${kind} image config is invalid`,
  );

  const expected = {
    backend: {
      user: "65532:65532",
      entrypoint: [],
      command: ["/usr/local/bin/api"],
      ports: [],
    },
    postgres: {
      user: "70:70",
      entrypoint: ["docker-entrypoint.sh"],
      command: ["postgres"],
      ports: ["5432/tcp"],
    },
    prometheus: {
      user: "65532",
      entrypoint: ["/bin/prometheus"],
      command: [
        "--config.file=/etc/prometheus/prometheus.yml",
        "--storage.tsdb.path=/prometheus",
      ],
      ports: ["9090/tcp"],
    },
    web: {
      user: "101:101",
      entrypoint: ["/docker-entrypoint.sh"],
      command: ["nginx", "-g", "daemon off;"],
      ports: ["8080/tcp"],
    },
  }[kind];
  invariant(expected, `unknown image inspection kind: ${kind}`);
  invariant(
    image.Config.User === expected.user,
    `${kind} image has wrong non-root user: ${image.Config.User || "root"}`,
  );
  exactStrings(
    image.Config.Entrypoint,
    expected.entrypoint,
    `${kind} image entrypoint differs`,
  );
  exactStrings(
    image.Config.Cmd,
    expected.command,
    `${kind} image command differs`,
  );
  exactSortedStrings(
    Object.keys(image.Config.ExposedPorts || {}),
    expected.ports,
    `${kind} image exposed ports differ`,
  );
}

export function validateImageArchiveBinding(
  indexDocument,
  dockerManifest,
) {
  invariant(
    indexDocument &&
      typeof indexDocument === "object" &&
      !Array.isArray(indexDocument) &&
      indexDocument.schemaVersion === 2 &&
      Array.isArray(indexDocument.manifests) &&
      indexDocument.manifests.length === 1,
    "image archive index must contain exactly one manifest",
  );
  invariant(
    /^sha256:[0-9a-f]{64}$/u.test(indexDocument.manifests[0].digest),
    "image archive index manifest digest is invalid",
  );
  invariant(
    Array.isArray(dockerManifest) && dockerManifest.length === 1,
    "Docker image archive must contain exactly one image",
  );
  const entry = dockerManifest[0];
  invariant(
    entry && typeof entry === "object" && !Array.isArray(entry),
    "Docker image archive manifest is invalid",
  );
  invariant(
    typeof entry.Config === "string" &&
      /^blobs\/sha256\/[0-9a-f]{64}$/u.test(entry.Config),
    "Docker image archive config path is invalid",
  );
  invariant(
    Array.isArray(entry.Layers) && entry.Layers.length > 0,
    "Docker image archive has no layers",
  );
  const layers = new Set();
  for (const layer of entry.Layers) {
    invariant(
      typeof layer === "string" && /^blobs\/sha256\/[0-9a-f]{64}$/u.test(layer),
      "Docker image archive layer path is invalid",
    );
    invariant(
      !layers.has(layer),
      "Docker image archive contains duplicate layers",
    );
    layers.add(layer);
  }
  const configDigest = entry.Config.slice("blobs/sha256/".length);
  return {
    imageConfigID: `sha256:${configDigest}`,
    configPath: entry.Config,
  };
}

function serviceNetworks(service) {
  return service.networks ? Object.keys(service.networks) : [];
}

function serviceEnvironment(service, name) {
  const environment = service.environment || {};
  invariant(
    environment &&
      typeof environment === "object" &&
      !Array.isArray(environment),
    `${name} environment is invalid`,
  );
  return environment;
}

function authorityBearingEnvironmentName(name) {
  return (
    name === "PGPASSWORD" ||
    name === "POSTGRES_PASSWORD" ||
    /^DATABASE_[A-Z0-9_]+_(?:PASSWORD|URL)$/u.test(name) ||
    /(?:PRIVATE|PUBLIC)_KEY/u.test(name) ||
    /(?:^|_)SOCKET(?:_|$)/u.test(name) ||
    /(?:^|_)CAPABILITY(?:_|$)/u.test(name) ||
    /(?:^|_)(?:HMAC|HASH)_KEY$/u.test(name) ||
    /ACTIVATION_SECRET_FILE$/u.test(name)
  );
}

function validateSensitiveEnvironmentAuthority(services) {
  const reviewedNames = new Set([
    ...Object.keys(reviewedSensitiveEnvironmentOwners),
    ...Object.keys(demoHistoryEnvironmentOwners),
  ]);
  for (const [serviceName, service] of Object.entries(services)) {
    for (const name of Object.keys(serviceEnvironment(service, serviceName))) {
      invariant(
        !authorityBearingEnvironmentName(name) || reviewedNames.has(name),
        `${serviceName} has an unreviewed authority-bearing environment field ${name}`,
      );
    }
  }
  for (const [key, expectedOwners] of Object.entries(
    reviewedSensitiveEnvironmentOwners,
  )) {
    const actualOwners = [];
    for (const [name, service] of Object.entries(services)) {
      const environment = serviceEnvironment(service, name);
      if (Object.hasOwn(environment, key)) {
        invariant(
          typeof environment[key] === "string",
          `${name} has an invalid sensitive environment field ${key}`,
        );
        actualOwners.push(name);
      }
    }
    exactSortedStrings(
      actualOwners,
      expectedOwners,
      `sensitive environment ownership differs for ${key}`,
    );
    const expectedValue = reviewedSensitiveEnvironmentFixedValues[key];
    if (expectedValue !== undefined) {
      for (const owner of expectedOwners) {
        invariant(
          serviceEnvironment(services[owner], owner)[key] === expectedValue,
          `${owner} sensitive environment fixed value differs for ${key}`,
        );
      }
    }
  }
}

function validateDemoHistoryAuthority(services) {
  for (const [key, expectedOwners] of Object.entries(
    demoHistoryEnvironmentOwners,
  )) {
    const actualOwners = [];
    for (const [name, service] of Object.entries(services)) {
      const environment = serviceEnvironment(service, name);
      if (Object.hasOwn(environment, key)) {
        invariant(
          typeof environment[key] === "string",
          `${name} has an invalid demo history environment field ${key}`,
        );
        actualOwners.push(name);
      }
    }
    exactSortedStrings(
      actualOwners,
      expectedOwners,
      `demo activation environment ownership differs for ${key}`,
    );
    const expectedValue = fixedDemoHistoryEnvironmentValues[key];
    if (expectedValue !== undefined) {
      for (const owner of expectedOwners) {
        invariant(
          serviceEnvironment(services[owner], owner)[key] === expectedValue,
          `${owner} demo history fixed value differs for ${key}`,
        );
      }
    }
  }

  for (const [service, expectedDependencies] of Object.entries(
    reviewedComposeDependencies,
  )) {
    const dependencies = services[service].depends_on || {};
    invariant(
      dependencies &&
        typeof dependencies === "object" &&
        !Array.isArray(dependencies),
      `${service} Compose dependencies are invalid`,
    );
    exactSortedStrings(
      Object.keys(dependencies),
      Object.keys(expectedDependencies),
      `${service} Compose dependency inventory differs`,
    );
    for (const [dependency, expectedEdge] of Object.entries(
      expectedDependencies,
    )) {
      const edge = dependencies[dependency];
      invariant(
        edge && typeof edge === "object" && !Array.isArray(edge),
        `${service} Compose dependency on ${dependency} is invalid`,
      );
      exactSortedStrings(
        Object.keys(edge),
        Object.keys(expectedEdge),
        `${service} Compose dependency on ${dependency} fields differ`,
      );
      invariant(
        edge.condition === expectedEdge.condition &&
          edge.required === expectedEdge.required &&
          edge.restart === expectedEdge.restart,
        `${service} Compose dependency on ${dependency} differs`,
      );
    }
  }
}

function validateComposeVolumeNames(document) {
  invariant(
    document.name === "sentinelflow",
    "Compose project name differs from the reviewed runtime",
  );
  const volumes = document.volumes;
  invariant(
    volumes && typeof volumes === "object" && !Array.isArray(volumes),
    "Compose top-level volume inventory is unavailable",
  );
  exactSortedStrings(
    Object.keys(volumes),
    Object.keys(reviewedComposeVolumeNames),
    "Compose top-level volume inventory differs",
  );
  for (const [logicalName, expectedName] of Object.entries(
    reviewedComposeVolumeNames,
  )) {
    const volume = volumes[logicalName];
    invariant(
      volume && typeof volume === "object" && !Array.isArray(volume),
      `Compose volume ${logicalName} is invalid`,
    );
    exactSortedStrings(
      Object.keys(volume),
      ["name"],
      `Compose volume ${logicalName} fields differ`,
    );
    invariant(
      volume.name === expectedName,
      `Compose volume ${logicalName} explicit name differs`,
    );
  }
  for (const kind of ["configs", "secrets"]) {
    const resources = document[kind];
    invariant(
      resources === undefined ||
        (resources &&
          typeof resources === "object" &&
          !Array.isArray(resources) &&
          Object.keys(resources).length === 0),
      `Compose top-level ${kind} are not part of the reviewed runtime`,
    );
  }
}

function validateComposeMounts(services) {
  exactSortedStrings(
    Object.keys(reviewedComposeMounts),
    Object.keys(expectedComposeServices),
    "reviewed Compose mount service inventory differs",
  );
  const dynamicSources = new Map();
  for (const [serviceName, expectedMounts] of Object.entries(
    reviewedComposeMounts,
  )) {
    const configuredMounts = services[serviceName].volumes || [];
    invariant(
      Array.isArray(configuredMounts),
      `${serviceName} mount inventory is invalid`,
    );
    invariant(
      configuredMounts.length === expectedMounts.length,
      `${serviceName} mount inventory differs`,
    );
    const mountsByTarget = new Map();
    for (const mount of configuredMounts) {
      invariant(
        mount && typeof mount === "object" && !Array.isArray(mount),
        `${serviceName} mount configuration is invalid`,
      );
      invariant(
        typeof mount.target === "string" && !mountsByTarget.has(mount.target),
        `${serviceName} has a duplicate or invalid mount target`,
      );
      mountsByTarget.set(mount.target, mount);
    }
    for (const expected of expectedMounts) {
      const mount = mountsByTarget.get(expected.target);
      invariant(
        mount !== undefined,
        `${serviceName} mount target differs for ${expected.target}`,
      );
      const expectedKeys = ["type", "source", "target", expected.type];
      if (expected.readOnly) {
        expectedKeys.push("read_only");
      }
      exactSortedStrings(
        Object.keys(mount),
        expectedKeys,
        `${serviceName} mount fields differ for ${expected.target}`,
      );
      invariant(
        mount.type === expected.type &&
          typeof mount.source === "string" &&
          mount.source.length > 0 &&
          mount.target === expected.target &&
          (mount.read_only === true) === expected.readOnly,
        `${serviceName} mount contract differs for ${expected.target}`,
      );
      invariant(
        mount[expected.type] &&
          typeof mount[expected.type] === "object" &&
          !Array.isArray(mount[expected.type]) &&
          (expected.type === "bind" &&
          expected.bind?.create_host_path === false
            ? Object.keys(mount.bind).length === 0 ||
              (Object.keys(mount.bind).length === 1 &&
                mount.bind.create_host_path === false)
            : JSON.stringify(mount[expected.type]) ===
              JSON.stringify(expected[expected.type] || {})),
        `${serviceName} mount options differ for ${expected.target}`,
      );
      if (expected.type === "volume") {
        invariant(
          mount.source === expected.source,
          `${serviceName} mount source differs for ${expected.target}`,
        );
        continue;
      }
      invariant(
        path.isAbsolute(mount.source) && !mount.source.includes("\u0000"),
        `${serviceName} bind source is invalid for ${expected.target}`,
      );
      const sourceSegments = new Set(mount.source.split(/[\\/]/u));
      invariant(
        !Object.entries(reviewedComposeVolumeNames).some(
          ([logicalName, explicitName]) =>
            sourceSegments.has(logicalName) || sourceSegments.has(explicitName),
        ),
        `${serviceName} bind source aliases a reviewed named volume for ${expected.target}`,
      );
      if (expected.source !== undefined) {
        invariant(
          mount.source === expected.source,
          `${serviceName} bind source differs for ${expected.target}`,
        );
        continue;
      }
      const prior = dynamicSources.get(expected.sourceGroup);
      invariant(
        prior === undefined || prior === mount.source,
        `${serviceName} dynamic bind source differs for ${expected.target}`,
      );
      dynamicSources.set(expected.sourceGroup, mount.source);
    }
  }
  invariant(
    dynamicSources.get("demo-history") !== dynamicSources.get("demo-secrets"),
    "demo history and secret bind sources must remain distinct",
  );
}

function validateComposeHealthchecks(services) {
  exactSortedStrings(
    Object.keys(reviewedComposeHealthchecks),
    Object.keys(expectedComposeServices),
    "reviewed Compose healthcheck service inventory differs",
  );
  for (const [name, expected] of Object.entries(reviewedComposeHealthchecks)) {
    const service = services[name];
    if (expected === null) {
      invariant(
        !Object.hasOwn(service, "healthcheck"),
        `${name} must not define a healthcheck`,
      );
      continue;
    }
    const healthcheck = service.healthcheck;
    invariant(
      healthcheck &&
        typeof healthcheck === "object" &&
        !Array.isArray(healthcheck),
      `${name} healthcheck is unavailable or invalid`,
    );
    exactSortedStrings(
      Object.keys(healthcheck),
      ["interval", "retries", "start_period", "test", "timeout"],
      `${name} healthcheck fields differ`,
    );
    invariant(
      Array.isArray(healthcheck.test) &&
        healthcheck.test.length > 0 &&
        healthcheck.test.every((argument) => typeof argument === "string"),
      `${name} healthcheck command is invalid`,
    );
    invariant(
      JSON.stringify(healthcheck.test) === JSON.stringify(expected.test),
      `${name} healthcheck command differs`,
    );
    for (const field of ["interval", "timeout", "retries", "start_period"]) {
      invariant(
        healthcheck[field] === expected[field],
        `${name} healthcheck ${field} differs`,
      );
    }
  }
}

export function validateComposeRuntimePolicy(document) {
  invariant(
    document && typeof document === "object" && !Array.isArray(document),
    "Compose configuration is invalid",
  );
  invariant(
    document.services && typeof document.services === "object",
    "Compose services are unavailable",
  );
  exactSortedStrings(
    Object.keys(document.services),
    Object.keys(expectedComposeServices),
    "Compose service inventory differs from the reviewed runtime",
  );
  exactSortedStrings(
    Object.keys(reviewedComposeCommands),
    Object.keys(expectedComposeServices),
    "reviewed Compose command service inventory differs",
  );

  for (const [name, expected] of Object.entries(expectedComposeServices)) {
    const service = document.services[name];
    const reviewedCommandValue = reviewedComposeCommands[name];
    invariant(
      (Array.isArray(reviewedCommandValue)
        ? reviewedCommandValue[0] || null
        : null) === expected.command,
      `${name} reviewed command executable is inconsistent`,
    );
    invariant(
      service.image === expected.image,
      `${name} uses an unexpected image`,
    );
    invariant(
      service.privileged !== true,
      `${name} must not run as a privileged container`,
    );
    invariant(
      service.entrypoint === null || service.entrypoint === undefined,
      `${name} must not override its reviewed image entrypoint`,
    );
    for (const hook of [
      "post_start",
      "pre_stop",
      "lifecycle",
      "lifecycle_hooks",
    ]) {
      invariant(
        !Object.hasOwn(service, hook),
        `${name} must not define the ${hook} lifecycle hook`,
      );
    }
    invariant(
      (service.read_only === true) === (expected.readOnly ?? true),
      `${name} has an unexpected read-only-root setting`,
    );
    exactSortedStrings(
      service.cap_drop,
      ["ALL"],
      `${name} capability drop set differs`,
    );
    exactSortedStrings(
      service.cap_add,
      expected.capAdd || [],
      `${name} capability add set differs`,
    );
    exactSortedStrings(
      service.security_opt,
      ["no-new-privileges:true"],
      `${name} security options differ`,
    );
    invariant(
      (service.user || null) === (expected.user || null),
      `${name} has an unexpected user override`,
    );
    invariant(
      (service.network_mode || null) === (expected.networkMode || null),
      `${name} has an unexpected network mode`,
    );
    exactSortedStrings(
      serviceNetworks(service),
      expected.networks || [],
      `${name} network attachment differs`,
    );
    const configuredCommand =
      service.command === undefined ? null : service.command;
    invariant(
      configuredCommand === null ||
        (Array.isArray(configuredCommand) &&
          configuredCommand.length > 0 &&
          configuredCommand.every((argument) => typeof argument === "string")),
      `${name} command is invalid`,
    );
    invariant(
      JSON.stringify(configuredCommand) ===
        JSON.stringify(reviewedCommandValue),
      `${name} has an unexpected command`,
    );
    invariant(
      service.volumes_from === undefined ||
        (Array.isArray(service.volumes_from) &&
          service.volumes_from.length === 0),
      `${name} must not inherit another service's volumes`,
    );
    for (const kind of ["configs", "secrets"]) {
      invariant(
        service[kind] === undefined ||
          (Array.isArray(service[kind]) && service[kind].length === 0),
        `${name} must not receive unreviewed Compose ${kind}`,
      );
    }
    for (const mount of service.volumes || []) {
      invariant(
        mount && typeof mount === "object" && !Array.isArray(mount),
        `${name} mount configuration is invalid`,
      );
      invariant(
        mount.target !== "/var/run/docker.sock" &&
          mount.source !== "/var/run/docker.sock",
        `${name} must not mount the Docker socket`,
      );
    }
  }

  validateDemoHistoryAuthority(document.services);
  validateSensitiveEnvironmentAuthority(document.services);
  validateComposeVolumeNames(document);
  validateComposeMounts(document.services);
  validateComposeHealthchecks(document.services);

  const localBuilds = new Map();
  for (const [name, service] of Object.entries(document.services)) {
    if (!service.build) {
      continue;
    }
    const dockerfile = service.build.dockerfile;
    invariant(
      typeof dockerfile === "string" &&
        dockerfile.startsWith("deployments/Dockerfile."),
      `${name} build uses an unexpected Dockerfile`,
    );
    const prior = localBuilds.get(service.image);
    invariant(
      !prior || prior === dockerfile,
      `${service.image} is built from multiple Dockerfiles`,
    );
    localBuilds.set(service.image, dockerfile);
  }
  invariant(
    localBuilds.get("sentinelflow/backend:demo") ===
      "deployments/Dockerfile.backend",
    "backend runtime image has no reviewed build",
  );
  invariant(
    localBuilds.get("sentinelflow/postgres:demo") ===
      "deployments/Dockerfile.postgres",
    "PostgreSQL and migration runtime image has no reviewed build",
  );
  invariant(
    localBuilds.get("sentinelflow/web:demo") === "deployments/Dockerfile.web",
    "web runtime image has no reviewed build",
  );
  exactSortedStrings(
    [
      ...new Set(
        Object.values(document.services).map((service) => service.image),
      ),
    ],
    [
      "sentinelflow/backend:demo",
      "sentinelflow/postgres:demo",
      "sentinelflow/web:demo",
      approvedPrometheusImage,
    ],
    "Compose runtime image inventory differs",
  );

  const postgres = document.services.postgres;
  exactSortedStrings(
    postgres.tmpfs,
    [
      "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777,uid=70,gid=70",
      "/var/run/postgresql:rw,noexec,nosuid,nodev,size=4m,mode=0750,uid=70,gid=70",
    ],
    "PostgreSQL writable tmpfs contract differs",
  );
  const postgresMounts = new Map(
    (postgres.volumes || []).map((mount) => [mount.target, mount]),
  );
  exactSortedStrings(
    [...postgresMounts.keys()],
    ["/etc/postgresql/sentinelflow-pg_hba.conf", "/var/lib/postgresql/data"],
    "PostgreSQL mount contract differs",
  );
  const dataMount = postgresMounts.get("/var/lib/postgresql/data");
  invariant(
    dataMount.type === "volume" && dataMount.read_only !== true,
    "PostgreSQL PGDATA must be the sole writable named-volume mount",
  );
  const hbaMount = postgresMounts.get(
    "/etc/postgresql/sentinelflow-pg_hba.conf",
  );
  invariant(
    hbaMount.type === "bind" && hbaMount.read_only === true,
    "PostgreSQL HBA contract must be a read-only bind mount",
  );
}

export function validateVulnerabilityExceptions(
  policy,
  { now = new Date() } = {},
) {
  if (policy === undefined || policy === null) {
    return [];
  }
  invariant(
    policy.schema_version === "sentinelflow-vulnerability-exceptions-v1",
    "vulnerability exception policy has an unsupported schema",
  );
  invariant(
    Array.isArray(policy.exceptions),
    "vulnerability exception policy must contain an exceptions array",
  );
  invariant(
    policy.exceptions.length <= 10,
    "vulnerability exception policy exceeds the bounded review limit",
  );

  const identifiers = new Set();
  let previousKey = "";
  for (const exception of policy.exceptions) {
    invariant(
      exception && typeof exception === "object" && !Array.isArray(exception),
      "vulnerability exception entry is invalid",
    );
    exactSortedStrings(
      Object.keys(exception),
      [
        "expires_at",
        "fixed_version",
        "image_reference",
        "installed_version",
        "package_name",
        "package_type",
        "rationale",
        "severity",
        "target",
        "upstream_url",
        "vulnerability_id",
      ],
      "vulnerability exception fields differ",
    );
    invariant(
      /^CVE-\d{4}-\d{4,}$/u.test(exception.vulnerability_id),
      "vulnerability exception has an invalid CVE identifier",
    );
    validateImageReference(exception.image_reference);
    invariant(
      exception.severity === "CRITICAL",
      "only exact CRITICAL findings can use this exception contract",
    );
    for (const field of [
      "fixed_version",
      "installed_version",
      "package_name",
      "package_type",
      "rationale",
      "target",
    ]) {
      invariant(
        typeof exception[field] === "string" && exception[field].length > 0,
        `vulnerability exception has an empty ${field}`,
      );
      invariant(
        !/[\r\n*?]/u.test(exception[field]),
        `vulnerability exception ${field} must be exact and single-line`,
      );
    }
    invariant(
      /^https:\/\/(?:github\.com|go\.dev|pkg\.go\.dev)\//u.test(
        exception.upstream_url,
      ),
      "vulnerability exception must link to an approved primary upstream",
    );
    const expiry = Date.parse(exception.expires_at);
    invariant(
      Number.isFinite(expiry) &&
        new Date(expiry).toISOString() === exception.expires_at,
      "vulnerability exception expiry must be canonical RFC 3339 UTC",
    );
    invariant(
      expiry > now.getTime(),
      `vulnerability exception expired: ${exception.vulnerability_id}`,
    );
    invariant(
      expiry - now.getTime() <= 30 * 24 * 60 * 60 * 1000,
      `vulnerability exception exceeds 30 days: ${exception.vulnerability_id}`,
    );
    const key = [
      exception.image_reference,
      exception.target,
      exception.package_type,
      exception.package_name,
      exception.installed_version,
      exception.vulnerability_id,
    ].join("\0");
    invariant(!identifiers.has(key), "duplicate vulnerability exception");
    invariant(
      previousKey === "" || previousKey < key,
      "vulnerability exceptions must be strictly sorted",
    );
    identifiers.add(key);
    previousKey = key;
  }
  return policy.exceptions;
}

function findingKey(imageReference, result, finding) {
  return [
    imageReference,
    result.Target,
    result.Type,
    finding.PkgName,
    finding.InstalledVersion,
    finding.VulnerabilityID,
  ].join("\0");
}

function exceptionKey(exception) {
  return [
    exception.image_reference,
    exception.target,
    exception.package_type,
    exception.package_name,
    exception.installed_version,
    exception.vulnerability_id,
  ].join("\0");
}

export function validateTrivyReport(
  report,
  { imageReference, imageID, exceptionPolicy = null, now = new Date() },
) {
  validateImageReference(imageReference, {
    locallyBuilt: imageReference.startsWith("sentinelflow/"),
  });
  invariant(
    /^sha256:[0-9a-f]{64}$/u.test(imageID),
    "expected image ID is invalid",
  );
  invariant(
    report && typeof report === "object" && !Array.isArray(report),
    "Trivy report is invalid",
  );
  invariant(
    report.SchemaVersion === 2,
    "Trivy report schema must be version 2",
  );
  invariant(
    report.ArtifactType === "container_image",
    "Trivy report is not bound to a container image",
  );
  invariant(
    report.Metadata && report.Metadata.ImageID === imageID,
    "Trivy report image ID does not match the verified archive config",
  );
  invariant(
    report.Metadata.OS &&
      typeof report.Metadata.OS.Family === "string" &&
      report.Metadata.OS.Family.length > 0,
    "Trivy report has no detected operating system",
  );
  invariant(
    Array.isArray(report.Results) && report.Results.length > 0,
    "Trivy report has no scan results",
  );

  const exceptions = validateVulnerabilityExceptions(exceptionPolicy, { now });
  const relevantExceptions = new Map(
    exceptions
      .filter((entry) => entry.image_reference === imageReference)
      .map((entry) => [exceptionKey(entry), entry]),
  );
  const consumedExceptions = new Set();
  let osPackageCount = 0;
  const unexcepted = [];

  for (const result of report.Results) {
    invariant(
      result &&
        typeof result.Target === "string" &&
        result.Target.length > 0 &&
        typeof result.Class === "string" &&
        typeof result.Type === "string",
      "Trivy report contains an invalid result",
    );
    if (result.Class === "os-pkgs") {
      invariant(
        Array.isArray(result.Packages) && result.Packages.length > 0,
        `Trivy OS inventory is empty for ${result.Target}`,
      );
      osPackageCount += result.Packages.length;
    }
    for (const finding of result.Vulnerabilities || []) {
      invariant(
        finding &&
          typeof finding.VulnerabilityID === "string" &&
          typeof finding.PkgName === "string" &&
          typeof finding.InstalledVersion === "string" &&
          typeof finding.Severity === "string",
        "Trivy report contains an invalid vulnerability finding",
      );
      if (finding.Severity !== "CRITICAL") {
        continue;
      }
      const key = findingKey(imageReference, result, finding);
      const exception = relevantExceptions.get(key);
      if (
        exception &&
        exception.fixed_version === (finding.FixedVersion || "") &&
        exception.severity === finding.Severity
      ) {
        consumedExceptions.add(key);
        continue;
      }
      unexcepted.push(
        `${finding.VulnerabilityID}:${result.Target}:${finding.PkgName}@${finding.InstalledVersion}`,
      );
    }
  }
  invariant(
    osPackageCount > 0,
    "Trivy report contains no OS package inventory",
  );
  invariant(
    consumedExceptions.size === relevantExceptions.size,
    "vulnerability exception policy contains an unused or stale image exception",
  );
  invariant(
    unexcepted.length === 0,
    `unexcepted CRITICAL vulnerabilities: ${unexcepted.sort().join(", ")}`,
  );
  return { osPackageCount, exceptionCount: consumedExceptions.size };
}

export function validateImageSpdxDocument(document) {
  invariant(
    document && typeof document === "object" && !Array.isArray(document),
    "image SBOM is invalid",
  );
  invariant(document.spdxVersion === "SPDX-2.3", "image SBOM must be SPDX 2.3");
  invariant(
    document.dataLicense === "CC0-1.0",
    "image SBOM license must be CC0-1.0",
  );
  invariant(
    Array.isArray(document.packages) && document.packages.length > 1,
    "image SBOM has no package inventory",
  );
  invariant(
    Array.isArray(document.relationships) && document.relationships.length > 0,
    "image SBOM has no relationships",
  );
  const packageUrls = document.packages.flatMap((packageEntry) =>
    (packageEntry.externalRefs || [])
      .filter((reference) => reference.referenceType === "purl")
      .map((reference) => reference.referenceLocator),
  );
  invariant(
    packageUrls.some((packageUrl) => /^pkg:(?:apk|deb)\//u.test(packageUrl)),
    "image SBOM has no Alpine or Debian OS package URLs",
  );
  const serialized = JSON.stringify(document);
  invariant(
    !/(?:sk-[A-Za-z0-9_-]{20,}|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|OPENAI_API_KEY)/u.test(
      serialized,
    ),
    "image SBOM contains possible secret material",
  );
}

function readJson(relativePath) {
  return JSON.parse(
    fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8"),
  );
}

function pinnedGoToolchain() {
  const goModule = fs.readFileSync(path.join(repositoryRoot, "go.mod"), "utf8");
  const match = goModule.match(/^go\s+(1\.\d+\.\d+)\s*$/mu);
  invariant(match, "go.mod must pin a full major.minor.patch Go version");
  return `go${match[1]}`;
}

function listFiles(directory, predicate) {
  const absoluteDirectory = path.join(repositoryRoot, directory);
  if (!fs.existsSync(absoluteDirectory)) {
    return [];
  }

  const files = [];
  const visit = (currentDirectory) => {
    for (const entry of fs
      .readdirSync(currentDirectory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const absolutePath = path.join(currentDirectory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(
          `supply-chain input must not be a symlink: ${path.relative(repositoryRoot, absolutePath)}`,
        );
      }
      if (entry.isDirectory()) {
        visit(absolutePath);
      } else if (entry.isFile() && predicate(absolutePath)) {
        files.push(absolutePath);
      }
    }
  };
  visit(absoluteDirectory);
  return files;
}

export function isExactNpmVersion(version) {
  return exactNpmVersionPattern.test(version);
}

export function validateActionReference(reference) {
  if (reference.startsWith("./")) {
    invariant(
      !reference.split("/").includes(".."),
      `local action escapes the repository: ${reference}`,
    );
    return;
  }

  if (reference.startsWith("docker://")) {
    invariant(
      sha256DigestPattern.test(reference),
      `Docker action is not pinned by sha256 digest: ${reference}`,
    );
    return;
  }

  const separator = reference.lastIndexOf("@");
  invariant(separator > 0, `remote action has no ref: ${reference}`);
  const actionPath = reference.slice(0, separator);
  const actionRef = reference.slice(separator + 1);
  invariant(
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.\/-]+)?$/u.test(
      actionPath,
    ),
    `invalid remote action path: ${reference}`,
  );
  invariant(
    fullCommitPattern.test(actionRef),
    `remote action is not pinned to a full lowercase commit SHA: ${reference}`,
  );
}

export function validateImageReference(
  reference,
  { locallyBuilt = false } = {},
) {
  invariant(reference.length > 0, "empty image reference");
  invariant(
    !/\s/u.test(reference),
    `image reference contains whitespace: ${reference}`,
  );
  if (locallyBuilt) {
    invariant(
      !reference.includes("${"),
      `locally built image reference must not be dynamically selected: ${reference}`,
    );
    return;
  }
  invariant(
    sha256DigestPattern.test(reference),
    `external image is not pinned by sha256 digest: ${reference}`,
  );
}

export function validatePrometheusImage(reference) {
  invariant(
    reference === approvedPrometheusImage,
    "Prometheus must use the reviewed v3.13.1 distroless multi-architecture digest",
  );
}

export function validateObservabilityVerificationText(text, filename) {
  const assignment = `image="${approvedPrometheusImage}"`;
  const assignmentIndex = text.indexOf(assignment);
  const pullIndex = text.indexOf('docker pull "$image"');
  const inspectIndex = text.indexOf('docker image inspect "$image"');
  invariant(
    assignmentIndex >= 0,
    `${filename} does not pin the reviewed Prometheus verification image`,
  );
  invariant(
    pullIndex > assignmentIndex && inspectIndex > pullIndex,
    `${filename} must pull the exact Prometheus digest before inspection`,
  );
}

export function validateImageGateText(text, filename = "<image-gate>") {
  for (const [name, reference] of [
    ["buildkit_builder_image", approvedBuildkitImage],
    ["scanner_image", approvedTrivyImage],
    ["scanner_database", approvedTrivyDatabase],
    ["prometheus_image", approvedPrometheusImage],
  ]) {
    invariant(
      text.includes(`${name}="${reference}"`),
      `${filename} does not pin the reviewed ${name}`,
    );
  }
  invariant(
      text.includes('docker buildx create') &&
      text.includes('image=$buildkit_builder_image') &&
      text.includes('docker pull "$scanner_image"') &&
      text.includes('--user "$scanner_user"') &&
      text.includes("TRIVY_CACHE_DIR=/tmp/trivy") &&
      text.includes("target=/tmp/trivy") &&
      text.includes("verify-scanner-version") &&
      text.includes("verify-scanner-db"),
    `${filename} does not verify immutable scanner acquisition`,
  );
  invariant(
    text.includes("--severity CRITICAL") &&
      text.includes("verify-image-archive") &&
      text.includes("verify-vulnerability-report") &&
      text.includes("verify-image-sbom"),
    `${filename} does not enforce archive binding, CRITICAL, and image-SBOM policy`,
  );
  invariant(
    !text.includes("--ignore-unfixed") &&
      !text.includes("/var/run/docker.sock") &&
      !/(?:trivy|scanner)[^\n]*:latest/u.test(text),
    `${filename} weakens scanner coverage or authority`,
  );
  invariant(
    text.includes("nft --version") &&
      text.includes("/etc/ssl/certs/ca-certificates.crt") &&
      text.includes("find /app/contracts -type d") &&
      text.includes('"555:0:0"') &&
      text.includes("find /app/contracts -type f") &&
      text.includes('"444:0:0"') &&
      text.includes("/etc/nginx/conf.d/default.conf") &&
      text.includes('"101:101"') &&
      text.includes("find /usr/share/nginx/html -type d") &&
      text.includes("find /usr/share/nginx/html -type f") &&
      text.includes("--read-only") &&
      text.includes("--cap-drop ALL"),
    `${filename} does not probe runtime dependencies under the reviewed isolation`,
  );
  const reproducibleBuildsIndex = text.indexOf(
    "images: reproducible no-cache application builds",
  );
  const runtimeProbeIndex = text.indexOf(
    "images: unprivileged read-only runtime dependency probes",
  );
  const scannerPullIndex = text.indexOf('docker pull "$scanner_image"');
  invariant(
    reproducibleBuildsIndex >= 0 &&
      runtimeProbeIndex > reproducibleBuildsIndex &&
      scannerPullIndex > runtimeProbeIndex,
    `${filename} must fail fast on runtime probes before scanner acquisition`,
  );
  invariant(
    (text.match(/--network none/gu) || []).length >= 4,
    `${filename} must run every post-download scanner operation without a network`,
  );
  for (const receipt of [
    'demo_analysis_receipt="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
    'demo_validation_receipt="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"',
    'demo_receipt_volume="sentinelflow-postgres-demo-receipts-$run_id"',
    '--env "ANALYSIS_RECEIPT=$demo_analysis_receipt"',
    '--env "VALIDATION_RECEIPT=$demo_validation_receipt"',
    'chown 0:70 /receipts /receipts/analysis.sha256 /receipts/validation.sha256',
    'chmod 0440 /receipts/analysis.sha256 /receipts/validation.sha256',
    'find /receipts -mindepth 1 -maxdepth 1 | wc -l',
    'type=volume,source=$demo_receipt_volume,target=/run/sentinelflow-demo-history-capability-receipts,readonly',
  ]) {
    invariant(
      text.includes(receipt),
      `${filename} does not stage the reviewed synthetic demo capability receipts for the isolated migration gate`,
    );
  }
}

function stripYamlScalar(value) {
  const withoutComment = value.replace(/\s+#.*$/u, "").trim();
  if (
    withoutComment.length >= 2 &&
    ((withoutComment.startsWith('"') && withoutComment.endsWith('"')) ||
      (withoutComment.startsWith("'") && withoutComment.endsWith("'")))
  ) {
    return withoutComment.slice(1, -1);
  }
  return withoutComment;
}

export function inspectWorkflowText(text, filename = "<workflow>") {
  let actionCount = 0;
  for (const [index, line] of text.split(/\r?\n/u).entries()) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*(.+?)\s*$/u);
    if (!match) {
      continue;
    }
    const reference = stripYamlScalar(match[1]);
    try {
      validateActionReference(reference);
    } catch (error) {
      throw new Error(`${filename}:${index + 1}: ${error.message}`);
    }
    actionCount += 1;
  }
  return actionCount;
}

function indentation(line) {
  const match = line.match(/^[ ]*/u);
  return match ? match[0].length : 0;
}

export function inspectYamlImages(text, filename = "<yaml>") {
  const lines = text.split(/\r?\n/u);
  const images = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^(\s*)image:\s*(.+?)\s*$/u);
    if (!match) {
      continue;
    }
    const imageIndentation = match[1].length;
    const reference = stripYamlScalar(match[2]);
    let locallyBuilt = false;

    for (let sibling = index + 1; sibling < lines.length; sibling += 1) {
      const siblingLine = lines[sibling];
      if (/^\s*(?:#.*)?$/u.test(siblingLine)) {
        continue;
      }
      const siblingIndentation = indentation(siblingLine);
      if (siblingIndentation < imageIndentation) {
        break;
      }
      if (
        siblingIndentation === imageIndentation &&
        /^\s*build:\s*/u.test(siblingLine)
      ) {
        locallyBuilt = true;
      }
    }

    images.push({ index, reference, locallyBuilt });
  }

  const locallyBuiltReferences = new Set(
    images
      .filter((image) => image.locallyBuilt)
      .map((image) => image.reference),
  );
  for (const image of images) {
    try {
      validateImageReference(image.reference, {
        locallyBuilt:
          image.locallyBuilt || locallyBuiltReferences.has(image.reference),
      });
    } catch (error) {
      throw new Error(`${filename}:${image.index + 1}: ${error.message}`);
    }
  }
  return images.length;
}

export function inspectDockerfileText(text, filename = "<Dockerfile>") {
  const lines = text.split(/\r?\n/u);
  const syntax = lines[0]?.match(/^# syntax=(\S+)$/u);
  invariant(
    syntax,
    `${filename}: first line must select a Dockerfile frontend`,
  );
  try {
    validateImageReference(syntax[1]);
  } catch (error) {
    throw new Error(`${filename}:1: ${error.message}`);
  }

  let baseImageCount = 0;
  for (const [index, line] of lines.entries()) {
    const match = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/iu);
    if (!match) {
      continue;
    }
    const reference = match[1];
    if (reference.toLowerCase() !== "scratch") {
      try {
        validateImageReference(reference);
      } catch (error) {
        throw new Error(`${filename}:${index + 1}: ${error.message}`);
      }
    }
    baseImageCount += 1;
  }
  invariant(baseImageCount > 0, `${filename}: no FROM instruction found`);

  if (filename === "deployments/Dockerfile.backend") {
    const finalStageOffset = [...text.matchAll(/^\s*FROM\s+/gimu)].at(
      -1,
    )?.index;
    invariant(
      Number.isInteger(finalStageOffset),
      `${filename}: backend final stage is missing`,
    );
    const finalStage = text.slice(finalStageOffset);
    const contractsCopy = finalStage.search(
      /^\s*COPY\s+--chown=0:0\s+contracts\s+\.\/contracts\s*$/gimu,
    );
    const directoryMode = finalStage.search(
      /find\s+\/app\/contracts\s+-type\s+d\s+-exec\s+chmod\s+0555\s+\{\}\s+\+/u,
    );
    const fileMode = finalStage.search(
      /find\s+\/app\/contracts\s+-type\s+f\s+-exec\s+chmod\s+0444\s+\{\}\s+\+/u,
    );
    invariant(
      contractsCopy >= 0,
      `${filename}: backend contracts must be copied as root:root in the final image`,
    );
    invariant(
      directoryMode > contractsCopy,
      `${filename}: backend contract directories must be normalized to 0555 after COPY`,
    );
    invariant(
      fileMode > contractsCopy,
      `${filename}: backend contract regular files must be normalized to 0444 after COPY`,
    );
  }
  if (filename === "deployments/Dockerfile.web") {
    const finalStageOffset = [...text.matchAll(/^\s*FROM\s+/gimu)].at(
      -1,
    )?.index;
    invariant(
      Number.isInteger(finalStageOffset),
      `${filename}: web final stage is missing`,
    );
    const finalStage = text.slice(finalStageOffset);
    const configCopy = finalStage.search(
      /^\s*COPY\s+--chown=0:0\s+deployments\/nginx\.conf\s+\/etc\/nginx\/conf\.d\/default\.conf\s*$/gimu,
    );
    const staticCopy = finalStage.search(
      /^\s*COPY\s+--chown=0:0\s+--from=build\s+\/src\/web\/dist\/\s+\/usr\/share\/nginx\/html\/\s*$/gimu,
    );
    const configMode = finalStage.search(
      /chmod\s+0444\s+\/etc\/nginx\/conf\.d\/default\.conf/u,
    );
    const directoryMode = finalStage.search(
      /find\s+\/usr\/share\/nginx\/html\s+-type\s+d\s+-exec\s+chmod\s+0555\s+\{\}\s+\+/u,
    );
    const fileMode = finalStage.search(
      /find\s+\/usr\/share\/nginx\/html\s+-type\s+f\s+-exec\s+chmod\s+0444\s+\{\}\s+\+/u,
    );
    const buildRoot = finalStage.search(/^\s*USER\s+0:0\s*$/gimu);
    const runtimeUser = finalStage.search(/^\s*USER\s+101:101\s*$/gimu);
    invariant(
      configCopy >= 0,
      `${filename}: nginx configuration must be copied as root:root in the final image`,
    );
    invariant(
      staticCopy >= 0,
      `${filename}: web static files must be copied as root:root in the final image`,
    );
    invariant(
      buildRoot >= 0 && (configMode < 0 || buildRoot < configMode),
      `${filename}: web permission normalization must run as build-time root`,
    );
    invariant(
      configMode > configCopy,
      `${filename}: nginx configuration must be normalized to 0444 after COPY`,
    );
    invariant(
      directoryMode > staticCopy,
      `${filename}: web static directories must be normalized to 0555 after COPY`,
    );
    invariant(
      fileMode > staticCopy,
      `${filename}: web static regular files must be normalized to 0444 after COPY`,
    );
    invariant(
      runtimeUser > fileMode,
      `${filename}: web final image must restore runtime user 101:101 after normalization`,
    );
  }
  return baseImageCount;
}

function runJsonCommand(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, GOTOOLCHAIN: pinnedGoToolchain() },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed: ${(result.stderr || result.stdout).trim()}`,
    );
  }
  return JSON.parse(result.stdout);
}

function checkGoPolicy() {
  const goModule = runJsonCommand("go", ["mod", "edit", "-json"]);
  invariant(
    /^1\.\d+\.\d+$/u.test(goModule.Go || ""),
    "go.mod must pin a full major.minor.patch Go version",
  );
  invariant(
    !goModule.Toolchain,
    "go.mod toolchain indirection is not allowed; pin the Go version directly",
  );
  invariant(
    !goModule.Tool || goModule.Tool.length === 0,
    "go.mod tool directives require an explicit reviewed exception",
  );
  invariant(
    !goModule.Replace || goModule.Replace.length === 0,
    "go.mod replace directives require an explicit reviewed exception",
  );
  invariant(
    !goModule.Exclude || goModule.Exclude.length === 0,
    "go.mod exclude directives require an explicit reviewed exception",
  );
  invariant(
    !goModule.Retract || goModule.Retract.length === 0,
    "go.mod retract directives are not valid in the application module",
  );

  const sums = fs.readFileSync(path.join(repositoryRoot, "go.sum"), "utf8");
  for (const requirement of goModule.Require || []) {
    const modulePath = requirement.Path;
    const version = requirement.Version;
    invariant(
      exactGoVersionPattern.test(version) ||
        goPseudoVersionPattern.test(version),
      `Go module is not pinned to an exact semantic or pseudo-version: ${modulePath}@${version}`,
    );
    const escaped = `${modulePath} ${version}`.replace(
      /[.*+?^${}()|[\]\\]/gu,
      "\\$&",
    );
    invariant(
      new RegExp(`^${escaped}(?:/go\\.mod)? h1:`, "mu").test(sums),
      `go.sum has no checksum for ${modulePath}@${version}`,
    );
  }
}

function decodeIntegrity(integrity, packagePath) {
  const match = integrity.match(/^sha512-([A-Za-z0-9+/]+={0,2})$/u);
  invariant(
    match,
    `npm package does not have a sha512 integrity value: ${packagePath}`,
  );
  const bytes = Buffer.from(match[1], "base64");
  invariant(
    bytes.length === 64,
    `npm package has malformed sha512 integrity bytes: ${packagePath}`,
  );
  return bytes.toString("hex").toUpperCase();
}

function checkNpmPolicy() {
  const packageJson = readJson("web/package.json");
  const packageLock = readJson("web/package-lock.json");
  invariant(
    packageLock.lockfileVersion === 3,
    "web/package-lock.json must use lockfileVersion 3",
  );
  invariant(
    packageLock.requires === true,
    "web/package-lock.json must include dependency requirements",
  );
  invariant(
    packageLock.packages && packageLock.packages[""],
    "web/package-lock.json has no root package entry",
  );

  const rootLock = packageLock.packages[""];
  for (const dependencyClass of ["dependencies", "devDependencies"]) {
    const declared = packageJson[dependencyClass] || {};
    const lockedRoot = rootLock[dependencyClass] || {};
    invariant(
      JSON.stringify(declared) === JSON.stringify(lockedRoot),
      `${dependencyClass} differs between package.json and package-lock.json`,
    );
    for (const [name, version] of Object.entries(declared)) {
      invariant(
        isExactNpmVersion(version),
        `npm dependency is not pinned to an exact version: ${name}@${version}`,
      );
    }
  }

  for (const [packagePath, metadata] of Object.entries(packageLock.packages)) {
    if (!packagePath || metadata.link) {
      continue;
    }
    invariant(
      isExactNpmVersion(metadata.version || ""),
      `npm lock entry has no exact version: ${packagePath}`,
    );
    invariant(
      typeof metadata.resolved === "string" &&
        metadata.resolved.startsWith("https://registry.npmjs.org/"),
      `npm lock entry is not resolved through the HTTPS npm registry: ${packagePath}`,
    );
    decodeIntegrity(metadata.integrity || "", packagePath);
  }
}

function checkPinnedToolInvocations() {
  const workflowFiles = listFiles(".github/workflows", (filename) =>
    /\.ya?ml$/u.test(filename),
  );
  const exactToolVersion =
    /^(?:v)?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
  for (const filename of workflowFiles) {
    const text = fs.readFileSync(filename, "utf8");
    invariant(
      !/^\s*runs-on:\s*[^#\n]*latest\s*(?:#.*)?$/mu.test(text),
      `${path.relative(repositoryRoot, filename)} uses a mutable latest runner label`,
    );
    for (const match of text.matchAll(
      /\bgo\s+(?:install|run)\s+[^\s@]+@([^\s"']+)/gu,
    )) {
      invariant(
        exactToolVersion.test(match[1]),
        `${path.relative(repositoryRoot, filename)} uses an unpinned Go tool version: ${match[0]}`,
      );
    }
    for (const match of text.matchAll(/\bnpx\s+--yes\s+([^\s"']+)/gu)) {
      const separator = match[1].lastIndexOf("@");
      const version = separator >= 0 ? match[1].slice(separator + 1) : "";
      invariant(
        exactToolVersion.test(version),
        `${path.relative(repositoryRoot, filename)} uses an unpinned npx package: ${match[1]}`,
      );
    }
  }
}

function checkRepositoryPolicy() {
  validateComposeSourceBindPolicy(
    fs.readFileSync(path.join(repositoryRoot, "deployments/compose.yaml"), "utf8"),
  );
  const workflowFiles = listFiles(".github/workflows", (filename) =>
    /\.ya?ml$/u.test(filename),
  );
  invariant(workflowFiles.length > 0, "no GitHub Actions workflows found");
  let actionCount = 0;
  for (const filename of workflowFiles) {
    const relative = path.relative(repositoryRoot, filename);
    const text = fs.readFileSync(filename, "utf8");
    actionCount += inspectWorkflowText(text, relative);
    inspectYamlImages(text, relative);
  }
  invariant(actionCount > 0, "no GitHub Action references found");

  const deploymentYamlFiles = listFiles("deployments", (filename) =>
    /\.ya?ml$/u.test(filename),
  );
  let prometheusImageCount = 0;
  for (const filename of deploymentYamlFiles) {
    const text = fs.readFileSync(filename, "utf8");
    inspectYamlImages(text, path.relative(repositoryRoot, filename));
    for (const match of text.matchAll(
      /^\s*image:\s*(prom\/prometheus:\S+)\s*$/gmu,
    )) {
      validatePrometheusImage(stripYamlScalar(match[1]));
      prometheusImageCount += 1;
    }
  }
  invariant(
    prometheusImageCount === 1,
    "exactly one approved Prometheus deployment image is required",
  );
  const observabilityVerification = path.join(
    repositoryRoot,
    "deployments/observability/verify.sh",
  );
  validateObservabilityVerificationText(
    fs.readFileSync(observabilityVerification, "utf8"),
    "deployments/observability/verify.sh",
  );
  const imageGate = path.join(repositoryRoot, "scripts/check-images.sh");
  validateImageGateText(
    fs.readFileSync(imageGate, "utf8"),
    "scripts/check-images.sh",
  );

  const dockerfiles = listFiles("deployments", (filename) =>
    path.basename(filename).startsWith("Dockerfile"),
  );
  invariant(dockerfiles.length > 0, "no deployment Dockerfiles found");
  for (const filename of dockerfiles) {
    inspectDockerfileText(
      fs.readFileSync(filename, "utf8"),
      path.relative(repositoryRoot, filename),
    );
  }

  checkPinnedToolInvocations();
  checkGoPolicy();
  checkNpmPolicy();
}

function spdxIdentifier(prefix, value) {
  const digest = crypto
    .createHash("sha256")
    .update(value)
    .digest("hex")
    .slice(0, 24);
  return `SPDXRef-${prefix}-${digest}`;
}

function checksumFromGoSum(sum, modulePath) {
  const match = sum.match(/^h1:([A-Za-z0-9+/]+={0,2})$/u);
  invariant(match, `Go module has malformed h1 checksum: ${modulePath}`);
  const bytes = Buffer.from(match[1], "base64");
  invariant(
    bytes.length === 32,
    `Go module has malformed sha256 checksum bytes: ${modulePath}`,
  );
  return bytes.toString("hex").toUpperCase();
}

function goBuildModules() {
  const template = "{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Sum}}{{end}}";
  const result = spawnSync(
    "go",
    [
      "list",
      "-mod=readonly",
      "-deps",
      "-f",
      template,
      "./cmd/...",
      "./internal/...",
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { ...process.env, GOTOOLCHAIN: pinnedGoToolchain() },
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `go list for SBOM failed: ${(result.stderr || result.stdout).trim()}`,
    );
  }

  const modules = new Map();
  for (const line of result.stdout.split(/\r?\n/u)) {
    if (!line) {
      continue;
    }
    const [modulePath, version, sum] = line.split("\t");
    if (!version) {
      continue;
    }
    invariant(
      sum,
      `used Go module has no content checksum: ${modulePath}@${version}`,
    );
    modules.set(`${modulePath}@${version}`, { modulePath, version, sum });
  }
  return [...modules.values()].sort((a, b) =>
    `${a.modulePath}@${a.version}`.localeCompare(
      `${b.modulePath}@${b.version}`,
    ),
  );
}

function npmPackageName(packagePath) {
  const marker = "node_modules/";
  const last = packagePath.lastIndexOf(marker);
  invariant(last >= 0, `unexpected npm lock package path: ${packagePath}`);
  const remaining = packagePath.slice(last + marker.length);
  if (remaining.startsWith("@")) {
    return remaining.split("/").slice(0, 2).join("/");
  }
  return remaining.split("/")[0];
}

function npmPurl(name, version) {
  if (name.startsWith("@")) {
    const [scope, packageName] = name.split("/");
    invariant(scope && packageName, `invalid scoped npm package name: ${name}`);
    return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(packageName)}@${version}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}@${version}`;
}

export function buildSpdxDocument({
  goModules,
  npmLock,
  inputDigest,
  created,
}) {
  const goRootId = "SPDXRef-Package-SentinelFlow-Go";
  const webRootId = "SPDXRef-Package-SentinelFlow-Web";
  const packages = [
    {
      name: "github.com/devwooops/sentinelflow",
      SPDXID: goRootId,
      versionInfo: "0.1.0-source",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "MIT",
      licenseDeclared: "MIT",
      copyrightText: "NOASSERTION",
      primaryPackagePurpose: "APPLICATION",
    },
    {
      name: npmLock.name,
      SPDXID: webRootId,
      versionInfo: npmLock.version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      primaryPackagePurpose: "APPLICATION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: npmPurl(npmLock.name, npmLock.version),
        },
      ],
    },
  ];
  const relationships = [
    {
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: goRootId,
    },
    {
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: webRootId,
    },
  ];

  for (const module of goModules) {
    const id = spdxIdentifier(
      "GoModule",
      `${module.modulePath}@${module.version}`,
    );
    packages.push({
      name: module.modulePath,
      SPDXID: id,
      versionInfo: module.version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      checksums: [
        {
          algorithm: "SHA256",
          checksumValue: checksumFromGoSum(module.sum, module.modulePath),
        },
      ],
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: `pkg:golang/${module.modulePath}@${module.version}`,
        },
      ],
    });
    relationships.push({
      spdxElementId: goRootId,
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: id,
    });
  }

  const npmPackages = Object.entries(npmLock.packages)
    .filter(([packagePath, metadata]) => packagePath && !metadata.link)
    .sort(([left], [right]) => left.localeCompare(right));
  for (const [packagePath, metadata] of npmPackages) {
    const name = npmPackageName(packagePath);
    const id = spdxIdentifier(
      "NpmPackage",
      `${packagePath}:${name}@${metadata.version}`,
    );
    packages.push({
      name,
      SPDXID: id,
      versionInfo: metadata.version,
      downloadLocation: metadata.resolved,
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: metadata.license || "NOASSERTION",
      copyrightText: "NOASSERTION",
      checksums: [
        {
          algorithm: "SHA512",
          checksumValue: decodeIntegrity(metadata.integrity, packagePath),
        },
      ],
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: npmPurl(name, metadata.version),
        },
      ],
    });
    relationships.push({
      spdxElementId: webRootId,
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: id,
    });
  }

  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "sentinelflow-source-dependencies",
    documentNamespace: `https://github.com/devwooops/sentinelflow/sbom/${inputDigest}`,
    comment:
      "Reproducible source dependency SBOM from the Go build graph and npm lockfile. Runtime image OS/package inventories are emitted and verified separately by the pinned container-image gate.",
    creationInfo: {
      created,
      creators: ["Tool: sentinelflow-supply-chain-policy-v1"],
    },
    packages,
    relationships,
  };
}

export function validateSpdxDocument(document) {
  invariant(document.spdxVersion === "SPDX-2.3", "SBOM must be SPDX 2.3 JSON");
  invariant(
    document.dataLicense === "CC0-1.0",
    "SBOM dataLicense must be CC0-1.0",
  );
  invariant(
    document.SPDXID === "SPDXRef-DOCUMENT",
    "SBOM document SPDXID is invalid",
  );
  invariant(
    /^https:\/\/github\.com\/devwooops\/sentinelflow\/sbom\/[0-9a-f]{64}$/u.test(
      document.documentNamespace,
    ),
    "SBOM namespace is invalid",
  );
  invariant(
    !Number.isNaN(Date.parse(document.creationInfo?.created)),
    "SBOM creation time is invalid",
  );
  invariant(
    Array.isArray(document.packages) && document.packages.length > 2,
    "SBOM has no dependency packages",
  );
  invariant(
    Array.isArray(document.relationships) && document.relationships.length > 2,
    "SBOM has no dependency relationships",
  );

  const identifiers = new Set(["SPDXRef-DOCUMENT"]);
  for (const packageEntry of document.packages) {
    invariant(
      /^SPDXRef-[A-Za-z0-9.-]+$/u.test(packageEntry.SPDXID || ""),
      `invalid package SPDXID: ${packageEntry.SPDXID}`,
    );
    invariant(
      !identifiers.has(packageEntry.SPDXID),
      `duplicate SPDXID: ${packageEntry.SPDXID}`,
    );
    identifiers.add(packageEntry.SPDXID);
    invariant(
      packageEntry.filesAnalyzed === false,
      `dependency package unexpectedly claims file analysis: ${packageEntry.SPDXID}`,
    );
    for (const checksum of packageEntry.checksums || []) {
      const expectedLength =
        checksum.algorithm === "SHA256"
          ? 64
          : checksum.algorithm === "SHA512"
            ? 128
            : 0;
      invariant(
        expectedLength > 0,
        `unsupported SBOM checksum algorithm: ${checksum.algorithm}`,
      );
      invariant(
        new RegExp(`^[0-9A-F]{${expectedLength}}$`, "u").test(
          checksum.checksumValue,
        ),
        `invalid SBOM checksum: ${packageEntry.SPDXID}`,
      );
    }
  }
  for (const relationship of document.relationships) {
    invariant(
      identifiers.has(relationship.spdxElementId),
      `SBOM relationship source does not exist: ${relationship.spdxElementId}`,
    );
    invariant(
      identifiers.has(relationship.relatedSpdxElement),
      `SBOM relationship target does not exist: ${relationship.relatedSpdxElement}`,
    );
    invariant(
      ["DESCRIBES", "DEPENDS_ON"].includes(relationship.relationshipType),
      `unexpected SBOM relationship: ${relationship.relationshipType}`,
    );
  }

  const serialized = JSON.stringify(document);
  invariant(
    !/(?:sk-[A-Za-z0-9_-]{20,}|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|OPENAI_API_KEY)/u.test(
      serialized,
    ),
    "SBOM contains possible secret material",
  );
}

function generateSpdx() {
  const packageLock = readJson("web/package-lock.json");
  const inputHash = crypto.createHash("sha256");
  for (const filename of [
    "go.mod",
    "go.sum",
    "web/package.json",
    "web/package-lock.json",
  ]) {
    inputHash.update(filename);
    inputHash.update("\0");
    inputHash.update(fs.readFileSync(path.join(repositoryRoot, filename)));
    inputHash.update("\0");
  }
  const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH || "0";
  invariant(
    /^\d+$/u.test(sourceDateEpoch),
    "SOURCE_DATE_EPOCH must be a non-negative integer",
  );
  const created = new Date(Number(sourceDateEpoch) * 1000)
    .toISOString()
    .replace(".000Z", "Z");
  const document = buildSpdxDocument({
    goModules: goBuildModules(),
    npmLock: packageLock,
    inputDigest: inputHash.digest("hex"),
    created,
  });
  validateSpdxDocument(document);
  return document;
}

function writeNewFile(filename, contents) {
  const absolutePath = path.resolve(process.cwd(), filename);
  invariant(
    !fs.existsSync(absolutePath),
    `refusing to overwrite SBOM output: ${absolutePath}`,
  );
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(absolutePath, contents, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

function readStrictJsonFile(filename, description) {
  const absolute = path.resolve(process.cwd(), filename);
  const metadata = fs.lstatSync(absolute);
  invariant(metadata.isFile(), `${description} is not a regular file`);
  invariant(!metadata.isSymbolicLink(), `${description} must not be a symlink`);
  return JSON.parse(fs.readFileSync(absolute, "utf8"));
}

function verifyScannerDatabaseDirectory(directory) {
  const absolute = path.resolve(process.cwd(), directory);
  const metadata = fs.lstatSync(absolute);
  invariant(metadata.isDirectory(), "Trivy database path is not a directory");
  invariant(
    !metadata.isSymbolicLink(),
    "Trivy database path must not be a symlink",
  );
  const entries = fs.readdirSync(absolute).sort();
  exactSortedStrings(
    entries,
    ["metadata.json", "trivy.db"],
    "Trivy database directory differs from the frozen contract",
  );
  const checksums = {};
  for (const filename of entries) {
    const entryPath = path.join(absolute, filename);
    const entryMetadata = fs.lstatSync(entryPath);
    invariant(
      entryMetadata.isFile() && !entryMetadata.isSymbolicLink(),
      `Trivy database contains a non-regular entry: ${filename}`,
    );
    if (filename === "trivy.db") {
      checksums[filename] = crypto
        .createHash("sha256")
        .update(fs.readFileSync(entryPath))
        .digest("hex");
    }
  }
  validateScannerDatabaseChecksums(checksums);
  validateScannerDatabaseMetadata(
    JSON.parse(fs.readFileSync(path.join(absolute, "metadata.json"), "utf8")),
  );
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "check") {
    invariant(args.length === 0, "check accepts no arguments");
    checkRepositoryPolicy();
    process.stdout.write("supply-chain static policy: passed\n");
    return;
  }
  if (command === "sbom") {
    invariant(
      args.length === 2 && args[0] === "--output",
      "usage: supply-chain-policy.mjs sbom --output <path>",
    );
    writeNewFile(args[1], `${JSON.stringify(generateSpdx(), null, 2)}\n`);
    process.stdout.write(`SPDX SBOM generated: ${path.basename(args[1])}\n`);
    return;
  }
  if (command === "verify-sbom") {
    invariant(
      args.length === 1,
      "usage: supply-chain-policy.mjs verify-sbom <path>",
    );
    const filename = path.resolve(process.cwd(), args[0]);
    invariant(
      fs.statSync(filename).isFile(),
      `SBOM is not a regular file: ${filename}`,
    );
    const document = JSON.parse(fs.readFileSync(filename, "utf8"));
    validateSpdxDocument(document);
    process.stdout.write(
      `SPDX SBOM verified: ${path.basename(filename)} (${document.packages.length} packages, ${document.relationships.length} relationships)\n`,
    );
    return;
  }
  if (command === "verify-scanner-version") {
    invariant(
      args.length === 1,
      "usage: supply-chain-policy.mjs verify-scanner-version <version-output>",
    );
    validateScannerVersionOutput(args[0]);
    process.stdout.write("Trivy scanner version verified\n");
    return;
  }
  if (command === "verify-scanner-db") {
    invariant(
      args.length === 1,
      "usage: supply-chain-policy.mjs verify-scanner-db <db-directory>",
    );
    verifyScannerDatabaseDirectory(args[0]);
    process.stdout.write("Trivy database snapshot verified\n");
    return;
  }
  if (command === "verify-image-inspection") {
    invariant(
      args.length === 2,
      "usage: supply-chain-policy.mjs verify-image-inspection <kind> <json>",
    );
    validateImageInspection(
      args[0],
      readStrictJsonFile(args[1], "image inspection"),
    );
    process.stdout.write(`${args[0]} image configuration verified\n`);
    return;
  }
  if (command === "verify-image-archive") {
    invariant(
      args.length === 2,
      "usage: supply-chain-policy.mjs verify-image-archive <index-json> <docker-manifest-json>",
    );
    const result = validateImageArchiveBinding(
      readStrictJsonFile(args[0], "image archive index"),
      readStrictJsonFile(args[1], "Docker image archive manifest"),
    );
    process.stdout.write(`${result.imageConfigID}\t${result.configPath}\n`);
    return;
  }
  if (command === "verify-compose-runtime") {
    invariant(
      args.length === 1,
      "usage: supply-chain-policy.mjs verify-compose-runtime <json>",
    );
    validateComposeRuntimePolicy(
      readStrictJsonFile(args[0], "Compose runtime configuration"),
    );
    process.stdout.write("Compose runtime isolation policy verified\n");
    return;
  }
  if (command === "verify-vulnerability-report") {
    invariant(
      args.length === 3 || args.length === 4,
      "usage: supply-chain-policy.mjs verify-vulnerability-report <image-ref> <image-config-id> <report> [exception-policy]",
    );
    const exceptionPolicy =
      args.length === 4
        ? readStrictJsonFile(args[3], "vulnerability exception policy")
        : null;
    const result = validateTrivyReport(
      readStrictJsonFile(args[2], "Trivy vulnerability report"),
      {
        imageReference: args[0],
        imageID: args[1],
        exceptionPolicy,
      },
    );
    process.stdout.write(
      `container vulnerability report verified (${result.osPackageCount} OS packages, ${result.exceptionCount} exceptions)\n`,
    );
    return;
  }
  if (command === "verify-image-sbom") {
    invariant(
      args.length === 1,
      "usage: supply-chain-policy.mjs verify-image-sbom <spdx-json>",
    );
    validateImageSpdxDocument(readStrictJsonFile(args[0], "image SBOM"));
    process.stdout.write("container SPDX SBOM verified\n");
    return;
  }
  throw new Error("usage: supply-chain-policy.mjs <check|sbom|verify-sbom>");
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`supply-chain policy failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
