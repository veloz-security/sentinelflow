#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const JSON_LIMIT = 1024 * 1024;
const JOURNAL_LIMIT = 64 * 1024 * 1024;
const AUDIT_PAGE_LIMIT = 100;
// A healthy release-expiry action schedules read-only inspection no more than
// once every 30 seconds. This deliberately generous bound admits retry
// evidence too, while preventing an unbounded control-plane read from masking
// a truncated audit proof.
const MAX_ACTION_AUDIT_PAGES = 64;
const POLL_INTERVAL_MS = 1_000;
const API_TIMEOUT_MS = 10_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const AUDIT_CURSOR = /^a1\.[A-Za-z0-9_-]{11}$/;
const IPV4 = /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const MILLISECOND_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ASCII_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const CSRF = /^[A-Za-z0-9_-]{43}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const IMAGE_TAG = /^sentinelflow\/(?:backend|postgres|web):e2e-[a-z0-9][a-z0-9-]{0,95}$/;
const DOCKER_NETWORK_ID = /^[0-9a-f]{64}$/;
const E2E_PROJECT = /^sf-demo-e2e-[a-z0-9]{1,32}-[1-9][0-9]{0,9}$/;
const PROMETHEUS_IMAGE = 'prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80';
const STATE_SCHEMA = 'sentinelflow-demo-e2e-state-v4';
const BROWSER_QA_LOCATOR_SCHEMA = 'sentinelflow-browser-qa-locator-v2';
const DEMO_MODES = Object.freeze(['fast_revoke', 'release_expiry']);
const COVERAGE_READINESS_SCHEMA = 'sentinelflow-demo-e2e-coverage-readiness-v2';
const COVERAGE_DETECTOR_WINDOW_SECONDS = 300;
const COVERAGE_READINESS_MARGIN_SECONDS = 5;
const COVERAGE_READINESS_REQUIRED_SECONDS = 305;
const DETECTION_STABILITY_SCHEMA = 'sentinelflow-demo-e2e-detection-stability-v1';
const DETECTION_DIAGNOSTIC_SCHEMA = 'sentinelflow-demo-e2e-detection-diagnostic-v3';
const EXPIRY_DIAGNOSTIC_SCHEMA = 'sentinelflow-demo-e2e-expiry-diagnostic-v1';
const EXPIRY_DIAGNOSTIC_MAX_RESULTS = 16;
const EXPIRY_DIAGNOSTIC_MAX_SCHEDULES = 16;
const EXPIRY_DIAGNOSTIC_MAX_AUDIT = 24;
const DIAGNOSTIC_GATE_NAMES = Object.freeze([
  'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
  'protected_network', 'owned_schema_syntax', 'historical_impact',
]);
const BASE_COMPOSE_SERVICES = Object.freeze([
  'api', 'controlmetricsexporter', 'demo-activation-handoff', 'demo-activator', 'demo-app', 'detector', 'dispatcher', 'executor', 'gateway',
  'history-importer', 'lifecycleworker', 'migrate', 'postgres', 'prometheus', 'retentionworker',
  'secret-init', 'simulator', 'stubworker', 'validationworker', 'validator', 'web', 'worker',
]);
const BACKEND_COMPOSE_SERVICES = Object.freeze([
  'api', 'controlmetricsexporter', 'demo-activator', 'demo-app', 'detector', 'dispatcher', 'executor', 'gateway',
  'history-importer', 'lifecycleworker', 'retentionworker', 'secret-init', 'simulator', 'stubworker',
  'validationworker', 'validator', 'worker',
]);
const STUB_RUNTIME_SERVICES = Object.freeze(BASE_COMPOSE_SERVICES.filter(
  (service) => service !== 'simulator' && service !== 'worker',
));
const ONE_SHOT_SERVICES = new Set([
  'demo-activation-handoff', 'demo-activator', 'history-importer', 'migrate', 'secret-init',
]);
const EXPECTED_NETWORKS = Object.freeze({
  api: ['control', 'ingest', 'management'],
  controlmetricsexporter: ['control', 'observability'],
  'demo-activation-handoff': ['control'],
  'demo-activator': ['control'],
  'demo-app': ['ingest', 'origin'],
  detector: ['control'], dispatcher: ['control'], gateway: ['edge', 'ingest', 'observability', 'origin'],
  'history-importer': ['control'], lifecycleworker: ['control'], migrate: ['control'], postgres: ['control'],
  prometheus: ['observability'], retentionworker: ['control'], stubworker: ['control'],
  validationworker: ['control'], web: ['management'], executor: [], validator: [], 'secret-init': [],
});
const EXPECTED_CAPABILITIES = Object.freeze({
  executor: ['NET_ADMIN'], validator: ['NET_ADMIN'], 'secret-init': ['CHOWN', 'DAC_OVERRIDE', 'FOWNER'],
});
const AUTHORITY_MOUNTS = Object.freeze({
  migrate: {
    '/run/sentinelflow-demo-history-capability-receipts': {
      type: 'volume', source: 'demo-history-capability-receipts', rw: false,
    },
  },
  'demo-activation-handoff': {
    '/run/sentinelflow-demo-history-capability-receipts': {
      type: 'volume', source: 'demo-history-capability-receipts', rw: false,
    },
  },
  'demo-app': {
    '/var/lib/sentinelflow-auth-adapter': {
      type: 'volume', source: 'auth-state', rw: true,
    },
  },
  gateway: {
    '/var/lib/sentinelflow-gateway': { type: 'volume', source: 'gateway-state', rw: true },
    '/run/sentinelflow-ready': { type: 'volume', source: 'executor-readiness', rw: false },
  },
  executor: {
    '/run/secrets/sentinelflow': { type: 'volume', source: 'executor-secrets', rw: false },
    '/run/sentinelflow-executor': { type: 'volume', source: 'executor-socket', rw: true },
    '/run/sentinelflow-ready': { type: 'volume', source: 'executor-readiness', rw: true },
    '/var/lib/sentinelflow-executor': { type: 'volume', source: 'executor-state', rw: true },
  },
  validator: {
    '/run/sentinelflow-validator': { type: 'volume', source: 'validator-socket', rw: true },
  },
  'demo-activator': {
    '/run/secrets/sentinelflow-demo-history-analysis': {
      type: 'volume', source: 'demo-history-analysis-activation', rw: false,
    },
    '/run/secrets/sentinelflow-demo-history-validation': {
      type: 'volume', source: 'demo-history-validation-activation', rw: false,
    },
  },
  stubworker: {
    '/run/secrets/sentinelflow-demo-history-analysis': {
      type: 'volume', source: 'demo-history-analysis-activation', rw: false,
    },
  },
  validationworker: {
    '/run/secrets/sentinelflow-demo-history-validation': {
      type: 'volume', source: 'demo-history-validation-activation', rw: false,
    },
    '/run/sentinelflow-validator': { type: 'volume', source: 'validator-socket', rw: false },
  },
  worker: {
    '/run/secrets/sentinelflow-demo-history-analysis': {
      type: 'volume', source: 'demo-history-analysis-activation', rw: false,
    },
  },
  dispatcher: {
    '/run/secrets/sentinelflow': { type: 'volume', source: 'dispatcher-secrets', rw: false },
    '/run/sentinelflow-executor': { type: 'volume', source: 'executor-socket', rw: false },
  },
  'secret-init': {
    '/source': { type: 'bind', rw: false },
    '/volumes/auth-state': { type: 'volume', source: 'auth-state', rw: true },
    '/volumes/dispatcher-secrets': { type: 'volume', source: 'dispatcher-secrets', rw: true },
    '/volumes/executor-secrets': { type: 'volume', source: 'executor-secrets', rw: true },
    '/volumes/executor-socket': { type: 'volume', source: 'executor-socket', rw: true },
    '/volumes/executor-state': { type: 'volume', source: 'executor-state', rw: true },
    '/volumes/gateway-state': { type: 'volume', source: 'gateway-state', rw: true },
    '/volumes/readiness': { type: 'volume', source: 'executor-readiness', rw: true },
    '/volumes/validator-socket': { type: 'volume', source: 'validator-socket', rw: true },
    '/volumes/demo-history-capability-receipts': {
      type: 'volume', source: 'demo-history-capability-receipts', rw: true,
    },
    '/volumes/demo-history-analysis-activation': {
      type: 'volume', source: 'demo-history-analysis-activation', rw: true,
    },
    '/volumes/demo-history-validation-activation': {
      type: 'volume', source: 'demo-history-validation-activation', rw: true,
    },
  },
});
const AUTHORITY_MOUNT_PATHS = new Set(Object.values(AUTHORITY_MOUNTS).flatMap((paths) => Object.keys(paths)));
const AUTHORITY_VOLUME_SOURCES = new Set(Object.values(AUTHORITY_MOUNTS).flatMap((mounts) =>
  Object.values(mounts).filter((mount) => mount.type === 'volume').map((mount) => mount.source)));
const SENSITIVE_ENV_OWNERS = Object.freeze({
  ADMIN_PASSWORD_ARGON2ID_HASH: ['api'],
  AUTH_ACCOUNT_HASH_KEY: ['demo-app'],
  AUTH_EVENT_HMAC_KEY: ['api', 'demo-app'],
  DATABASE_API_URL: ['api'],
  DATABASE_DISPATCHER_URL: ['dispatcher'],
  DATABASE_DEMO_ACTIVATOR_PASSWORD: ['demo-activation-handoff'],
  DATABASE_DEMO_ACTIVATOR_URL: ['demo-activator'],
  DATABASE_DEMO_IMPORTER_PASSWORD: ['migrate'],
  DATABASE_DEMO_IMPORTER_URL: ['history-importer'],
  DATABASE_LIFECYCLE_URL: ['lifecycleworker'],
  DATABASE_METRICS_URL: ['controlmetricsexporter'],
  DATABASE_RETENTION_URL: ['retentionworker'],
  DATABASE_WORKER_URL: ['detector', 'stubworker', 'validationworker'],
  DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: ['demo-activator', 'stubworker', 'worker'],
  DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE: ['demo-activator', 'validationworker'],
  DISPATCHER_RESULT_PUBLIC_KEY_FILE: ['dispatcher'],
  DISPATCHER_SIGNING_PRIVATE_KEY_FILE: ['dispatcher'],
  EXECUTOR_DISPATCH_PUBLIC_KEY_FILE: ['executor'],
  EXECUTOR_REPLAY_JOURNAL: ['executor'],
  EXECUTOR_RESULT_PRIVATE_KEY_FILE: ['executor'],
  EXECUTOR_SOCKET: ['dispatcher', 'executor'],
  EXECUTOR_STARTUP_MODE: ['executor'],
  GATEWAY_EVENT_HMAC_KEY: ['api', 'gateway'],
  NFT_BINARY_EXPECTED_SHA256: ['executor', 'validationworker', 'validator'],
  NFT_EXPECTED_VERSION: ['executor', 'validationworker', 'validator'],
  NFT_VALIDATOR_SOCKET: ['validationworker', 'validator'],
  OPENAI_API_KEY: [],
  PGPASSWORD: ['demo-activation-handoff', 'migrate'],
  POSTGRES_PASSWORD: ['postgres'],
  SESSION_HMAC_KEY: ['api'],
});
const EXPECTED_USERS = Object.freeze({
  ...Object.fromEntries(STUB_RUNTIME_SERVICES.map((service) => [service, '65532:65532'])),
  executor: '0:65532', migrate: '70:70', postgres: '70:70', prometheus: '65532:65532',
  'demo-activation-handoff': '70:70',
  'secret-init': '0:0', validator: '0:65532', web: '101:101',
});
const shellWrapper = (lines) => Object.freeze([
  '/bin/sh', '-eu', '-c', `${lines.join('\n')}\n`,
]);
const EXPECTED_RUNTIME_COMMANDS = Object.freeze({
  'demo-activation-handoff': Object.freeze(['/opt/sentinelflow/demo-activation-handoff.sh']),
  'secret-init': shellWrapper([
    `test -f /source/dispatcher-capability-private.pem`,
    `test -f /source/dispatcher-capability-public.pem`,
    `test -f /source/executor-result-private.pem`,
    `test -f /source/executor-result-public.pem`,
    `test -f /source/demo-history-analysis-activation.capability`,
    `test -f /source/demo-history-validation-activation.capability`,
    `test ! -L /source/demo-history-analysis-activation.capability`,
    `test ! -L /source/demo-history-validation-activation.capability`,
    `test "$(stat -c '%a' /source/demo-history-analysis-activation.capability)" = '400'`,
    `test "$(stat -c '%a' /source/demo-history-validation-activation.capability)" = '400'`,
    `test "$(wc -c </source/demo-history-analysis-activation.capability)" -eq 32`,
    `test "$(wc -c </source/demo-history-validation-activation.capability)" -eq 32`,
    `activation_comparison=0`,
    `cmp -s /source/demo-history-analysis-activation.capability /source/demo-history-validation-activation.capability || activation_comparison=$?`,
    `test "$activation_comparison" -eq 1`,
    `chown 65532:65532 /volumes/gateway-state /volumes/auth-state`,
    `chmod 0700 /volumes/gateway-state /volumes/auth-state`,
    `chown 0:65532 /volumes/executor-state /volumes/executor-socket /volumes/validator-socket /volumes/readiness`,
    `chmod 0750 /volumes/executor-state /volumes/executor-socket /volumes/validator-socket /volumes/readiness`,
    `chown 65532:65532 /volumes/dispatcher-secrets`,
    `chmod 0700 /volumes/dispatcher-secrets`,
    `chown 0:65532 /volumes/executor-secrets`,
    `chmod 0700 /volumes/executor-secrets`,
    `chown 0:70 /volumes/demo-history-capability-receipts`,
    `chmod 0750 /volumes/demo-history-capability-receipts`,
    `chown 65532:65532 /volumes/demo-history-analysis-activation /volumes/demo-history-validation-activation`,
    `chmod 0700 /volumes/demo-history-analysis-activation /volumes/demo-history-validation-activation`,
    `install -o 65532 -g 65532 -m 0600 /source/dispatcher-capability-private.pem /volumes/dispatcher-secrets/dispatcher-capability-private.pem`,
    `install -o 65532 -g 65532 -m 0644 /source/executor-result-public.pem /volumes/dispatcher-secrets/executor-result-public.pem`,
    `install -o 0 -g 65532 -m 0644 /source/dispatcher-capability-public.pem /volumes/executor-secrets/dispatcher-capability-public.pem`,
    `install -o 0 -g 65532 -m 0600 /source/executor-result-private.pem /volumes/executor-secrets/executor-result-private.pem`,
    `analysis_digest="$(sha256sum /source/demo-history-analysis-activation.capability | cut -d ' ' -f 1)"`,
    `validation_digest="$(sha256sum /source/demo-history-validation-activation.capability | cut -d ' ' -f 1)"`,
    `case "$analysis_digest" in *[!0-9a-f]*|'') exit 1 ;; esac`,
    `case "$validation_digest" in *[!0-9a-f]*|'') exit 1 ;; esac`,
    `test "\${#analysis_digest}" -eq 64`,
    `test "\${#validation_digest}" -eq 64`,
    `test "$analysis_digest" != "$validation_digest"`,
    `find /volumes/demo-history-capability-receipts -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +`,
    `printf 'sha256:%s\\n' "$analysis_digest" >/volumes/demo-history-capability-receipts/analysis.sha256`,
    `printf 'sha256:%s\\n' "$validation_digest" >/volumes/demo-history-capability-receipts/validation.sha256`,
    `chown 0:70 /volumes/demo-history-capability-receipts/analysis.sha256 /volumes/demo-history-capability-receipts/validation.sha256`,
    `chmod 0440 /volumes/demo-history-capability-receipts/analysis.sha256 /volumes/demo-history-capability-receipts/validation.sha256`,
    `test "$(stat -c '%u:%g:%a:%s' /volumes/demo-history-capability-receipts/analysis.sha256)" = '0:70:440:72'`,
    `test "$(stat -c '%u:%g:%a:%s' /volumes/demo-history-capability-receipts/validation.sha256)" = '0:70:440:72'`,
    `test "$(find /volumes/demo-history-capability-receipts -mindepth 1 -maxdepth 1 | wc -l)" -eq 2`,
    `install -o 65532 -g 65532 -m 0400 /source/demo-history-analysis-activation.capability /volumes/demo-history-analysis-activation/activation-capability`,
    `install -o 65532 -g 65532 -m 0400 /source/demo-history-validation-activation.capability /volumes/demo-history-validation-activation/activation-capability`,
    `test "$(stat -c '%u:%g:%a:%s' /volumes/demo-history-analysis-activation/activation-capability)" = '65532:65532:400:32'`,
    `test "$(stat -c '%u:%g:%a:%s' /volumes/demo-history-validation-activation/activation-capability)" = '65532:65532:400:32'`,
    `cmp -s /source/demo-history-analysis-activation.capability /volumes/demo-history-analysis-activation/activation-capability`,
    `cmp -s /source/demo-history-validation-activation.capability /volumes/demo-history-validation-activation/activation-capability`,
  ]),
  gateway: shellWrapper([
    `fresh_executor() {`,
    `  test -f /run/sentinelflow-ready/executor-heartbeat || return 1`,
    `  now="$(date +%s)"`,
    `  modified="$(stat -c %Y /run/sentinelflow-ready/executor-heartbeat 2>/dev/null || echo 0)"`,
    `  test "$((now - modified))" -le 3`,
    `}`,
    `attempts=0`,
    `until fresh_executor; do`,
    `  attempts="$((attempts + 1))"`,
    `  test "$attempts" -lt 300 || exit 1`,
    `  sleep 0.1`,
    `done`,
    `exec /usr/local/bin/gateway`,
  ]),
  executor: shellWrapper([
    `rm -f /run/sentinelflow-ready/executor-heartbeat`,
    `/usr/local/bin/executor &`,
    `child="$!"`,
    `heartbeat=""`,
    `stop() {`,
    `  test -z "$heartbeat" || kill "$heartbeat" 2>/dev/null || true`,
    `  kill -TERM "$child" 2>/dev/null || true`,
    `  wait "$child" 2>/dev/null || true`,
    `  rm -f /run/sentinelflow-ready/executor-heartbeat`,
    `}`,
    `trap stop TERM INT EXIT`,
    `attempts=0`,
    `while test ! -S /run/sentinelflow-executor/executor.sock; do`,
    `  kill -0 "$child" 2>/dev/null || exit 1`,
    `  attempts="$((attempts + 1))"`,
    `  test "$attempts" -lt 300 || exit 1`,
    `  sleep 0.1`,
    `done`,
    `(`,
    `  while kill -0 "$child" 2>/dev/null; do`,
    `    touch /run/sentinelflow-ready/executor-heartbeat`,
    `    sleep 1`,
    `  done`,
    `) &`,
    `heartbeat="$!"`,
    `wait "$child"`,
  ]),
  dispatcher: shellWrapper([
    `attempts=0`,
    `while test ! -S /run/sentinelflow-executor/executor.sock; do`,
    `  attempts="$((attempts + 1))"`,
    `  test "$attempts" -lt 300 || exit 1`,
    `  sleep 0.1`,
    `done`,
    `exec /usr/local/bin/dispatcher`,
  ]),
});
const EXPECTED_INCIDENTS = new Map([
  ['203.0.113.22', 'path_scan'],
  ['203.0.113.23', 'request_burst'],
  ['203.0.113.24', 'brute_force'],
  // The frozen credential-stuffing plan crosses both exact-login brute-force
  // and distinct-account credential-stuffing thresholds; correlation therefore
  // owns one mixed incident without dropping either deterministic signal.
  ['203.0.113.20', 'mixed'],
]);
const DIAGNOSTIC_SOURCES = Object.freeze([
  '203.0.113.20', '203.0.113.21', '203.0.113.22', '203.0.113.23', '203.0.113.24',
]);
const DIAGNOSTIC_SIGNAL_KINDS = new Set([
  'path_scan', 'request_burst', 'brute_force', 'credential_stuffing',
]);
const DIAGNOSTIC_INCIDENT_KINDS = new Set([...DIAGNOSTIC_SIGNAL_KINDS, 'mixed', 'unknown']);
const DIAGNOSTIC_SUSPICIOUS_PATH_IDS = new Set([
  'admin_console', 'env_file', 'git_config', 'wp_admin', 'phpmyadmin', 'server_status',
  'actuator_env', 'backup_archive',
]);

export function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function record(value, label) {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} is invalid`);
  return value;
}

function exactRecord(value, label, required, optional = []) {
  const result = record(value, label);
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(result);
  invariant(
    required.every((key) => Object.hasOwn(result, key)) &&
      keys.every((key) => allowed.has(key)) && new Set(keys).size === keys.length,
    `${label} shape is invalid`,
  );
  return result;
}

function integer(value, minimum, maximum, label) {
  invariant(Number.isSafeInteger(value) && value >= minimum && value <= maximum, `${label} is invalid`);
  return value;
}

function string(value, pattern, label) {
  invariant(typeof value === 'string' && pattern.test(value), `${label} is invalid`);
  return value;
}

function auditCursor(value, label) {
  const checked = string(value, AUDIT_CURSOR, label);
  const encoded = checked.slice('a1.'.length);
  let bytes;
  try {
    bytes = Buffer.from(encoded, 'base64url');
  } catch {
    throw new Error(`${label} is invalid`);
  }
  const sequence = bytes.length === 8 ? bytes.readBigUInt64BE(0) : 0n;
  invariant(bytes.length === 8 && sequence > 0n && sequence <= BigInt(Number.MAX_SAFE_INTEGER) &&
    bytes.toString('base64url') === encoded,
    `${label} is invalid`);
  return Object.freeze({ value: checked, sequence: Number(sequence) });
}

function timestamp(value, label) {
  const checked = string(value, TIMESTAMP, label);
  invariant(Number.isFinite(Date.parse(checked)), `${label} is invalid`);
  return checked;
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestText(value) {
  invariant(typeof value === 'string', 'digest input is invalid');
  return digestBytes(Buffer.from(value, 'utf8'));
}

function decodeNonce(value) {
  string(value, NONCE, 'challenge nonce');
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    throw new Error('challenge nonce is invalid');
  }
  invariant(decoded.length === 32 && decoded.toString('base64url') === value, 'challenge nonce is invalid');
  return decoded;
}

export function canonicalJSON(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    invariant(Number.isFinite(value), 'JSON contains a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJSON(item)).join(',')}]`;
  }
  invariant(value !== null && typeof value === 'object', 'JSON contains an unsupported value');
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
}

export function digestJSON(value) {
  return `sha256:${createHash('sha256').update(canonicalJSON(value), 'utf8').digest('hex')}`;
}

async function readJSON(filename, label = 'JSON file') {
  let source;
  try {
    source = await readFile(filename, 'utf8');
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  invariant(Buffer.byteLength(source, 'utf8') > 0 && Buffer.byteLength(source, 'utf8') <= JSON_LIMIT, `${label} size is invalid`);
  try {
    return JSON.parse(source);
  } catch {
    throw new Error(`${label} is invalid`);
  }
}

async function readPrivateJournal(filename, label) {
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  try {
    const initial = await handle.stat({ bigint: true });
    invariant(initial.isFile() && initial.nlink === 1n &&
      (initial.mode & 0o777n) === 0o600n && initial.uid === BigInt(process.geteuid()) &&
      initial.size > 0n && initial.size <= BigInt(JOURNAL_LIMIT), `${label} file contract is invalid`);
    const contents = Buffer.alloc(Number(initial.size));
    let offset = 0;
    while (offset < contents.length) {
      const { bytesRead } = await handle.read(contents, offset, contents.length - offset, offset);
      invariant(bytesRead > 0, `${label} changed while being read`);
      offset += bytesRead;
    }
    const final = await handle.stat({ bigint: true });
    invariant(final.dev === initial.dev && final.ino === initial.ino && final.size === initial.size &&
      final.mode === initial.mode && final.nlink === initial.nlink && final.uid === initial.uid &&
      final.mtimeNs === initial.mtimeNs && final.ctimeNs === initial.ctimeNs,
    `${label} changed while being read`);
    return contents;
  } finally {
    await handle.close();
  }
}

async function writePrivateJSON(filename, value) {
  await writeFile(filename, `${JSON.stringify(value)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}

async function writePrivateText(filename, value) {
  invariant(typeof value === 'string' && Buffer.byteLength(value, 'utf8') > 0, 'private text payload is invalid');
  await writeFile(filename, value, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}

async function assertPrivatePath(filename, expectedType, expectedMode, label) {
  let value;
  try {
    value = await lstat(filename, { bigint: true });
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  invariant(!value.isSymbolicLink() && value.uid === BigInt(process.geteuid()) &&
    (value.mode & 0o777n) === BigInt(expectedMode) &&
    (expectedType === 'file' ? value.isFile() && value.nlink === 1n : value.isDirectory() && value.nlink >= 1n),
  `${label} contract is invalid`);
  return value;
}

async function assertPathAbsent(filename, label) {
  try {
    await lstat(filename);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw new Error(`${label} cannot be inspected`);
  }
  throw new Error(`${label} already exists`);
}

async function writeStrictPrivateJSON(filename, value) {
  const body = `${canonicalJSON(value)}\n`;
  invariant(Buffer.byteLength(body, 'utf8') > 1 && Buffer.byteLength(body, 'utf8') <= JSON_LIMIT,
    'strict private JSON payload is invalid');
  let handle;
  try {
    handle = await open(filename,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  } catch {
    throw new Error('strict private JSON output cannot be created');
  }
  let initial;
  try {
    initial = await handle.stat({ bigint: true });
    invariant(initial.isFile() && initial.nlink === 1n && initial.uid === BigInt(process.geteuid()) &&
      (initial.mode & 0o777n) === 0o600n && initial.size === 0n,
    'strict private JSON output contract is invalid');
    await handle.writeFile(body, 'utf8');
    await handle.sync();
    const final = await handle.stat({ bigint: true });
    invariant(final.dev === initial.dev && final.ino === initial.ino && final.isFile() && final.nlink === 1n &&
      final.uid === initial.uid && (final.mode & 0o777n) === 0o600n &&
      final.size === BigInt(Buffer.byteLength(body, 'utf8')),
    'strict private JSON output changed while being written');
  } catch (error) {
    await handle.close().catch(() => {});
    handle = undefined;
    await unlink(filename).catch(() => {});
    throw error;
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function replacePrivateJSON(filename, value) {
  const current = await lstat(filename);
  invariant(current.isFile() && !current.isSymbolicLink() && (current.mode & 0o777) === 0o600, 'E2E state file mode is invalid');
  const temporary = `${filename}.next-${randomBytes(8).toString('hex')}`;
  try {
    await writePrivateJSON(temporary, value);
    await rename(temporary, filename);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function runBoundedCommand(timeoutSeconds, argv) {
  integer(timeoutSeconds, 1, 1800, 'bounded command timeout');
  invariant(Array.isArray(argv) && argv.length >= 1 && argv.length <= 256, 'bounded command arguments are invalid');
  invariant(argv.every((argument) => typeof argument === 'string' && argument.length > 0 && argument.length <= 4096 &&
    !argument.includes('\0')), 'bounded command arguments are invalid');
  invariant(/^(?:\/[A-Za-z0-9._+-]+)+$|^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(argv[0]), 'bounded command executable is invalid');
  await new Promise((resolve, reject) => {
    let timedOut = false;
    let forceTimer;
    const child = spawn(argv[0], argv.slice(1), {
      detached: true,
      env: process.env,
      stdio: 'inherit',
    });
    const signalGroup = (signal) => {
      if (child.pid === undefined) return;
      try {
        process.kill(-child.pid, signal);
      } catch {
        // The child group may already be gone.
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      signalGroup('SIGTERM');
      forceTimer = setTimeout(() => signalGroup('SIGKILL'), 2_000);
      forceTimer.unref();
    }, timeoutSeconds * 1_000);
    timer.unref();
    child.once('error', () => {
      clearTimeout(timer);
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      reject(new Error('bounded command could not start'));
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      if (timedOut) signalGroup('SIGKILL');
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      if (!timedOut && code === 0 && signal === null) {
        resolve();
      } else {
        reject(new Error(timedOut ? 'bounded command timed out' : 'bounded command failed'));
      }
    });
  });
  return true;
}

function canonicalIPv4(value) {
  if (typeof value !== 'string' || !IPV4.test(value)) {
    return false;
  }
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => Number(octet) <= 255);
}

export function parseNFTSet(document, targetIPv4) {
  invariant(canonicalIPv4(targetIPv4), 'nft target is invalid');
  const root = record(document, 'nft document');
  invariant(Array.isArray(root.nftables) && root.nftables.length === 2, 'nft document shape is invalid');
  const metadata = record(record(root.nftables[0], 'nft metadata entry').metainfo, 'nft metadata');
  invariant(Number(metadata.json_schema_version) === 1, 'nft JSON schema is invalid');
  const set = record(record(root.nftables[1], 'nft set entry').set, 'nft set');
  invariant(
    set.family === 'inet' && set.table === 'sentinelflow' && set.name === 'blacklist_ipv4' &&
      set.type === 'ipv4_addr' && Number.isSafeInteger(set.handle) && set.handle > 0 &&
      Array.isArray(set.flags) && set.flags.length === 1 && set.flags[0] === 'timeout',
    'nft owned set contract is invalid',
  );
  const elements = set.elem === undefined ? [] : set.elem;
  invariant(Array.isArray(elements), 'nft element collection is invalid');
  const seen = new Set();
  let remainingTTLSeconds = 0;
  for (const wrapped of elements) {
    const element = record(record(wrapped, 'nft element wrapper').elem, 'nft element');
    invariant(
      canonicalIPv4(element.val) && !seen.has(element.val) &&
        Number.isSafeInteger(element.timeout) && element.timeout >= 60 && element.timeout <= 86_400 &&
        Number.isSafeInteger(element.expires) && element.expires >= 1 && element.expires <= element.timeout,
      'nft element is invalid',
    );
    seen.add(element.val);
    if (element.val === targetIPv4) {
      remainingTTLSeconds = element.expires;
    }
  }
  return Object.freeze({
    state: remainingTTLSeconds > 0 ? 'active' : 'absent',
    remainingTTLSeconds,
    digest: digestJSON(document),
  });
}

export function validateSimulatorReport(report, scenario) {
  const value = record(report, 'simulator report');
  const expectedCounts = new Map([
    ['normal', 8],
    ['path-scan', 8],
    ['request-burst', 120],
    ['brute-force', 10],
    ['credential-stuffing', 20],
  ]);
  invariant(expectedCounts.has(scenario), 'simulator scenario is invalid');
  invariant(
    value.schema_version === 'simulator-report-v1' && value.result === 'passed' && value.scenario === scenario &&
      value.attempted === expectedCounts.get(scenario) && value.completed === value.attempted && value.failed === 0 &&
      DIGEST.test(value.plan_digest) && Array.isArray(value.status_counts),
    `simulator ${scenario} report failed`,
  );
  return value;
}

function normalizedVolumeSources(service) {
  const volumes = Array.isArray(service?.volumes) ? service.volumes : [];
  return volumes.map((volume) => {
    if (typeof volume === 'string') {
      return volume.split(':', 1)[0];
    }
    return volume?.type === 'bind' ? volume.source : '';
  }).filter(Boolean).map((source) => path.resolve(source));
}

function publishedPort(service, target) {
  const ports = Array.isArray(service?.ports) ? service.ports : [];
  const match = ports.find((port) => Number(port?.target) === target && port?.protocol === 'tcp');
  invariant(match && match.host_ip === '127.0.0.1', `published port ${target} is invalid`);
  return Number(match.published);
}

function environmentKeys(container) {
  const entries = Array.isArray(container?.Config?.Env) ? container.Config.Env : [];
  const keys = entries.map((entry) => {
    invariant(typeof entry === 'string' && entry.includes('='), 'container environment entry is invalid');
    return entry.slice(0, entry.indexOf('='));
  });
  invariant(new Set(keys).size === keys.length, 'container environment contains duplicate keys');
  return keys.sort();
}

function sortedUnique(values, label) {
  invariant(Array.isArray(values) && values.every((value) => typeof value === 'string'), `${label} is invalid`);
  invariant(new Set(values).size === values.length, `${label} contains duplicates`);
  return [...values].sort();
}

function exactStrings(actual, expected, label) {
  const left = sortedUnique(actual, label);
  const right = [...expected].sort();
  invariant(left.length === right.length && left.every((value, index) => value === right[index]), `${label} drifted`);
}

export function validateBaseServiceList(source) {
  invariant(typeof source === 'string' && Buffer.byteLength(source, 'utf8') <= 4096, 'base Compose service list is invalid');
  const services = source.split('\n').filter((value) => value !== '');
  invariant(services.every((value) => /^[a-z][a-z0-9-]{0,63}$/.test(value)), 'base Compose service list is invalid');
  exactStrings(services, BASE_COMPOSE_SERVICES, 'base Compose service list');
  return true;
}

export function validateEngineNoneNetworkIDOutput(source) {
  invariant(typeof source === 'string' && Buffer.byteLength(source, 'utf8') === 65 &&
    DOCKER_NETWORK_ID.test(source.slice(0, -1)) && source.endsWith('\n'),
  'Docker none network ID output is invalid');
  return source.slice(0, -1);
}

export function buildComposeOverride(backendImage, postgresImage, webImage) {
  const expected = [backendImage, postgresImage, webImage];
  invariant(expected.every((image) => typeof image === 'string' && IMAGE_TAG.test(image)), 'E2E image tag is invalid');
  invariant(backendImage.startsWith('sentinelflow/backend:'), 'backend E2E image tag is invalid');
  invariant(postgresImage.startsWith('sentinelflow/postgres:'), 'PostgreSQL E2E image tag is invalid');
  invariant(webImage.startsWith('sentinelflow/web:'), 'web E2E image tag is invalid');
  return Object.freeze({
    services: Object.fromEntries([
      ...BACKEND_COMPOSE_SERVICES.map((service) => [service, { image: backendImage }]),
      ['postgres', { image: postgresImage }],
      ['migrate', { image: postgresImage }],
      ['demo-activation-handoff', { image: postgresImage }],
      ['web', { image: webImage }],
    ]),
  });
}

export function validateComposeOverride(value, expected) {
  const root = exactRecord(value, 'Compose override', ['services']);
  const services = record(root.services, 'Compose override services');
  const names = Object.keys(services);
  exactStrings(names, [...BACKEND_COMPOSE_SERVICES, 'postgres', 'migrate', 'demo-activation-handoff', 'web'], 'Compose override services');
  for (const name of names) {
    const service = exactRecord(services[name], `Compose override service ${name}`, ['image']);
    const image = BACKEND_COMPOSE_SERVICES.includes(name) ? expected.backendImage :
      (name === 'web' ? expected.webImage : expected.postgresImage);
    invariant(service.image === image, `Compose override image for ${name} drifted`);
  }
  return true;
}

export function validateComposeConfig(config, expected) {
  const root = record(config, 'Compose config');
  const services = record(root.services, 'Compose services');
  invariant(root.name === expected.project, 'Compose project name drifted');
  invariant(Object.hasOwn(services, 'stubworker') && !Object.hasOwn(services, 'worker'), 'Compose did not select exactly stub-ai');
  exactStrings(Object.keys(services), STUB_RUNTIME_SERVICES, 'resolved Compose services');
  invariant(publishedPort(services.api, 8083) === expected.apiPort, 'API host port drifted');
  invariant(publishedPort(services.gateway, 8080) === expected.gatewayPort, 'Gateway host port drifted');
  invariant(publishedPort(services.web, 8080) === expected.webPort, 'web host port drifted');
  for (const service of ['demo-activation-handoff', 'demo-activator', 'history-importer', 'migrate']) {
    invariant(services[service]?.environment?.SENTINELFLOW_ENV === 'demo', `${service} demo gate drifted`);
  }
  for (const [service, dependency] of [
    ['history-importer', 'migrate'],
    ['demo-activation-handoff', 'history-importer'],
    ['demo-activator', 'demo-activation-handoff'],
    ['stubworker', 'demo-activator'],
    ['validationworker', 'demo-activator'],
  ]) {
    invariant(services[service]?.depends_on?.[dependency]?.condition === 'service_completed_successfully',
      `${service} completion dependency on ${dependency} drifted`);
  }

  const secretSource = path.resolve(expected.secretSource);
  const historySource = path.resolve(expected.historySource);
  invariant(normalizedVolumeSources(services['secret-init']).includes(secretSource), 'Compose secret source escaped the temporary bundle');
  invariant(normalizedVolumeSources(services['history-importer']).includes(historySource), 'Compose history source escaped the temporary bundle');
  invariant(normalizedVolumeSources(services['demo-activator']).includes(historySource), 'activator history source escaped the temporary bundle');
  invariant(normalizedVolumeSources(services.stubworker).includes(historySource), 'analysis history source escaped the temporary bundle');
  invariant(normalizedVolumeSources(services.validationworker).includes(historySource), 'validator history source escaped the temporary bundle');

  for (const [name, service] of Object.entries(services)) {
    invariant(!Object.hasOwn(service?.environment ?? {}, 'OPENAI_API_KEY'), `service ${name} received an OpenAI key field`);
    const expectedImage = BACKEND_COMPOSE_SERVICES.includes(name) ? expected.backendImage :
      (name === 'web' ? expected.webImage :
        (['postgres', 'migrate', 'demo-activation-handoff'].includes(name) ? expected.postgresImage : PROMETHEUS_IMAGE));
    invariant(service.image === expectedImage, `service ${name} did not resolve to its unique expected image`);
  }
  return true;
}

function normalizedCapabilities(container, field) {
  const values = Array.isArray(container?.HostConfig?.[field]) ? container.HostConfig[field] : [];
  return values.map((value) => typeof value === 'string' && value.startsWith('CAP_') ? value.slice(4) : value);
}

function runtimeMounts(container, service) {
  const mounts = Array.isArray(container?.Mounts) ? container.Mounts : [];
  return mounts.map((mount) => {
    invariant(
      mount !== null && typeof mount === 'object' && typeof mount.Type === 'string' &&
        typeof mount.Destination === 'string' && typeof mount.Source === 'string' &&
        (mount.Name === undefined || typeof mount.Name === 'string') && typeof mount.RW === 'boolean',
      `service ${service} mount inspection is invalid`,
    );
    invariant(
      mount.Destination !== '/var/run/docker.sock' && mount.Source !== '/var/run/docker.sock',
      `service ${service} received the Docker socket`,
    );
    return mount;
  });
}

function composeVolumeName(project, source) {
  return `${project}_${source}`;
}

function validateAuthorityMounts(mounts, service, project) {
  const expectedMounts = AUTHORITY_MOUNTS[service] ?? {};
  const authorityVolumeNames = new Set([...AUTHORITY_VOLUME_SOURCES].map(
    (source) => composeVolumeName(project, source),
  ));
  const sensitiveMounts = mounts.filter((mount) =>
    AUTHORITY_MOUNT_PATHS.has(mount.Destination) ||
      (mount.Type === 'volume' && authorityVolumeNames.has(mount.Name)));

  for (const mount of sensitiveMounts) {
    const expected = expectedMounts[mount.Destination];
    invariant(expected !== undefined,
      `service ${service} has an unauthorized authority mount at ${mount.Destination}`);
    invariant(mount.Type === expected.type,
      `service ${service} authority mount type drifted for ${mount.Destination}`);
    if (expected.type === 'volume') {
      invariant(mount.Name === composeVolumeName(project, expected.source),
        `service ${service} authority mount source drifted for ${mount.Destination}`);
    } else {
      invariant((mount.Name === undefined || mount.Name === '') && path.isAbsolute(mount.Source),
        `service ${service} authority bind source drifted for ${mount.Destination}`);
    }
    invariant(mount.RW === expected.rw,
      `service ${service} authority mount mode drifted for ${mount.Destination}`);
  }
  exactStrings(sensitiveMounts.map((mount) => mount.Destination), Object.keys(expectedMounts),
    `service ${service} authority mounts`);
}

function validateRuntimeCommand(value, service) {
  const expected = EXPECTED_RUNTIME_COMMANDS[service];
  if (expected === undefined) return;
  const command = value.Config?.Cmd;
  invariant(Array.isArray(command) && command.length === expected.length &&
    command.every((argument, index) => typeof argument === 'string' && argument === expected[index]),
  `service ${service} runtime command drifted`);
}

function validateBuiltinNoneNetwork(value, expectedNoneNetworkID) {
  const network = exactRecord(value, 'runtime Docker none network', [
    'Id', 'Name', 'Driver', 'Containers',
  ]);
  invariant(network.Id === expectedNoneNetworkID && network.Name === 'none' && network.Driver === 'null',
    'runtime Docker none network identity drifted');
  return record(network.Containers, 'runtime Docker none network containers');
}

function validateIsolatedRuntimeNetwork(value, service, expectedNoneNetworkID, noneNetworkContainers) {
  const networks = record(value.NetworkSettings?.Networks, `service ${service} network inspection`);
  const names = Object.keys(networks);
  invariant(value.HostConfig?.NetworkMode === 'none' &&
    (names.length === 0 || names.length === 1 && names[0] === 'none'),
  `service ${service} network isolation drifted`);
  string(value.Id, DOCKER_NETWORK_ID, `service ${service} full container ID`);
  const hasMembership = Object.hasOwn(noneNetworkContainers, value.Id);
  if (names.length === 0) {
    invariant(!hasMembership, `service ${service} has unexpected Docker none network membership`);
    return true;
  }
  const none = exactRecord(networks.none, `service ${service} inert none network`, [
    'IPAMConfig', 'Links', 'Aliases', 'DriverOpts', 'GwPriority', 'NetworkID', 'EndpointID',
    'Gateway', 'IPAddress', 'MacAddress', 'IPPrefixLen', 'IPv6Gateway', 'GlobalIPv6Address',
    'GlobalIPv6PrefixLen', 'DNSNames',
  ]);
  invariant(none.NetworkID === expectedNoneNetworkID,
    `service ${service} none network ID does not match the engine`);
  invariant(none.IPAMConfig === null && none.Links === null && none.Aliases === null &&
    none.DriverOpts === null && none.DNSNames === null && none.GwPriority === 0 &&
    none.Gateway === '' && none.IPAddress === '' && none.MacAddress === '' && none.IPPrefixLen === 0 &&
    none.IPv6Gateway === '' && none.GlobalIPv6Address === '' && none.GlobalIPv6PrefixLen === 0,
  `service ${service} inert none network is not empty`);
  if (none.EndpointID === '') {
    invariant(!hasMembership, `service ${service} has unexpected Docker none network membership`);
    return true;
  }
  invariant(value.State?.Running === true, `service ${service} exited with a Docker none network endpoint`);
  string(none.EndpointID, DOCKER_NETWORK_ID, `service ${service} Docker none network endpoint ID`);
  invariant(hasMembership, `service ${service} Docker none network endpoint membership is missing`);
  const membership = exactRecord(
    noneNetworkContainers[value.Id], `service ${service} Docker none network membership`,
    ['Name', 'EndpointID', 'MacAddress', 'IPv4Address', 'IPv6Address'],
  );
  invariant(typeof value.Name === 'string' && value.Name === `/${membership.Name}` &&
    membership.EndpointID === none.EndpointID && membership.MacAddress === '' &&
    membership.IPv4Address === '' && membership.IPv6Address === '',
  `service ${service} Docker none network membership is not inert or digest-bound`);
  return true;
}

export function validateRuntimeInspection(inspections, expected) {
  invariant(Array.isArray(inspections), 'container inspection is invalid');
  const runtimeExpected = exactRecord(
    expected, 'runtime expectation', [
      'project', 'backendImage', 'postgresImage', 'webImage', 'noneNetworkID', 'noneNetworkInspection',
    ],
  );
  string(runtimeExpected.project, /^sf-demo-e2e-[a-z0-9-]{1,80}$/, 'runtime project');
  string(runtimeExpected.noneNetworkID, DOCKER_NETWORK_ID, 'runtime Docker none network ID');
  const noneNetworkContainers = validateBuiltinNoneNetwork(
    runtimeExpected.noneNetworkInspection, runtimeExpected.noneNetworkID,
  );
  validateComposeOverride(
    buildComposeOverride(runtimeExpected.backendImage, runtimeExpected.postgresImage, runtimeExpected.webImage),
    runtimeExpected,
  );
  const byService = new Map();
  for (const raw of inspections) {
    const value = record(raw, 'container inspection');
    const service = value.Config?.Labels?.['com.docker.compose.service'];
    invariant(typeof service === 'string' && STUB_RUNTIME_SERVICES.includes(service), 'unexpected Compose service inspection');
    invariant(value.Config?.Labels?.['com.docker.compose.project'] === runtimeExpected.project, 'container project label drifted');
    invariant(!byService.has(service), `duplicate container inspection for ${service}`);
    byService.set(service, value);
  }
  exactStrings([...byService.keys()], STUB_RUNTIME_SERVICES, 'runtime Compose services');
  const gateway = byService.get('gateway');

  for (const service of STUB_RUNTIME_SERVICES) {
    const value = byService.get(service);
    if (ONE_SHOT_SERVICES.has(service)) {
      invariant(value?.State?.Running === false && value?.State?.Status === 'exited' && value?.State?.ExitCode === 0,
        `one-shot service ${service} did not exit successfully`);
    } else {
      invariant(value?.State?.Running === true, `service ${service} is not running`);
    }
    if (!ONE_SHOT_SERVICES.has(service) && value.State.Health !== undefined) {
      invariant(value.State.Health.Status === 'healthy', `service ${service} is not healthy`);
    }

    const expectedImage = BACKEND_COMPOSE_SERVICES.includes(service) ? runtimeExpected.backendImage :
      (service === 'web' ? runtimeExpected.webImage :
        (['postgres', 'migrate', 'demo-activation-handoff'].includes(service) ? runtimeExpected.postgresImage : PROMETHEUS_IMAGE));
    invariant(value.Config?.Image === expectedImage, `service ${service} runtime image drifted`);
    invariant(value.Config?.User === EXPECTED_USERS[service], `service ${service} runtime user drifted`);
    validateRuntimeCommand(value, service);
    exactStrings(normalizedCapabilities(value, 'CapAdd'), EXPECTED_CAPABILITIES[service] ?? [], `service ${service} added capabilities`);
    exactStrings(normalizedCapabilities(value, 'CapDrop'), ['ALL'], `service ${service} dropped capabilities`);
    invariant(value.HostConfig?.Privileged === false, `service ${service} is privileged`);
    invariant(value.HostConfig?.ReadonlyRootfs === true, `service ${service} writable root filesystem drifted`);
    exactStrings(value.HostConfig?.SecurityOpt ?? [], ['no-new-privileges:true'], `service ${service} security options`);
    invariant((value.HostConfig?.Devices ?? []).length === 0, `service ${service} received a device`);
    invariant((value.HostConfig?.DeviceRequests ?? []).length === 0, `service ${service} received a device request`);

    const networkMode = value.HostConfig?.NetworkMode;
    const networkInspection = record(value.NetworkSettings?.Networks, `service ${service} network inspection`);
    const networks = Object.keys(networkInspection);
    if (service === 'executor') {
      invariant(networkMode === `container:${gateway.Id}` && networks.length === 0,
        'executor does not share exactly the Gateway network namespace');
    } else if (service === 'validator' || service === 'secret-init') {
      validateIsolatedRuntimeNetwork(value, service, runtimeExpected.noneNetworkID, noneNetworkContainers);
    } else {
      invariant(typeof networkMode === 'string' && !['host', 'none'].includes(networkMode) &&
        !networkMode.startsWith('container:'), `service ${service} network mode drifted`);
      exactStrings(networks, EXPECTED_NETWORKS[service].map((network) => `${runtimeExpected.project}_${network}`),
        `service ${service} networks`);
    }

    const mounts = runtimeMounts(value, service);
    validateAuthorityMounts(mounts, service, runtimeExpected.project);

    const env = environmentKeys(value);
    for (const [key, owners] of Object.entries(SENSITIVE_ENV_OWNERS)) {
      invariant(env.includes(key) === owners.includes(service), `service ${service} sensitive environment ownership drifted for ${key}`);
    }
  }
  return true;
}

function diagnosticCount(value, label) {
  return integer(value, 0, 1_000_000, label);
}

function diagnosticTimestamp(value, label) {
  if (value === null) return null;
  return timestamp(value, label);
}

function diagnosticCode(value, label) {
  if (value === null) return null;
  return string(value, /^[a-z0-9][a-z0-9._-]{0,63}$/, label);
}

function validateDiagnosticOutbox(value, label) {
  invariant(Array.isArray(value) && value.length <= 16, `${label} is invalid`);
  let previousJobID = '';
  for (const [index, raw] of value.entries()) {
    const itemLabel = `${label} ${index}`;
    const job = exactRecord(raw, itemLabel, [
      'job_id', 'aggregate_version', 'state', 'attempts', 'max_attempts', 'last_error_code',
    ]);
    const jobID = string(job.job_id, UUID, `${itemLabel} ID`);
    invariant(jobID > previousJobID, `${label} IDs are not sorted and unique`);
    previousJobID = jobID;
    integer(job.aggregate_version, 1, 1_000_000, `${itemLabel} aggregate version`);
    invariant(['pending', 'leased', 'retry', 'completed', 'dead'].includes(job.state),
      `${itemLabel} state is invalid`);
    const attempts = integer(job.attempts, 0, 100, `${itemLabel} attempts`);
    const maximum = integer(job.max_attempts, 1, 100, `${itemLabel} maximum attempts`);
    invariant(attempts <= maximum, `${itemLabel} attempt bound is invalid`);
    const failure = diagnosticCode(job.last_error_code, `${itemLabel} error code`);
    invariant((['retry', 'dead'].includes(job.state) && failure !== null) ||
      (job.state === 'completed' && failure === null) || ['pending', 'leased'].includes(job.state),
    `${itemLabel} error state is invalid`);
  }
  return true;
}

function validateDiagnosticAnalysisAttempts(value, incidentVersion, label) {
  invariant(Array.isArray(value) && value.length <= 16, `${label} is invalid`);
  let previousKey = '';
  for (const [index, raw] of value.entries()) {
    const itemLabel = `${label} ${index}`;
    const attempt = exactRecord(raw, itemLabel, [
      'analysis_id', 'incident_version', 'outbox_attempt', 'claim_state', 'claim_failure_code',
      'result_state', 'result_failure_code',
    ]);
    const analysisID = string(attempt.analysis_id, UUID, `${itemLabel} ID`);
    const version = integer(attempt.incident_version, 1, incidentVersion, `${itemLabel} incident version`);
    const key = `${String(version).padStart(7, '0')}:${analysisID}`;
    invariant(key > previousKey, `${label} are not sorted and unique`);
    previousKey = key;
    integer(attempt.outbox_attempt, 1, 100, `${itemLabel} outbox attempt`);
    invariant(['started', 'succeeded', 'failed', 'interrupted', 'no_call'].includes(attempt.claim_state),
      `${itemLabel} claim state is invalid`);
    const claimFailure = diagnosticCode(attempt.claim_failure_code, `${itemLabel} claim failure code`);
    invariant((['interrupted', 'no_call'].includes(attempt.claim_state) && claimFailure !== null) ||
      (!['interrupted', 'no_call'].includes(attempt.claim_state) && claimFailure === null),
    `${itemLabel} claim failure state is invalid`);
    invariant(attempt.result_state === null ||
      ['succeeded', 'failed', 'interrupted', 'no_call'].includes(attempt.result_state),
    `${itemLabel} result state is invalid`);
    const resultFailure = diagnosticCode(attempt.result_failure_code, `${itemLabel} result failure code`);
    invariant((attempt.result_state === null && resultFailure === null) ||
      (attempt.result_state === 'succeeded' && resultFailure === null) ||
      (['failed', 'interrupted', 'no_call'].includes(attempt.result_state) && resultFailure !== null),
    `${itemLabel} result failure state is invalid`);
  }
  return true;
}

function validateDiagnosticValidationAttempts(value, incidentVersion, label) {
  invariant(Array.isArray(value) && value.length <= 16, `${label} is invalid`);
  let previousKey = '';
  for (const [index, raw] of value.entries()) {
    const itemLabel = `${label} ${index}`;
    const attempt = exactRecord(raw, itemLabel, [
      'validation_attempt_id', 'incident_version', 'outbox_attempt', 'claim_state',
      'claim_failure_code', 'result_state', 'result_failure_code', 'failed_gate',
    ]);
    const attemptID = string(attempt.validation_attempt_id, UUID, `${itemLabel} ID`);
    const version = integer(attempt.incident_version, 1, incidentVersion, `${itemLabel} incident version`);
    const key = `${String(version).padStart(7, '0')}:${attemptID}`;
    invariant(key > previousKey, `${label} are not sorted and unique`);
    previousKey = key;
    integer(attempt.outbox_attempt, 1, 100, `${itemLabel} outbox attempt`);
    invariant(['started', 'valid', 'invalid', 'interrupted'].includes(attempt.claim_state),
      `${itemLabel} claim state is invalid`);
    const claimFailure = diagnosticCode(attempt.claim_failure_code, `${itemLabel} claim failure code`);
    invariant((['invalid', 'interrupted'].includes(attempt.claim_state) && claimFailure !== null) ||
      (!['invalid', 'interrupted'].includes(attempt.claim_state) && claimFailure === null),
    `${itemLabel} claim failure state is invalid`);
    invariant(attempt.result_state === null || ['valid', 'invalid', 'interrupted'].includes(attempt.result_state),
      `${itemLabel} result state is invalid`);
    const resultFailure = diagnosticCode(attempt.result_failure_code, `${itemLabel} result failure code`);
    invariant(attempt.failed_gate === null || DIAGNOSTIC_GATE_NAMES.includes(attempt.failed_gate),
      `${itemLabel} failed gate is invalid`);
    invariant((attempt.result_state === null && resultFailure === null && attempt.failed_gate === null) ||
      (attempt.result_state === 'valid' && resultFailure === null && attempt.failed_gate === null) ||
      (attempt.result_state === 'invalid' && resultFailure !== null && attempt.failed_gate !== null) ||
      (attempt.result_state === 'interrupted' && resultFailure !== null && attempt.failed_gate === null),
    `${itemLabel} result failure state is invalid`);
  }
  return true;
}

function validateDiagnosticGates(value, snapshotState, label) {
  invariant(Array.isArray(value) && value.length <= DIAGNOSTIC_GATE_NAMES.length, `${label} is invalid`);
  for (const [index, raw] of value.entries()) {
    const gate = exactRecord(raw, `${label} ${index}`, ['order', 'name', 'passed', 'result_code']);
    invariant(gate.order === index + 1 && gate.name === DIAGNOSTIC_GATE_NAMES[index],
      `${label} order is invalid`);
    invariant(typeof gate.passed === 'boolean', `${label} pass state is invalid`);
    const resultCode = diagnosticCode(gate.result_code, `${label} result code`);
    invariant((gate.passed && resultCode === 'ok') || (!gate.passed && resultCode !== 'ok'),
      `${label} result is inconsistent`);
  }
  if (snapshotState === 'valid') {
    invariant(value.length === DIAGNOSTIC_GATE_NAMES.length && value.every((gate) => gate.passed),
      `${label} valid snapshot gates are incomplete`);
  }
  return true;
}

function validateDiagnosticPolicies(value, incidentVersion, label) {
  invariant(Array.isArray(value) && value.length <= 16, `${label} is invalid`);
  let previousPolicyKey = '';
  for (const [index, raw] of value.entries()) {
    const policyLabel = `${label} ${index}`;
    const policy = exactRecord(raw, policyLabel, [
      'policy_id', 'version', 'incident_version', 'state', 'state_revision', 'validation_snapshots',
    ]);
    const policyID = string(policy.policy_id, UUID, `${policyLabel} ID`);
    const version = integer(policy.version, 1, 1_000_000, `${policyLabel} version`);
    const policyKey = `${policyID}:${String(version).padStart(7, '0')}`;
    invariant(policyKey > previousPolicyKey, `${label} are not sorted and unique`);
    previousPolicyKey = policyKey;
    integer(policy.incident_version, 1, incidentVersion, `${policyLabel} incident version`);
    invariant([
      'draft', 'validating', 'valid', 'invalid', 'stale', 'approved', 'rejected',
      'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate',
    ].includes(policy.state), `${policyLabel} state is invalid`);
    integer(policy.state_revision, 1, Number.MAX_SAFE_INTEGER, `${policyLabel} state revision`);
    invariant(Array.isArray(policy.validation_snapshots) && policy.validation_snapshots.length <= 16,
      `${policyLabel} validation snapshots are invalid`);
    let previousSnapshotID = '';
    for (const [snapshotIndex, rawSnapshot] of policy.validation_snapshots.entries()) {
      const snapshotLabel = `${policyLabel} validation snapshot ${snapshotIndex}`;
      const snapshot = exactRecord(rawSnapshot, snapshotLabel, [
        'validation_snapshot_id', 'state', 'failure_code', 'gates',
      ]);
      const snapshotID = string(snapshot.validation_snapshot_id, UUID, `${snapshotLabel} ID`);
      invariant(snapshotID > previousSnapshotID,
        `${policyLabel} validation snapshot IDs are not sorted and unique`);
      previousSnapshotID = snapshotID;
      invariant(['draft', 'valid', 'invalid', 'stale'].includes(snapshot.state),
        `${snapshotLabel} state is invalid`);
      const failure = diagnosticCode(snapshot.failure_code, `${snapshotLabel} failure code`);
      invariant((snapshot.state === 'valid' && failure === null) ||
        (snapshot.state === 'invalid' && failure !== null) || ['draft', 'stale'].includes(snapshot.state),
      `${snapshotLabel} failure state is invalid`);
      validateDiagnosticGates(snapshot.gates, snapshot.state, `${snapshotLabel} gates`);
    }
  }
  return true;
}

function validateDiagnosticPipelineIncidents(value, label) {
  invariant(Array.isArray(value) && value.length <= 16, `${label} is invalid`);
  let previousIncidentID = '';
  for (const [index, raw] of value.entries()) {
    const incidentLabel = `${label} ${index}`;
    const incident = exactRecord(raw, incidentLabel, [
      'incident_id', 'kind', 'state', 'version', 'evidence_version', 'analyze_outbox',
      'analysis_attempts', 'validate_outbox', 'validation_attempts', 'policies',
    ]);
    const incidentID = string(incident.incident_id, UUID, `${incidentLabel} ID`);
    invariant(incidentID > previousIncidentID, `${label} IDs are not sorted and unique`);
    previousIncidentID = incidentID;
    invariant(DIAGNOSTIC_INCIDENT_KINDS.has(incident.kind), `${incidentLabel} kind is invalid`);
    invariant(['open', 'analyzing', 'review_ready', 'analysis_failed', 'closed'].includes(incident.state),
      `${incidentLabel} state is invalid`);
    const version = integer(incident.version, 1, 1_000_000, `${incidentLabel} version`);
    if (incident.evidence_version !== null) {
      integer(incident.evidence_version, 1, version, `${incidentLabel} evidence version`);
    }
    validateDiagnosticOutbox(incident.analyze_outbox, `${incidentLabel} analyze outbox`);
    validateDiagnosticAnalysisAttempts(incident.analysis_attempts, version,
      `${incidentLabel} analysis attempts`);
    validateDiagnosticOutbox(incident.validate_outbox, `${incidentLabel} validate outbox`);
    validateDiagnosticValidationAttempts(incident.validation_attempts, version,
      `${incidentLabel} validation attempts`);
    validateDiagnosticPolicies(incident.policies, version, `${incidentLabel} policies`);
  }
  return true;
}

function validateDiagnosticContainer(value, service) {
  const container = exactRecord(value, `detection diagnostic ${service}`, ['running', 'restart_count']);
  invariant(typeof container.running === 'boolean',
    `detection diagnostic ${service} state is invalid`);
  integer(container.restart_count, 0, 1_000_000,
    `detection diagnostic ${service} restart count`);
  return Object.freeze({ running: container.running, restart_count: container.restart_count });
}

export function validateDetectionDiagnostic(databaseValue, detectorValue, validationworkerValue, stage) {
  string(stage, /^[a-z0-9][a-z0-9_-]{0,63}$/, 'detection diagnostic stage');
  const database = exactRecord(databaseValue, 'detection diagnostic database', ['schema_version', 'sources']);
  invariant(database.schema_version === DETECTION_DIAGNOSTIC_SCHEMA,
    'detection diagnostic schema drifted');
  invariant(Array.isArray(database.sources) && database.sources.length === DIAGNOSTIC_SOURCES.length,
    'detection diagnostic sources are invalid');
  database.sources.forEach((raw, sourceIndex) => {
    const label = `detection diagnostic source ${sourceIndex}`;
    const source = exactRecord(raw, label, [
      'source_ipv4', 'gateway_event_count', 'auth_event_count', 'suspicious_path_ids',
      'gateway_batch_shapes', 'detect_outbox', 'signals', 'incidents', 'pipeline_incidents', 'evaluation_time',
      'gateway_coverage_start', 'auth_coverage_start', 'exact_gateway_coverage_batch_count',
    ]);
    invariant(source.source_ipv4 === DIAGNOSTIC_SOURCES[sourceIndex], `${label} identity drifted`);
    diagnosticCount(source.gateway_event_count, `${label} Gateway event count`);
    diagnosticCount(source.auth_event_count, `${label} auth event count`);
    diagnosticCount(source.exact_gateway_coverage_batch_count, `${label} exact coverage count`);
    diagnosticTimestamp(source.evaluation_time, `${label} evaluation time`);
    diagnosticTimestamp(source.gateway_coverage_start, `${label} Gateway coverage start`);
    diagnosticTimestamp(source.auth_coverage_start, `${label} auth coverage start`);

    invariant(Array.isArray(source.suspicious_path_ids) && source.suspicious_path_ids.length <= 8,
      `${label} suspicious path summary is invalid`);
    let previousPath = '';
    for (const rawPath of source.suspicious_path_ids) {
      const pathSummary = exactRecord(rawPath, `${label} suspicious path`, ['id', 'count']);
      invariant(DIAGNOSTIC_SUSPICIOUS_PATH_IDS.has(pathSummary.id) && pathSummary.id > previousPath,
        `${label} suspicious path identity is invalid`);
      diagnosticCount(pathSummary.count, `${label} suspicious path count`);
      previousPath = pathSummary.id;
    }

    invariant(Array.isArray(source.gateway_batch_shapes) && source.gateway_batch_shapes.length <= 100,
      `${label} Gateway batch shape summary is invalid`);
    for (const rawShape of source.gateway_batch_shapes) {
      const shape = exactRecord(rawShape, `${label} Gateway batch shape`, [
        'event_count', 'has_exact_coverage', 'count',
      ]);
      integer(shape.event_count, 1, 100, `${label} Gateway batch event count`);
      invariant(typeof shape.has_exact_coverage === 'boolean', `${label} Gateway batch coverage flag is invalid`);
      diagnosticCount(shape.count, `${label} Gateway batch shape count`);
    }

    invariant(Array.isArray(source.detect_outbox) && source.detect_outbox.length <= 100,
      `${label} detect outbox summary is invalid`);
    for (const rawJob of source.detect_outbox) {
      const job = exactRecord(rawJob, `${label} detect outbox`, [
        'aggregate_type', 'state', 'attempts', 'max_attempts', 'last_error_code', 'count',
      ]);
      invariant(['ingest_batch', 'auth_binding'].includes(job.aggregate_type) &&
        ['pending', 'leased', 'retry', 'completed', 'dead'].includes(job.state),
      `${label} detect outbox identity is invalid`);
      integer(job.attempts, 0, 100, `${label} detect outbox attempts`);
      integer(job.max_attempts, 1, 100, `${label} detect outbox maximum attempts`);
      invariant(job.attempts <= job.max_attempts, `${label} detect outbox attempt bound is invalid`);
      invariant(job.last_error_code === null ||
        (typeof job.last_error_code === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(job.last_error_code)),
      `${label} detect outbox error code is invalid`);
      diagnosticCount(job.count, `${label} detect outbox count`);
    }

    invariant(Array.isArray(source.signals) && source.signals.length <= 16,
      `${label} signal summary is invalid`);
    for (const rawSignal of source.signals) {
      const signal = exactRecord(rawSignal, `${label} signal`, ['kind', 'source_health_status', 'count']);
      invariant(DIAGNOSTIC_SIGNAL_KINDS.has(signal.kind) &&
        ['complete', 'incomplete'].includes(signal.source_health_status), `${label} signal identity is invalid`);
      diagnosticCount(signal.count, `${label} signal count`);
    }

    invariant(Array.isArray(source.incidents) && source.incidents.length <= 16,
      `${label} incident summary is invalid`);
    for (const rawIncident of source.incidents) {
      const incident = exactRecord(rawIncident, `${label} incident`, ['kind', 'state', 'count']);
      invariant(DIAGNOSTIC_INCIDENT_KINDS.has(incident.kind) &&
        ['open', 'analyzing', 'review_ready', 'analysis_failed', 'closed'].includes(incident.state),
      `${label} incident identity is invalid`);
      diagnosticCount(incident.count, `${label} incident count`);
    }
    validateDiagnosticPipelineIncidents(source.pipeline_incidents, `${label} pipeline incidents`);
  });

  const detector = validateDiagnosticContainer(detectorValue, 'detector');
  const validationworker = validateDiagnosticContainer(validationworkerValue, 'validationworker');
  return Object.freeze({
    schema_version: database.schema_version,
    stage,
    detector,
    validationworker,
    sources: database.sources,
  });
}

function expiryDiagnosticTimestamp(value, label) {
  if (value === null) return null;
  return timestamp(value, label);
}

function validateExpiryDiagnosticRuntime(value, service) {
  const runtime = exactRecord(value, `expiry diagnostic ${service}`, ['running', 'restart_count']);
  invariant(typeof runtime.running === 'boolean', `expiry diagnostic ${service} state is invalid`);
  integer(runtime.restart_count, 0, 1_000_000, `expiry diagnostic ${service} restart count`);
  return Object.freeze(runtime);
}

// This intentionally projects only lifecycle metadata.  It never includes JCS,
// signatures, capabilities, request data, account data, or container metadata.
export function validateExpiryDiagnostic(databaseValue, runtimeValue) {
  const database = exactRecord(databaseValue, 'expiry diagnostic database', [
    'schema_version', 'action', 'expiry_bounds', 'results', 'schedules', 'audit',
  ]);
  invariant(database.schema_version === EXPIRY_DIAGNOSTIC_SCHEMA,
    'expiry diagnostic schema drifted');
  let action = null;
  if (database.action !== null) {
    const raw = exactRecord(database.action, 'expiry diagnostic action', [
      'target_ipv4', 'state', 'version', 'queued_at', 'applied_at', 'expected_expires_at',
      'finished_at', 'updated_at',
    ]);
    action = Object.freeze({
      target_ipv4: string(raw.target_ipv4, IPV4, 'expiry diagnostic target'),
      state: string(raw.state, /^(?:approved|queued|active|expired|failed|revoked|indeterminate)$/,
        'expiry diagnostic action state'),
      version: integer(raw.version, 1, 2_147_483_647, 'expiry diagnostic action version'),
      queued_at: expiryDiagnosticTimestamp(raw.queued_at, 'expiry diagnostic queued_at'),
      applied_at: expiryDiagnosticTimestamp(raw.applied_at, 'expiry diagnostic applied_at'),
      expected_expires_at: expiryDiagnosticTimestamp(raw.expected_expires_at,
        'expiry diagnostic expected_expires_at'),
      finished_at: expiryDiagnosticTimestamp(raw.finished_at, 'expiry diagnostic finished_at'),
      updated_at: expiryDiagnosticTimestamp(raw.updated_at, 'expiry diagnostic updated_at'),
    });
  }

  let expiryBounds = null;
  if (database.expiry_bounds !== null) {
    const raw = exactRecord(database.expiry_bounds, 'expiry diagnostic bounds', [
      'source_result_digest', 'expires_not_before', 'expires_not_after',
    ]);
    const lower = timestamp(raw.expires_not_before, 'expiry diagnostic lower expiry bound');
    const upper = timestamp(raw.expires_not_after, 'expiry diagnostic upper expiry bound');
    invariant(Date.parse(upper) > Date.parse(lower), 'expiry diagnostic bounds are invalid');
    expiryBounds = Object.freeze({
      source_result_digest: string(raw.source_result_digest, DIGEST, 'expiry diagnostic source result digest'),
      expires_not_before: lower,
      expires_not_after: upper,
    });
  }

  invariant(Array.isArray(database.results) && database.results.length <= EXPIRY_DIAGNOSTIC_MAX_RESULTS,
    'expiry diagnostic results are invalid');
  const results = database.results.map((raw, index) => {
    const item = exactRecord(raw, `expiry diagnostic result ${index}`, [
      'schema_version', 'operation', 'classification', 'readback_state', 'remaining_ttl_seconds',
      'started_at', 'completed_at', 'persisted_at', 'readback_started_at', 'readback_completed_at',
      'result_digest',
    ]);
    invariant(['execution-result-v1', 'execution-result-v2'].includes(item.schema_version),
      `expiry diagnostic result ${index} schema is invalid`);
    invariant(['add', 'revoke', 'inspect'].includes(item.operation),
      `expiry diagnostic result ${index} operation is invalid`);
    invariant([
      'applied', 'recovered_active', 'revoked', 'inspect_active', 'inspect_absent',
      'inspect_mismatch', 'failed', 'indeterminate',
    ].includes(item.classification), `expiry diagnostic result ${index} classification is invalid`);
    invariant(['active', 'absent', 'mismatch', 'unavailable'].includes(item.readback_state),
      `expiry diagnostic result ${index} read-back state is invalid`);
    if (item.remaining_ttl_seconds !== null) {
      integer(item.remaining_ttl_seconds, 0, 86_400, `expiry diagnostic result ${index} remaining TTL`);
    }
    const started = timestamp(item.started_at, `expiry diagnostic result ${index} started_at`);
    const completed = timestamp(item.completed_at, `expiry diagnostic result ${index} completed_at`);
    const persisted = timestamp(item.persisted_at, `expiry diagnostic result ${index} persisted_at`);
    const readbackStarted = expiryDiagnosticTimestamp(item.readback_started_at,
      `expiry diagnostic result ${index} readback_started_at`);
    const readbackCompleted = expiryDiagnosticTimestamp(item.readback_completed_at,
      `expiry diagnostic result ${index} readback_completed_at`);
    invariant((readbackStarted === null) === (readbackCompleted === null),
      `expiry diagnostic result ${index} read-back interval is incomplete`);
    if (readbackStarted !== null) {
      invariant(Date.parse(readbackStarted) >= Date.parse(started) &&
        Date.parse(readbackCompleted) >= Date.parse(readbackStarted) &&
        Date.parse(readbackCompleted) <= Date.parse(completed),
      `expiry diagnostic result ${index} read-back interval is invalid`);
    }
    return Object.freeze({ ...item, started_at: started, completed_at: completed, persisted_at: persisted,
      readback_started_at: readbackStarted, readback_completed_at: readbackCompleted,
      result_digest: string(item.result_digest, DIGEST, `expiry diagnostic result ${index} digest`) });
  });

  invariant(Array.isArray(database.schedules) && database.schedules.length <= EXPIRY_DIAGNOSTIC_MAX_SCHEDULES,
    'expiry diagnostic schedules are invalid');
  const schedules = database.schedules.map((raw, index) => {
    const item = exactRecord(raw, `expiry diagnostic schedule ${index}`, [
      'purpose', 'state', 'due_at', 'attempts', 'last_error_code', 'last_error_digest',
      'source_result_digest', 'updated_at',
    ]);
    invariant(['reconciliation', 'expiry_confirmation', 'operator_status'].includes(item.purpose) &&
      ['pending', 'leased', 'retry', 'dispatched', 'completed', 'dead'].includes(item.state),
    `expiry diagnostic schedule ${index} identity is invalid`);
    integer(item.attempts, 0, 8, `expiry diagnostic schedule ${index} attempts`);
    if (item.last_error_code !== null) string(item.last_error_code, /^[a-z][a-z0-9_]{0,63}$/,
      `expiry diagnostic schedule ${index} error code`);
    if (item.last_error_digest !== null) string(item.last_error_digest, DIGEST,
      `expiry diagnostic schedule ${index} error digest`);
    return Object.freeze({ ...item,
      due_at: timestamp(item.due_at, `expiry diagnostic schedule ${index} due_at`),
      updated_at: timestamp(item.updated_at, `expiry diagnostic schedule ${index} updated_at`),
      source_result_digest: string(item.source_result_digest, DIGEST,
        `expiry diagnostic schedule ${index} source result digest`),
    });
  });

  invariant(Array.isArray(database.audit) && database.audit.length <= EXPIRY_DIAGNOSTIC_MAX_AUDIT,
    'expiry diagnostic audit is invalid');
  const audit = database.audit.map((raw, index) => {
    const item = exactRecord(raw, `expiry diagnostic audit ${index}`, [
      'action', 'outcome', 'primary_digest', 'secondary_digest', 'recorded_at',
    ]);
    string(item.action, /^[a-z][a-z0-9_]{0,127}$/, `expiry diagnostic audit ${index} action`);
    invariant(['accepted', 'rejected', 'succeeded', 'failed', 'indeterminate'].includes(item.outcome),
      `expiry diagnostic audit ${index} outcome is invalid`);
    if (item.primary_digest !== null) string(item.primary_digest, DIGEST,
      `expiry diagnostic audit ${index} primary digest`);
    if (item.secondary_digest !== null) string(item.secondary_digest, DIGEST,
      `expiry diagnostic audit ${index} secondary digest`);
    return Object.freeze({ ...item,
      recorded_at: timestamp(item.recorded_at, `expiry diagnostic audit ${index} recorded_at`),
    });
  });

  const runtime = exactRecord(runtimeValue, 'expiry diagnostic runtime', [
    'dispatcher', 'executor', 'lifecycleworker',
  ]);
  return Object.freeze({
    schema_version: database.schema_version, action, expiry_bounds: expiryBounds,
    results: Object.freeze(results), schedules: Object.freeze(schedules), audit: Object.freeze(audit),
    dispatcher: validateExpiryDiagnosticRuntime(runtime.dispatcher, 'dispatcher'),
    executor: validateExpiryDiagnosticRuntime(runtime.executor, 'executor'),
    lifecycleworker: validateExpiryDiagnosticRuntime(runtime.lifecycleworker, 'lifecycleworker'),
  });
}

function coverageTimestamp(value, label, nullable = false) {
  if (nullable && value === null) return null;
  const checked = string(value, MILLISECOND_TIMESTAMP, label);
  invariant(Number.isFinite(Date.parse(checked)), `${label} is invalid`);
  return checked;
}

function coverageBindingDigests(value, label) {
  invariant(Array.isArray(value) && value.length <= 100, `${label} is invalid`);
  const digests = value.map((entry, index) => string(entry, DIGEST, `${label} ${index}`));
  invariant(digests.every((entry, index) => index === 0 || digests[index - 1] < entry),
    `${label} are not sorted and unique`);
  return Object.freeze(digests);
}

export function validateCoverageReadiness(value) {
  const result = exactRecord(value, 'coverage readiness result', [
    'schema_version', 'service_label', 'detector_window_seconds', 'readiness_margin_seconds',
    'required_coverage_seconds', 'common_watermark', 'required_coverage_start', 'endpoints', 'ready',
  ]);
  invariant(result.schema_version === COVERAGE_READINESS_SCHEMA && result.service_label === 'demo-app' &&
    result.detector_window_seconds === COVERAGE_DETECTOR_WINDOW_SECONDS &&
    result.readiness_margin_seconds === COVERAGE_READINESS_MARGIN_SECONDS &&
    result.required_coverage_seconds === COVERAGE_READINESS_REQUIRED_SECONDS,
  'coverage readiness identity is invalid');
  const watermark = coverageTimestamp(result.common_watermark, 'coverage readiness common watermark', true);
  const requiredStart = coverageTimestamp(result.required_coverage_start, 'coverage readiness required start', true);
  invariant((watermark === null) === (requiredStart === null) &&
    (watermark === null || Date.parse(watermark) - Date.parse(requiredStart) ===
      COVERAGE_READINESS_REQUIRED_SECONDS * 1_000), 'coverage readiness window is invalid');
  invariant(Array.isArray(result.endpoints) && result.endpoints.length === 2,
    'coverage readiness endpoints are invalid');
  const expectedKinds = ['auth', 'gateway'];
  const endpoints = result.endpoints.map((raw, index) => {
    const label = `coverage readiness endpoint ${index}`;
    const endpoint = exactRecord(raw, label, [
      'endpoint_kind', 'expected_source_count', 'active_source_count', 'represented_source_count',
      'rotation_source_count', 'binding_digests', 'current_binding_digests',
      'detector_coverage_start', 'latest_coverage_end',
      'unresolved_gap_count', 'blocking_health_count', 'ready',
    ]);
    invariant(endpoint.endpoint_kind === expectedKinds[index], `${label} identity is invalid`);
    const expectedCount = integer(endpoint.expected_source_count, 1, 1, `${label} expected source count`);
    const activeCount = integer(endpoint.active_source_count, 0, 100, `${label} active source count`);
    const representedCount = integer(
      endpoint.represented_source_count, 0, 100, `${label} represented source count`,
    );
    const rotationCount = integer(endpoint.rotation_source_count, 0, 100, `${label} rotation source count`);
    const gapCount = integer(endpoint.unresolved_gap_count, 0, 1_000_000, `${label} unresolved gap count`);
    const healthCount = integer(endpoint.blocking_health_count, 0, 1_000_000, `${label} blocking health count`);
    invariant(representedCount <= activeCount, `${label} source counts are invalid`);
    const bindingDigests = coverageBindingDigests(endpoint.binding_digests, `${label} binding digests`);
    const currentBindingDigests = coverageBindingDigests(
      endpoint.current_binding_digests, `${label} current binding digests`,
    );
    invariant(bindingDigests.length === activeCount, `${label} binding count is inconsistent`);
    const detectorStart = coverageTimestamp(
      endpoint.detector_coverage_start, `${label} detector coverage start`, true,
    );
    const latestEnd = coverageTimestamp(endpoint.latest_coverage_end, `${label} latest coverage end`, true);
    invariant(detectorStart === null || latestEnd !== null &&
      Date.parse(latestEnd) >= Date.parse(detectorStart),
    `${label} coverage interval is invalid`);
    const currentGeneration = bindingDigests.length === currentBindingDigests.length &&
      bindingDigests.every((digest, digestIndex) => digest === currentBindingDigests[digestIndex]);
    const ready = watermark !== null && expectedCount === 1 && activeCount === expectedCount &&
      representedCount === activeCount && rotationCount === 0 && currentGeneration && detectorStart !== null &&
      Date.parse(detectorStart) <= Date.parse(requiredStart) && Date.parse(latestEnd) >= Date.parse(watermark) &&
      gapCount === 0 && healthCount === 0;
    invariant(endpoint.ready === ready, `${label} readiness is inconsistent`);
    return Object.freeze({ ...endpoint, binding_digests: bindingDigests,
      current_binding_digests: currentBindingDigests });
  });
  invariant(typeof result.ready === 'boolean' && result.ready === endpoints.every((endpoint) => endpoint.ready),
    'coverage readiness aggregate is inconsistent');
  return Object.freeze({ ...result, endpoints: Object.freeze(endpoints) });
}

export function coverageReadinessAdvanced(firstValue, secondValue) {
  const first = validateCoverageReadiness(firstValue);
  const second = validateCoverageReadiness(secondValue);
  if (!first.ready || !second.ready || first.common_watermark === null || second.common_watermark === null) {
    return false;
  }
  return Date.parse(second.common_watermark) > Date.parse(first.common_watermark) &&
    first.endpoints.every((endpoint, index) => {
      const next = second.endpoints[index];
      return endpoint.endpoint_kind === next.endpoint_kind && endpoint.latest_coverage_end !== null &&
        next.latest_coverage_end !== null &&
        Date.parse(next.latest_coverage_end) > Date.parse(endpoint.latest_coverage_end) &&
        endpoint.binding_digests.length === next.binding_digests.length &&
        endpoint.binding_digests.every((digest, digestIndex) => digest === next.binding_digests[digestIndex]);
    });
}

export function validateDetectionStability(value) {
  const result = exactRecord(value, 'detection stability result', [
    'schema_version', 'observed_at', 'sources',
  ]);
  invariant(result.schema_version === DETECTION_STABILITY_SCHEMA,
    'detection stability schema drifted');
  const observedAt = coverageTimestamp(result.observed_at, 'detection stability observation');
  invariant(Array.isArray(result.sources) && result.sources.length === DIAGNOSTIC_SOURCES.length,
    'detection stability sources are invalid');
  let failed = false;
  let ready = true;
  const sources = result.sources.map((raw, sourceIndex) => {
    const label = `detection stability source ${sourceIndex}`;
    const source = exactRecord(raw, label, [
      'source_ipv4', 'active_detect_jobs', 'dead_detect_jobs', 'incidents',
    ]);
    invariant(source.source_ipv4 === DIAGNOSTIC_SOURCES[sourceIndex], `${label} identity drifted`);
    const activeJobs = integer(source.active_detect_jobs, 0, 1_000_000, `${label} active jobs`);
    const deadJobs = integer(source.dead_detect_jobs, 0, 1_000_000, `${label} dead jobs`);
    failed ||= deadJobs > 0;
    ready &&= activeJobs === 0 && deadJobs === 0;
    invariant(Array.isArray(source.incidents) && source.incidents.length <= 16,
      `${label} incidents are invalid`);
    let previousIncidentID = '';
    const incidents = source.incidents.map((rawIncident, incidentIndex) => {
      const incidentLabel = `${label} incident ${incidentIndex}`;
      const incident = exactRecord(rawIncident, incidentLabel, [
        'incident_id', 'kind', 'state', 'version', 'evidence_version', 'signal_count', 'policies',
      ]);
      string(incident.incident_id, UUID, `${incidentLabel} ID`);
      invariant(incident.incident_id > previousIncidentID, `${label} incident IDs are not sorted and unique`);
      previousIncidentID = incident.incident_id;
      invariant(DIAGNOSTIC_INCIDENT_KINDS.has(incident.kind), `${incidentLabel} kind is invalid`);
      invariant(['open', 'analyzing', 'review_ready', 'analysis_failed', 'closed'].includes(incident.state),
        `${incidentLabel} state is invalid`);
      const version = integer(incident.version, 1, 1_000_000, `${incidentLabel} version`);
      const evidenceVersion = incident.evidence_version === null ? null :
        integer(incident.evidence_version, 1, version, `${incidentLabel} evidence version`);
      integer(incident.signal_count, 0, 1_000_000, `${incidentLabel} signal count`);
      invariant(Array.isArray(incident.policies) && incident.policies.length <= 16,
        `${incidentLabel} policies are invalid`);
      let previousPolicyKey = '';
      const policies = incident.policies.map((rawPolicy, policyIndex) => {
        const policyLabel = `${incidentLabel} policy ${policyIndex}`;
        const policy = exactRecord(rawPolicy, policyLabel, [
          'policy_id', 'version', 'incident_version', 'state', 'state_revision',
          'policy_digest', 'evidence_snapshot_digest',
        ]);
        string(policy.policy_id, UUID, `${policyLabel} ID`);
        const policyVersion = integer(policy.version, 1, 1_000_000, `${policyLabel} version`);
        const policyKey = `${policy.policy_id}:${String(policyVersion).padStart(7, '0')}`;
        invariant(policyKey > previousPolicyKey, `${incidentLabel} policies are not sorted and unique`);
        previousPolicyKey = policyKey;
        invariant(integer(policy.incident_version, 1, 1_000_000,
          `${policyLabel} incident version`) === evidenceVersion,
          `${policyLabel} evidence version drifted`);
        invariant([
          'draft', 'validating', 'valid', 'invalid', 'stale', 'approved', 'rejected',
          'queued', 'active', 'expired', 'failed', 'revoked', 'indeterminate',
        ].includes(policy.state), `${policyLabel} state is invalid`);
        integer(policy.state_revision, 1, Number.MAX_SAFE_INTEGER, `${policyLabel} state revision`);
        string(policy.policy_digest, DIGEST, `${policyLabel} digest`);
        string(policy.evidence_snapshot_digest, DIGEST, `${policyLabel} evidence digest`);
        return Object.freeze(policy);
      });
      return Object.freeze({ ...incident, policies: Object.freeze(policies),
        evidence_version: evidenceVersion });
    });
    const expectedKind = EXPECTED_INCIDENTS.get(source.source_ipv4);
    if (expectedKind === undefined) {
      ready &&= incidents.length === 0;
    } else if (source.source_ipv4 === '203.0.113.20') {
      ready &&= incidents.length === 1 && incidents[0].kind === expectedKind &&
        incidents[0].state === 'review_ready' && incidents[0].evidence_version !== null &&
        incidents[0].version === incidents[0].evidence_version + 2 &&
        incidents[0].signal_count >= 1 && incidents[0].policies.length === 1 &&
        incidents[0].policies[0].incident_version === incidents[0].evidence_version &&
        incidents[0].policies[0].state === 'valid';
    } else {
      const incident = incidents[0];
      const invalidPolicy = incident?.state === 'review_ready' && incident.evidence_version !== null &&
        incident.version === incident.evidence_version + 2 && incident.policies.length === 1 &&
        incident.policies[0].incident_version === incident.evidence_version &&
        incident.policies[0].state === 'invalid';
      const noPolicyTerminal = ['analysis_failed', 'closed'].includes(incident?.state) &&
        incident?.policies.length === 0;
      ready &&= incidents.length === 1 && incident.kind === expectedKind &&
        incident.signal_count >= 1 && (invalidPolicy || noPolicyTerminal);
    }
    return Object.freeze({ ...source, incidents: Object.freeze(incidents) });
  });
  return Object.freeze({ ...result, observed_at: observedAt, sources: Object.freeze(sources), ready, failed });
}

export function detectionStabilityAdvanced(firstValue, secondValue) {
  const first = validateDetectionStability(firstValue);
  const second = validateDetectionStability(secondValue);
  if (!first.ready || !second.ready || first.failed || second.failed ||
    Date.parse(second.observed_at) <= Date.parse(first.observed_at)) {
    return false;
  }
  return canonicalJSON(first.sources) === canonicalJSON(second.sources);
}

function absolutePathWithin(root, candidate, label) {
  invariant(typeof candidate === 'string' && candidate.length > 0 && candidate.length <= 4096 &&
    !candidate.includes('\0') && path.isAbsolute(candidate) && path.normalize(candidate) === candidate &&
    candidate !== root && candidate.startsWith(`${root}${path.sep}`), `${label} is invalid`);
  return candidate;
}

export function validateBrowserQALocator(value, expected) {
  const contract = exactRecord(value, 'browser QA locator', [
    'schema_version', 'project', 'phase', 'web_url', 'credentials_file', 'action_id',
    'expected_action_state', 'deadline', 'stop_file',
  ]);
  const expectation = exactRecord(expected, 'browser QA locator expectation', [
    'root', 'project', 'phase', 'web_port', 'credentials_file', 'action_id',
    'expected_action_state', 'deadline', 'stop_file',
  ]);
  const root = string(expectation.root, /^\/.{0,4095}$/, 'browser QA root');
  invariant(!root.includes('\0') && path.isAbsolute(root) && path.normalize(root) === root,
    'browser QA root is invalid');
  const project = string(expectation.project, E2E_PROJECT, 'browser QA project');
  const phase = string(expectation.phase, /^(?:active|revoked)$/, 'browser QA phase');
  const webPort = integer(expectation.web_port, 1, 65_535, 'browser QA web port');
  const credentialsFile = absolutePathWithin(root, expectation.credentials_file, 'browser QA credential path');
  const stopFile = absolutePathWithin(root, expectation.stop_file, 'browser QA stop path');
  invariant(new Set([credentialsFile, stopFile]).size === 2,
    'browser QA locator paths are not independent');
  const actionID = string(expectation.action_id, UUID, 'browser QA action ID');
  const expectedActionState = string(
    expectation.expected_action_state, /^(?:active|revoked)$/, 'browser QA expected action state',
  );
  invariant(phase === expectedActionState, 'browser QA phase and expected action state differ');
  const deadline = timestamp(expectation.deadline, 'browser QA deadline');
  invariant(
    contract.schema_version === BROWSER_QA_LOCATOR_SCHEMA && contract.project === project &&
      contract.phase === phase && contract.web_url === `http://localhost:${webPort}/` &&
      contract.credentials_file === credentialsFile && contract.action_id === actionID &&
      contract.expected_action_state === expectedActionState &&
      contract.deadline === deadline && contract.stop_file === stopFile,
    'browser QA locator binding is invalid',
  );
  timestamp(contract.deadline, 'browser QA locator deadline');
  return Object.freeze({ ...contract });
}

export async function writeBrowserQALocator(options) {
  const value = exactRecord(options, 'browser QA locator options', [
    'output', 'root', 'project', 'phase', 'webPort', 'credentialsFile', 'stateFile',
    'holdSeconds', 'stopFile',
  ]);
  const root = string(value.root, /^\/.{0,4095}$/, 'browser QA root');
  invariant(!root.includes('\0') && path.isAbsolute(root) && path.normalize(root) === root,
    'browser QA root is invalid');
  const output = absolutePathWithin(root, value.output, 'browser QA locator output');
  const credentialsFile = absolutePathWithin(root, value.credentialsFile, 'browser QA credential path');
  const stateFile = absolutePathWithin(root, value.stateFile, 'browser QA state path');
  const stopFile = absolutePathWithin(root, value.stopFile, 'browser QA stop path');
  invariant(new Set([output, credentialsFile, stateFile, stopFile]).size === 4,
    'browser QA paths are not independent');
  const holdSeconds = integer(value.holdSeconds, 60, 1_800, 'browser QA hold seconds');
  const project = string(value.project, E2E_PROJECT, 'browser QA project');
  const phase = string(value.phase, /^(?:active|revoked)$/, 'browser QA phase');
  invariant(output === path.join(root, `browser-qa-${phase}-locator.json`) &&
    stopFile === path.join(root, `browser-qa-${phase}.stop`),
  'browser QA phase paths are invalid');
  const webPort = integer(value.webPort, 1, 65_535, 'browser QA web port');
  await assertPrivatePath(root, 'directory', 0o700, 'browser QA root');
  await assertPrivatePath(credentialsFile, 'file', 0o600, 'browser QA credential file');
  await assertPrivatePath(stateFile, 'file', 0o600, 'browser QA state file');
  await assertPathAbsent(output, 'browser QA locator output');
  await assertPathAbsent(stopFile, 'browser QA stop marker');
  const state = validateDemoState(await readJSON(stateFile, 'browser QA state file'), phase === 'revoked');
  invariant((phase === 'active' && state.revocation === null) ||
    (phase === 'revoked' && state.mode === 'fast_revoke' && state.revocation !== null),
  'browser QA phase does not match the E2E mode and lifecycle');
  const deadline = new Date(Date.now() + holdSeconds * 1_000).toISOString();
  const locator = {
    schema_version: BROWSER_QA_LOCATOR_SCHEMA,
    project,
    phase,
    web_url: `http://localhost:${webPort}/`,
    credentials_file: credentialsFile,
    action_id: state.action.action_id,
    expected_action_state: phase,
    deadline,
    stop_file: stopFile,
  };
  validateBrowserQALocator(locator, {
    root, project, phase, web_port: webPort, credentials_file: credentialsFile,
    action_id: state.action.action_id, expected_action_state: phase, deadline, stop_file: stopFile,
  });
  await writeStrictPrivateJSON(output, locator);
  const written = await assertPrivatePath(output, 'file', 0o600, 'browser QA locator output');
  invariant(written.size === BigInt(Buffer.byteLength(`${canonicalJSON(locator)}\n`, 'utf8')),
    'browser QA locator output size is invalid');
  return Object.freeze(locator);
}

const EVIDENCE_CHAIN_SQL = `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, sentinelflow;
COPY (
WITH candidates(selector, job_id) AS (
  VALUES
    ('add', :'add_job'::uuid),
    ('revoke', NULLIF(:'revoke_job', '')::uuid)
), selected(selector, job_id) AS (
  SELECT selector, job_id FROM candidates WHERE job_id IS NOT NULL
)
SELECT json_build_object(
  'schema_version', 'sentinelflow-demo-e2e-evidence-chain-v1',
  'selector', selected.selector,
  'job', json_build_object(
    'job_id', job.job_id::text, 'kind', job.kind, 'operation', job.operation,
    'state', job.state, 'aggregate_type', job.aggregate_type::text,
    'aggregate_id', job.aggregate_id::text, 'aggregate_version', job.aggregate_version
  ),
  'operation', json_build_object(
    'job_id', operation.job_id::text, 'operation', operation.operation,
    'action_id', operation.action_id::text, 'policy_id', operation.policy_id::text,
    'policy_version', operation.policy_version, 'target_ipv4', host(operation.target_ipv4),
    'artifact_digest', operation.artifact_digest::text,
    'original_add_digest', operation.original_add_digest::text,
    'evidence_snapshot_digest', operation.evidence_snapshot_digest::text,
    'validation_snapshot_id', operation.validation_snapshot_id::text,
    'validation_snapshot_digest', operation.validation_snapshot_digest::text,
    'authorization_id', operation.enforcement_authorization_id::text,
    'authorization_digest', operation.authorization_digest::text,
    'actor_id', operation.actor_id::text, 'reason_digest', operation.reason_digest::text,
    'owned_schema_digest', operation.owned_schema_digest::text
  ),
  'action', json_build_object(
    'action_id', action.action_id::text, 'policy_id', action.policy_id::text,
    'policy_version', action.policy_version, 'add_authorization_id', action.add_authorization_id::text,
    'target_ipv4', host(action.target_ipv4),
    'canonical_artifact_digest', action.canonical_artifact_digest::text,
    'state', action.state, 'version', action.version
  ),
  'authorization', json_build_object(
    'authorization_id', authz.authorization_id::text,
    'authorization_kind', authz.authorization_kind,
    'action_id', authz.action_id::text, 'policy_id', authz.policy_id::text,
    'policy_version', authz.policy_version,
    'decision_id', authz.approval_decision_id::text, 'decision', authz.decision,
    'target_ipv4', host(authz.target_ipv4),
    'policy_digest', authz.policy_digest::text,
    'generated_artifact_digest', authz.generated_artifact_digest::text,
    'canonical_artifact_digest', authz.canonical_artifact_digest::text,
    'original_add_digest', authz.original_add_digest::text,
    'evidence_snapshot_digest', authz.evidence_snapshot_digest::text,
    'validation_snapshot_digest', authz.validation_snapshot_digest::text,
    'actor_id', authz.actor_id::text,
    'reason_digest', authz.hil_reason_digest::text,
    'decision_nonce_digest', authz.decision_nonce_digest::text,
    'idempotency_key_digest', authz.idempotency_key_digest::text,
    'authorization_digest', authz.authorization_digest::text
  ),
  'decision', json_build_object(
    'decision_id', decision.decision_id::text, 'challenge_id', decision.challenge_id::text,
    'operation', decision.operation, 'decision', decision.decision,
    'resource_type', decision.resource_type, 'resource_id', decision.resource_id::text,
    'resource_version', decision.resource_version, 'policy_id', decision.policy_id::text,
    'policy_version', decision.policy_version, 'action_id', decision.action_id::text,
    'target_ipv4', host(decision.target_ipv4), 'policy_digest', decision.policy_digest::text,
    'evidence_snapshot_digest', decision.evidence_snapshot_digest::text,
    'generated_artifact_digest', decision.generated_artifact_digest::text,
    'canonical_artifact_digest', decision.canonical_artifact_digest::text,
    'original_add_digest', decision.original_add_digest::text,
    'validation_snapshot_digest', decision.validation_snapshot_digest::text,
    'actor_id', decision.actor_id::text, 'reason_id', decision.reason_id::text,
    'reason_digest', decision.reason_digest::text,
    'challenge_nonce_digest', decision.challenge_nonce_digest::text,
    'idempotency_key_digest', decision.idempotency_key_digest::text
  ),
  'challenge', json_build_object(
    'challenge_id', challenge.challenge_id::text, 'operation', challenge.operation,
    'resource_type', challenge.resource_type, 'resource_id', challenge.resource_id::text,
    'resource_version', challenge.resource_version, 'policy_id', challenge.policy_id::text,
    'policy_version', challenge.policy_version, 'action_id', challenge.action_id::text,
    'target_ipv4', host(challenge.target_ipv4), 'policy_digest', challenge.policy_digest::text,
    'evidence_snapshot_digest', challenge.evidence_snapshot_digest::text,
    'generated_artifact_digest', challenge.generated_artifact_digest::text,
    'canonical_artifact_digest', challenge.canonical_artifact_digest::text,
    'original_add_digest', challenge.original_add_digest::text,
    'validation_snapshot_digest', challenge.validation_snapshot_digest::text,
    'actor_id', challenge.actor_id::text, 'nonce_digest', challenge.nonce_digest::text,
    'idempotency_key_digest', challenge.idempotency_key_digest::text,
    'consumed_decision_id', challenge.consumed_decision_id::text
  ),
  'reason', json_build_object(
    'reason_id', reason.reason_id::text, 'operation', reason.operation,
    'actor_id', reason.actor_id::text, 'reason_digest', reason.reason_digest::text
  ),
  'revocation', CASE WHEN revocation.revocation_id IS NULL THEN NULL ELSE json_build_object(
    'revocation_id', revocation.revocation_id::text, 'action_id', revocation.action_id::text,
    'authorization_id', revocation.authorization_id::text,
    'decision_id', revocation.approval_decision_id::text,
    'actor_id', revocation.actor_id::text, 'reason_id', revocation.reason_id::text,
    'reason_digest', revocation.reason_digest::text, 'target_ipv4', host(revocation.target_ipv4),
    'original_add_digest', revocation.original_add_digest::text,
    'artifact_digest', revocation.artifact_digest::text, 'state', revocation.state
  ) END,
  'capability', json_build_object(
    'capability_id', capability.capability_id::text, 'job_id', capability.job_id::text,
    'operation', capability.operation, 'action_id', capability.action_id::text,
    'policy_id', capability.policy_id::text, 'policy_version', capability.policy_version,
    'target_ipv4', host(capability.target_ipv4), 'artifact_digest', capability.artifact_digest::text,
    'original_add_digest', capability.original_add_digest::text,
    'evidence_snapshot_digest', capability.evidence_snapshot_digest::text,
    'validation_snapshot_digest', capability.validation_snapshot_digest::text,
    'authorization_digest', capability.authorization_digest::text,
    'actor_id', capability.actor_id::text, 'reason_digest', capability.reason_digest::text,
    'owned_schema_digest', capability.owned_schema_digest::text,
    'capability_digest', capability.capability_digest::text,
    'signature_bytes', octet_length(capability.capability_signature),
    'consumed', capability.consumed_at IS NOT NULL
  ),
  'result', json_build_object(
    'result_id', result.result_id::text, 'capability_id', result.capability_id::text,
    'capability_digest', result.capability_digest::text, 'operation', result.operation,
    'action_id', result.action_id::text, 'artifact_digest', result.artifact_digest::text,
    'target_ipv4', host(result.target_ipv4), 'classification', result.classification,
    'readback_state', result.readback_state, 'journal_sequence', result.journal_sequence,
    'error_code', result.error_code, 'owned_schema_digest', result.owned_schema_digest::text,
    'result_digest', result.result_digest::text,
    'signature_bytes', octet_length(result.result_signature)
  ),
  'application', json_build_object(
    'result_id', application.result_id::text, 'result_digest', application.result_digest::text,
    'action_id', application.action_id::text, 'operation', application.operation,
    'classification', application.classification, 'resulting_state', application.resulting_state,
    'resulting_action_version', application.resulting_action_version
  ),
  'audit', json_build_object(
    'authorization_count', (SELECT count(*)::integer FROM audit_events audit
      WHERE audit.actor_type = 'administrator' AND audit.actor_id = authz.actor_id
        AND audit.enforcement_action_id = action.action_id
        AND audit.policy_id = action.policy_id AND audit.policy_version = action.policy_version
        AND audit.secondary_digest = authz.authorization_digest AND audit.outcome = 'accepted'
        AND ((operation.operation = 'add' AND audit.action = 'policy_approved'
              AND audit.object_type = 'policy' AND audit.object_id = action.policy_id)
          OR (operation.operation = 'revoke' AND audit.action = 'enforcement_revoke_authorized'
              AND audit.object_type = 'revocation' AND audit.object_id = revocation.revocation_id))),
    'authorization_event_id', (SELECT min(audit.event_id::text) FROM audit_events audit
      WHERE audit.actor_type = 'administrator' AND audit.actor_id = authz.actor_id
        AND audit.enforcement_action_id = action.action_id
        AND audit.secondary_digest = authz.authorization_digest AND audit.outcome = 'accepted'
        AND ((operation.operation = 'add' AND audit.action = 'policy_approved')
          OR (operation.operation = 'revoke' AND audit.action = 'enforcement_revoke_authorized'))),
    'authorization_primary_digest', (SELECT min(audit.primary_digest::text) FROM audit_events audit
      WHERE audit.actor_type = 'administrator' AND audit.actor_id = authz.actor_id
        AND audit.enforcement_action_id = action.action_id
        AND audit.secondary_digest = authz.authorization_digest AND audit.outcome = 'accepted'
        AND ((operation.operation = 'add' AND audit.action = 'policy_approved')
          OR (operation.operation = 'revoke' AND audit.action = 'enforcement_revoke_authorized'))),
    'queue_count', (SELECT count(*)::integer FROM audit_events audit
      WHERE audit.event_id = capability.capability_id AND audit.actor_type = 'dispatcher'
        AND audit.action = 'enforcement_queued' AND audit.object_type = 'enforcement_action'
        AND audit.object_id = action.action_id AND audit.enforcement_action_id = action.action_id
        AND audit.primary_digest = capability.capability_digest
        AND audit.secondary_digest = authz.authorization_digest AND audit.outcome = 'accepted'),
    'terminal_count', (SELECT count(*)::integer FROM audit_events audit
      WHERE audit.event_id = result.result_id AND audit.actor_type = 'executor'
        AND audit.action = CASE result.classification WHEN 'applied' THEN 'enforcement_active'
          WHEN 'recovered_active' THEN 'enforcement_active' WHEN 'revoked' THEN 'enforcement_revoked' ELSE 'invalid' END
        AND audit.object_type = 'enforcement_action' AND audit.object_id = action.action_id
        AND audit.enforcement_action_id = action.action_id
        AND audit.primary_digest = result.result_digest
        AND audit.secondary_digest = capability.capability_digest AND audit.outcome = 'succeeded')
  )
)::text
FROM selected
JOIN outbox_jobs job ON job.job_id = selected.job_id
JOIN dispatch_operations operation ON operation.job_id = job.job_id
JOIN enforcement_actions action ON action.action_id = operation.action_id
JOIN enforcement_authorizations authz
  ON authz.authorization_id = operation.enforcement_authorization_id
JOIN approval_decisions decision ON decision.decision_id = authz.approval_decision_id
JOIN decision_challenges challenge ON challenge.challenge_id = decision.challenge_id
JOIN hil_reasons reason ON reason.reason_id = decision.reason_id
LEFT JOIN revocation_operations revocation
  ON revocation.authorization_id = authz.authorization_id
JOIN execution_capabilities capability ON capability.job_id = job.job_id
JOIN execution_results result ON result.capability_id = capability.capability_id
JOIN lifecycle_result_applications_000026 application ON application.result_id = result.result_id
ORDER BY selected.selector
) TO STDOUT;
COMMIT;
`;

const COVERAGE_READINESS_SQL = `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, sentinelflow;
COPY (
WITH parameters(service_label, detector_window_seconds, readiness_margin_seconds,
    required_coverage_seconds, expected_source_count) AS (
  VALUES ('demo-app'::text, 300, 5, 305, 1)
), required_endpoints(endpoint_kind) AS (
  VALUES ('auth'::text), ('gateway'::text)
), current_bindings AS MATERIALIZED (
  SELECT binding.binding_id, binding.sender_id, binding.endpoint_kind, binding.binding_digest
  FROM sentinelflow.expected_source_bindings binding CROSS JOIN parameters
  WHERE binding.service_label = parameters.service_label
    AND binding.endpoint_kind IN ('auth', 'gateway')
    AND NOT EXISTS (
      SELECT 1 FROM sentinelflow.expected_source_binding_retirements retirement
      WHERE retirement.binding_id = binding.binding_id
    )
), observed AS MATERIALIZED (
  SELECT date_trunc('milliseconds', max(coverage.coverage_end)) AS observed_at
  FROM sentinelflow.source_coverage_attestations coverage
  JOIN sentinelflow.expected_source_bindings binding ON binding.binding_id = coverage.binding_id
  CROSS JOIN parameters
  WHERE binding.service_label = parameters.service_label
    AND binding.endpoint_kind IN ('auth', 'gateway')
    AND coverage.trust_state = 'trusted'
), active_observed AS MATERIALIZED (
  SELECT binding.binding_id, binding.sender_id, binding.endpoint_kind, binding.binding_digest
  FROM sentinelflow.expected_source_bindings binding
  CROSS JOIN parameters CROSS JOIN observed
  WHERE observed.observed_at IS NOT NULL
    AND binding.service_label = parameters.service_label
    AND binding.endpoint_kind IN ('auth', 'gateway')
    AND binding.effective_at <= observed.observed_at
    AND NOT EXISTS (
      SELECT 1 FROM sentinelflow.expected_source_binding_retirements retirement
      WHERE retirement.binding_id = binding.binding_id
        AND retirement.retired_at <= observed.observed_at
    )
), latest_observed AS MATERIALIZED (
  SELECT DISTINCT ON (active.binding_id)
    active.binding_id, active.sender_id, active.endpoint_kind,
    coverage.sender_epoch, coverage.coverage_end
  FROM active_observed active
  LEFT JOIN sentinelflow.source_coverage_attestations coverage
    ON coverage.binding_id = active.binding_id AND coverage.trust_state = 'trusted'
  ORDER BY active.binding_id, coverage.coverage_end DESC NULLS LAST,
    coverage.received_at DESC NULLS LAST, coverage.coverage_event_id
), watermark AS MATERIALIZED (
  SELECT date_trunc('milliseconds', min(latest.coverage_end)) AS common_watermark
  FROM latest_observed latest
), active_watermark AS MATERIALIZED (
  SELECT binding.binding_id, binding.sender_id, binding.endpoint_kind, binding.binding_digest
  FROM sentinelflow.expected_source_bindings binding
  CROSS JOIN parameters CROSS JOIN watermark
  WHERE watermark.common_watermark IS NOT NULL
    AND binding.service_label = parameters.service_label
    AND binding.endpoint_kind IN ('auth', 'gateway')
    AND binding.effective_at <= watermark.common_watermark
    AND NOT EXISTS (
      SELECT 1 FROM sentinelflow.expected_source_binding_retirements retirement
      WHERE retirement.binding_id = binding.binding_id
        AND retirement.retired_at <= watermark.common_watermark
    )
), watermark_segments AS MATERIALIZED (
  SELECT coverage.binding_id, coverage.sender_epoch, coverage.segment_id,
    min(coverage.coverage_start) AS segment_start,
    min(coverage.covered_through_sequence) AS segment_first_sequence,
    max(coverage.coverage_end) AS segment_end
  FROM sentinelflow.source_coverage_attestations coverage
  JOIN active_watermark active ON active.binding_id = coverage.binding_id
  CROSS JOIN watermark
  WHERE coverage.trust_state = 'trusted'
  GROUP BY coverage.binding_id, coverage.sender_epoch, coverage.segment_id,
    watermark.common_watermark
  HAVING max(coverage.coverage_end) >= watermark.common_watermark
), latest_watermark AS MATERIALIZED (
  SELECT DISTINCT ON (active.binding_id)
    active.binding_id, active.sender_id, active.endpoint_kind, active.binding_digest,
    segment.sender_epoch, segment.segment_id, segment.segment_start,
    segment.segment_first_sequence, segment.segment_end AS coverage_end
  FROM active_watermark active
  LEFT JOIN watermark_segments segment ON segment.binding_id = active.binding_id
  ORDER BY active.binding_id, segment.segment_end DESC NULLS LAST,
    segment.segment_start DESC NULLS LAST, segment.segment_id
), rotation_changes AS MATERIALIZED (
  SELECT changed.endpoint_kind, count(*)::integer AS source_count
  FROM (
    (SELECT binding_id, endpoint_kind FROM active_observed
      EXCEPT SELECT binding_id, endpoint_kind FROM active_watermark)
    UNION ALL
    (SELECT binding_id, endpoint_kind FROM active_watermark
      EXCEPT SELECT binding_id, endpoint_kind FROM active_observed)
  ) changed
  GROUP BY changed.endpoint_kind
), unresolved_gaps AS MATERIALIZED (
  SELECT latest.endpoint_kind, count(DISTINCT opened.lifecycle_id)::integer AS gap_count
  FROM latest_watermark latest CROSS JOIN watermark
  JOIN sentinelflow.ingest_gap_lifecycle opened
    ON opened.lifecycle_state = 'opened'
   AND opened.sender_id = latest.sender_id
   AND opened.endpoint_kind = latest.endpoint_kind
   AND opened.sender_epoch = latest.sender_epoch
   AND opened.detected_at <= watermark.common_watermark
  WHERE latest.coverage_end >= watermark.common_watermark
    AND NOT COALESCE((
      -- A split gap closes only when the as-of-watermark terminal multirange
      -- covers every sequence in the original opened range; holes remain open.
      SELECT int8range(opened.sequence_start, opened.sequence_end, '[]') <@
        range_agg(int8range(terminal.sequence_start, terminal.sequence_end, '[]'))
      FROM sentinelflow.ingest_gap_lifecycle terminal
      WHERE terminal.lifecycle_state IN ('late_closed', 'lost')
        AND terminal.sender_id = opened.sender_id
        AND terminal.endpoint_kind = opened.endpoint_kind
        AND terminal.sender_epoch = opened.sender_epoch
        AND terminal.sequence_start >= opened.sequence_start
        AND terminal.sequence_end <= opened.sequence_end
        AND terminal.detected_by_batch_id = opened.detected_by_batch_id
        AND terminal.detected_at = opened.detected_at
        AND terminal.resolved_at <= watermark.common_watermark
    ), false)
  GROUP BY latest.endpoint_kind
), latest_health AS MATERIALIZED (
  SELECT DISTINCT ON (latest.binding_id)
    latest.binding_id, latest.endpoint_kind, health.state, health.trust_state
  FROM latest_watermark latest CROSS JOIN watermark
  JOIN sentinelflow.source_health_intervals health
    ON health.source_id = latest.sender_id
   AND health.affected_sender_epoch = latest.sender_epoch
   AND health.occurred_at <= watermark.common_watermark
  JOIN sentinelflow.ingest_batches batch
    ON batch.sender_id = health.sender_id
   AND batch.sender_epoch = health.sender_epoch
   AND batch.batch_id = health.batch_id
   AND batch.endpoint_kind = latest.endpoint_kind
  WHERE latest.coverage_end >= watermark.common_watermark
    -- Health batches before the first attestation in this selected segment are
    -- the reset evidence that created the clean segment, not sticky current state.
    -- Same/later-sequence health remains applicable and fails closed below.
    AND batch.sequence >= latest.segment_first_sequence
  ORDER BY latest.binding_id, health.occurred_at DESC, health.received_at DESC,
    CASE health.state WHEN 'lost' THEN 0 WHEN 'degraded' THEN 1 ELSE 2 END,
    health.event_id
), blocking_health AS MATERIALIZED (
  SELECT health.endpoint_kind, count(*)::integer AS health_count
  FROM latest_health health
  WHERE health.trust_state <> 'trusted' OR health.state IN ('degraded', 'lost')
  GROUP BY health.endpoint_kind
), endpoint_summary AS MATERIALIZED (
  SELECT required.endpoint_kind, parameters.expected_source_count,
    (SELECT count(*)::integer FROM active_watermark active
      WHERE active.endpoint_kind = required.endpoint_kind) AS active_source_count,
    (SELECT count(*)::integer FROM latest_watermark latest CROSS JOIN watermark current
      WHERE latest.endpoint_kind = required.endpoint_kind
        AND latest.coverage_end >= current.common_watermark) AS represented_source_count,
    COALESCE((SELECT changes.source_count FROM rotation_changes changes
      WHERE changes.endpoint_kind = required.endpoint_kind), 0) AS rotation_source_count,
    COALESCE((SELECT jsonb_agg(active.binding_digest::text ORDER BY active.binding_digest::text)
      FROM active_watermark active
      WHERE active.endpoint_kind = required.endpoint_kind), '[]'::jsonb) AS binding_digests,
    COALESCE((SELECT jsonb_agg(active.binding_digest::text ORDER BY active.binding_digest::text)
      FROM current_bindings active
      WHERE active.endpoint_kind = required.endpoint_kind), '[]'::jsonb) AS current_binding_digests,
    CASE WHEN watermark.common_watermark IS NULL THEN NULL ELSE
      sentinelflow.detection_coverage_start(
        required.endpoint_kind, parameters.service_label, watermark.common_watermark)
    END AS detector_coverage_start,
    (SELECT min(latest.coverage_end) FROM latest_watermark latest
      WHERE latest.endpoint_kind = required.endpoint_kind) AS latest_coverage_end,
    COALESCE((SELECT gaps.gap_count FROM unresolved_gaps gaps
      WHERE gaps.endpoint_kind = required.endpoint_kind), 0) AS unresolved_gap_count,
    COALESCE((SELECT health.health_count FROM blocking_health health
      WHERE health.endpoint_kind = required.endpoint_kind), 0) AS blocking_health_count,
    watermark.common_watermark
  FROM required_endpoints required CROSS JOIN parameters CROSS JOIN watermark
), endpoint_ready AS MATERIALIZED (
  SELECT summary.*,
    summary.common_watermark IS NOT NULL
      AND summary.expected_source_count = 1
      AND summary.active_source_count = summary.expected_source_count
      AND summary.represented_source_count = summary.active_source_count
      AND summary.rotation_source_count = 0
      AND summary.binding_digests = summary.current_binding_digests
      AND summary.detector_coverage_start IS NOT NULL
      AND summary.detector_coverage_start <= summary.common_watermark - interval '305 seconds'
      AND summary.latest_coverage_end >= summary.common_watermark
      AND summary.unresolved_gap_count = 0
      AND summary.blocking_health_count = 0 AS ready
  FROM endpoint_summary summary
)
SELECT jsonb_build_object(
  'schema_version', 'sentinelflow-demo-e2e-coverage-readiness-v2',
  'service_label', parameters.service_label,
  'detector_window_seconds', parameters.detector_window_seconds,
  'readiness_margin_seconds', parameters.readiness_margin_seconds,
  'required_coverage_seconds', parameters.required_coverage_seconds,
  'common_watermark', CASE WHEN watermark.common_watermark IS NULL THEN NULL ELSE
    to_char(watermark.common_watermark AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
  'required_coverage_start', CASE WHEN watermark.common_watermark IS NULL THEN NULL ELSE
    to_char((watermark.common_watermark - interval '305 seconds') AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
  'endpoints', (SELECT jsonb_agg(jsonb_build_object(
    'endpoint_kind', endpoint.endpoint_kind,
    'expected_source_count', endpoint.expected_source_count,
    'active_source_count', endpoint.active_source_count,
    'represented_source_count', endpoint.represented_source_count,
    'rotation_source_count', endpoint.rotation_source_count,
    'binding_digests', endpoint.binding_digests,
    'current_binding_digests', endpoint.current_binding_digests,
    'detector_coverage_start', CASE WHEN endpoint.detector_coverage_start IS NULL THEN NULL ELSE
      to_char(endpoint.detector_coverage_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'latest_coverage_end', CASE WHEN endpoint.latest_coverage_end IS NULL THEN NULL ELSE
      to_char(endpoint.latest_coverage_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'unresolved_gap_count', endpoint.unresolved_gap_count,
    'blocking_health_count', endpoint.blocking_health_count,
    'ready', endpoint.ready
  ) ORDER BY endpoint.endpoint_kind) FROM endpoint_ready endpoint),
  'ready', COALESCE((SELECT bool_and(endpoint.ready) AND count(*) = 2 FROM endpoint_ready endpoint), false)
)::text
FROM parameters CROSS JOIN watermark
) TO STDOUT;
COMMIT;
`;

const DETECTION_STABILITY_SQL = `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, sentinelflow;
COPY (
WITH expected(source_ipv4) AS (
  VALUES ('203.0.113.20'), ('203.0.113.21'), ('203.0.113.22'), ('203.0.113.23'), ('203.0.113.24')
), job_sources AS MATERIALIZED (
  SELECT expected.source_ipv4, job.state
  FROM expected
  JOIN sentinelflow.outbox_jobs job ON job.kind = 'detect' AND (
    (job.aggregate_type = 'ingest_batch' AND (
      EXISTS (SELECT 1 FROM sentinelflow.gateway_events event
        WHERE event.batch_id = job.aggregate_id AND host(event.source_ip) = expected.source_ipv4)
      OR EXISTS (SELECT 1 FROM sentinelflow.auth_events event
        WHERE event.batch_id = job.aggregate_id AND host(event.source_ip) = expected.source_ipv4)
    )) OR (job.aggregate_type = 'auth_binding' AND EXISTS (
      SELECT 1 FROM sentinelflow.auth_events event
      WHERE event.event_id = job.aggregate_id AND host(event.source_ip) = expected.source_ipv4
    ))
  )
)
SELECT jsonb_build_object(
  'schema_version', 'sentinelflow-demo-e2e-detection-stability-v1',
  'observed_at', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'sources', (SELECT jsonb_agg(jsonb_build_object(
    'source_ipv4', expected.source_ipv4,
    'active_detect_jobs', (SELECT count(*)::integer FROM job_sources job
      WHERE job.source_ipv4 = expected.source_ipv4 AND job.state IN ('pending', 'leased', 'retry')),
    'dead_detect_jobs', (SELECT count(*)::integer FROM job_sources job
      WHERE job.source_ipv4 = expected.source_ipv4 AND job.state = 'dead'),
    'incidents', COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'incident_id', incident.incident_id::text,
      'kind', incident.kind,
      'state', incident.state,
      'version', incident.version,
      'evidence_version', incident.evidence_version,
      'signal_count', (SELECT count(*)::integer FROM sentinelflow.incident_signals signal
        WHERE signal.incident_id = incident.incident_id),
      'policies', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'policy_id', policy.policy_id::text,
        'version', policy.version,
        'incident_version', policy.incident_version,
        'state', policy.state,
        'state_revision', policy.state_revision,
        'policy_digest', policy.policy_digest::text,
        'evidence_snapshot_digest', policy.evidence_snapshot_digest::text
      ) ORDER BY policy.policy_id, policy.version)
      FROM sentinelflow.policy_proposals policy
      WHERE policy.incident_id = incident.incident_id
        AND policy.incident_version = incident.evidence_version), '[]'::jsonb)
    ) ORDER BY incident.incident_id)
    FROM sentinelflow.incidents incident
    WHERE incident.service_label = 'demo-app'
      AND host(incident.source_ip) = expected.source_ipv4), '[]'::jsonb)
  ) ORDER BY expected.source_ipv4) FROM expected)
)::text
) TO STDOUT;
COMMIT;
`;

const DETECTION_DIAGNOSTIC_SQL = `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, sentinelflow;
COPY (
WITH expected(source_ipv4) AS (
  VALUES ('203.0.113.20'), ('203.0.113.21'), ('203.0.113.22'), ('203.0.113.23'), ('203.0.113.24')
), summaries AS (
  SELECT expected.source_ipv4,
    evaluation.evaluation_time,
    CASE WHEN evaluation.evaluation_time IS NULL THEN NULL ELSE
      sentinelflow.detection_coverage_start('gateway', 'demo-app', evaluation.evaluation_time)
    END AS gateway_coverage_start,
    CASE WHEN evaluation.evaluation_time IS NULL THEN NULL ELSE
      sentinelflow.detection_coverage_start('auth', 'demo-app', evaluation.evaluation_time)
    END AS auth_coverage_start
  FROM expected
  LEFT JOIN LATERAL (
    SELECT date_trunc('milliseconds', max(event.completed_at)) AS evaluation_time
    FROM sentinelflow.gateway_events event
    WHERE host(event.source_ip) = expected.source_ipv4
  ) evaluation ON true
)
SELECT jsonb_build_object(
  'schema_version', '${DETECTION_DIAGNOSTIC_SCHEMA}',
  'sources', jsonb_agg(jsonb_build_object(
    'source_ipv4', source.source_ipv4,
    'gateway_event_count', (SELECT count(*)::integer FROM sentinelflow.gateway_events event
      WHERE host(event.source_ip) = source.source_ipv4),
    'auth_event_count', (SELECT count(*)::integer FROM sentinelflow.auth_events event
      WHERE host(event.source_ip) = source.source_ipv4),
    'suspicious_path_ids', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'id', path.id, 'count', path.count) ORDER BY path.id)
      FROM (SELECT event.suspicious_path_id AS id, count(*)::integer AS count
        FROM sentinelflow.gateway_events event
        WHERE host(event.source_ip) = source.source_ipv4 AND event.suspicious_path_id <> 'none'
        GROUP BY event.suspicious_path_id) path), '[]'::jsonb),
    'gateway_batch_shapes', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'event_count', batch_summary.event_count,
        'has_exact_coverage', batch_summary.has_exact_coverage,
        'count', batch_summary.count)
        ORDER BY batch_summary.event_count, batch_summary.has_exact_coverage)
      FROM (SELECT batch.event_count, batch.has_exact_coverage, count(*)::integer AS count
        FROM (SELECT scoped.sender_id, scoped.sender_epoch, scoped.batch_id,
            (SELECT count(*)::integer FROM sentinelflow.gateway_events all_events
              WHERE all_events.sender_id = scoped.sender_id
                AND all_events.sender_epoch = scoped.sender_epoch
                AND all_events.batch_id = scoped.batch_id) AS event_count,
            EXISTS (SELECT 1 FROM sentinelflow.source_coverage_attestations coverage
              WHERE coverage.sender_id = scoped.sender_id AND coverage.endpoint_kind = 'gateway'
                AND coverage.sender_epoch = scoped.sender_epoch
                AND coverage.covered_through_batch_id = scoped.batch_id
                AND coverage.trust_state = 'trusted') AS has_exact_coverage
          FROM (SELECT DISTINCT event.sender_id, event.sender_epoch, event.batch_id
            FROM sentinelflow.gateway_events event
            WHERE host(event.source_ip) = source.source_ipv4) scoped
        ) batch
        GROUP BY batch.event_count, batch.has_exact_coverage
      ) batch_summary), '[]'::jsonb),
    'detect_outbox', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'aggregate_type', job_summary.aggregate_type, 'state', job_summary.state,
        'attempts', job_summary.attempts, 'max_attempts', job_summary.max_attempts,
        'last_error_code', job_summary.last_error_code, 'count', job_summary.count)
        ORDER BY job_summary.aggregate_type, job_summary.state, job_summary.attempts,
          job_summary.last_error_code NULLS FIRST)
      FROM (SELECT job.aggregate_type::text, job.state, job.attempts, job.max_attempts,
          job.last_error_code::text, count(*)::integer AS count
        FROM sentinelflow.outbox_jobs job
        WHERE job.kind = 'detect' AND (
          (job.aggregate_type = 'ingest_batch' AND (
            EXISTS (SELECT 1 FROM sentinelflow.gateway_events event
              WHERE event.batch_id = job.aggregate_id AND host(event.source_ip) = source.source_ipv4)
            OR EXISTS (SELECT 1 FROM sentinelflow.auth_events event
              WHERE event.batch_id = job.aggregate_id AND host(event.source_ip) = source.source_ipv4)
          )) OR (job.aggregate_type = 'auth_binding' AND EXISTS (
            SELECT 1 FROM sentinelflow.auth_events event
            WHERE event.event_id = job.aggregate_id AND host(event.source_ip) = source.source_ipv4
          )))
        GROUP BY job.aggregate_type, job.state, job.attempts, job.max_attempts, job.last_error_code
      ) job_summary), '[]'::jsonb),
    'signals', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'kind', signal_summary.kind, 'source_health_status', signal_summary.source_health_status,
        'count', signal_summary.count) ORDER BY signal_summary.kind, signal_summary.source_health_status)
      FROM (SELECT signal.kind, signal.source_health_status, count(*)::integer AS count
        FROM sentinelflow.signals signal WHERE host(signal.source_ip) = source.source_ipv4
        GROUP BY signal.kind, signal.source_health_status) signal_summary), '[]'::jsonb),
    'incidents', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'kind', incident_summary.kind, 'state', incident_summary.state, 'count', incident_summary.count)
        ORDER BY incident_summary.kind, incident_summary.state)
      FROM (SELECT incident.kind, incident.state, count(*)::integer AS count
        FROM sentinelflow.incidents incident WHERE host(incident.source_ip) = source.source_ipv4
        GROUP BY incident.kind, incident.state) incident_summary), '[]'::jsonb),
    'pipeline_incidents', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'incident_id', pipeline_incident.incident_id::text,
        'kind', pipeline_incident.kind,
        'state', pipeline_incident.state,
        'version', pipeline_incident.version,
        'evidence_version', pipeline_incident.evidence_version,
        'analyze_outbox', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'job_id', analyze_job.job_id::text,
            'aggregate_version', analyze_job.aggregate_version,
            'state', analyze_job.state,
            'attempts', analyze_job.attempts,
            'max_attempts', analyze_job.max_attempts,
            'last_error_code', analyze_job.last_error_code::text
          ) ORDER BY analyze_job.job_id)
          FROM (SELECT job.job_id, job.aggregate_version, job.state, job.attempts,
              job.max_attempts, job.last_error_code
            FROM sentinelflow.outbox_jobs job
            WHERE job.kind = 'analyze' AND job.aggregate_type = 'incident'
              AND job.aggregate_id = pipeline_incident.incident_id
            ORDER BY job.job_id LIMIT 16) analyze_job), '[]'::jsonb),
        'analysis_attempts', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'analysis_id', analysis_attempt.analysis_id::text,
            'incident_version', analysis_attempt.incident_version,
            'outbox_attempt', analysis_attempt.outbox_attempt,
            'claim_state', analysis_attempt.claim_state,
            'claim_failure_code', analysis_attempt.claim_failure_code,
            'result_state', analysis_attempt.result_state,
            'result_failure_code', analysis_attempt.result_failure_code
          ) ORDER BY analysis_attempt.incident_version, analysis_attempt.analysis_id)
          FROM (SELECT claim.analysis_id, claim.incident_version, claim.outbox_attempt,
              claim.state AS claim_state, claim.no_call_code::text AS claim_failure_code,
              result.result_state, result.failure_reason AS result_failure_code
            FROM sentinelflow.analysis_attempt_claims claim
            LEFT JOIN sentinelflow.analysis_attempt_results result USING (analysis_id)
            WHERE claim.incident_id = pipeline_incident.incident_id
            ORDER BY claim.incident_version, claim.analysis_id LIMIT 16) analysis_attempt), '[]'::jsonb),
        'validate_outbox', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'job_id', validate_job.job_id::text,
            'aggregate_version', validate_job.aggregate_version,
            'state', validate_job.state,
            'attempts', validate_job.attempts,
            'max_attempts', validate_job.max_attempts,
            'last_error_code', validate_job.last_error_code::text
          ) ORDER BY validate_job.job_id)
          FROM (SELECT job.job_id, job.aggregate_version, job.state, job.attempts,
              job.max_attempts, job.last_error_code
            FROM sentinelflow.outbox_jobs job
            JOIN sentinelflow.analysis_attempt_claims claim ON claim.analysis_id = job.aggregate_id
            WHERE job.kind = 'validate' AND job.aggregate_type = 'analysis_staging'
              AND claim.incident_id = pipeline_incident.incident_id
            ORDER BY job.job_id LIMIT 16) validate_job), '[]'::jsonb),
        'validation_attempts', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'validation_attempt_id', validation_attempt.validation_attempt_id::text,
            'incident_version', validation_attempt.incident_version,
            'outbox_attempt', validation_attempt.outbox_attempt,
            'claim_state', validation_attempt.claim_state,
            'claim_failure_code', validation_attempt.claim_failure_code,
            'result_state', validation_attempt.result_state,
            'result_failure_code', validation_attempt.result_failure_code,
            'failed_gate', validation_attempt.failed_gate
          ) ORDER BY validation_attempt.incident_version, validation_attempt.validation_attempt_id)
          FROM (SELECT claim.validation_attempt_id, claim.incident_version, claim.outbox_attempt,
              claim.state AS claim_state, claim.failure_code::text AS claim_failure_code,
              result.result_state, result.failure_code::text AS result_failure_code,
              result.failed_gate
            FROM sentinelflow.validation_attempt_claims claim
            LEFT JOIN sentinelflow.validation_attempt_results result USING (validation_attempt_id)
            WHERE claim.incident_id = pipeline_incident.incident_id
            ORDER BY claim.incident_version, claim.validation_attempt_id LIMIT 16) validation_attempt), '[]'::jsonb),
        'policies', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'policy_id', pipeline_policy.policy_id::text,
            'version', pipeline_policy.version,
            'incident_version', pipeline_policy.incident_version,
            'state', pipeline_policy.state,
            'state_revision', pipeline_policy.state_revision,
            'validation_snapshots', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                'validation_snapshot_id', snapshot.validation_snapshot_id::text,
                'state', snapshot.state,
                'failure_code', snapshot.failure_code::text,
                'gates', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                    'order', gate.gate_order,
                    'name', gate.gate_name,
                    'passed', gate.passed,
                    'result_code', gate.result_code::text
                  ) ORDER BY gate.gate_order)
                  FROM (SELECT gate_order, gate_name, passed, result_code
                    FROM sentinelflow.validation_gates
                    WHERE validation_snapshot_id = snapshot.validation_snapshot_id
                    ORDER BY gate_order LIMIT 6) gate), '[]'::jsonb)
              ) ORDER BY snapshot.validation_snapshot_id)
              FROM (SELECT validation_snapshot_id, state, failure_code
                FROM sentinelflow.validation_snapshots
                WHERE policy_id = pipeline_policy.policy_id AND policy_version = pipeline_policy.version
                ORDER BY validation_snapshot_id LIMIT 16) snapshot), '[]'::jsonb)
          ) ORDER BY pipeline_policy.policy_id, pipeline_policy.version)
          FROM (SELECT policy_id, version, incident_version, state, state_revision
            FROM sentinelflow.policy_proposals
            WHERE incident_id = pipeline_incident.incident_id
            ORDER BY policy_id, version LIMIT 16) pipeline_policy), '[]'::jsonb)
      ) ORDER BY pipeline_incident.incident_id)
      FROM (SELECT incident_id, kind, state, version, evidence_version
        FROM sentinelflow.incidents
        WHERE service_label = 'demo-app' AND host(source_ip) = source.source_ipv4
        ORDER BY incident_id LIMIT 16) pipeline_incident), '[]'::jsonb),
    'evaluation_time', CASE WHEN source.evaluation_time IS NULL THEN NULL ELSE
      to_char(source.evaluation_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'gateway_coverage_start', CASE WHEN source.gateway_coverage_start IS NULL THEN NULL ELSE
      to_char(source.gateway_coverage_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'auth_coverage_start', CASE WHEN source.auth_coverage_start IS NULL THEN NULL ELSE
      to_char(source.auth_coverage_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'exact_gateway_coverage_batch_count', (SELECT count(DISTINCT event.batch_id)::integer
      FROM sentinelflow.gateway_events event
      JOIN sentinelflow.source_coverage_attestations coverage
        ON coverage.sender_id = event.sender_id AND coverage.endpoint_kind = 'gateway'
       AND coverage.sender_epoch = event.sender_epoch
       AND coverage.covered_through_batch_id = event.batch_id AND coverage.trust_state = 'trusted'
      WHERE host(event.source_ip) = source.source_ipv4)
  ) ORDER BY source.source_ipv4)
)::text
FROM summaries source
) TO STDOUT;
COMMIT;
`;

// `action_id` is a psql value supplied only after the private demo state has
// been structurally validated.  This is deliberately a narrow, read-only
// projection for an expiry convergence failure, not a general audit export.
const EXPIRY_DIAGNOSTIC_SQL = `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog, sentinelflow;
COPY (
WITH selected_action AS (
  SELECT action.*
  FROM sentinelflow.enforcement_actions action
  WHERE action.action_id = :'action_id'::uuid
), result_rows AS (
  SELECT result.*, bounds.readback_started_at, bounds.readback_completed_at
  FROM sentinelflow.execution_results result
  JOIN selected_action action ON action.action_id = result.action_id
  LEFT JOIN sentinelflow.execution_result_readback_bounds_000034 bounds USING (result_id)
  ORDER BY result.persisted_at DESC, result.result_id DESC
  LIMIT ${EXPIRY_DIAGNOSTIC_MAX_RESULTS}
), schedule_rows AS (
  SELECT schedule.*, source.result_digest AS source_result_digest_bound
  FROM sentinelflow.lifecycle_inspection_schedules_000026 schedule
  JOIN selected_action action ON action.action_id = schedule.action_id
  JOIN sentinelflow.execution_results source ON source.result_id = schedule.source_result_id
  ORDER BY schedule.updated_at DESC, schedule.schedule_id DESC
  LIMIT ${EXPIRY_DIAGNOSTIC_MAX_SCHEDULES}
), audit_rows AS (
  SELECT audit.*
  FROM sentinelflow.audit_events audit
  JOIN selected_action action ON action.action_id = audit.enforcement_action_id
  ORDER BY audit.recorded_at DESC, audit.sequence DESC
  LIMIT ${EXPIRY_DIAGNOSTIC_MAX_AUDIT}
)
SELECT jsonb_build_object(
  'schema_version', '${EXPIRY_DIAGNOSTIC_SCHEMA}',
  'action', (SELECT jsonb_build_object(
    'target_ipv4', host(action.target_ipv4), 'state', action.state, 'version', action.version,
    'queued_at', CASE WHEN action.queued_at IS NULL THEN NULL ELSE to_char(action.queued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'applied_at', CASE WHEN action.applied_at IS NULL THEN NULL ELSE to_char(action.applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'expected_expires_at', CASE WHEN action.expected_expires_at IS NULL THEN NULL ELSE to_char(action.expected_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'finished_at', CASE WHEN action.finished_at IS NULL THEN NULL ELSE to_char(action.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'updated_at', to_char(action.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) FROM selected_action action),
  'expiry_bounds', (SELECT jsonb_build_object(
    'source_result_digest', source.result_digest::text,
    'expires_not_before', to_char(bounds.expires_not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'expires_not_after', to_char(bounds.expires_not_after AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) FROM sentinelflow.enforcement_expiry_bounds_000034 bounds
    JOIN sentinelflow.execution_results source ON source.result_id = bounds.source_result_id
    JOIN selected_action action ON action.action_id = bounds.action_id),
  'results', COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'schema_version', result.schema_version, 'operation', result.operation,
    'classification', result.classification, 'readback_state', result.readback_state,
    'remaining_ttl_seconds', result.remaining_ttl_seconds,
    'started_at', to_char(result.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'completed_at', to_char(result.completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'persisted_at', to_char(result.persisted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'readback_started_at', CASE WHEN result.readback_started_at IS NULL THEN NULL ELSE to_char(result.readback_started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'readback_completed_at', CASE WHEN result.readback_completed_at IS NULL THEN NULL ELSE to_char(result.readback_completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'result_digest', result.result_digest::text
  ) ORDER BY result.persisted_at DESC, result.result_id DESC) FROM result_rows result), '[]'::jsonb),
  'schedules', COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'purpose', schedule.purpose, 'state', schedule.state,
    'due_at', to_char(schedule.due_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'attempts', schedule.attempts, 'last_error_code', schedule.last_error_code::text,
    'last_error_digest', schedule.last_error_digest::text,
    'source_result_digest', schedule.source_result_digest_bound::text,
    'updated_at', to_char(schedule.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) ORDER BY schedule.updated_at DESC, schedule.schedule_id DESC) FROM schedule_rows schedule), '[]'::jsonb),
  'audit', COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'action', audit.action::text, 'outcome', audit.outcome,
    'primary_digest', audit.primary_digest::text, 'secondary_digest', audit.secondary_digest::text,
    'recorded_at', to_char(audit.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) ORDER BY audit.recorded_at DESC, audit.sequence DESC) FROM audit_rows audit), '[]'::jsonb)
)::text
) TO STDOUT;
COMMIT;
`;

async function readNDJSON(filename, label) {
  let source;
  try {
    source = await readFile(filename, 'utf8');
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  invariant(Buffer.byteLength(source, 'utf8') > 0 && Buffer.byteLength(source, 'utf8') <= 4 * JSON_LIMIT,
    `${label} size is invalid`);
  const lines = source.split('\n').filter((line) => line !== '');
  invariant(lines.length > 0 && lines.length <= 16, `${label} row count is invalid`);
  return lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`${label} is invalid`);
    }
  });
}

export function validateEvidenceChainRows(rows, stateValue, phase) {
  const state = validateDemoState(stateValue, true);
  string(phase, /^(?:active|revoked|expired)$/, 'E2E evidence phase');
  invariant((phase === 'active' && state.mode === 'release_expiry') ||
    (phase === 'revoked' && state.mode === 'fast_revoke') ||
    (phase === 'expired' && state.mode === 'release_expiry'),
  'E2E evidence phase does not match the mode');
  const expectedSelectors = state.mode === 'fast_revoke' ? ['add', 'revoke'] : ['add'];
  invariant(Array.isArray(rows) && rows.length === expectedSelectors.length,
    'E2E evidence chain row count is invalid');
  const bySelector = new Map();
  for (const raw of rows) {
    const row = exactRecord(raw, 'E2E evidence chain row', [
      'schema_version', 'selector', 'job', 'operation', 'action', 'authorization', 'decision',
      'challenge', 'reason', 'revocation', 'capability', 'result', 'application', 'audit',
    ]);
    invariant(row.schema_version === 'sentinelflow-demo-e2e-evidence-chain-v1', 'E2E evidence chain schema drifted');
    string(row.selector, /^(?:add|revoke)$/, 'E2E evidence selector');
    invariant(!bySelector.has(row.selector), 'E2E evidence selector is duplicated');
    bySelector.set(row.selector, row);
  }
  exactStrings([...bySelector.keys()], expectedSelectors, 'E2E evidence selectors');

  const specifications = [[
    'add', state.action, 'add', state.action.add_outbox_job_id,
    state.action.add_result_id, state.action.add_result_digest, 'active',
    state.action.action_version, state.action.add_authorization_digest,
  ]];
  if (state.mode === 'fast_revoke') {
    specifications.push([
      'revoke', state.action, 'revoke', state.revocation.outbox_job_id,
      state.revocation.result_id, state.revocation.result_digest, 'revoked',
      state.revocation.action_version_after, state.revocation.authorization_digest,
    ]);
  }
  let addAuthorizationID;
  for (const [selector, evidence, operationName, jobID, resultID, resultDigest, resultingState,
    resultingVersion, authorizationDigest] of specifications) {
    const row = bySelector.get(selector);
    const job = exactRecord(row.job, `${selector} job`, [
      'job_id', 'kind', 'operation', 'state', 'aggregate_type', 'aggregate_id', 'aggregate_version',
    ]);
    const operation = exactRecord(row.operation, `${selector} operation`, [
      'job_id', 'operation', 'action_id', 'policy_id', 'policy_version', 'target_ipv4',
      'artifact_digest', 'original_add_digest', 'evidence_snapshot_digest', 'validation_snapshot_id',
      'validation_snapshot_digest', 'authorization_id', 'authorization_digest', 'actor_id',
      'reason_digest', 'owned_schema_digest',
    ]);
    const action = exactRecord(row.action, `${selector} action`, [
      'action_id', 'policy_id', 'policy_version', 'add_authorization_id', 'target_ipv4',
      'canonical_artifact_digest', 'state', 'version',
    ]);
    const authorization = exactRecord(row.authorization, `${selector} authorization`, [
      'authorization_id', 'authorization_kind', 'action_id', 'policy_id', 'policy_version',
      'decision_id', 'decision', 'target_ipv4', 'policy_digest', 'generated_artifact_digest',
      'canonical_artifact_digest', 'original_add_digest', 'evidence_snapshot_digest',
      'validation_snapshot_digest', 'actor_id', 'reason_digest', 'decision_nonce_digest',
      'idempotency_key_digest', 'authorization_digest',
    ]);
    const decision = exactRecord(row.decision, `${selector} decision`, [
      'decision_id', 'challenge_id', 'operation', 'decision', 'resource_type', 'resource_id',
      'resource_version', 'policy_id', 'policy_version', 'action_id', 'target_ipv4', 'policy_digest',
      'evidence_snapshot_digest', 'generated_artifact_digest', 'canonical_artifact_digest',
      'original_add_digest', 'validation_snapshot_digest', 'actor_id', 'reason_id', 'reason_digest',
      'challenge_nonce_digest', 'idempotency_key_digest',
    ]);
    const challenge = exactRecord(row.challenge, `${selector} challenge`, [
      'challenge_id', 'operation', 'resource_type', 'resource_id', 'resource_version', 'policy_id',
      'policy_version', 'action_id', 'target_ipv4', 'policy_digest', 'evidence_snapshot_digest',
      'generated_artifact_digest', 'canonical_artifact_digest', 'original_add_digest',
      'validation_snapshot_digest', 'actor_id', 'nonce_digest', 'idempotency_key_digest',
      'consumed_decision_id',
    ]);
    const reason = exactRecord(row.reason, `${selector} reason`, ['reason_id', 'operation', 'actor_id', 'reason_digest']);
    const capability = exactRecord(row.capability, `${selector} capability`, [
      'capability_id', 'job_id', 'operation', 'action_id', 'policy_id', 'policy_version',
      'target_ipv4', 'artifact_digest', 'original_add_digest', 'evidence_snapshot_digest',
      'validation_snapshot_digest', 'authorization_digest', 'actor_id', 'reason_digest',
      'owned_schema_digest', 'capability_digest', 'signature_bytes', 'consumed',
    ]);
    const result = exactRecord(row.result, `${selector} result`, [
      'result_id', 'capability_id', 'capability_digest', 'operation', 'action_id', 'artifact_digest',
      'target_ipv4', 'classification', 'readback_state', 'journal_sequence', 'error_code',
      'owned_schema_digest', 'result_digest', 'signature_bytes',
    ]);
    const application = exactRecord(row.application, `${selector} application`, [
      'result_id', 'result_digest', 'action_id', 'operation', 'classification', 'resulting_state',
      'resulting_action_version',
    ]);
    const audit = exactRecord(row.audit, `${selector} audit`, [
      'authorization_count', 'authorization_event_id', 'authorization_primary_digest',
      'queue_count', 'terminal_count',
    ]);

    // HIL records bind the original generated command as well as the canonical
    // artifact. Only the canonical artifact is allowed to cross the dispatch
    // boundary into an executor capability or result.
    const canonicalArtifactDigest = operationName === 'add' ?
      evidence.canonical_artifact_digest : state.revocation.revoke_artifact_digest;
    const generatedArtifactDigest = operationName === 'add' ?
      evidence.generated_artifact_digest : canonicalArtifactDigest;
    const originalAddDigest = operationName === 'add' ? null : evidence.canonical_artifact_digest;
    const decisionOperation = operationName === 'add' ? 'approve' : 'revoke';
    const decisionValue = operationName === 'add' ? 'approved' : 'revoked';
    const resourceType = operationName === 'add' ? 'policy' : 'enforcement_action';
    const resourceID = operationName === 'add' ? evidence.policy_id : evidence.action_id;
    const resourceVersion = operationName === 'add' ? evidence.policy_version : evidence.action_version;
    const expectedClassification = operationName === 'add' ? ['applied', 'recovered_active'] : ['revoked'];
    const expectedReadback = operationName === 'add' ? 'active' : 'absent';

    invariant(job.job_id === jobID && job.kind === `dispatch_${operationName}` && job.operation === operationName &&
      job.state === 'completed' && job.aggregate_type === 'enforcement_action' &&
      job.aggregate_id === evidence.action_id, `${selector} outbox binding is invalid`);
    invariant(operation.job_id === job.job_id && operation.operation === operationName &&
      operation.action_id === evidence.action_id && operation.policy_id === evidence.policy_id &&
      operation.policy_version === evidence.policy_version && operation.target_ipv4 === evidence.target_ipv4 &&
      operation.artifact_digest === canonicalArtifactDigest && operation.original_add_digest === originalAddDigest &&
      operation.authorization_digest === authorizationDigest, `${selector} dispatch operation binding is invalid`);
    invariant(authorization.authorization_id === operation.authorization_id &&
      authorization.authorization_kind === operationName && authorization.action_id === evidence.action_id &&
      authorization.decision === (operationName === 'add' ? 'approve' : 'revoke') &&
      authorization.authorization_digest === authorizationDigest,
    `${selector} authorization binding is invalid`);
    invariant(decision.decision_id === authorization.decision_id && decision.challenge_id === challenge.challenge_id &&
      decision.operation === decisionOperation && decision.decision === decisionValue &&
      decision.resource_type === resourceType && decision.resource_id === resourceID &&
      decision.resource_version === resourceVersion && decision.action_id === (operationName === 'add' ? null : evidence.action_id),
    `${selector} decision binding is invalid`);
    invariant(challenge.operation === decisionOperation && challenge.resource_type === resourceType &&
      challenge.resource_id === resourceID && challenge.resource_version === resourceVersion &&
      challenge.action_id === (operationName === 'add' ? null : evidence.action_id) &&
      challenge.consumed_decision_id === decision.decision_id,
    `${selector} challenge binding is invalid`);
    invariant(operation.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
      operation.validation_snapshot_id === evidence.validation_snapshot_id &&
      operation.validation_snapshot_digest === evidence.validation_snapshot_digest &&
      operation.reason_digest === authorization.reason_digest && DIGEST.test(operation.owned_schema_digest),
    `${selector} dispatch evidence binding is invalid`);
    invariant(authorization.policy_id === evidence.policy_id && authorization.policy_version === evidence.policy_version &&
      authorization.target_ipv4 === evidence.target_ipv4 && authorization.policy_digest === evidence.policy_digest &&
      authorization.generated_artifact_digest === generatedArtifactDigest &&
      authorization.canonical_artifact_digest === canonicalArtifactDigest &&
      authorization.original_add_digest === originalAddDigest &&
      authorization.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
      authorization.validation_snapshot_digest === evidence.validation_snapshot_digest &&
      authorization.actor_id === operation.actor_id && authorization.reason_digest === operation.reason_digest &&
      DIGEST.test(authorization.decision_nonce_digest) && DIGEST.test(authorization.idempotency_key_digest),
    `${selector} authorization evidence binding is invalid`);
    invariant(decision.policy_id === evidence.policy_id && decision.policy_version === evidence.policy_version &&
      decision.target_ipv4 === evidence.target_ipv4 && decision.policy_digest === evidence.policy_digest &&
      decision.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
      decision.generated_artifact_digest === generatedArtifactDigest &&
      decision.canonical_artifact_digest === canonicalArtifactDigest &&
      decision.original_add_digest === originalAddDigest &&
      decision.validation_snapshot_digest === evidence.validation_snapshot_digest &&
      decision.actor_id === authorization.actor_id && decision.reason_id === reason.reason_id &&
      decision.reason_digest === authorization.reason_digest &&
      decision.challenge_nonce_digest === authorization.decision_nonce_digest &&
      decision.idempotency_key_digest === authorization.idempotency_key_digest,
    `${selector} decision evidence binding is invalid`);
    invariant(challenge.policy_id === evidence.policy_id && challenge.policy_version === evidence.policy_version &&
      challenge.target_ipv4 === evidence.target_ipv4 && challenge.policy_digest === evidence.policy_digest &&
      challenge.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
      challenge.generated_artifact_digest === generatedArtifactDigest &&
      challenge.canonical_artifact_digest === canonicalArtifactDigest &&
      challenge.original_add_digest === originalAddDigest &&
      challenge.validation_snapshot_digest === evidence.validation_snapshot_digest &&
      challenge.actor_id === authorization.actor_id && challenge.nonce_digest === authorization.decision_nonce_digest &&
      challenge.idempotency_key_digest === authorization.idempotency_key_digest,
    `${selector} challenge evidence binding is invalid`);
    invariant(reason.operation === decisionOperation && reason.actor_id === authorization.actor_id &&
      reason.reason_digest === authorization.reason_digest, `${selector} reason binding is invalid`);

    invariant(
      job.job_id === jobID && job.kind === `dispatch_${operationName}` && job.operation === operationName &&
        job.state === 'completed' && job.aggregate_type === 'enforcement_action' &&
        job.aggregate_id === evidence.action_id && Number.isSafeInteger(job.aggregate_version) && job.aggregate_version >= 1 &&
      operation.job_id === job.job_id && operation.operation === operationName &&
        operation.action_id === evidence.action_id && operation.policy_id === evidence.policy_id &&
        operation.policy_version === evidence.policy_version && operation.target_ipv4 === evidence.target_ipv4 &&
        operation.artifact_digest === canonicalArtifactDigest && operation.original_add_digest === originalAddDigest &&
        operation.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
        operation.validation_snapshot_id === evidence.validation_snapshot_id &&
        operation.validation_snapshot_digest === evidence.validation_snapshot_digest &&
        operation.authorization_digest === authorizationDigest && DIGEST.test(operation.owned_schema_digest) &&
      action.action_id === evidence.action_id && action.policy_id === evidence.policy_id &&
        action.policy_version === evidence.policy_version && action.target_ipv4 === evidence.target_ipv4 &&
        action.canonical_artifact_digest === evidence.canonical_artifact_digest &&
      authorization.authorization_id === operation.authorization_id &&
        authorization.authorization_kind === operationName && authorization.action_id === evidence.action_id &&
        authorization.policy_id === evidence.policy_id && authorization.policy_version === evidence.policy_version &&
        authorization.decision === (operationName === 'add' ? 'approve' : 'revoke') &&
        authorization.target_ipv4 === evidence.target_ipv4 && authorization.policy_digest === evidence.policy_digest &&
        authorization.generated_artifact_digest === generatedArtifactDigest &&
        authorization.canonical_artifact_digest === canonicalArtifactDigest &&
        authorization.original_add_digest === originalAddDigest &&
        authorization.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
        authorization.validation_snapshot_digest === evidence.validation_snapshot_digest &&
        authorization.actor_id === operation.actor_id && authorization.reason_digest === operation.reason_digest &&
        authorization.authorization_digest === authorizationDigest && DIGEST.test(authorization.decision_nonce_digest) &&
        DIGEST.test(authorization.idempotency_key_digest) &&
      decision.decision_id === authorization.decision_id && decision.challenge_id === challenge.challenge_id &&
        decision.operation === decisionOperation && decision.decision === decisionValue &&
        decision.resource_type === resourceType && decision.resource_id === resourceID &&
        decision.resource_version === resourceVersion && decision.policy_id === evidence.policy_id &&
        decision.policy_version === evidence.policy_version &&
        decision.action_id === (operationName === 'add' ? null : evidence.action_id) &&
        decision.target_ipv4 === evidence.target_ipv4 && decision.policy_digest === evidence.policy_digest &&
        decision.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
        decision.generated_artifact_digest === generatedArtifactDigest &&
        decision.canonical_artifact_digest === canonicalArtifactDigest &&
        decision.original_add_digest === originalAddDigest &&
        decision.validation_snapshot_digest === evidence.validation_snapshot_digest &&
        decision.actor_id === authorization.actor_id && decision.reason_id === reason.reason_id &&
        decision.reason_digest === authorization.reason_digest &&
        decision.challenge_nonce_digest === authorization.decision_nonce_digest &&
        decision.idempotency_key_digest === authorization.idempotency_key_digest &&
      challenge.operation === decisionOperation && challenge.resource_type === resourceType &&
        challenge.resource_id === resourceID && challenge.resource_version === resourceVersion &&
        challenge.policy_id === evidence.policy_id && challenge.policy_version === evidence.policy_version &&
        challenge.action_id === (operationName === 'add' ? null : evidence.action_id) &&
        challenge.target_ipv4 === evidence.target_ipv4 && challenge.policy_digest === evidence.policy_digest &&
        challenge.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
        challenge.generated_artifact_digest === generatedArtifactDigest &&
        challenge.canonical_artifact_digest === canonicalArtifactDigest &&
        challenge.original_add_digest === originalAddDigest &&
        challenge.validation_snapshot_digest === evidence.validation_snapshot_digest &&
        challenge.actor_id === authorization.actor_id && challenge.nonce_digest === authorization.decision_nonce_digest &&
        challenge.idempotency_key_digest === authorization.idempotency_key_digest &&
        challenge.consumed_decision_id === decision.decision_id &&
      reason.operation === decisionOperation && reason.actor_id === authorization.actor_id &&
        reason.reason_digest === authorization.reason_digest,
      `${selector} HIL and dispatch chain binding is invalid`,
    );

    if (operationName === 'add') {
      invariant(row.revocation === null && action.add_authorization_id === authorization.authorization_id,
        `${selector} add authorization link is invalid`);
      invariant(
        (phase === 'revoked' && action.state === 'revoked' &&
          action.version === state.revocation.action_version_after) ||
          (phase === 'active' && action.state === 'active' &&
            action.version === evidence.action_version) ||
          (phase === 'expired' && action.state === 'expired' &&
            action.version === evidence.action_version + 1),
        `${selector} current action descendant is invalid`,
      );
      addAuthorizationID = authorization.authorization_id;
    } else {
      const revocation = exactRecord(row.revocation, 'revoke operation', [
        'revocation_id', 'action_id', 'authorization_id', 'decision_id', 'actor_id', 'reason_id',
        'reason_digest', 'target_ipv4', 'original_add_digest', 'artifact_digest', 'state',
      ]);
      invariant(
        revocation.revocation_id === state.revocation.revocation_id &&
          revocation.action_id === evidence.action_id && revocation.authorization_id === authorization.authorization_id &&
          revocation.decision_id === decision.decision_id && revocation.actor_id === authorization.actor_id &&
          revocation.reason_id === reason.reason_id && revocation.reason_digest === reason.reason_digest &&
          revocation.target_ipv4 === evidence.target_ipv4 &&
          revocation.original_add_digest === evidence.canonical_artifact_digest &&
          revocation.artifact_digest === state.revocation.revoke_artifact_digest && revocation.state === 'revoked' &&
          authorization.authorization_id === state.revocation.authorization_id &&
          capability.capability_digest === state.revocation.execution_capability_digest &&
          action.add_authorization_id === addAuthorizationID,
        'revoke operation durable chain is invalid',
      );
    }

    const assertChain = () => invariant(
      capability.job_id === job.job_id && capability.operation === operationName &&
        capability.action_id === evidence.action_id && capability.policy_id === evidence.policy_id &&
        capability.policy_version === evidence.policy_version && capability.target_ipv4 === evidence.target_ipv4 &&
        capability.artifact_digest === canonicalArtifactDigest && capability.original_add_digest === originalAddDigest &&
        capability.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
        capability.validation_snapshot_digest === evidence.validation_snapshot_digest &&
        capability.authorization_digest === authorizationDigest && capability.actor_id === authorization.actor_id &&
        capability.reason_digest === authorization.reason_digest &&
        capability.owned_schema_digest === operation.owned_schema_digest && DIGEST.test(capability.capability_digest) &&
        capability.signature_bytes === 64 && capability.consumed === true &&
      result.result_id === resultID && result.capability_id === capability.capability_id &&
        result.capability_digest === capability.capability_digest && result.operation === operationName &&
        result.action_id === evidence.action_id && result.artifact_digest === canonicalArtifactDigest &&
        result.target_ipv4 === evidence.target_ipv4 && expectedClassification.includes(result.classification) &&
        result.readback_state === expectedReadback && result.error_code === 'none' &&
        result.owned_schema_digest === operation.owned_schema_digest && result.result_digest === resultDigest &&
        result.signature_bytes === 64 &&
      application.result_id === result.result_id && application.result_digest === result.result_digest &&
        application.action_id === evidence.action_id && application.operation === operationName &&
        application.classification === result.classification && application.resulting_state === resultingState &&
        application.resulting_action_version === resultingVersion &&
      audit.authorization_count === 1 && audit.queue_count === (operationName === 'add' ? 1 : 0) && audit.terminal_count === 1 &&
        UUID.test(audit.authorization_event_id) && DIGEST.test(audit.authorization_primary_digest),
      `${selector} capability, result, lifecycle, or audit chain is invalid`,
    );
    assertChain();
    if (operationName === 'add') {
      invariant(result.journal_sequence === evidence.add_journal_sequence,
        `${selector} add journal sequence drifted`);
    } else {
      invariant(result.journal_sequence === state.revocation.journal_sequence &&
        audit.authorization_event_id === state.revocation.audit_event_id &&
        audit.authorization_primary_digest === state.revocation.decision_digest,
      'revoke audit or journal binding is invalid');
    }
  }
  return true;
}

const JOURNAL_PAYLOAD_FIELDS = Object.freeze([
  'artifact_b64url', 'artifact_digest', 'capability_digest', 'capability_id',
  'capability_jcs_b64url', 'capability_signature_b64url', 'deadline', 'journal_sequence',
  'operation', 'owned_schema_digest', 'phase', 'previous_record_digest', 'received_at',
  'record_checksum', 'schema_version', 'target_ipv4', 'terminal_result_digest',
  'terminal_result_jcs_b64url', 'terminal_result_signature_b64url',
]);
const CAPABILITY_FIELDS = Object.freeze([
  'schema_version', 'capability_id', 'operation', 'job_id', 'action_id', 'policy_id',
  'policy_version', 'target_ipv4', 'artifact_digest', 'original_add_digest',
  'evidence_snapshot_digest', 'validation_snapshot_digest', 'authorization_digest', 'actor_id',
  'reason_digest', 'owned_schema_digest', 'issued_at', 'not_before', 'expires_at', 'nonce',
]);
const RESULT_V1_FIELDS = Object.freeze([
  'schema_version', 'result_id', 'capability_id', 'capability_digest', 'operation', 'action_id',
  'artifact_digest', 'target_ipv4', 'classification', 'nft_exit_class', 'readback_state',
  'element_handle', 'remaining_ttl_seconds', 'owned_schema_digest', 'started_at', 'completed_at',
  'journal_sequence', 'error_code',
]);
const RESULT_V2_FIELDS = Object.freeze([
  'schema_version', 'result_id', 'capability_id', 'capability_digest', 'operation', 'action_id',
  'artifact_digest', 'target_ipv4', 'classification', 'nft_exit_class', 'readback_state',
  'element_handle', 'remaining_ttl_seconds', 'owned_schema_digest', 'started_at', 'readback_started_at',
  'readback_completed_at', 'completed_at', 'journal_sequence', 'error_code',
]);
const JOURNAL_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function decodeBase64URL(value, minimum, maximum, label) {
  invariant(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), `${label} is invalid`);
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    throw new Error(`${label} is invalid`);
  }
  invariant(decoded.length >= minimum && decoded.length <= maximum && decoded.toString('base64url') === value,
    `${label} is invalid`);
  return decoded;
}

function parseCanonicalObject(bytes, label, fields) {
  invariant(Buffer.isBuffer(bytes) && bytes.length >= 2, `${label} is invalid`);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label} is invalid`);
  }
  const result = exactRecord(value, label, fields);
  invariant(Buffer.from(canonicalJSON(result), 'utf8').equals(bytes), `${label} is not canonical JCS`);
  return result;
}

function journalTimestamp(value, label) {
  const checked = string(value, JOURNAL_TIME, label);
  invariant(Number.isFinite(Date.parse(checked)), `${label} is invalid`);
  return checked;
}

function parseCapability(bytes, artifact, payload) {
  invariant(bytes.length <= 16_384 && artifact.length >= 1 && artifact.length <= 16_384, 'journal capability size is invalid');
  const value = parseCanonicalObject(bytes, 'journal capability', CAPABILITY_FIELDS);
  const issuedAt = journalTimestamp(value.issued_at, 'capability issued_at');
  const notBefore = journalTimestamp(value.not_before, 'capability not_before');
  const expiresAt = journalTimestamp(value.expires_at, 'capability expires_at');
  invariant(
    value.schema_version === 'execution-capability-v1' && UUID.test(value.capability_id) &&
      UUID.test(value.job_id) && UUID.test(value.action_id) && UUID.test(value.policy_id) &&
      ['add', 'revoke', 'inspect'].includes(value.operation) &&
      Number.isSafeInteger(value.policy_version) && value.policy_version >= 1 && value.policy_version <= 2_147_483_647 &&
      canonicalIPv4(value.target_ipv4) && DIGEST.test(value.artifact_digest) &&
      DIGEST.test(value.evidence_snapshot_digest) && DIGEST.test(value.validation_snapshot_digest) &&
      DIGEST.test(value.authorization_digest) && DIGEST.test(value.reason_digest) &&
      DIGEST.test(value.owned_schema_digest) && /^[a-z0-9][a-z0-9._-]{0,127}$/.test(value.actor_id) &&
      decodeBase64URL(value.nonce, 16, 16, 'capability nonce').length === 16 &&
      Date.parse(notBefore) >= Date.parse(issuedAt) && Date.parse(expiresAt) > Date.parse(notBefore) &&
      Date.parse(expiresAt) - Date.parse(issuedAt) <= 60_000 &&
      digestBytes(artifact) === value.artifact_digest && digestBytes(bytes) === payload.capability_digest &&
      value.capability_id === payload.capability_id && value.operation === payload.operation &&
      value.target_ipv4 === payload.target_ipv4 && value.artifact_digest === payload.artifact_digest &&
      value.owned_schema_digest === payload.owned_schema_digest,
    'journal capability binding is invalid',
  );
  if (value.operation === 'add') {
    invariant(value.original_add_digest === null &&
      new RegExp(`^add element inet sentinelflow blacklist_ipv4 \\{ ${value.target_ipv4.replaceAll('.', '\\.')} timeout [1-9][0-9]{0,4}[smh] \\}\\n$`).test(artifact.toString('utf8')),
    'journal add artifact is invalid');
  } else {
    invariant(DIGEST.test(value.original_add_digest), 'journal original add digest is invalid');
    if (value.operation === 'revoke') {
      invariant(artifact.toString('utf8') === `delete element inet sentinelflow blacklist_ipv4 { ${value.target_ipv4} }\n`,
        'journal revoke artifact is invalid');
    } else {
      const inspect = parseCanonicalObject(artifact, 'journal inspect artifact', [
        'schema_version', 'operation', 'action_id', 'target_ipv4', 'original_add_digest',
        'owned_schema_digest', 'purpose',
      ]);
      invariant(inspect.schema_version === 'nft-inspect-v1' && inspect.operation === 'inspect' &&
        inspect.action_id === value.action_id && inspect.target_ipv4 === value.target_ipv4 &&
        inspect.original_add_digest === value.original_add_digest &&
        inspect.owned_schema_digest === value.owned_schema_digest &&
        ['reconciliation', 'expiry_confirmation', 'operator_status'].includes(inspect.purpose),
      'journal inspect artifact binding is invalid');
    }
  }
  return value;
}

function parseResult(bytes, payload, capability, startedSequence) {
  invariant(bytes.length <= 16_384, 'journal result size is invalid');
  let raw;
  try {
    raw = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('journal result is invalid');
  }
  invariant(raw !== null && typeof raw === 'object' && !Array.isArray(raw), 'journal result is invalid');
  const fields = raw.schema_version === 'execution-result-v1' ? RESULT_V1_FIELDS
    : raw.schema_version === 'execution-result-v2' ? RESULT_V2_FIELDS : null;
  invariant(fields !== null, 'journal result schema is invalid');
  const value = parseCanonicalObject(bytes, 'journal result', fields);
  const startedAt = journalTimestamp(value.started_at, 'result started_at');
  const completedAt = journalTimestamp(value.completed_at, 'result completed_at');
  invariant(
    ['execution-result-v1', 'execution-result-v2'].includes(value.schema_version) && UUID.test(value.result_id) &&
      value.capability_id === capability.capability_id && value.capability_digest === payload.capability_digest &&
      value.operation === capability.operation && value.action_id === capability.action_id &&
      value.artifact_digest === capability.artifact_digest && value.target_ipv4 === capability.target_ipv4 &&
      value.owned_schema_digest === capability.owned_schema_digest &&
      Number.isSafeInteger(value.journal_sequence) && value.journal_sequence === startedSequence &&
      Number.isFinite(Date.parse(startedAt)) && Number.isFinite(Date.parse(completedAt)) &&
      Date.parse(completedAt) >= Date.parse(startedAt) && Date.parse(completedAt) - Date.parse(startedAt) <= 2_000 &&
      digestBytes(bytes) === payload.terminal_result_digest &&
      value.element_handle === null &&
      ['add', 'revoke', 'inspect'].includes(value.operation) &&
      ['active', 'absent', 'mismatch', 'unavailable'].includes(value.readback_state) &&
      typeof value.error_code === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value.error_code),
    'journal result binding is invalid',
  );
  if (value.schema_version === 'execution-result-v2') {
    const readbackStartedAt = journalTimestamp(value.readback_started_at, 'result readback_started_at');
    const readbackCompletedAt = journalTimestamp(value.readback_completed_at, 'result readback_completed_at');
    invariant(
      Date.parse(readbackStartedAt) >= Date.parse(startedAt) &&
        Date.parse(readbackCompletedAt) >= Date.parse(readbackStartedAt) &&
        Date.parse(readbackCompletedAt) <= Date.parse(completedAt),
      'journal result v2 read-back interval is invalid',
    );
  }
  const successful = {
    add: ['applied', 'recovered_active'], revoke: ['revoked'],
    inspect: ['inspect_active', 'inspect_absent', 'inspect_mismatch'],
  }[value.operation];
  invariant(successful.includes(value.classification) && value.error_code === 'none', 'journal contains a non-success terminal operation');
  if (['applied', 'recovered_active', 'inspect_active'].includes(value.classification)) {
    invariant(value.readback_state === 'active' && Number.isSafeInteger(value.remaining_ttl_seconds) &&
      value.remaining_ttl_seconds >= 1 && value.remaining_ttl_seconds <= 86_400,
    'journal active result is invalid');
  } else if (value.classification === 'revoked' || value.classification === 'inspect_absent') {
    invariant(value.readback_state === 'absent' && value.remaining_ttl_seconds === null,
      'journal absent result is invalid');
  }
  return value;
}

export function parseJournalBuffer(contents) {
  invariant(Buffer.isBuffer(contents) && contents.length > 0 && contents.length <= JOURNAL_LIMIT,
    'executor journal size is invalid');
  const started = new Map();
  const terminals = [];
  let offset = 0;
  let expectedSequence = 1;
  let previousPayloadDigest = null;
  while (offset < contents.length) {
    invariant(contents.length - offset >= 56, 'executor journal has a torn frame');
    const header = contents.subarray(offset, offset + 24);
    invariant(header.subarray(0, 8).equals(Buffer.from('SFJNLv1\n')) && header[8] === 1 &&
      [1, 2].includes(header[9]) && header[10] === 0 && header[11] === 0,
    'executor journal frame header is invalid');
    const sequenceBig = header.readBigUInt64BE(12);
    invariant(sequenceBig <= BigInt(Number.MAX_SAFE_INTEGER), 'executor journal sequence is invalid');
    const sequence = Number(sequenceBig);
    const payloadLength = header.readUInt32BE(20);
    invariant(sequence === expectedSequence && payloadLength >= 1 && payloadLength <= 32 * 1024,
      'executor journal frame sequence or size is invalid');
    const frameLength = 24 + payloadLength + 32;
    invariant(offset + frameLength <= contents.length, 'executor journal has a torn frame');
    const frame = contents.subarray(offset, offset + frameLength);
    const payloadBytes = frame.subarray(24, 24 + payloadLength);
    const checksum = frame.subarray(24 + payloadLength);
    invariant(createHash('sha256').update(frame.subarray(0, 24 + payloadLength)).digest().equals(checksum),
      'executor journal frame checksum is invalid');
    const payload = parseCanonicalObject(payloadBytes, 'executor journal payload', JOURNAL_PAYLOAD_FIELDS);
    const checksumPayload = { ...payload };
    delete checksumPayload.record_checksum;
    invariant(
      payload.schema_version === 'executor-journal-record-v1' && payload.journal_sequence === sequence &&
        payload.phase === (header[9] === 1 ? 'started' : 'terminal') &&
        ['add', 'revoke', 'inspect'].includes(payload.operation) && UUID.test(payload.capability_id) &&
        canonicalIPv4(payload.target_ipv4) && DIGEST.test(payload.artifact_digest) &&
        DIGEST.test(payload.capability_digest) && DIGEST.test(payload.owned_schema_digest) &&
        payload.record_checksum === digestJSON(checksumPayload) &&
        payload.previous_record_digest === previousPayloadDigest,
      'executor journal payload chain is invalid',
    );
    const receivedAt = journalTimestamp(payload.received_at, 'journal received_at');
    const deadline = journalTimestamp(payload.deadline, 'journal deadline');
    invariant(Date.parse(deadline) > Date.parse(receivedAt) && Date.parse(deadline) - Date.parse(receivedAt) <= 2_000,
      'executor journal deadline is invalid');
    const capabilityBytes = decodeBase64URL(payload.capability_jcs_b64url, 2, 16_384, 'journal capability JCS');
    const capabilitySignature = decodeBase64URL(payload.capability_signature_b64url, 64, 64, 'journal capability signature');
    const artifact = decodeBase64URL(payload.artifact_b64url, 1, 16_384, 'journal artifact');
    invariant(capabilitySignature.length === 64, 'journal capability signature is invalid');
    const capability = parseCapability(capabilityBytes, artifact, payload);
    if (header[9] === 1) {
      invariant(payload.terminal_result_digest === null && payload.terminal_result_jcs_b64url === null &&
        payload.terminal_result_signature_b64url === null && !started.has(capability.capability_id),
      'executor journal started frame is invalid');
      started.set(capability.capability_id, {
        sequence, payload, capability, capabilityBytes, artifact,
        capabilitySignature,
      });
    } else {
      const start = started.get(capability.capability_id);
      invariant(start !== undefined && start.terminal === undefined &&
        start.payload.capability_jcs_b64url === payload.capability_jcs_b64url &&
        start.payload.capability_signature_b64url === payload.capability_signature_b64url &&
        start.payload.artifact_b64url === payload.artifact_b64url &&
        start.payload.deadline === payload.deadline && start.payload.received_at === payload.received_at,
      'executor journal terminal frame has no exact started frame');
      invariant(DIGEST.test(payload.terminal_result_digest), 'journal terminal result digest is invalid');
      const resultBytes = decodeBase64URL(payload.terminal_result_jcs_b64url, 2, 16_384, 'journal result JCS');
      decodeBase64URL(payload.terminal_result_signature_b64url, 64, 64, 'journal result signature');
      const result = parseResult(resultBytes, payload, capability, start.sequence);
      start.terminal = sequence;
      terminals.push(Object.freeze({
        operation: capability.operation,
        action_id: capability.action_id,
        job_id: capability.job_id,
        capability_id: capability.capability_id,
        capability_digest: payload.capability_digest,
        authorization_digest: capability.authorization_digest,
        target_ipv4: capability.target_ipv4,
        artifact_digest: capability.artifact_digest,
        original_add_digest: capability.original_add_digest,
        started_sequence: start.sequence,
        terminal_sequence: sequence,
        result_id: result.result_id,
        result_digest: payload.terminal_result_digest,
        classification: result.classification,
        readback_state: result.readback_state,
      }));
    }
    previousPayloadDigest = digestBytes(payloadBytes);
    expectedSequence += 1;
    offset += frameLength;
  }
  invariant([...started.values()].every((item) => item.terminal !== undefined),
    'executor journal contains a started-only operation');
  const snapshot = {
    schema_version: 'sentinelflow-demo-e2e-journal-snapshot-v1',
    frame_count: expectedSequence - 1,
    terminal_operations: terminals,
    prefix_digest: digestBytes(contents),
  };
  return Object.freeze(snapshot);
}

function validateJournalSnapshotShape(value) {
  const snapshot = exactRecord(value, 'journal snapshot', [
    'schema_version', 'frame_count', 'terminal_operations', 'prefix_digest',
  ]);
  invariant(snapshot.schema_version === 'sentinelflow-demo-e2e-journal-snapshot-v1' &&
    Number.isSafeInteger(snapshot.frame_count) && snapshot.frame_count >= 2 &&
    Array.isArray(snapshot.terminal_operations) && snapshot.frame_count === snapshot.terminal_operations.length * 2 &&
    DIGEST.test(snapshot.prefix_digest), 'journal snapshot shape is invalid');
  const operations = snapshot.terminal_operations.map((raw) => exactRecord(raw, 'journal terminal operation', [
    'operation', 'action_id', 'job_id', 'capability_id', 'capability_digest', 'authorization_digest',
    'target_ipv4', 'artifact_digest', 'original_add_digest', 'started_sequence', 'terminal_sequence',
    'result_id', 'result_digest', 'classification', 'readback_state',
  ]));
  invariant(new Set(operations.map((item) => item.capability_id)).size === operations.length &&
    new Set(operations.map((item) => item.job_id)).size === operations.length,
  'journal snapshot contains duplicate authority');
  return { ...snapshot, terminal_operations: operations };
}

export function validateJournalSnapshot(value, stateValue, phase) {
  const snapshot = validateJournalSnapshotShape(value);
  const state = validateDemoState(stateValue, true);
  string(phase, /^(?:active|revoked|expired)$/, 'journal lifecycle phase');
  invariant((phase === 'active' && state.mode === 'release_expiry') ||
    (phase === 'revoked' && state.mode === 'fast_revoke') ||
    (phase === 'expired' && state.mode === 'release_expiry'),
  'journal lifecycle phase does not match the mode');
  const expected = [[
    state.action, 'add', state.action.add_outbox_job_id,
    state.action.add_result_id, state.action.add_result_digest,
    state.action.add_journal_sequence, state.action.add_authorization_digest,
  ]];
  if (state.mode === 'fast_revoke') {
    expected.push([
      state.action, 'revoke', state.revocation.outbox_job_id,
      state.revocation.result_id, state.revocation.result_digest,
      state.revocation.journal_sequence, state.revocation.authorization_digest,
    ]);
  }
  for (const [action, operation, jobID, resultID, resultDigest, journalSequence, authorizationDigest] of expected) {
    const matches = snapshot.terminal_operations.filter((item) => item.job_id === jobID);
    invariant(matches.length === 1, `journal ${operation} evidence is missing or duplicated`);
    const item = matches[0];
    invariant(item.operation === operation && item.action_id === action.action_id &&
      item.target_ipv4 === action.target_ipv4 && item.authorization_digest === authorizationDigest &&
      item.result_id === resultID && item.result_digest === resultDigest &&
      item.started_sequence === journalSequence && item.terminal_sequence > item.started_sequence &&
      item.artifact_digest === (operation === 'add' ?
        action.canonical_artifact_digest : state.revocation.revoke_artifact_digest) &&
      item.original_add_digest === (operation === 'add' ? null : action.canonical_artifact_digest),
    `journal ${operation} evidence binding is invalid`);
    if (operation === 'revoke') {
      invariant(item.capability_digest === state.revocation.execution_capability_digest,
        'journal revoke capability digest is invalid');
    }
  }
  invariant(snapshot.terminal_operations.every((item) => item.action_id === state.action.action_id &&
    item.target_ipv4 === state.action.target_ipv4), 'journal contains a foreign action');
  const adds = snapshot.terminal_operations.filter((item) => item.operation === 'add');
  invariant(adds.length === 1, 'journal contains a duplicate add operation');
  const inspections = snapshot.terminal_operations.filter((item) => item.operation === 'inspect');
  invariant(inspections.length >= 1 && inspections.every((item) =>
    item.original_add_digest === state.action.canonical_artifact_digest &&
      item.started_sequence > adds[0].terminal_sequence),
  'journal requires a same-action inspection after add');
  invariant(inspections.every((item) =>
    (item.classification === 'inspect_active' && item.readback_state === 'active') ||
      (item.classification === 'inspect_absent' && item.readback_state === 'absent')),
  'journal contains an unsuccessful or inconsistent inspection');
  const activeInspections = inspections.filter((item) => item.classification === 'inspect_active' &&
    item.readback_state === 'active');
  invariant(activeInspections.length >= 1, 'journal signed active inspection is missing');
  const absentInspections = inspections.filter((item) => item.classification === 'inspect_absent' &&
    item.readback_state === 'absent');
  const revokes = snapshot.terminal_operations.filter((item) => item.operation === 'revoke');
  const firstAbsentStartedSequence = absentInspections.length === 0 ? null :
    Math.min(...absentInspections.map((item) => item.started_sequence));
  invariant((phase === 'revoked' && revokes.length === 1 && activeInspections.length >= 1 &&
    activeInspections.every((item) => item.terminal_sequence < revokes[0].started_sequence) &&
    absentInspections.every((item) => item.started_sequence > revokes[0].terminal_sequence)) ||
    (phase === 'active' && revokes.length === 0 && absentInspections.length === 0 &&
      inspections.every((item) => item.classification === 'inspect_active')) ||
    (phase === 'expired' && revokes.length === 0 && absentInspections.length >= 1 &&
      activeInspections.length >= 1 && activeInspections.every((item) =>
        item.terminal_sequence < firstAbsentStartedSequence)),
  'journal mode-specific revoke ordering is invalid');
  const actualMutations = snapshot.terminal_operations
    .filter((item) => item.operation === 'add' || item.operation === 'revoke')
    .map((item) => `${item.operation}:${item.action_id}`)
    .sort();
  const expectedMutations = [`add:${state.action.action_id}`];
  if (state.mode === 'fast_revoke') expectedMutations.push(`revoke:${state.action.action_id}`);
  expectedMutations.sort();
  invariant(canonicalJSON(actualMutations) === canonicalJSON(expectedMutations) &&
    snapshot.terminal_operations.every((item) => ['add', 'revoke', 'inspect'].includes(item.operation)),
  'journal mutating operation multiset is invalid');
  return true;
}

export function compareJournalSnapshots(beforeValue, afterValue, stateValue, phase, beforeRaw, afterRaw) {
  const before = validateJournalSnapshotShape(beforeValue);
  const after = validateJournalSnapshotShape(afterValue);
  validateJournalSnapshot(before, stateValue, phase);
  validateJournalSnapshot(after, stateValue, phase);
  invariant(after.frame_count >= before.frame_count && after.terminal_operations.length >= before.terminal_operations.length,
    'executor journal shrank across restart');
  invariant(canonicalJSON(after.terminal_operations.slice(0, before.terminal_operations.length)) ===
    canonicalJSON(before.terminal_operations), 'executor journal prefix changed across restart');
  invariant(after.terminal_operations.slice(before.terminal_operations.length).every((item) => item.operation === 'inspect'),
    'restart appended a mutating journal operation');
  invariant(after.terminal_operations.slice(before.terminal_operations.length).every((item) =>
    item.action_id === validateDemoState(stateValue, true).action.action_id),
  'restart appended a foreign inspection');
  if (after.frame_count === before.frame_count) {
    invariant(after.prefix_digest === before.prefix_digest, 'executor journal bytes changed without append');
  }
  if (beforeRaw !== undefined || afterRaw !== undefined) {
    invariant(Buffer.isBuffer(beforeRaw) && beforeRaw.length > 0 && beforeRaw.length <= JOURNAL_LIMIT &&
      Buffer.isBuffer(afterRaw) && afterRaw.length > 0 && afterRaw.length <= JOURNAL_LIMIT,
    'executor journal raw snapshot size is invalid');
    invariant(digestBytes(beforeRaw) === before.prefix_digest && digestBytes(afterRaw) === after.prefix_digest,
      'executor journal raw snapshot digest is invalid');
    invariant(afterRaw.length >= beforeRaw.length, 'executor journal raw bytes shrank across restart');
    invariant(afterRaw.subarray(0, beforeRaw.length).equals(beforeRaw),
      'executor journal raw byte prefix changed across restart');
  }
  return true;
}

export function compareJournalBuffers(beforeRaw, afterRaw, stateValue, phase) {
  const before = parseJournalBuffer(beforeRaw);
  const after = parseJournalBuffer(afterRaw);
  return compareJournalSnapshots(before, after, stateValue, phase, beforeRaw, afterRaw);
}

function safeAPIError(status, body) {
  let code = 'invalid_response';
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed?.code === 'string' && /^[a-z_]{1,64}$/.test(parsed.code)) {
      code = parsed.code;
    }
  } catch {
    // Response bytes are intentionally not included in the diagnostic.
  }
  return new Error(`management API request failed: status=${status} code=${code}`);
}

function validateSessionProjection(value, label = 'administrator session') {
  const session = exactRecord(value, label, ['actor_id', 'session_id', 'authenticated_at', 'expires_at']);
  const authenticatedAt = timestamp(session.authenticated_at, `${label} authenticated_at`);
  const expiresAt = timestamp(session.expires_at, `${label} expires_at`);
  invariant(Date.parse(expiresAt) > Date.parse(authenticatedAt), `${label} lifetime is invalid`);
  return Object.freeze({
    actor_id: string(session.actor_id, ASCII_ID, `${label} actor_id`),
    session_id: string(session.session_id, UUID, `${label} session_id`),
    authenticated_at: authenticatedAt,
    expires_at: expiresAt,
  });
}

function setCookieValue(headers) {
  const values = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  const raw = values.length === 1 ? values[0] : headers.get('set-cookie');
  invariant(typeof raw === 'string' && raw.length <= 4096, 'management API cookie is invalid');
  const lower = raw.toLowerCase();
  invariant(
    raw.startsWith('sentinelflow_admin=') && lower.includes('; path=/') &&
      lower.includes('; httponly') && lower.includes('; samesite=strict') && !lower.includes('; secure'),
    'management API cookie attributes are invalid',
  );
  const separator = raw.indexOf(';');
  const pair = separator === -1 ? raw : raw.slice(0, separator);
  invariant(pair.length > 'sentinelflow_admin='.length, 'management API cookie payload is empty');
  return pair;
}

export async function readBoundedResponseBody(response, maximumBytes = JSON_LIMIT) {
  invariant(response !== null && typeof response === 'object' && response.body !== null &&
    typeof response.body?.getReader === 'function', 'management API response body is unavailable');
  integer(maximumBytes, 1, JSON_LIMIT, 'management API response bound');
  const declaredLength = response.headers?.get?.('content-length');
  if (declaredLength !== null && declaredLength !== undefined) {
    invariant(/^(?:0|[1-9][0-9]{0,9})$/.test(declaredLength) && Number(declaredLength) <= maximumBytes,
      'management API response exceeded its bound');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      invariant(value instanceof Uint8Array && value.length > 0, 'management API response stream is invalid');
      total += value.length;
      if (total > maximumBytes) {
        await reader.cancel().catch(() => {});
        throw new Error('management API response exceeded its bound');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  const encoded = Buffer.concat(chunks, total);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(encoded);
  } catch {
    throw new Error('management API response encoding is invalid');
  }
}

export class ManagementClient {
  constructor(baseURL, origin, limits = undefined) {
    const parsed = new URL(baseURL);
    invariant(parsed.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(parsed.hostname) && parsed.pathname === '/', 'management base URL is invalid');
    const parsedOrigin = new URL(origin);
    invariant(parsedOrigin.protocol === 'http:' && parsedOrigin.hostname === 'localhost' && parsedOrigin.pathname === '/', 'management browser origin is invalid');
    this.baseURL = parsed.toString().replace(/\/$/, '');
    this.origin = parsedOrigin.origin;
    this.cookie = '';
    this.csrf = '';
    this.session = undefined;
    if (limits === undefined) {
      this.requestTimeoutMS = API_TIMEOUT_MS;
      this.maximumResponseBytes = JSON_LIMIT;
    } else {
      const checked = exactRecord(limits, 'management client limits', ['requestTimeoutMS', 'maximumResponseBytes']);
      this.requestTimeoutMS = integer(checked.requestTimeoutMS, 25, API_TIMEOUT_MS, 'management request timeout');
      this.maximumResponseBytes = integer(checked.maximumResponseBytes, 1, JSON_LIMIT, 'management response bound');
    }
  }

  async request(pathname, options = {}) {
    invariant(/^\/api\/v1\/[A-Za-z0-9?&=._~:%/-]*$/.test(pathname), 'management API path is invalid');
    const method = options.method ?? 'GET';
    const headers = new Headers({ Accept: 'application/json' });
    if (this.cookie) {
      headers.set('Cookie', this.cookie);
    }
    let body;
    if (method === 'POST') {
      headers.set('Content-Type', 'application/json');
      headers.set('Origin', this.origin);
      if (options.csrf !== false && this.csrf) {
        headers.set('X-CSRF-Token', this.csrf);
      }
      if (options.idempotencyKey) {
        headers.set('Idempotency-Key', options.idempotencyKey);
      }
      body = JSON.stringify(options.body ?? {});
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMS);
    let response;
    let responseBody;
    try {
      response = await fetch(`${this.baseURL}${pathname}`, {
        method,
        headers,
        body,
        redirect: 'error',
        signal: controller.signal,
      });
      responseBody = await readBoundedResponseBody(response, this.maximumResponseBytes);
    } catch (error) {
      if (error instanceof Error && [
        'management API response exceeded its bound',
        'management API response encoding is invalid',
        'management API response stream is invalid',
      ].includes(error.message)) {
        throw error;
      }
      throw new Error('management API request was unavailable');
    } finally {
      clearTimeout(timer);
    }
    const expected = options.expected ?? 200;
    if (response.status !== expected) {
      if (options.acceptError === response.status) {
        return { status: response.status, body: responseBody };
      }
      throw safeAPIError(response.status, responseBody);
    }
    if (options.captureCookie) {
      const previous = this.cookie;
      this.cookie = setCookieValue(response.headers);
      if (options.requireRotation) {
        invariant(previous !== '' && this.cookie !== previous, 'privileged action did not rotate the session cookie');
      }
    }
    invariant(response.headers.get('content-type') === 'application/json; charset=utf-8', 'management API content type is invalid');
    try {
      return JSON.parse(responseBody);
    } catch {
      throw new Error('management API JSON response is invalid');
    }
  }

  async login(credentials) {
    const response = await this.request('/api/v1/session/login', {
      method: 'POST',
      body: credentials,
      captureCookie: true,
    });
    const envelope = exactRecord(response, 'login response', ['session', 'csrf_token']);
    this.csrf = string(envelope.csrf_token, CSRF, 'CSRF token');
    this.session = validateSessionProjection(envelope.session);
  }

  acceptPrivilegeRotation(envelope, label) {
    const previous = this.session;
    invariant(previous !== undefined, `${label} has no source session`);
    const next = validateSessionProjection(envelope.session, `${label} session`);
    const nextCSRF = string(envelope.csrf_token, CSRF, `${label} CSRF token`);
    invariant(
      next.actor_id === previous.actor_id && next.authenticated_at === previous.authenticated_at &&
        next.session_id !== previous.session_id && nextCSRF !== this.csrf,
      `${label} session rotation is invalid`,
    );
    this.session = next;
    this.csrf = nextCSRF;
  }
}

async function loadCredentials(filename) {
  const value = record(await readJSON(filename, 'credential file'), 'credential file');
  invariant(
    typeof value.username === 'string' && value.username.length >= 1 && value.username.length <= 128 &&
      typeof value.password === 'string' && value.password.length >= 16 && value.password.length <= 128,
    'credential file contract is invalid',
  );
  return { username: value.username, password: value.password };
}

async function sleep(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function poll(description, timeoutSeconds, operation) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await operation();
      if (result !== undefined && result !== null && result !== false) {
        return result;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  if (lastError instanceof Error && !lastError.message.includes('status=404')) {
    throw new Error(`${description} did not converge: ${lastError.message}`);
  }
  throw new Error(`${description} did not converge`);
}

async function loginClient(baseURL, origin, credentialsFile) {
  const credentials = await loadCredentials(credentialsFile);
  try {
    const client = new ManagementClient(baseURL, origin);
    await client.login(credentials);
    return client;
  } finally {
    credentials.password = '';
  }
}

async function findIncident(client, sourceIPv4, expectedKind) {
  const items = await incidentsForSource(client, sourceIPv4);
  return items.find((item) => item?.source_ip === sourceIPv4 && item?.kind === expectedKind);
}

async function incidentsForSource(client, sourceIPv4) {
  const page = record(await client.request(`/api/v1/incidents?source=${encodeURIComponent(sourceIPv4)}&limit=100`), 'incident page');
  invariant(Array.isArray(page.items), 'incident page items are invalid');
  return page.items;
}

function exactBinding(policy, operation = 'approve') {
  const validation = record(policy.latest_validation, 'policy validation');
  invariant(validation.state === 'valid' && Array.isArray(validation.gates) && validation.gates.length > 0 && validation.gates.every((gate) => gate?.passed === true), 'policy validation is not fully valid');
  return {
    operation,
    policy_version: integer(policy.version, 1, 2_147_483_647, 'policy version'),
    target_ipv4: string(policy.target_ipv4, IPV4, 'policy target'),
    ttl_seconds: integer(policy.ttl_seconds, 60, 86_400, 'policy TTL'),
    policy_digest: string(policy.policy_digest, DIGEST, 'policy digest'),
    generated_artifact_digest: string(policy.generated_artifact_digest, DIGEST, 'generated artifact digest'),
    canonical_artifact_digest: string(policy.canonical_artifact_digest, DIGEST, 'canonical artifact digest'),
    evidence_snapshot_digest: string(policy.evidence_snapshot_digest, DIGEST, 'evidence snapshot digest'),
    validation_snapshot_digest: string(validation.snapshot_digest, DIGEST, 'validation snapshot digest'),
  };
}

export async function auditForAction(client, actionID) {
  const checkedActionID = string(actionID, UUID, 'audit action ID');
  const items = [];
  const seenCursors = new Set();
  let cursor;
  let previousSequence = Number.MAX_SAFE_INTEGER;
  for (let pageNumber = 0; pageNumber < MAX_ACTION_AUDIT_PAGES; pageNumber += 1) {
    const query = `action_id=${encodeURIComponent(checkedActionID)}&limit=${AUDIT_PAGE_LIMIT}` +
      (cursor === undefined ? '' : `&cursor=${encodeURIComponent(cursor)}`);
    const page = auditPage(await client.request(`/api/v1/audit-events?${query}`), 'action audit page');
    for (const item of page.items) {
      invariant(item.sequence < previousSequence, 'action audit sequence is not strictly descending');
      previousSequence = item.sequence;
      items.push(item);
    }
    if (page.nextCursor === undefined) {
      return items;
    }
    invariant(page.items.length === AUDIT_PAGE_LIMIT, 'action audit next cursor does not bind a full page');
    invariant(page.nextCursorSequence === page.items.at(-1).sequence,
      'action audit next cursor does not bind the final sequence');
    invariant(!seenCursors.has(page.nextCursor), 'action audit cursor repeated');
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new Error('action audit pagination exceeds strict bound');
}

async function auditForPolicy(client, policyID) {
  return auditItems(await client.request(
    `/api/v1/audit-events?policy_id=${encodeURIComponent(policyID)}&limit=100`,
  ), { complete: true, policyID });
}

function auditItems(value, options = {}) {
  const page = auditPage(value, options.label ?? 'audit page', options);
  if (options.complete === true) {
    invariant(page.nextCursor === undefined, 'policy audit proof is paginated');
  }
  return page.items;
}

function auditPage(value, pageLabel, options = {}) {
  const page = exactRecord(value, 'audit page', ['items'], ['next_cursor']);
  invariant(Array.isArray(page.items) && page.items.length <= AUDIT_PAGE_LIMIT, 'audit page items are invalid');
  let nextCursor;
  let nextCursorSequence;
  if (Object.hasOwn(page, 'next_cursor')) {
    const parsedCursor = auditCursor(page.next_cursor, `${pageLabel} next cursor`);
    nextCursor = parsedCursor.value;
    nextCursorSequence = parsedCursor.sequence;
  }
  const items = page.items.map((raw, index) => {
    const label = `${pageLabel} item ${index}`;
    const item = exactRecord(raw, label, [
      'sequence', 'event_id', 'actor_type', 'actor_id', 'action', 'object_type',
      'outcome', 'occurred_at', 'recorded_at',
    ], [
      'object_id', 'incident_id', 'policy_id', 'policy_version', 'enforcement_action_id',
      'trace_id', 'primary_digest', 'secondary_digest',
    ]);
    integer(item.sequence, 1, Number.MAX_SAFE_INTEGER, `${label} sequence`);
    string(item.event_id, UUID, `${label} ID`);
    string(item.actor_type, /^(?:administrator|system|dispatcher|executor)$/, `${label} actor type`);
    string(item.actor_id, ASCII_ID, `${label} actor ID`);
    string(item.action, /^[a-z][a-z0-9_]{0,127}$/, `${label} action`);
    string(item.object_type, /^[a-z][a-z0-9_]{0,127}$/, `${label} object type`);
    string(item.outcome, /^(?:accepted|rejected|succeeded|failed|indeterminate)$/, `${label} outcome`);
    timestamp(item.occurred_at, `${label} occurred_at`);
    timestamp(item.recorded_at, `${label} recorded_at`);
    for (const key of ['object_id', 'incident_id', 'policy_id', 'enforcement_action_id', 'trace_id']) {
      if (Object.hasOwn(item, key)) string(item[key], UUID, `${label} ${key}`);
    }
    if (Object.hasOwn(item, 'policy_version')) {
      integer(item.policy_version, 1, 2_147_483_647, `${label} policy version`);
    }
    for (const key of ['primary_digest', 'secondary_digest']) {
      if (Object.hasOwn(item, key)) string(item[key], DIGEST, `${label} ${key}`);
    }
    if (options.policyID !== undefined) {
      invariant(item.policy_id === options.policyID, `${label} policy binding is invalid`);
    }
    return Object.freeze({ ...item });
  });
  return Object.freeze({ items: Object.freeze(items), nextCursor, nextCursorSequence });
}

function parseAPIErrorCode(response, expected) {
  let parsed;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    throw new Error('management API error envelope is invalid');
  }
  const envelope = exactRecord(parsed, 'management API error', ['code', 'message', 'trace_id', 'details']);
  invariant(
    envelope.code === expected && typeof envelope.message === 'string' && envelope.message.length <= 256 &&
      UUID.test(envelope.trace_id) && Object.keys(record(envelope.details, 'management API error details')).length === 0,
    `management API did not return ${expected}`,
  );
}

export function validateDeterministicPolicy(detail, policy, sourceIPv4, expectedKind) {
  const incident = record(detail.incident, 'incident');
  const analysis = record(detail.latest_analysis, 'incident analysis');
  invariant(
    incident.source_ip === sourceIPv4 && incident.kind === expectedKind && incident.state === 'review_ready' &&
      analysis.provider_kind === 'deterministic_stub' &&
      analysis.adapter_id === 'sentinelflow-deterministic-ai-stub-v1' &&
      analysis.result_state === 'succeeded' && analysis.classification === expectedKind &&
      UUID.test(analysis.analysis_id) && DIGEST.test(analysis.output_digest),
    `${expectedKind} deterministic analysis is invalid`,
  );
  invariant(
    policy.incident_id === incident.incident_id && policy.incident_version === analysis.incident_version &&
      policy.analysis_id === analysis.analysis_id && policy.state === 'valid' &&
      policy.target_ipv4 === sourceIPv4 && policy.action === 'block_ip' &&
      policy.ttl_seconds === 1800 && policy.timeout_token === '30m' && policy.parse_state === 'valid' &&
      policy.parse_error_code === undefined && UUID.test(policy.command_candidate_id) &&
      DIGEST.test(policy.policy_digest) && DIGEST.test(policy.evidence_snapshot_digest) &&
      DIGEST.test(policy.generated_artifact_digest) && DIGEST.test(policy.canonical_artifact_digest) &&
      policy.generated_command === `add element inet sentinelflow blacklist_ipv4 { ${sourceIPv4} timeout 30m }` &&
      policy.canonical_command === `add element inet sentinelflow blacklist_ipv4 { ${sourceIPv4} timeout 30m }\n`,
    `${expectedKind} policy/candidate contract is invalid`,
  );
  const validation = record(policy.latest_validation, 'policy validation');
  const gateNames = [
    'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
    'protected_network', 'owned_schema_syntax', 'historical_impact',
  ];
  invariant(
    validation.state === 'valid' && validation.source_health_status === 'complete' &&
      validation.failure_code === undefined && DIGEST.test(validation.snapshot_digest) &&
      DIGEST.test(validation.base_chain_contract_raw_digest) &&
      DIGEST.test(validation.live_owned_schema_digest) &&
      DIGEST.test(validation.protected_ipv4_static_digest) &&
      DIGEST.test(validation.protected_ipv4_effective_config_digest) &&
      DIGEST.test(validation.historical_impact_digest) &&
      (validation.history_dataset_digest === undefined || DIGEST.test(validation.history_dataset_digest)) &&
      (validation.history_manifest_digest === undefined || DIGEST.test(validation.history_manifest_digest)) &&
      Array.isArray(validation.gates) && validation.gates.length === gateNames.length &&
      validation.gates.every((gate, index) => gate?.order === index + 1 && gate?.name === gateNames[index] &&
        gate?.passed === true && DIGEST.test(gate?.input_digest ?? '') && DIGEST.test(gate?.result_digest ?? '')),
    `${expectedKind} validation contract is invalid`,
  );
  invariant(
    Array.isArray(detail.signals) && detail.signals.length >= 1 &&
      detail.signals.every((signal) => signal?.source_health_status === 'complete' && DIGEST.test(signal?.evidence_digest ?? '')),
    `${expectedKind} deterministic evidence is invalid`,
  );
  return policy;
}

export async function waitForValidPolicy(client, incidentSummary, expectedKind, timeoutSeconds) {
  const incidentID = string(incidentSummary.incident_id, UUID, 'incident ID');
  const sourceIPv4 = string(incidentSummary.source_ip, IPV4, 'incident source');
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const detail = record(await client.request(`/api/v1/incidents/${incidentID}`), 'incident detail');
    const incident = record(detail.incident, 'incident');
    invariant(
      incident.incident_id === incidentID && incident.source_ip === sourceIPv4 &&
        incident.kind === expectedKind,
      `${expectedKind} incident request binding is invalid`,
    );
    if (['open', 'analyzing'].includes(incident.state)) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    invariant(incident.state === 'review_ready', `${expectedKind} incident is not review-ready`);
    invariant(detail.latest_analysis !== undefined,
      `${expectedKind} review-ready incident has no latest analysis`);
    const analysis = record(detail.latest_analysis, 'incident analysis');
    invariant(
      analysis.provider_kind === 'deterministic_stub' && UUID.test(analysis.analysis_id) &&
        Number.isSafeInteger(analysis.incident_version) && analysis.incident_version >= 1,
      `${expectedKind} deterministic analysis binding is invalid`,
    );
    invariant(Array.isArray(detail.policies), 'incident policies are invalid');
    const current = detail.policies.filter(
      (summary) => summary?.incident_version === analysis.incident_version,
    );
    if (current.length === 0) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    invariant(current.length === 1, `${expectedKind} current policy binding is ambiguous`);
    const summary = record(current[0], 'current policy summary');
    const policyID = string(summary.policy_id, UUID, 'current policy ID');
    const policy = record(await client.request(`/api/v1/policies/${policyID}`), 'current policy');
    invariant(
      policy.policy_id === policyID && policy.version === summary.version &&
        policy.incident_version === summary.incident_version &&
        policy.policy_digest === summary.policy_digest &&
        policy.evidence_snapshot_digest === summary.evidence_snapshot_digest,
      `${expectedKind} policy summary binding is invalid`,
    );
    if (['draft', 'validating'].includes(policy.state)) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    invariant(
      policy.state === 'valid' && policy.latest_validation?.state === 'valid',
      `${expectedKind} current policy is terminal but not valid`,
    );
    return validateDeterministicPolicy(detail, policy, sourceIPv4, expectedKind);
  }
  throw new Error(`${expectedKind} valid deterministic policy did not converge`);
}

export async function waitForFailClosedIncident(client, incidentSummary, expectedKind, timeoutSeconds) {
  const incidentID = string(incidentSummary.incident_id, UUID, 'fail-closed incident ID');
  const sourceIPv4 = string(incidentSummary.source_ip, IPV4, 'fail-closed incident source');
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const detail = record(await client.request(`/api/v1/incidents/${incidentID}`), 'fail-closed incident detail');
    const incident = record(detail.incident, 'fail-closed incident');
    invariant(
      incident.incident_id === incidentID && incident.source_ip === sourceIPv4 &&
        incident.kind === expectedKind,
      `${expectedKind} fail-closed incident request binding is invalid`,
    );
    invariant(
      !['analysis_failed', 'closed'].includes(incident.state),
      `${expectedKind} fail-closed incident reached an unexpected terminal state`,
    );
    if (['open', 'analyzing'].includes(incident.state)) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    invariant(incident.state === 'review_ready',
      `${expectedKind} fail-closed incident is not review-ready`);
    invariant(detail.latest_analysis !== undefined,
      `${expectedKind} fail-closed review-ready incident has no latest analysis`);
    const analysis = record(detail.latest_analysis, `${expectedKind} fail-closed analysis`);
    invariant(
      analysis.provider_kind === 'deterministic_stub' &&
        analysis.adapter_id === 'sentinelflow-deterministic-ai-stub-v1' &&
        analysis.result_state === 'succeeded' && analysis.classification === expectedKind &&
        UUID.test(analysis.analysis_id) && Number.isSafeInteger(analysis.incident_version) &&
        analysis.incident_version >= 1,
      `${expectedKind} fail-closed analysis binding is invalid`,
    );
    invariant(Array.isArray(detail.policies) && detail.policies.length <= 16,
      `${expectedKind} fail-closed policies are invalid`);
    const current = detail.policies.filter(
      (summary) => summary?.incident_version === analysis.incident_version,
    );
    if (current.length === 0) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    invariant(current.length === 1, `${expectedKind} current fail-closed policy binding is ambiguous`);
    const summary = record(current[0], `${expectedKind} current fail-closed policy summary`);
    const policyID = string(summary.policy_id, UUID, `${expectedKind} fail-closed policy ID`);
    const policy = record(await client.request(`/api/v1/policies/${policyID}`),
      `${expectedKind} current fail-closed policy`);
    invariant(
      policy.policy_id === policyID && policy.version === summary.version &&
        policy.incident_id === incidentID && policy.incident_version === analysis.incident_version &&
        policy.analysis_id === analysis.analysis_id && policy.target_ipv4 === sourceIPv4 &&
        policy.policy_digest === summary.policy_digest &&
        policy.evidence_snapshot_digest === summary.evidence_snapshot_digest,
      `${expectedKind} fail-closed policy binding is invalid`,
    );
    if (['draft', 'validating'].includes(policy.state)) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    invariant(
      policy.state === 'invalid' && policy.parse_state === 'canonical' &&
        policy.parse_error_code === undefined && policy.latest_validation === undefined &&
        policy.decision === undefined,
      `${expectedKind} fail-closed policy terminal contract is invalid`,
    );
    const attempt = exactRecord(policy.latest_validation_attempt,
      `${expectedKind} latest validation attempt`, [
        'validation_attempt_id', 'policy_id', 'analysis_id', 'incident_id',
        'incident_version', 'state', 'failure_code', 'failed_gate',
        'prepared_snapshot_digest', 'terminal_mutation_digest', 'completed_at', 'gates',
      ]);
    invariant(
      UUID.test(attempt.validation_attempt_id) && attempt.policy_id === policyID &&
        attempt.analysis_id === analysis.analysis_id && attempt.incident_id === incidentID &&
        attempt.incident_version === analysis.incident_version && attempt.state === 'invalid' &&
        attempt.failure_code === 'history_demo_binding_mismatch' &&
        attempt.failed_gate === 'historical_impact' &&
        DIGEST.test(attempt.prepared_snapshot_digest) &&
        DIGEST.test(attempt.terminal_mutation_digest) &&
        TIMESTAMP.test(attempt.completed_at) && Number.isFinite(Date.parse(attempt.completed_at)) &&
        Array.isArray(attempt.gates) && attempt.gates.length === DIAGNOSTIC_GATE_NAMES.length,
      `${expectedKind} fail-closed validation attempt is invalid`,
    );
    attempt.gates.forEach((rawGate, index) => {
      const gate = exactRecord(rawGate, `${expectedKind} fail-closed validation gate ${index + 1}`, [
        'order', 'name', 'state', 'result_code', 'artifact_digest',
      ]);
      const terminal = index === DIAGNOSTIC_GATE_NAMES.length - 1;
      invariant(
        gate.order === index + 1 && gate.name === DIAGNOSTIC_GATE_NAMES[index] &&
          gate.state === (terminal ? 'failed' : 'passed') &&
          gate.result_code === (terminal ? attempt.failure_code : 'ok') &&
          DIGEST.test(gate.artifact_digest),
        `${expectedKind} fail-closed validation gate ${index + 1} is invalid`,
      );
    });
    const audit = await auditForPolicy(client, policyID);
    invariant(
      !audit.some((item) =>
        ['policy_approved', 'policy_rejected'].includes(item.action) ||
        item.action.startsWith('enforcement_')),
      `${expectedKind} fail-closed policy created a HIL or enforcement audit`,
    );
    return true;
  }
  throw new Error(`${expectedKind} fail-closed validation did not converge`);
}

async function proveDigestMismatchNoAction(client, policy) {
  const binding = exactBinding(policy);
  const last = binding.policy_digest.at(-1);
  const mismatched = {
    ...binding,
    policy_digest: `${binding.policy_digest.slice(0, -1)}${last === '0' ? '1' : '0'}`,
  };
  const response = await client.request(`/api/v1/policies/${policy.policy_id}/decision-challenges`, {
    method: 'POST', body: mismatched,
    idempotencyKey: `e2e.mismatch.${randomBytes(16).toString('hex')}`, acceptError: 409,
  });
  parseAPIErrorCode(response, 'digest_mismatch');
  const unchanged = record(await client.request(`/api/v1/policies/${policy.policy_id}`), 'unchanged policy');
  invariant(unchanged.state === 'valid' && unchanged.decision === undefined, 'digest mismatch changed policy state');
  const audit = await auditForPolicy(client, policy.policy_id);
  invariant(
    !audit.some((item) => ['policy_approved', 'policy_rejected'].includes(item?.action)),
    'digest mismatch created a HIL action audit',
  );
}

async function rejectPolicy(client, policy) {
  const binding = exactBinding(policy, 'reject');
  const idempotencyKey = `e2e.reject.${randomBytes(16).toString('hex')}`;
  const challenge = record(await client.request(`/api/v1/policies/${policy.policy_id}/decision-challenges`, {
    method: 'POST', body: binding,
    idempotencyKey, expected: 201,
  }), 'reject challenge');
  const decision = record(await client.request(`/api/v1/policies/${policy.policy_id}/decisions`, {
    method: 'POST',
    body: {
      ...binding,
      challenge: challenge.challenge,
      challenge_nonce: challenge.challenge_nonce,
      reason: {
        schema_version: 'hil-reason-v1',
        reason_code: 'false_positive',
        reason_text: 'Separate E2E rejection proves that analysis does not imply enforcement authority.',
      },
    },
    idempotencyKey,
    captureCookie: true,
    requireRotation: true,
  }), 'reject decision');
  client.acceptPrivilegeRotation(decision, 'reject decision');
  invariant(
    decision.action_id === null && decision.authorization_digest === null && decision.outbox_job_id === null &&
      decision.decision?.decision === 'rejected',
    'reject decision created enforcement authority',
  );
  const rejected = record(await client.request(`/api/v1/policies/${policy.policy_id}`), 'rejected policy');
  invariant(rejected.state === 'rejected' && rejected.decision?.decision === 'rejected', 'policy did not converge to rejected');
  const audit = await auditForPolicy(client, policy.policy_id);
  invariant(
    audit.some((item) => item?.action === 'policy_rejected' && item?.outcome === 'rejected' &&
      item?.policy_id === policy.policy_id && item?.enforcement_action_id === undefined),
    'exact policy rejection audit is missing',
  );
}

function validateExecutionResult(value, label = 'action result') {
  const result = exactRecord(value, label, [
    'result_id', 'operation', 'classification', 'readback_state', 'journal_sequence',
    'error_code', 'result_digest', 'persisted_at',
  ], ['remaining_ttl_seconds']);
  const normalized = {
    result_id: string(result.result_id, UUID, `${label} ID`),
    operation: string(result.operation, /^(?:add|revoke|inspect)$/, `${label} operation`),
    classification: string(
      result.classification,
      /^(?:applied|recovered_active|revoked|inspect_active|inspect_absent|inspect_mismatch|failed|indeterminate)$/,
      `${label} classification`,
    ),
    readback_state: string(result.readback_state, /^(?:active|absent|mismatch|unknown)$/, `${label} read-back`),
    journal_sequence: integer(result.journal_sequence, 1, Number.MAX_SAFE_INTEGER, `${label} journal sequence`),
    error_code: string(result.error_code, /^[a-z][a-z0-9_]{0,63}$/, `${label} error code`),
    result_digest: string(result.result_digest, DIGEST, `${label} digest`),
    persisted_at: timestamp(result.persisted_at, `${label} persisted_at`),
    ...(Object.hasOwn(result, 'remaining_ttl_seconds') ? {
      remaining_ttl_seconds: integer(result.remaining_ttl_seconds, 1, 86_400, `${label} remaining TTL`),
    } : {}),
  };
  const successfulActive = ['applied', 'recovered_active', 'inspect_active'].includes(normalized.classification);
  const successfulAbsent = ['revoked', 'inspect_absent'].includes(normalized.classification);
  invariant(
    (!['failed', 'indeterminate'].includes(normalized.classification) && normalized.error_code === 'none') &&
      (!successfulActive || normalized.readback_state === 'active' && normalized.remaining_ttl_seconds !== undefined) &&
      (!successfulAbsent || normalized.readback_state === 'absent' && normalized.remaining_ttl_seconds === undefined),
    `${label} lifecycle contract is invalid`,
  );
  return Object.freeze(normalized);
}

function validateActionEnvelope(action, label = 'enforcement action') {
  const value = exactRecord(action, label, [
    'action_id', 'policy_id', 'policy_version', 'validation_snapshot_id', 'evidence_snapshot_digest',
    'target_ipv4', 'canonical_artifact_digest', 'ttl_seconds', 'state', 'approved_at', 'version',
    'created_at', 'updated_at',
  ], ['queued_at', 'applied_at', 'expected_expires_at', 'finished_at', 'latest_result']);
  const normalized = {
    ...value,
    action_id: string(value.action_id, UUID, `${label} ID`),
    policy_id: string(value.policy_id, UUID, `${label} policy ID`),
    policy_version: integer(value.policy_version, 1, 2_147_483_647, `${label} policy version`),
    validation_snapshot_id: string(value.validation_snapshot_id, UUID, `${label} validation snapshot ID`),
    evidence_snapshot_digest: string(value.evidence_snapshot_digest, DIGEST, `${label} evidence digest`),
    target_ipv4: string(value.target_ipv4, IPV4, `${label} target`),
    canonical_artifact_digest: string(value.canonical_artifact_digest, DIGEST, `${label} artifact digest`),
    ttl_seconds: integer(value.ttl_seconds, 60, 86_400, `${label} TTL`),
    state: string(value.state, /^(?:queued|active|expired|failed|revoked|indeterminate)$/, `${label} state`),
    approved_at: timestamp(value.approved_at, `${label} approved_at`),
    version: integer(value.version, 1, 2_147_483_647, `${label} version`),
    created_at: timestamp(value.created_at, `${label} created_at`),
    updated_at: timestamp(value.updated_at, `${label} updated_at`),
    ...(Object.hasOwn(value, 'queued_at') ? { queued_at: timestamp(value.queued_at, `${label} queued_at`) } : {}),
    ...(Object.hasOwn(value, 'applied_at') ? { applied_at: timestamp(value.applied_at, `${label} applied_at`) } : {}),
    ...(Object.hasOwn(value, 'expected_expires_at') ? {
      expected_expires_at: timestamp(value.expected_expires_at, `${label} expected_expires_at`),
    } : {}),
    ...(Object.hasOwn(value, 'finished_at') ? { finished_at: timestamp(value.finished_at, `${label} finished_at`) } : {}),
    ...(Object.hasOwn(value, 'latest_result') ? { latest_result: validateExecutionResult(value.latest_result, `${label} result`) } : {}),
  };
  invariant(canonicalIPv4(normalized.target_ipv4), `${label} target is invalid`);
  invariant(
    Date.parse(normalized.updated_at) >= Date.parse(normalized.created_at) &&
      (normalized.state !== 'active' || normalized.applied_at !== undefined && normalized.expected_expires_at !== undefined) &&
      (!['expired', 'failed', 'revoked'].includes(normalized.state) || normalized.finished_at !== undefined),
    `${label} timeline is invalid`,
  );
  return Object.freeze(normalized);
}

export function validateActiveAction(action, expected = undefined) {
  const value = validateActionEnvelope(action);
  const result = value.latest_result;
  invariant(value.state === 'active' && result !== undefined, 'action did not converge to active');
  invariant(
    (result.operation === 'add' && ['applied', 'recovered_active'].includes(result.classification) ||
      result.operation === 'inspect' && result.classification === 'inspect_active') &&
      result.readback_state === 'active' && result.remaining_ttl_seconds <= value.ttl_seconds,
    'action has no signed active read-back result',
  );
  if (expected !== undefined) {
    invariant(
      value.action_id === expected.action_id && value.policy_id === expected.policy_id &&
        value.policy_version === expected.policy_version && value.version === expected.action_version &&
        value.target_ipv4 === expected.target_ipv4 &&
        value.canonical_artifact_digest === expected.canonical_artifact_digest &&
        value.applied_at === expected.applied_at && value.expected_expires_at === expected.expected_expires_at &&
        (result.operation !== 'add' || result.result_digest === expected.add_result_digest &&
          result.journal_sequence === expected.add_journal_sequence) &&
        (result.operation !== 'inspect' || result.journal_sequence > expected.add_journal_sequence) &&
        result.remaining_ttl_seconds <= expected.add_remaining_ttl_seconds,
      'action changed or refreshed TTL across reconciliation',
    );
  }
  return value;
}

function validateInitiallyAppliedAction(action) {
  const value = validateActiveAction(action);
  invariant(
    value.latest_result.operation === 'add' && ['applied', 'recovered_active'].includes(value.latest_result.classification),
    'action initial add result was not observed',
  );
  return value;
}

export function validateExpiredAction(action, auditItems, state) {
  const value = validateActionEnvelope(action, 'expired action');
  const result = value.latest_result;
  invariant(
    value.action_id === state.action_id && value.state === 'expired' &&
      value.version === state.action_version + 1 && result?.operation === 'inspect' &&
      result.classification === 'inspect_absent' && result.readback_state === 'absent' &&
      result.journal_sequence > state.add_journal_sequence,
    'action has no signed expiry read-back result',
  );
  const expectedExpiry = Date.parse(state.expected_expires_at);
  invariant(
    auditItems.some((item) => item?.enforcement_action_id === state.action_id &&
      item?.action === 'enforcement_expired' && item?.outcome === 'succeeded' &&
      item?.primary_digest === result.result_digest && DIGEST.test(item?.secondary_digest ?? '') &&
      Number.isFinite(Date.parse(item?.recorded_at)) && Date.parse(item.recorded_at) >= expectedExpiry),
    'action expiry lifecycle audit is missing',
  );
  return true;
}

export function validateRevokedAction(action, state, revocation = undefined) {
  const value = validateActionEnvelope(action, 'revoked action');
  const result = value.latest_result;
  invariant(
    value.action_id === state.action_id && value.policy_id === state.policy_id && value.state === 'revoked' &&
      value.version === state.action_version + 1 && value.target_ipv4 === state.target_ipv4 &&
      value.canonical_artifact_digest === state.canonical_artifact_digest &&
      value.applied_at === state.applied_at && value.expected_expires_at === state.expected_expires_at &&
      result?.operation === 'revoke' && result.classification === 'revoked' &&
      result.readback_state === 'absent' && result.journal_sequence > state.add_journal_sequence,
    'action has no exact revoked terminal result',
  );
  if (revocation !== undefined) {
    invariant(
      value.version === revocation.action_version_after && value.finished_at === revocation.finished_at &&
        result.result_id === revocation.result_id && result.result_digest === revocation.result_digest &&
        result.journal_sequence === revocation.journal_sequence,
      'revoked action changed across restart',
    );
  }
  return value;
}

const ACTION_EVIDENCE_FIELDS = [
  'incident_id', 'policy_id', 'policy_version', 'policy_digest', 'validation_snapshot_id',
  'validation_snapshot_digest', 'evidence_snapshot_digest', 'action_id', 'action_version',
  'target_ipv4', 'ttl_seconds', 'generated_artifact_digest', 'canonical_artifact_digest', 'approved_at', 'queued_at',
  'applied_at', 'expected_expires_at', 'add_result_id', 'add_result_digest',
  'add_journal_sequence', 'add_remaining_ttl_seconds', 'add_authorization_digest', 'add_outbox_job_id',
];

function validateActionEvidence(value, label) {
  const evidence = exactRecord(value, label, ACTION_EVIDENCE_FIELDS);
  const normalized = {
    incident_id: string(evidence.incident_id, UUID, `${label} incident ID`),
    policy_id: string(evidence.policy_id, UUID, `${label} policy ID`),
    policy_version: integer(evidence.policy_version, 1, 2_147_483_647, `${label} policy version`),
    policy_digest: string(evidence.policy_digest, DIGEST, `${label} policy digest`),
    validation_snapshot_id: string(evidence.validation_snapshot_id, UUID, `${label} validation snapshot ID`),
    validation_snapshot_digest: string(evidence.validation_snapshot_digest, DIGEST, `${label} validation digest`),
    evidence_snapshot_digest: string(evidence.evidence_snapshot_digest, DIGEST, `${label} evidence digest`),
    action_id: string(evidence.action_id, UUID, `${label} action ID`),
    action_version: integer(evidence.action_version, 1, 2_147_483_647, `${label} action version`),
    target_ipv4: string(evidence.target_ipv4, IPV4, `${label} target`),
    ttl_seconds: integer(evidence.ttl_seconds, 60, 86_400, `${label} TTL`),
    generated_artifact_digest: string(evidence.generated_artifact_digest, DIGEST, `${label} generated artifact digest`),
    canonical_artifact_digest: string(evidence.canonical_artifact_digest, DIGEST, `${label} artifact digest`),
    approved_at: timestamp(evidence.approved_at, `${label} approved_at`),
    queued_at: timestamp(evidence.queued_at, `${label} queued_at`),
    applied_at: timestamp(evidence.applied_at, `${label} applied_at`),
    expected_expires_at: timestamp(evidence.expected_expires_at, `${label} expected_expires_at`),
    add_result_id: string(evidence.add_result_id, UUID, `${label} add result ID`),
    add_result_digest: string(evidence.add_result_digest, DIGEST, `${label} add result digest`),
    add_journal_sequence: integer(evidence.add_journal_sequence, 1, Number.MAX_SAFE_INTEGER, `${label} add journal sequence`),
    add_remaining_ttl_seconds: integer(evidence.add_remaining_ttl_seconds, 1, evidence.ttl_seconds, `${label} add remaining TTL`),
    add_authorization_digest: string(evidence.add_authorization_digest, DIGEST, `${label} add authorization digest`),
    add_outbox_job_id: string(evidence.add_outbox_job_id, UUID, `${label} add outbox ID`),
  };
  invariant(canonicalIPv4(normalized.target_ipv4), `${label} target is invalid`);
  return Object.freeze(normalized);
}

const REVOCATION_EVIDENCE_FIELDS = [
  'action_version_before', 'action_version_after', 'challenge_id', 'revoke_artifact_digest',
  'decision_id', 'decision_digest', 'reason_digest', 'revocation_id', 'authorization_id',
  'authorization_digest', 'outbox_job_id', 'audit_event_id', 'execution_capability_digest',
  'result_id', 'result_digest', 'journal_sequence', 'finished_at',
];

function validateRevocationEvidence(value, action) {
  const evidence = exactRecord(value, 'revocation evidence', REVOCATION_EVIDENCE_FIELDS);
  const normalized = {
    action_version_before: integer(evidence.action_version_before, 1, 2_147_483_647, 'revocation action version before'),
    action_version_after: integer(evidence.action_version_after, 2, 2_147_483_647, 'revocation action version after'),
    challenge_id: string(evidence.challenge_id, UUID, 'revocation challenge ID'),
    revoke_artifact_digest: string(evidence.revoke_artifact_digest, DIGEST, 'revoke artifact digest'),
    decision_id: string(evidence.decision_id, UUID, 'revocation decision ID'),
    decision_digest: string(evidence.decision_digest, DIGEST, 'revocation decision digest'),
    reason_digest: string(evidence.reason_digest, DIGEST, 'revocation reason digest'),
    revocation_id: string(evidence.revocation_id, UUID, 'revocation ID'),
    authorization_id: string(evidence.authorization_id, UUID, 'revocation authorization ID'),
    authorization_digest: string(evidence.authorization_digest, DIGEST, 'revocation authorization digest'),
    outbox_job_id: string(evidence.outbox_job_id, UUID, 'revocation outbox ID'),
    audit_event_id: string(evidence.audit_event_id, UUID, 'revocation audit ID'),
    execution_capability_digest: string(evidence.execution_capability_digest, DIGEST, 'revocation capability digest'),
    result_id: string(evidence.result_id, UUID, 'revocation result ID'),
    result_digest: string(evidence.result_digest, DIGEST, 'revocation result digest'),
    journal_sequence: integer(evidence.journal_sequence, 1, Number.MAX_SAFE_INTEGER, 'revocation journal sequence'),
    finished_at: timestamp(evidence.finished_at, 'revocation finished_at'),
  };
  invariant(
    normalized.action_version_before === action.action_version &&
      normalized.action_version_after === action.action_version + 1 &&
      normalized.journal_sequence > action.add_journal_sequence,
    'revocation evidence is not ordered after the add',
  );
  return Object.freeze(normalized);
}

export function validateDemoState(value, requireTerminalMode = false) {
  const state = exactRecord(value, 'E2E state file', [
    'schema_version', 'mode', 'action', 'revocation',
  ]);
  invariant(state.schema_version === STATE_SCHEMA, 'E2E state schema is invalid');
  invariant(DEMO_MODES.includes(state.mode), 'E2E mode is invalid');
  const action = validateActionEvidence(state.action, 'action evidence');
  invariant(action.target_ipv4 === '203.0.113.20', 'E2E action target is not the frozen demo source');
  const revocation = state.revocation === null ? null : validateRevocationEvidence(state.revocation, action);
  invariant(state.mode !== 'release_expiry' || revocation === null,
    'release expiry mode cannot contain revocation authority');
  invariant(!requireTerminalMode || state.mode === 'release_expiry' || revocation !== null,
    'fast revoke mode is missing revocation evidence');
  return Object.freeze({
    schema_version: STATE_SCHEMA,
    mode: state.mode,
    action,
    revocation,
  });
}

function revocationBinding(action, evidence) {
  invariant(
    action.action_id === evidence.action_id && action.policy_id === evidence.policy_id &&
      action.policy_version === evidence.policy_version && action.state === 'active',
    'revocation source action is not the persisted active action',
  );
  return Object.freeze({
    action_version: action.version,
    target_ipv4: action.target_ipv4,
    original_add_digest: action.canonical_artifact_digest,
  });
}

export function validateRevocationChallengeEnvelope(envelope, action, evidence, session) {
  const item = exactRecord(envelope, 'revocation challenge envelope', [
    'challenge', 'challenge_nonce', 'canonical_revoke_artifact', 'policy_id', 'policy_version',
  ]);
  const challenge = exactRecord(item.challenge, 'revocation challenge', [
    'authenticated_at', 'canonical_artifact_digest', 'challenge_id', 'evidence_snapshot_digest',
    'expires_at', 'generated_artifact_digest', 'issued_at', 'nonce_digest', 'operation',
    'original_add_digest', 'policy_digest', 'reauth_required_after_seconds', 'resource_id',
    'resource_type', 'resource_version', 'schema_version', 'session_digest', 'target_ipv4',
    'validation_snapshot_digest', 'validation_valid_until',
  ]);
  invariant(canonicalJSON(challenge) === JSON.stringify(challenge), 'revocation challenge is not canonical JCS');
  const exactArtifact = `delete element inet sentinelflow blacklist_ipv4 { ${action.target_ipv4} }\n`;
  const artifactDigest = digestText(exactArtifact);
  const nonce = decodeNonce(item.challenge_nonce);
  const nonceDigest = digestBytes(nonce);
  nonce.fill(0);
  const authenticatedAt = timestamp(challenge.authenticated_at, 'revocation authenticated_at');
  const issuedAt = timestamp(challenge.issued_at, 'revocation issued_at');
  const expiresAt = timestamp(challenge.expires_at, 'revocation expires_at');
  const validationValidUntil = timestamp(challenge.validation_valid_until, 'revocation validation_valid_until');
  invariant(
    challenge.schema_version === 'hil-challenge-v1' && challenge.operation === 'revoke' &&
      challenge.resource_type === 'enforcement_action' &&
      string(challenge.challenge_id, UUID, 'revocation challenge ID') !== '' &&
      challenge.resource_id === action.action_id && challenge.resource_version === action.version &&
      challenge.target_ipv4 === action.target_ipv4 &&
      challenge.original_add_digest === action.canonical_artifact_digest &&
      challenge.policy_digest === evidence.policy_digest &&
      challenge.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
      challenge.validation_snapshot_digest === evidence.validation_snapshot_digest &&
      challenge.generated_artifact_digest === artifactDigest &&
      challenge.canonical_artifact_digest === artifactDigest &&
      challenge.nonce_digest === nonceDigest && DIGEST.test(challenge.session_digest) &&
      challenge.authenticated_at === session.authenticated_at &&
      challenge.reauth_required_after_seconds === 900 &&
      item.canonical_revoke_artifact === exactArtifact && item.policy_id === action.policy_id &&
      item.policy_version === action.policy_version &&
      Date.parse(authenticatedAt) <= Date.parse(issuedAt) &&
      Date.parse(issuedAt) < Date.parse(expiresAt) &&
      Date.parse(expiresAt) <= Date.parse(validationValidUntil) &&
      Date.parse(expiresAt) <= Date.parse(session.expires_at) &&
      Date.parse(expiresAt) <= Date.parse(action.expected_expires_at) &&
      Date.parse(expiresAt) - Date.parse(issuedAt) <= 5 * 60 * 1000 &&
      Date.parse(issuedAt) - Date.parse(authenticatedAt) <= 15 * 60 * 1000,
    'revocation challenge binding is invalid',
  );
  return Object.freeze({
    challenge: Object.freeze({ ...challenge }),
    challenge_nonce: item.challenge_nonce,
    canonical_revoke_artifact: exactArtifact,
    policy_id: item.policy_id,
    policy_version: item.policy_version,
    artifact_digest: artifactDigest,
  });
}

export function validateRevocationDecisionEnvelope(
  envelope,
  challengeEnvelope,
  action,
  evidence,
  reason,
  idempotencyKey,
  sourceSession,
) {
  const item = exactRecord(envelope, 'revocation decision envelope', [
    'decision', 'revocation_id', 'authorization_id', 'authorization_digest', 'outbox_job_id',
    'audit_event_id', 'session', 'csrf_token',
  ]);
  const decision = exactRecord(item.decision, 'revocation decision', [
    'actor_id', 'canonical_artifact_digest', 'challenge_id', 'decided_at', 'decision',
    'decision_id', 'decision_valid_until', 'evidence_snapshot_digest', 'generated_artifact_digest',
    'idempotency_key_digest', 'nonce_digest', 'operation', 'original_add_digest', 'policy_digest',
    'reason_digest', 'resource_id', 'resource_type', 'resource_version', 'schema_version',
    'session_digest', 'target_ipv4', 'validation_snapshot_digest',
  ]);
  invariant(canonicalJSON(decision) === JSON.stringify(decision), 'revocation decision is not canonical JCS');
  const nextSession = validateSessionProjection(item.session, 'rotated revocation session');
  const nextCSRF = string(item.csrf_token, CSRF, 'rotated revocation CSRF token');
  const normalizedReason = exactRecord(reason, 'revocation reason', ['schema_version', 'reason_code', 'reason_text']);
  invariant(
    normalizedReason.schema_version === 'hil-reason-v1' && normalizedReason.reason_code === 'operator_request' &&
      typeof normalizedReason.reason_text === 'string' && normalizedReason.reason_text.length > 0 &&
      normalizedReason.reason_text.length <= 500 && normalizedReason.reason_text.normalize('NFC') === normalizedReason.reason_text &&
      !/[\u0000-\u001f\u007f]/.test(normalizedReason.reason_text),
    'revocation reason is invalid',
  );
  const challenge = challengeEnvelope.challenge;
  const reasonDigest = digestJSON(normalizedReason);
  const idempotencyDigest = digestText(idempotencyKey);
  const decidedAt = timestamp(decision.decided_at, 'revocation decided_at');
  const validUntil = timestamp(decision.decision_valid_until, 'revocation decision_valid_until');
  const ids = [
    decision.decision_id, item.revocation_id, item.authorization_id, item.outbox_job_id, item.audit_event_id,
  ];
  ids.forEach((value, index) => string(value, UUID, `revocation response ID ${index + 1}`));
  invariant(new Set(ids).size === ids.length, 'revocation response IDs are not distinct');
  invariant(
    decision.schema_version === 'hil-decision-v1' && decision.operation === 'revoke' &&
      decision.decision === 'revoked' && decision.resource_type === 'enforcement_action' &&
      decision.actor_id === sourceSession.actor_id && decision.challenge_id === challenge.challenge_id &&
      decision.session_digest === challenge.session_digest && decision.resource_id === action.action_id &&
      decision.resource_version === action.version && decision.target_ipv4 === action.target_ipv4 &&
      decision.original_add_digest === action.canonical_artifact_digest &&
      decision.policy_digest === challenge.policy_digest &&
      decision.generated_artifact_digest === challenge.generated_artifact_digest &&
      decision.canonical_artifact_digest === challenge.canonical_artifact_digest &&
      decision.evidence_snapshot_digest === evidence.evidence_snapshot_digest &&
      decision.validation_snapshot_digest === evidence.validation_snapshot_digest &&
      decision.nonce_digest === challenge.nonce_digest && decision.idempotency_key_digest === idempotencyDigest &&
      decision.reason_digest === reasonDigest &&
      Date.parse(decidedAt) >= Date.parse(challenge.issued_at) &&
      Date.parse(decidedAt) < Date.parse(challenge.expires_at) &&
      Date.parse(validUntil) > Date.parse(decidedAt) && Date.parse(validUntil) <= Date.parse(challenge.expires_at) &&
      Date.parse(validUntil) <= Date.parse(challenge.validation_valid_until) &&
      nextSession.actor_id === sourceSession.actor_id &&
      nextSession.authenticated_at === sourceSession.authenticated_at &&
      nextSession.session_id !== sourceSession.session_id,
    'revocation decision binding is invalid',
  );
  const authorization = {
    action_id: decision.resource_id,
    actor_id: decision.actor_id,
    authorization_id: item.authorization_id,
    authorization_kind: 'revoke',
    canonical_artifact_digest: decision.canonical_artifact_digest,
    decided_at: decision.decided_at,
    decision: 'revoke',
    decision_nonce_digest: decision.nonce_digest,
    evidence_snapshot_digest: decision.evidence_snapshot_digest,
    generated_artifact_digest: decision.generated_artifact_digest,
    hil_reason_digest: decision.reason_digest,
    idempotency_key_digest: decision.idempotency_key_digest,
    original_add_digest: decision.original_add_digest,
    policy_digest: decision.policy_digest,
    policy_id: evidence.policy_id,
    policy_version: evidence.policy_version,
    schema_version: 'enforcement-authorization-v1',
    target_ipv4: decision.target_ipv4,
    valid_until: decision.decision_valid_until,
  };
  invariant(
    string(item.authorization_digest, DIGEST, 'revocation authorization digest') === digestJSON(authorization),
    'revocation authorization digest is invalid',
  );
  return Object.freeze({
    decision: Object.freeze({ ...decision }),
    decision_digest: digestJSON(decision),
    reason_digest: reasonDigest,
    revocation_id: item.revocation_id,
    authorization_id: item.authorization_id,
    authorization_digest: item.authorization_digest,
    outbox_job_id: item.outbox_job_id,
    audit_event_id: item.audit_event_id,
    session: nextSession,
    csrf_token: nextCSRF,
  });
}

function actionEvidence(incident, policy, action, decision) {
  const validation = record(policy.latest_validation, 'approved policy validation');
  const result = action.latest_result;
  const evidence = {
    incident_id: string(incident.incident_id, UUID, 'approved incident ID'),
    policy_id: action.policy_id,
    policy_version: action.policy_version,
    policy_digest: string(policy.policy_digest, DIGEST, 'approved policy digest'),
    validation_snapshot_id: action.validation_snapshot_id,
    validation_snapshot_digest: string(validation.snapshot_digest, DIGEST, 'approved validation digest'),
    evidence_snapshot_digest: action.evidence_snapshot_digest,
    action_id: action.action_id,
    action_version: action.version,
    target_ipv4: action.target_ipv4,
    ttl_seconds: action.ttl_seconds,
    generated_artifact_digest: string(policy.generated_artifact_digest, DIGEST, 'generated artifact digest'),
    canonical_artifact_digest: action.canonical_artifact_digest,
    approved_at: action.approved_at,
    queued_at: action.queued_at,
    applied_at: action.applied_at,
    expected_expires_at: action.expected_expires_at,
    add_result_id: result.result_id,
    add_result_digest: result.result_digest,
    add_journal_sequence: result.journal_sequence,
    add_remaining_ttl_seconds: result.remaining_ttl_seconds,
    add_authorization_digest: decision.authorization_digest,
    add_outbox_job_id: decision.outbox_job_id,
  };
  return validateActionEvidence(evidence, 'new action evidence');
}

function exactLifecycleAudit(items, evidence) {
  const approvals = items.filter((item) => item.action === 'policy_approved' && item.outcome === 'accepted' &&
    item.policy_id === evidence.policy_id && item.enforcement_action_id === evidence.action_id);
  const applications = items.filter((item) => item.action === 'enforcement_active' && item.outcome === 'succeeded' &&
    item.actor_type === 'executor' && item.object_type === 'enforcement_action' &&
    item.object_id === evidence.action_id && item.enforcement_action_id === evidence.action_id &&
    item.primary_digest === evidence.add_result_digest && DIGEST.test(item.secondary_digest ?? ''));
  invariant(approvals.length === 1 && applications.length === 1, 'exact approval/add lifecycle audit is invalid');
}

async function approvePolicy(client, incident, policy, timeoutSeconds, checkCSRF = false) {
  const binding = exactBinding(policy);
  if (checkCSRF) {
    const denied = await client.request(`/api/v1/policies/${policy.policy_id}/decision-challenges`, {
      method: 'POST', body: binding,
      idempotencyKey: `e2e.csrf.${randomBytes(16).toString('hex')}`, csrf: false, acceptError: 403,
    });
    parseAPIErrorCode(denied, 'csrf_invalid');
  }
  const idempotencyKey = `e2e.approve.${randomBytes(16).toString('hex')}`;
  const challenge = exactRecord(await client.request(
    `/api/v1/policies/${policy.policy_id}/decision-challenges`,
    { method: 'POST', body: binding, idempotencyKey, expected: 201 },
  ), 'HIL challenge', ['challenge', 'challenge_nonce']);
  record(challenge.challenge, 'HIL challenge artifact');
  decodeNonce(challenge.challenge_nonce).fill(0);
  const decision = exactRecord(await client.request(`/api/v1/policies/${policy.policy_id}/decisions`, {
    method: 'POST',
    body: {
      ...binding,
      challenge: challenge.challenge,
      challenge_nonce: challenge.challenge_nonce,
      reason: {
        schema_version: 'hil-reason-v1',
        reason_code: 'threat_confirmed',
        reason_text: 'Verified deterministic demo threshold and exact bounded policy artifact.',
      },
    },
    idempotencyKey,
    captureCookie: true,
    requireRotation: true,
  }), 'HIL decision', [
    'decision', 'action_id', 'authorization_digest', 'outbox_job_id', 'session', 'csrf_token',
  ]);
  invariant(
    decision.decision?.decision === 'approved' && UUID.test(decision.action_id) &&
      DIGEST.test(decision.authorization_digest) && UUID.test(decision.outbox_job_id),
    'HIL approval did not create exact authority',
  );
  client.acceptPrivilegeRotation(decision, 'approval decision');
  const action = await poll('active enforcement action', timeoutSeconds, async () => {
    try {
      return validateInitiallyAppliedAction(await client.request(`/api/v1/enforcement-actions/${decision.action_id}`));
    } catch {
      return undefined;
    }
  });
  invariant(
    action.policy_id === policy.policy_id && action.policy_version === policy.version &&
      action.target_ipv4 === binding.target_ipv4 &&
      action.canonical_artifact_digest === binding.canonical_artifact_digest,
    'action binding drifted',
  );
  const evidence = actionEvidence(incident, policy, action, decision);
  await poll('approval and add audit', timeoutSeconds, async () => {
    try {
      exactLifecycleAudit(await auditForAction(client, action.action_id), evidence);
      return true;
    } catch {
      return undefined;
    }
  });
  return evidence;
}

async function approveFlow(baseURL, origin, credentialsFile, outputFile, timeoutSeconds, mode) {
  invariant(DEMO_MODES.includes(mode), 'E2E approve mode is invalid');
  const client = await loginClient(baseURL, origin, credentialsFile);
  const normal = await incidentsForSource(client, '203.0.113.21');
  invariant(normal.length === 0, 'normal scenario unexpectedly produced an incident');
  const incidents = new Map();
  for (const [source, kind] of EXPECTED_INCIDENTS) {
    incidents.set(source, await poll(`${kind} incident`, timeoutSeconds, () => findIncident(client, source, kind)));
  }
  const policy = await waitForValidPolicy(
    client, incidents.get('203.0.113.20'), EXPECTED_INCIDENTS.get('203.0.113.20'), timeoutSeconds,
  );
  for (const [source, kind] of EXPECTED_INCIDENTS) {
    if (source !== '203.0.113.20') {
      await waitForFailClosedIncident(client, incidents.get(source), kind, timeoutSeconds);
    }
  }
  const action = await approvePolicy(
    client, incidents.get('203.0.113.20'), policy, timeoutSeconds, true,
  );
  invariant(action.target_ipv4 === '203.0.113.20', 'single-action demo target drifted');
  const state = validateDemoState({
    schema_version: STATE_SCHEMA,
    mode,
    action,
    revocation: null,
  });
  await writePrivateJSON(outputFile, state);
}

async function verifyInspectedFlow(baseURL, origin, credentialsFile, stateFile, timeoutSeconds) {
  const state = validateDemoState(await readJSON(stateFile, 'E2E state file'));
  invariant(state.revocation === null, 'active inspection must precede revocation');
  const client = await loginClient(baseURL, origin, credentialsFile);
  await poll('signed active inspection and audit', timeoutSeconds, async () => {
    try {
      const action = validateActiveAction(
        await client.request(`/api/v1/enforcement-actions/${state.action.action_id}`), state.action,
      );
      const result = action.latest_result;
      if (result.operation !== 'inspect' || result.classification !== 'inspect_active' ||
        result.readback_state !== 'active' || result.journal_sequence <= state.action.add_journal_sequence) {
        return undefined;
      }
      const audit = await auditForAction(client, state.action.action_id);
      exactLifecycleAudit(audit, state.action);
      const inspected = audit.filter((item) => item.actor_type === 'executor' &&
        item.action === 'enforcement_inspected_active' && item.object_type === 'enforcement_action' &&
        item.object_id === state.action.action_id && item.policy_id === state.action.policy_id &&
        item.policy_version === state.action.policy_version &&
        item.enforcement_action_id === state.action.action_id &&
        item.primary_digest === result.result_digest && DIGEST.test(item.secondary_digest ?? '') &&
        item.outcome === 'succeeded');
      return inspected.length === 1;
    } catch {
      return undefined;
    }
  });
}

function revocationDecisionBody(binding, challenge, reason, overrides = {}) {
  return {
    ...binding,
    challenge: challenge.challenge,
    challenge_nonce: challenge.challenge_nonce,
    canonical_revoke_artifact: challenge.canonical_revoke_artifact,
    policy_id: challenge.policy_id,
    policy_version: challenge.policy_version,
    reason,
    ...overrides,
  };
}

async function proveRevocationNegativeFlow(baseURL, origin, credentialsFile, stateFile) {
  const state = validateDemoState(await readJSON(stateFile, 'E2E state file'));
  invariant(state.mode === 'fast_revoke', 'revocation negative is allowed only in fast revoke mode');
  invariant(state.revocation === null, 'negative revocation must precede valid revocation');
  const client = await loginClient(baseURL, origin, credentialsFile);
  const action = validateActiveAction(
    await client.request(`/api/v1/enforcement-actions/${state.action.action_id}`),
    state.action,
  );
  const binding = revocationBinding(action, state.action);
  const idempotencyKey = `e2e.revoke-negative.${randomBytes(16).toString('hex')}`;
  const challenge = validateRevocationChallengeEnvelope(await client.request(
    `/api/v1/enforcement-actions/${action.action_id}/revocation-challenges`,
    { method: 'POST', body: binding, idempotencyKey, expected: 201 },
  ), action, state.action, client.session);
  const reason = {
    schema_version: 'hil-reason-v1', reason_code: 'operator_request',
    reason_text: 'This mismatched decision must not acquire revocation authority.',
  };
  const rejected = await client.request(`/api/v1/enforcement-actions/${action.action_id}/revocations`, {
    method: 'POST',
    body: revocationDecisionBody(binding, challenge, reason, { action_version: binding.action_version + 1 }),
    idempotencyKey,
    acceptError: 409,
  });
  parseAPIErrorCode(rejected, 'digest_mismatch');
  const unchanged = validateActiveAction(
    await client.request(`/api/v1/enforcement-actions/${action.action_id}`), state.action,
  );
  invariant(unchanged.version === action.version, 'rejected revocation changed the action version');
  const audit = await auditForAction(client, action.action_id);
  exactLifecycleAudit(audit, state.action);
  invariant(
    !audit.some((item) => ['enforcement_revoke_authorized', 'enforcement_revoked'].includes(item.action)),
    'rejected revocation created durable authority',
  );
}

function exactRevocationAudit(items, state, decision, action) {
  const authorized = items.filter((item) => item.event_id === decision.audit_event_id &&
    item.actor_type === 'administrator' && item.actor_id === decision.decision.actor_id &&
    item.action === 'enforcement_revoke_authorized' && item.object_type === 'revocation' &&
    item.object_id === decision.revocation_id && item.policy_id === state.policy_id &&
    item.policy_version === state.policy_version && item.enforcement_action_id === state.action_id &&
    item.primary_digest === decision.decision_digest && item.secondary_digest === decision.authorization_digest &&
    item.outcome === 'accepted');
  const revoked = items.filter((item) => item.actor_type === 'executor' &&
    item.action === 'enforcement_revoked' && item.object_type === 'enforcement_action' &&
    item.object_id === state.action_id && item.policy_id === state.policy_id &&
    item.policy_version === state.policy_version && item.enforcement_action_id === state.action_id &&
    item.primary_digest === action.latest_result.result_digest && DIGEST.test(item.secondary_digest ?? '') &&
    item.outcome === 'succeeded');
  invariant(authorized.length === 1 && revoked.length === 1, 'exact revocation lifecycle audit is invalid');
  exactLifecycleAudit(items, state);
  return revoked[0].secondary_digest;
}

async function revokeFlow(baseURL, origin, credentialsFile, stateFile, timeoutSeconds) {
  const state = validateDemoState(await readJSON(stateFile, 'E2E state file'));
  invariant(state.mode === 'fast_revoke', 'revoke is allowed only in fast revoke mode');
  invariant(state.revocation === null, 'valid revocation was already recorded');
  const client = await loginClient(baseURL, origin, credentialsFile);
  const action = validateActiveAction(
    await client.request(`/api/v1/enforcement-actions/${state.action.action_id}`),
    state.action,
  );
  const binding = revocationBinding(action, state.action);
  const idempotencyKey = `e2e.revoke.${randomBytes(16).toString('hex')}`;
  const challenge = validateRevocationChallengeEnvelope(await client.request(
    `/api/v1/enforcement-actions/${action.action_id}/revocation-challenges`,
    { method: 'POST', body: binding, idempotencyKey, expected: 201 },
  ), action, state.action, client.session);
  const reason = Object.freeze({
    schema_version: 'hil-reason-v1',
    reason_code: 'operator_request',
    reason_text: 'Operator-requested deterministic removal of the synthetic credential-stuffing block.',
  });
  const sourceSession = client.session;
  const response = await client.request(`/api/v1/enforcement-actions/${action.action_id}/revocations`, {
    method: 'POST', body: revocationDecisionBody(binding, challenge, reason), idempotencyKey,
    captureCookie: true, requireRotation: true,
  });
  const decision = validateRevocationDecisionEnvelope(
    response, challenge, action, state.action, reason, idempotencyKey, sourceSession,
  );
  client.acceptPrivilegeRotation(response, 'revocation decision');
  const revokedAction = await poll('revoked enforcement action', timeoutSeconds, async () => {
    try {
      return validateRevokedAction(
        await client.request(`/api/v1/enforcement-actions/${action.action_id}`), state.action,
      );
    } catch {
      return undefined;
    }
  });
  const auditResult = await poll('revocation lifecycle audit', timeoutSeconds, async () => {
    try {
      const items = await auditForAction(client, action.action_id);
      return { capabilityDigest: exactRevocationAudit(items, state.action, decision, revokedAction) };
    } catch {
      return undefined;
    }
  });
  const policy = record(await client.request(`/api/v1/policies/${state.action.policy_id}`), 'revoked policy');
  invariant(policy.state === 'revoked', 'revoked action policy did not converge');
  const revocation = validateRevocationEvidence({
    action_version_before: action.version,
    action_version_after: revokedAction.version,
    challenge_id: challenge.challenge.challenge_id,
    revoke_artifact_digest: challenge.artifact_digest,
    decision_id: decision.decision.decision_id,
    decision_digest: decision.decision_digest,
    reason_digest: decision.reason_digest,
    revocation_id: decision.revocation_id,
    authorization_id: decision.authorization_id,
    authorization_digest: decision.authorization_digest,
    outbox_job_id: decision.outbox_job_id,
    audit_event_id: decision.audit_event_id,
    execution_capability_digest: auditResult.capabilityDigest,
    result_id: revokedAction.latest_result.result_id,
    result_digest: revokedAction.latest_result.result_digest,
    journal_sequence: revokedAction.latest_result.journal_sequence,
    finished_at: revokedAction.finished_at,
  }, state.action);
  const completed = validateDemoState({ ...state, revocation }, true);
  await replacePrivateJSON(stateFile, completed);
}

async function verifyRestartFlow(baseURL, origin, credentialsFile, stateFile) {
  const state = validateDemoState(await readJSON(stateFile, 'E2E state file'), true);
  const client = await loginClient(baseURL, origin, credentialsFile);
  const audit = await auditForAction(client, state.action.action_id);
  exactLifecycleAudit(audit, state.action);
  const policy = await client.request(`/api/v1/policies/${state.action.policy_id}`);
  if (state.mode === 'fast_revoke') {
    const revoked = validateRevokedAction(
      await client.request(`/api/v1/enforcement-actions/${state.action.action_id}`),
      state.action, state.revocation,
    );
    const authorized = audit.filter((item) => item.event_id === state.revocation.audit_event_id &&
      item.action === 'enforcement_revoke_authorized' && item.object_id === state.revocation.revocation_id &&
      item.primary_digest === state.revocation.decision_digest &&
      item.secondary_digest === state.revocation.authorization_digest && item.outcome === 'accepted');
    const completed = audit.filter((item) => item.action === 'enforcement_revoked' &&
      item.primary_digest === state.revocation.result_digest &&
      item.secondary_digest === state.revocation.execution_capability_digest && item.outcome === 'succeeded');
    invariant(authorized.length === 1 && completed.length === 1 &&
      revoked.latest_result.operation === 'revoke' && policy?.state === 'revoked',
    'fast revoke lifecycle changed across restart');
    return;
  }
  const active = validateActiveAction(
    await client.request(`/api/v1/enforcement-actions/${state.action.action_id}`), state.action,
  );
  invariant(active.state === 'active' && policy?.state === 'active' &&
    !audit.some((item) => ['enforcement_revoke_authorized', 'enforcement_revoked'].includes(item.action)),
  'release expiry action drifted across restart');
}

async function verifyExpiredFlow(baseURL, origin, credentialsFile, stateFile, timeoutSeconds) {
  const state = validateDemoState(await readJSON(stateFile, 'E2E state file'), true);
  invariant(state.mode === 'release_expiry' && state.revocation === null,
    'expiry verification requires release expiry mode');
  const client = await loginClient(baseURL, origin, credentialsFile);
  await poll('expiry lifecycle and audit', timeoutSeconds, async () => {
    try {
      const action = await client.request(`/api/v1/enforcement-actions/${state.action.action_id}`);
      const audit = await auditForAction(client, state.action.action_id);
      validateExpiredAction(action, audit, state.action);
      exactLifecycleAudit(audit, state.action);
      return true;
    } catch {
      return undefined;
    }
  });
  const policy = await client.request(`/api/v1/policies/${state.action.policy_id}`);
  invariant(policy?.state === 'expired', 'release expiry policy did not become terminal');
}

function option(args, name) {
  const index = args.indexOf(name);
  invariant(index >= 0 && index + 1 < args.length, `missing ${name}`);
  return args[index + 1];
}

async function allocatePorts() {
  const servers = [];
  try {
    const ports = [];
    for (let index = 0; index < 3; index += 1) {
      const server = net.createServer();
      servers.push(server);
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, resolve);
      });
      const address = server.address();
      invariant(address && typeof address === 'object', 'could not allocate a loopback port');
      ports.push(address.port);
    }
    process.stdout.write(`${ports.join(' ')}\n`);
  } finally {
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  }
}

async function main(args) {
  const command = args[0];
  switch (command) {
    case 'allocate-ports':
      await allocatePorts();
      return;
    case 'run-bounded': {
      const timeoutIndex = args.indexOf('--timeout-seconds');
      const separator = args.indexOf('--');
      invariant(timeoutIndex === 1 && separator === 3 && args.length > 4, 'bounded command invocation is invalid');
      await runBoundedCommand(Number(args[2]), args.slice(separator + 1));
      return;
    }
    case 'write-compose-override': {
      const backendImage = option(args, '--backend-image');
      const postgresImage = option(args, '--postgres-image');
      const webImage = option(args, '--web-image');
      const override = buildComposeOverride(backendImage, postgresImage, webImage);
      validateComposeOverride(override, { backendImage, postgresImage, webImage });
      await writePrivateJSON(option(args, '--output'), override);
      return;
    }
    case 'check-service-list':
      validateBaseServiceList(await readFile(args[1], 'utf8'));
      return;
    case 'check-none-network-id':
      process.stdout.write(`${validateEngineNoneNetworkIDOutput(await readFile(args[1], 'utf8'))}\n`);
      return;
    case 'write-evidence-sql':
      await writePrivateText(option(args, '--output'), EVIDENCE_CHAIN_SQL);
      return;
    case 'write-detection-diagnostic-sql':
      await writePrivateText(option(args, '--output'), DETECTION_DIAGNOSTIC_SQL);
      return;
    case 'write-expiry-diagnostic-sql':
      await writePrivateText(option(args, '--output'), EXPIRY_DIAGNOSTIC_SQL);
      return;
    case 'write-detection-stability-sql':
      await writePrivateText(option(args, '--output'), DETECTION_STABILITY_SQL);
      return;
    case 'write-coverage-readiness-sql':
      await writePrivateText(option(args, '--output'), COVERAGE_READINESS_SQL);
      return;
    case 'write-browser-qa-locator':
      await writeBrowserQALocator({
        output: option(args, '--output'),
        root: option(args, '--root'),
        project: option(args, '--project'),
        phase: option(args, '--phase'),
        webPort: Number(option(args, '--web-port')),
        credentialsFile: option(args, '--credentials'),
        stateFile: option(args, '--state'),
        holdSeconds: Number(option(args, '--hold-seconds')),
        stopFile: option(args, '--stop-file'),
      });
      return;
    case 'print-detection-diagnostic': {
      const summary = validateDetectionDiagnostic(
        await readJSON(args[1], 'detection diagnostic database snapshot'),
        await readJSON(option(args, '--detector'), 'detection diagnostic detector snapshot'),
        await readJSON(option(args, '--validationworker'),
          'detection diagnostic validationworker snapshot'),
        option(args, '--stage'),
      );
      process.stdout.write(`DEMO_E2E_DIAGNOSTIC ${canonicalJSON(summary)}\n`);
      return;
    }
    case 'print-expiry-diagnostic': {
      const summary = validateExpiryDiagnostic(
        await readJSON(args[1], 'expiry diagnostic database snapshot'),
        await readJSON(option(args, '--runtime'), 'expiry diagnostic runtime snapshot'),
      );
      process.stdout.write(`DEMO_E2E_EXPIRY_DIAGNOSTIC ${canonicalJSON(summary)}\n`);
      return;
    }
    case 'print-expiry-action-id': {
      const state = validateDemoState(await readJSON(option(args, '--state'), 'E2E state file'), true);
      invariant(state.mode === 'release_expiry' && state.revocation === null,
        'expiry diagnostic requires release expiry state');
      process.stdout.write(`${state.action.action_id}\n`);
      return;
    }
    case 'print-coverage-readiness':
      process.stdout.write(`${canonicalJSON(validateCoverageReadiness(
        await readJSON(args[1], 'coverage readiness database snapshot'),
      ))}\n`);
      return;
    case 'print-detection-stability': {
      const summary = validateDetectionStability(
        await readJSON(args[1], 'detection stability database snapshot'),
      );
      const { ready: _ready, failed: _failed, ...canonical } = summary;
      process.stdout.write(`${canonicalJSON(canonical)}\n`);
      return;
    }
    case 'detection-stability-state': {
      const summary = validateDetectionStability(
        await readJSON(args[1], 'detection stability canonical snapshot'),
      );
      process.stdout.write(`${summary.failed ? 'failed' : (summary.ready ? 'ready' : 'waiting')}\n`);
      return;
    }
    case 'detection-stability-advance':
      process.stdout.write(`${detectionStabilityAdvanced(
        await readJSON(args[1], 'first detection stability snapshot'),
        await readJSON(args[2], 'second detection stability snapshot'),
      ) ? 'stable' : 'changed'}\n`);
      return;
    case 'coverage-readiness-state':
      process.stdout.write(`${validateCoverageReadiness(
        await readJSON(args[1], 'coverage readiness canonical snapshot'),
      ).ready ? 'ready' : 'waiting'}\n`);
      return;
    case 'coverage-readiness-advance':
      process.stdout.write(`${coverageReadinessAdvanced(
        await readJSON(args[1], 'first coverage readiness snapshot'),
        await readJSON(args[2], 'second coverage readiness snapshot'),
      ) ? 'advanced' : 'not-advanced'}\n`);
      return;
    case 'check-evidence-chain':
      validateEvidenceChainRows(
        await readNDJSON(args[1], 'E2E evidence chain'),
        await readJSON(option(args, '--state'), 'E2E state file'),
        option(args, '--phase'),
      );
      return;
    case 'journal-snapshot': {
      const snapshot = parseJournalBuffer(await readPrivateJournal(args[1], 'executor raw journal'));
      validateJournalSnapshot(
        snapshot, await readJSON(option(args, '--state'), 'E2E state file'), option(args, '--phase'),
      );
      await writePrivateJSON(option(args, '--output'), snapshot);
      return;
    }
    case 'journal-compare':
      compareJournalSnapshots(
        await readJSON(args[1], 'pre-restart journal snapshot'),
        await readJSON(args[2], 'post-restart journal snapshot'),
        await readJSON(option(args, '--state'), 'E2E state file'),
        option(args, '--phase'),
        await readPrivateJournal(option(args, '--before-raw'), 'pre-restart raw journal'),
        await readPrivateJournal(option(args, '--after-raw'), 'post-restart raw journal'),
      );
      return;
    case 'nft-state': {
      const result = parseNFTSet(await readJSON(args[1], 'nft read-back'), args[2]);
      process.stdout.write(`${result.state} ${result.remainingTTLSeconds} ${result.digest}\n`);
      return;
    }
    case 'check-simulator':
      validateSimulatorReport(await readJSON(args[1], 'simulator report'), args[2]);
      return;
    case 'check-compose': {
      const expected = {
        project: option(args, '--project'),
        secretSource: option(args, '--secrets'),
        historySource: option(args, '--history'),
        apiPort: Number(option(args, '--api-port')),
        gatewayPort: Number(option(args, '--gateway-port')),
        webPort: Number(option(args, '--web-port')),
        backendImage: option(args, '--backend-image'),
        postgresImage: option(args, '--postgres-image'),
        webImage: option(args, '--web-image'),
      };
      validateComposeConfig(await readJSON(args[1], 'Compose config'), expected);
      return;
    }
    case 'check-runtime':
      validateRuntimeInspection(await readJSON(args[1], 'container inspection'), {
        project: option(args, '--project'),
        backendImage: option(args, '--backend-image'),
        postgresImage: option(args, '--postgres-image'),
        webImage: option(args, '--web-image'),
        noneNetworkID: option(args, '--none-network-id'),
        noneNetworkInspection: await readJSON(
          option(args, '--none-network-inspection'), 'Docker none network inspection',
        ),
      });
      return;
    case 'state-summary': {
      const state = validateDemoState(await readJSON(args[1], 'E2E state file'));
      process.stdout.write(
        `${state.mode} ${state.action.target_ipv4} ${state.action.ttl_seconds}\n`,
      );
      return;
    }
    case 'db-selectors': {
      const state = validateDemoState(await readJSON(args[1], 'E2E state file'), true);
      const selectors = [`add ${state.action.add_outbox_job_id} ${state.action.action_id}`];
      if (state.mode === 'fast_revoke') {
        selectors.push(`revoke ${state.revocation.outbox_job_id} ${state.action.action_id}`);
      }
      process.stdout.write(`${selectors.join('\n')}\n`);
      return;
    }
    case 'approve':
      await approveFlow(
        option(args, '--base-url'), option(args, '--origin'), option(args, '--credentials'),
        option(args, '--output'), Number(option(args, '--timeout-seconds')), option(args, '--mode'),
      );
      return;
    case 'verify-inspected':
      await verifyInspectedFlow(
        option(args, '--base-url'), option(args, '--origin'), option(args, '--credentials'),
        option(args, '--state'), Number(option(args, '--timeout-seconds')),
      );
      return;
    case 'prove-revoke-negative':
      await proveRevocationNegativeFlow(
        option(args, '--base-url'), option(args, '--origin'), option(args, '--credentials'), option(args, '--state'),
      );
      return;
    case 'revoke':
      await revokeFlow(
        option(args, '--base-url'), option(args, '--origin'), option(args, '--credentials'),
        option(args, '--state'), Number(option(args, '--timeout-seconds')),
      );
      return;
    case 'verify-restart':
      await verifyRestartFlow(
        option(args, '--base-url'), option(args, '--origin'), option(args, '--credentials'), option(args, '--state'),
      );
      return;
    case 'verify-expired':
      await verifyExpiredFlow(
        option(args, '--base-url'), option(args, '--origin'), option(args, '--credentials'),
        option(args, '--state'), Number(option(args, '--timeout-seconds')),
      );
      return;
    default:
      throw new Error('unknown demo E2E helper command');
  }
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'unknown failure';
    process.stderr.write(`demo E2E helper failed: ${message}\n`);
    process.exitCode = 1;
  });
}
