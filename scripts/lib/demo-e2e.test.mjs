import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildComposeOverride,
  canonicalJSON,
  compareJournalBuffers,
  coverageReadinessAdvanced,
  detectionStabilityAdvanced,
  digestJSON,
  compareJournalSnapshots,
  ManagementClient,
  parseNFTSet,
  parseJournalBuffer,
  runBoundedCommand,
  validateActiveAction,
  validateBaseServiceList,
  validateBrowserQALocator,
  validateComposeConfig,
  validateComposeOverride,
  validateCoverageReadiness,
  validateDemoState,
  validateDetectionDiagnostic,
  validateDetectionStability,
  validateDeterministicPolicy,
  validateEngineNoneNetworkIDOutput,
  validateExpiredAction,
  validateEvidenceChainRows,
  validateJournalSnapshot,
  validateRevocationChallengeEnvelope,
  validateRevocationDecisionEnvelope,
  validateRevokedAction,
  validateRuntimeInspection,
  validateSimulatorReport,
  waitForFailClosedIncident,
  waitForValidPolicy,
  writeBrowserQALocator,
} from './demo-e2e.mjs';

const digest = (value) => `sha256:${value.repeat(64)}`;
const digestText = (value) => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const uuid = (suffix) => `019b0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const shellWrapper = (lines) => ['/bin/sh', '-eu', '-c', `${lines.join('\n')}\n`];
const runtimeWrapperCommands = {
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
  'demo-activation-handoff': ['/opt/sentinelflow/demo-activation-handoff.sh'],
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
};

function deterministicPolicyFixture() {
  const incidentID = uuid('900');
  const analysisID = uuid('910');
  const policyID = uuid('920');
  const policyDigest = digest('a');
  const evidenceDigest = digest('b');
  const gateNames = [
    'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
    'protected_network', 'owned_schema_syntax', 'historical_impact',
  ];
  const detail = {
    incident: {
      incident_id: incidentID, source_ip: '203.0.113.20', kind: 'mixed', state: 'review_ready',
    },
    latest_analysis: {
      analysis_id: analysisID, incident_version: 10, provider_kind: 'deterministic_stub',
      adapter_id: 'sentinelflow-deterministic-ai-stub-v1', result_state: 'succeeded',
      classification: 'mixed', output_digest: digest('c'),
    },
    signals: [{ source_health_status: 'complete', evidence_digest: digest('d') }],
    policies: [{
      policy_id: policyID, version: 1, incident_version: 10, state: 'valid',
      policy_digest: policyDigest, evidence_snapshot_digest: evidenceDigest,
    }],
  };
  const policy = {
    policy_id: policyID, version: 1, incident_id: incidentID, incident_version: 10,
    analysis_id: analysisID, command_candidate_id: uuid('930'), state: 'valid',
    target_ipv4: '203.0.113.20', action: 'block_ip', ttl_seconds: 1800,
    timeout_token: '30m', parse_state: 'valid', policy_digest: policyDigest,
    evidence_snapshot_digest: evidenceDigest, generated_artifact_digest: digest('e'),
    canonical_artifact_digest: digest('f'),
    generated_command: 'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
    canonical_command: 'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n',
    latest_validation: {
      state: 'valid', source_health_status: 'complete', snapshot_digest: digest('1'),
      base_chain_contract_raw_digest: digest('2'), live_owned_schema_digest: digest('3'),
      protected_ipv4_static_digest: digest('4'),
      protected_ipv4_effective_config_digest: digest('5'), historical_impact_digest: digest('6'),
      gates: gateNames.map((name, index) => ({
        order: index + 1, name, passed: true, input_digest: digest('7'), result_digest: digest('8'),
      })),
    },
  };
  return { detail, policy, incidentSummary: { incident_id: incidentID, source_ip: '203.0.113.20' } };
}

function failClosedPolicyFixture() {
  const incidentID = uuid('940');
  const analysisID = uuid('942');
  const policyID = uuid('941');
  const policyDigest = digest('a');
  const evidenceDigest = digest('b');
  const summary = {
    policy_id: policyID, version: 1, incident_version: 10, state: 'invalid',
    policy_digest: policyDigest, evidence_snapshot_digest: evidenceDigest,
  };
  const detail = {
    incident: {
      incident_id: incidentID, source_ip: '203.0.113.22', kind: 'path_scan', state: 'review_ready',
    },
    latest_analysis: {
      analysis_id: analysisID, incident_version: 10, provider_kind: 'deterministic_stub',
      adapter_id: 'sentinelflow-deterministic-ai-stub-v1', result_state: 'succeeded',
      classification: 'path_scan',
    },
    policies: [
      { policy_id: uuid('943'), version: 1, incident_version: 6, state: 'valid',
        policy_digest: digest('c'), evidence_snapshot_digest: digest('d') },
      summary,
    ],
  };
  const policy = {
    ...summary, incident_id: incidentID, analysis_id: analysisID, target_ipv4: '203.0.113.22',
    parse_state: 'canonical',
    latest_validation_attempt: {
      validation_attempt_id: uuid('944'), policy_id: policyID, analysis_id: analysisID,
      incident_id: incidentID, incident_version: 10, state: 'invalid',
      failure_code: 'history_demo_binding_mismatch', failed_gate: 'historical_impact',
      prepared_snapshot_digest: digest('e'), terminal_mutation_digest: digest('1'),
      completed_at: '2026-07-19T01:02:03Z',
      gates: [
        'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
        'protected_network', 'owned_schema_syntax', 'historical_impact',
      ].map((name, index) => ({
        order: index + 1, name, state: index < 5 ? 'passed' : 'failed',
        result_code: index < 5 ? 'ok' : 'history_demo_binding_mismatch',
        artifact_digest: digest('f'),
      })),
    },
  };
  return {
    detail, policy, summary,
    incidentSummary: { incident_id: incidentID, source_ip: '203.0.113.22' },
  };
}

test('valid policy selection uses the exact current analysis binding and accepts omitted optional history digests', async () => {
  const fixture = deterministicPolicyFixture();
  const historical = [
    { policy_id: uuid('999'), version: 1, incident_version: 2, state: 'valid',
      policy_digest: digest('9'), evidence_snapshot_digest: digest('0') },
    { policy_id: uuid('980'), version: 1, incident_version: 6, state: 'valid',
      policy_digest: digest('8'), evidence_snapshot_digest: digest('7') },
  ];
  fixture.detail.policies = [...historical, ...fixture.detail.policies];
  const requested = [];
  const client = { request: async (pathname) => {
    requested.push(pathname);
    if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
    if (pathname === `/api/v1/policies/${fixture.policy.policy_id}`) return fixture.policy;
    throw new Error(`unexpected historical policy read: ${pathname}`);
  } };
  const selected = await waitForValidPolicy(client, fixture.incidentSummary, 'mixed', 1);
  assert.equal(selected.policy_id, fixture.policy.policy_id);
  assert.deepEqual(requested, [
    `/api/v1/incidents/${fixture.incidentSummary.incident_id}`,
    `/api/v1/policies/${fixture.policy.policy_id}`,
  ]);
  assert.equal(Object.hasOwn(selected.latest_validation, 'history_dataset_digest'), false);
  assert.equal(Object.hasOwn(selected.latest_validation, 'history_manifest_digest'), false);
});

test('deterministic policy validation rejects stale policy-analysis-incident bindings', () => {
  const fixture = deterministicPolicyFixture();
  assert.throws(
    () => validateDeterministicPolicy(
      fixture.detail, { ...fixture.policy, incident_version: 6 }, '203.0.113.20', 'mixed',
    ),
    /policy\/candidate contract is invalid/,
  );
  assert.throws(
    () => validateDeterministicPolicy(
      fixture.detail, { ...fixture.policy, analysis_id: uuid('911') }, '203.0.113.20', 'mixed',
    ),
    /policy\/candidate contract is invalid/,
  );
  assert.throws(
    () => validateDeterministicPolicy(fixture.detail, {
      ...fixture.policy,
      latest_validation: { ...fixture.policy.latest_validation, history_manifest_digest: 'invalid' },
    }, '203.0.113.20', 'mixed'),
    /validation contract is invalid/,
  );
});

test('valid policy selection fails fast on management API errors after stability', async () => {
  const fixture = deterministicPolicyFixture();
  let attempts = 0;
  const client = { request: async () => {
    attempts += 1;
    throw new Error('management API request failed: status=503 code=service_unavailable');
  } };
  await assert.rejects(
    waitForValidPolicy(client, fixture.incidentSummary, 'mixed', 300),
    /status=503 code=service_unavailable/,
  );
  assert.equal(attempts, 1);

  const malformed = structuredClone(fixture.detail);
  malformed.policies = {};
  attempts = 0;
  await assert.rejects(
    waitForValidPolicy({ request: async () => {
      attempts += 1;
      return malformed;
    } }, fixture.incidentSummary, 'mixed', 300),
    /incident policies are invalid/,
  );
  assert.equal(attempts, 1);
});

test('fail-closed selection preserves the exact history binding mismatch terminal contract', async () => {
  const fixture = failClosedPolicyFixture();
  const incidentID = fixture.incidentSummary.incident_id;
  const policyID = fixture.policy.policy_id;
  const requested = [];
  const result = await waitForFailClosedIncident({ request: async (pathname) => {
    requested.push(pathname);
    if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
    if (pathname === `/api/v1/policies/${policyID}`) return fixture.policy;
    if (pathname === `/api/v1/audit-events?policy_id=${policyID}&limit=100`) return { items: [] };
    throw new Error(`unexpected request: ${pathname}`);
  } }, fixture.incidentSummary, 'path_scan', 1);
  assert.equal(result, true);
  assert.deepEqual(requested, [
    `/api/v1/incidents/${incidentID}`,
    `/api/v1/policies/${policyID}`,
    `/api/v1/audit-events?policy_id=${policyID}&limit=100`,
  ]);
});

test('valid and fail-closed selection reject incident request identity drift immediately', async () => {
  const valid = deterministicPolicyFixture();
  const driftedValid = structuredClone(valid.detail);
  driftedValid.incident.incident_id = uuid('945');
  await assert.rejects(
    waitForValidPolicy({ request: async () => driftedValid }, valid.incidentSummary, 'mixed', 300),
    /incident request binding is invalid/,
  );

  const failed = failClosedPolicyFixture();
  const driftedFailed = structuredClone(failed.detail);
  driftedFailed.incident.source_ip = '203.0.113.23';
  await assert.rejects(
    waitForFailClosedIncident({ request: async () => driftedFailed },
      failed.incidentSummary, 'path_scan', 300),
    /fail-closed incident request binding is invalid/,
  );
});

test('fail-closed selection rejects empty analysis terminal states and malformed gate evidence', async () => {
  const fixture = failClosedPolicyFixture();
  const terminal = structuredClone(fixture.detail);
  terminal.incident.state = 'analysis_failed';
  delete terminal.latest_analysis;
  terminal.policies = [];
  let attempts = 0;
  await assert.rejects(
    waitForFailClosedIncident({ request: async () => {
      attempts += 1;
      return terminal;
    } }, fixture.incidentSummary, 'path_scan', 300),
    /unexpected terminal state/,
  );
  assert.equal(attempts, 1);

  const malformed = structuredClone(fixture.policy);
  malformed.latest_validation_attempt.gates[5].result_code = 'ok';
  attempts = 0;
  await assert.rejects(
    waitForFailClosedIncident({ request: async (pathname) => {
      attempts += 1;
      if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
      if (pathname.startsWith('/api/v1/policies/')) return malformed;
      throw new Error(`unexpected request: ${pathname}`);
    } }, fixture.incidentSummary, 'path_scan', 300),
    /validation gate 6 is invalid/,
  );
  assert.equal(attempts, 2);

  const incorrectlyPromoted = structuredClone(fixture.policy);
  incorrectlyPromoted.parse_state = 'valid';
  attempts = 0;
  await assert.rejects(
    waitForFailClosedIncident({ request: async (pathname) => {
      attempts += 1;
      if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
      if (pathname.startsWith('/api/v1/policies/')) return incorrectlyPromoted;
      throw new Error(`unexpected request: ${pathname}`);
    } }, fixture.incidentSummary, 'path_scan', 300),
    /policy terminal contract is invalid/,
  );
  assert.equal(attempts, 2);
});

test('fail-closed selection rejects validation-attempt binding, digest, and schema drift', async () => {
  const fixture = failClosedPolicyFixture();
  const cases = [
    {
      name: 'analysis binding', pattern: /validation attempt is invalid/,
      mutate: (policy) => { policy.latest_validation_attempt.analysis_id = uuid('947'); },
    },
    {
      name: 'terminal mutation digest', pattern: /validation attempt is invalid/,
      mutate: (policy) => { policy.latest_validation_attempt.terminal_mutation_digest = 'invalid'; },
    },
    {
      name: 'legacy gate shape', pattern: /validation gate 1 shape is invalid/,
      mutate: (policy) => { policy.latest_validation_attempt.gates[0].passed = true; },
    },
  ];
  for (const testCase of cases) {
    const policy = structuredClone(fixture.policy);
    testCase.mutate(policy);
    let attempts = 0;
    await assert.rejects(
      waitForFailClosedIncident({ request: async (pathname) => {
        attempts += 1;
        if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
        if (pathname.startsWith('/api/v1/policies/')) return policy;
        throw new Error(`unexpected request: ${pathname}`);
      } }, fixture.incidentSummary, 'path_scan', 300),
      testCase.pattern,
      testCase.name,
    );
    assert.equal(attempts, 2, testCase.name);
  }
});

test('fail-closed selection rejects HIL and enforcement audit for the invalid current policy', async () => {
  const fixture = failClosedPolicyFixture();
  for (const [action, actorType, objectType] of [
    ['policy_approved', 'administrator', 'policy'],
    ['enforcement_queued', 'dispatcher', 'enforcement_action'],
    ['enforcement_active', 'executor', 'enforcement_action'],
  ]) {
    await assert.rejects(
      waitForFailClosedIncident({ request: async (pathname) => {
        if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
        if (pathname.startsWith('/api/v1/policies/')) return fixture.policy;
        if (pathname.startsWith('/api/v1/audit-events?')) {
          return { items: [{
            sequence: 1, event_id: uuid('946'), actor_type: actorType, actor_id: 'test-actor',
            action, object_type: objectType, outcome: 'accepted',
            occurred_at: '2026-07-19T01:02:04Z', recorded_at: '2026-07-19T01:02:04Z',
            policy_id: fixture.policy.policy_id,
          }] };
        }
        throw new Error(`unexpected request: ${pathname}`);
      } }, fixture.incidentSummary, 'path_scan', 300),
      /created a HIL or enforcement audit/,
      action,
    );
  }
});

test('fail-closed audit proof rejects pagination and policy filter drift', async () => {
  const fixture = failClosedPolicyFixture();
  const auditItem = {
    sequence: 1, event_id: uuid('952'), actor_type: 'system', actor_id: 'validation-worker',
    action: 'validation_rejected', object_type: 'validation_attempt', outcome: 'rejected',
    occurred_at: '2026-07-19T01:02:04Z', recorded_at: '2026-07-19T01:02:04Z',
    policy_id: fixture.policy.policy_id,
  };
  for (const testCase of [
    {
      name: 'pagination', page: { items: [], next_cursor: 'a1.ABCDEFGHIJK' },
      pattern: /policy audit proof is paginated/,
    },
    {
      name: 'wrong policy', page: { items: [{ ...auditItem, policy_id: uuid('953') }] },
      pattern: /policy binding is invalid/,
    },
    {
      name: 'missing policy', page: { items: [Object.fromEntries(
        Object.entries(auditItem).filter(([key]) => key !== 'policy_id'),
      )] },
      pattern: /policy binding is invalid/,
    },
  ]) {
    await assert.rejects(
      waitForFailClosedIncident({ request: async (pathname) => {
        if (pathname.startsWith('/api/v1/incidents/')) return fixture.detail;
        if (pathname.startsWith('/api/v1/policies/')) return fixture.policy;
        if (pathname.startsWith('/api/v1/audit-events?')) return testCase.page;
        throw new Error(`unexpected request: ${pathname}`);
      } }, fixture.incidentSummary, 'path_scan', 300),
      testCase.pattern,
      testCase.name,
    );
  }
});

test('fail-closed selection propagates API and schema errors on the first attempt', async () => {
  const incidentID = uuid('950');
  let attempts = 0;
  await assert.rejects(
    waitForFailClosedIncident({ request: async () => {
      attempts += 1;
      throw new Error('management API request failed: status=503 code=service_unavailable');
    } }, { incident_id: incidentID, source_ip: '203.0.113.22' }, 'path_scan', 300),
    /status=503 code=service_unavailable/,
  );
  assert.equal(attempts, 1);

  attempts = 0;
  await assert.rejects(
    waitForFailClosedIncident({ request: async () => {
      attempts += 1;
      return {
        incident: {
          incident_id: incidentID, source_ip: '203.0.113.22', kind: 'path_scan', state: 'review_ready',
        },
        latest_analysis: {
          analysis_id: uuid('951'), incident_version: 1, provider_kind: 'deterministic_stub',
          adapter_id: 'sentinelflow-deterministic-ai-stub-v1', result_state: 'succeeded',
          classification: 'path_scan',
        },
        policies: {},
      };
    } }, { incident_id: incidentID, source_ip: '203.0.113.22' }, 'path_scan', 300),
    /fail-closed policies are invalid/,
  );
  assert.equal(attempts, 1);
});

test('canonical JSON and digest ignore object insertion order', () => {
  const first = { z: [true, null, { b: 2, a: 'value' }], a: 1 };
  const second = { a: 1, z: [true, null, { a: 'value', b: 2 }] };
  assert.equal(canonicalJSON(first), '{"a":1,"z":[true,null,{"a":"value","b":2}]}');
  assert.equal(digestJSON(first), digestJSON(second));
});

test('nft parser distinguishes exact active and absent targets', () => {
  const document = {
    nftables: [
      { metainfo: { version: '1.1.6', release_name: 'test', json_schema_version: 1 } },
      {
        set: {
          family: 'inet', table: 'sentinelflow', name: 'blacklist_ipv4', type: 'ipv4_addr',
          handle: 17, flags: ['timeout'],
          elem: [{ elem: { val: '203.0.113.20', timeout: 1800, expires: 1777 } }],
        },
      },
    ],
  };
  assert.deepEqual(parseNFTSet(document, '203.0.113.20'), {
    state: 'active', remainingTTLSeconds: 1777, digest: digestJSON(document),
  });
  assert.deepEqual(parseNFTSet(document, '203.0.113.21'), {
    state: 'absent', remainingTTLSeconds: 0, digest: digestJSON(document),
  });
  const invalid = structuredClone(document);
  invalid.nftables[1].set.elem[0].elem.expires = 1801;
  assert.throws(() => parseNFTSet(invalid, '203.0.113.20'), /nft element is invalid/);
});

test('simulator report must be complete at the frozen boundary', () => {
  const report = {
    schema_version: 'simulator-report-v1', result: 'passed', scenario: 'request-burst',
    seed: 1, plan_digest: digest('a'), expected_shape: {}, attempted: 120, completed: 120,
    failed: 0, status_counts: [{ class: '2xx', count: 120 }],
  };
  assert.equal(validateSimulatorReport(report, 'request-burst'), report);
  assert.throws(
    () => validateSimulatorReport({ ...report, completed: 119, failed: 1 }, 'request-burst'),
    /report failed/,
  );
});

test('Compose config selects stub only, exact project, ports, and temporary binds', () => {
  const secretSource = '/tmp/sentinelflow-demo-e2e.test/secrets';
  const historySource = '/tmp/sentinelflow-demo-e2e.test/history';
  const backendImage = 'sentinelflow/backend:e2e-test-123';
  const postgresImage = 'sentinelflow/postgres:e2e-test-123';
  const webImage = 'sentinelflow/web:e2e-test-123';
  const override = buildComposeOverride(backendImage, postgresImage, webImage);
  assert.equal(validateComposeOverride(override, { backendImage, postgresImage, webImage }), true);
  const baseServices = [
    'api', 'controlmetricsexporter', 'demo-activation-handoff', 'demo-activator', 'demo-app', 'detector', 'dispatcher', 'executor', 'gateway',
    'history-importer', 'lifecycleworker', 'migrate', 'postgres', 'prometheus', 'retentionworker',
    'secret-init', 'simulator', 'stubworker', 'validationworker', 'validator', 'web', 'worker',
  ];
  assert.equal(validateBaseServiceList(`${baseServices.join('\n')}\n`), true);
  assert.throws(() => validateBaseServiceList(`${baseServices.slice(1).join('\n')}\n`), /drifted/);
  assert.throws(() => validateComposeOverride({ services: { ...override.services, extra: { image: backendImage } } }, {
    backendImage, postgresImage, webImage,
  }), /services drifted/);

  const services = Object.fromEntries(baseServices.filter((service) => !['simulator', 'worker'].includes(service)).map(
    (service) => [service, {
      image: service === 'web' ? webImage :
        (['postgres', 'migrate', 'demo-activation-handoff'].includes(service) ? postgresImage :
          (service === 'prometheus' ? 'prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80' : backendImage)),
      environment: {},
    }],
  ));
  const config = {
    name: 'sf-demo-e2e-test',
    services,
  };
  config.services.api.ports = [{ target: 8083, published: '41001', protocol: 'tcp', host_ip: '127.0.0.1' }];
  config.services.gateway.ports = [{ target: 8080, published: '41002', protocol: 'tcp', host_ip: '127.0.0.1' }];
  config.services.web.ports = [{ target: 8080, published: '41003', protocol: 'tcp', host_ip: '127.0.0.1' }];
  config.services['demo-activation-handoff'].environment.SENTINELFLOW_ENV = 'demo';
  config.services['demo-activator'].environment.SENTINELFLOW_ENV = 'demo';
  config.services['history-importer'].environment.SENTINELFLOW_ENV = 'demo';
  config.services.migrate.environment.SENTINELFLOW_ENV = 'demo';
  config.services['history-importer'].depends_on = { migrate: { condition: 'service_completed_successfully' } };
  config.services['demo-activation-handoff'].depends_on = {
    'history-importer': { condition: 'service_completed_successfully' },
  };
  config.services['demo-activator'].depends_on = {
    'demo-activation-handoff': { condition: 'service_completed_successfully' },
  };
  config.services.stubworker.depends_on = { 'demo-activator': { condition: 'service_completed_successfully' } };
  config.services.validationworker.depends_on = {
    'demo-activator': { condition: 'service_completed_successfully' },
  };
  config.services['secret-init'].volumes = [{ type: 'bind', source: secretSource, target: '/source' }];
  config.services['history-importer'].volumes = [{ type: 'bind', source: historySource, target: '/history' }];
  config.services['demo-activator'].volumes = [{ type: 'bind', source: historySource, target: '/history' }];
  config.services.stubworker.volumes = [{ type: 'bind', source: historySource, target: '/history' }];
  config.services.validationworker.volumes = [{ type: 'bind', source: historySource, target: '/history' }];
  assert.equal(validateComposeConfig(config, {
    project: 'sf-demo-e2e-test', secretSource, historySource,
    apiPort: 41001, gatewayPort: 41002, webPort: 41003,
    backendImage, postgresImage, webImage,
  }), true);
  config.services['demo-activator'].depends_on['demo-activation-handoff'].condition = 'service_started';
  assert.throws(() => validateComposeConfig(config, {
    project: 'sf-demo-e2e-test', secretSource, historySource,
    apiPort: 41001, gatewayPort: 41002, webPort: 41003,
    backendImage, postgresImage, webImage,
  }), /completion dependency on demo-activation-handoff drifted/);
  config.services['demo-activator'].depends_on['demo-activation-handoff'].condition = 'service_completed_successfully';
  config.services.migrate.environment.SENTINELFLOW_ENV = 'production';
  assert.throws(() => validateComposeConfig(config, {
    project: 'sf-demo-e2e-test', secretSource, historySource,
    apiPort: 41001, gatewayPort: 41002, webPort: 41003,
    backendImage, postgresImage, webImage,
  }), /migrate demo gate drifted/);
  config.services.migrate.environment.SENTINELFLOW_ENV = 'demo';
  config.services.worker = { environment: { OPENAI_API_KEY: 'must-not-be-present' } };
  assert.throws(() => validateComposeConfig(config, {
    project: 'sf-demo-e2e-test', secretSource, historySource,
    apiPort: 41001, gatewayPort: 41002, webPort: 41003,
    backendImage, postgresImage, webImage,
  }), /exactly stub-ai/);
});

test('Docker none network ID output is exactly one lowercase 64-hex line', () => {
  const id = 'a'.repeat(64);
  assert.equal(validateEngineNoneNetworkIDOutput(`${id}\n`), id);
  for (const invalid of [
    id, `${id}\n${id}\n`, `${id}\nextra\n`, `${'A'.repeat(64)}\n`, `${'a'.repeat(63)}\n`, ` ${id}\n`,
  ]) {
    assert.throws(() => validateEngineNoneNetworkIDOutput(invalid), /none network ID output is invalid/);
  }
});

test('runtime inspection enforces exact service, image, authority, network, and capability ownership', () => {
  const project = 'sf-demo-e2e-test';
  const backendImage = 'sentinelflow/backend:e2e-test-123';
  const postgresImage = 'sentinelflow/postgres:e2e-test-123';
  const webImage = 'sentinelflow/web:e2e-test-123';
  const services = [
    'api', 'controlmetricsexporter', 'demo-activation-handoff', 'demo-activator', 'demo-app', 'detector', 'dispatcher', 'executor', 'gateway',
    'history-importer', 'lifecycleworker', 'migrate', 'postgres', 'prometheus', 'retentionworker',
    'secret-init', 'stubworker', 'validationworker', 'validator', 'web',
  ];
  const networks = {
    api: ['control', 'ingest', 'management'], controlmetricsexporter: ['control', 'observability'],
    'demo-activation-handoff': ['control'],
    'demo-activator': ['control'],
    'demo-app': ['ingest', 'origin'], detector: ['control'], dispatcher: ['control'],
    gateway: ['edge', 'ingest', 'observability', 'origin'], 'history-importer': ['control'],
    lifecycleworker: ['control'], migrate: ['control'], postgres: ['control'], prometheus: ['observability'],
    retentionworker: ['control'], stubworker: ['control'], validationworker: ['control'], web: ['management'],
    executor: [], validator: [], 'secret-init': [],
  };
  const users = Object.fromEntries(services.map((service) => [service, '65532:65532']));
  Object.assign(users, {
    executor: '0:65532', migrate: '70:70', postgres: '70:70', prometheus: '65532:65532',
    'demo-activation-handoff': '70:70',
    'secret-init': '0:0', validator: '0:65532', web: '101:101',
  });
  const sensitiveEnvironment = {
    api: ['ADMIN_PASSWORD_ARGON2ID_HASH', 'AUTH_EVENT_HMAC_KEY', 'DATABASE_API_URL', 'GATEWAY_EVENT_HMAC_KEY', 'SESSION_HMAC_KEY'],
    'demo-app': ['AUTH_ACCOUNT_HASH_KEY', 'AUTH_EVENT_HMAC_KEY'],
    'demo-activator': ['DATABASE_DEMO_ACTIVATOR_URL', 'DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE',
      'DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE'],
    detector: ['DATABASE_WORKER_URL'],
    dispatcher: ['DATABASE_DISPATCHER_URL', 'DISPATCHER_RESULT_PUBLIC_KEY_FILE', 'DISPATCHER_SIGNING_PRIVATE_KEY_FILE', 'EXECUTOR_SOCKET'],
    executor: ['EXECUTOR_DISPATCH_PUBLIC_KEY_FILE', 'EXECUTOR_REPLAY_JOURNAL', 'EXECUTOR_RESULT_PRIVATE_KEY_FILE', 'EXECUTOR_SOCKET', 'EXECUTOR_STARTUP_MODE', 'NFT_BINARY_EXPECTED_SHA256', 'NFT_EXPECTED_VERSION'],
    gateway: ['GATEWAY_EVENT_HMAC_KEY'],
    'history-importer': ['DATABASE_DEMO_IMPORTER_URL'], lifecycleworker: ['DATABASE_LIFECYCLE_URL'],
    'demo-activation-handoff': ['DATABASE_DEMO_ACTIVATOR_PASSWORD', 'PGPASSWORD'],
    migrate: ['DATABASE_DEMO_IMPORTER_PASSWORD', 'PGPASSWORD'],
    postgres: ['POSTGRES_PASSWORD'], retentionworker: ['DATABASE_RETENTION_URL'],
    controlmetricsexporter: ['DATABASE_METRICS_URL'], stubworker: [
      'DATABASE_WORKER_URL', 'DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE',
    ],
    validationworker: ['DATABASE_WORKER_URL', 'DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE',
      'NFT_BINARY_EXPECTED_SHA256', 'NFT_EXPECTED_VERSION', 'NFT_VALIDATOR_SOCKET'],
    validator: ['NFT_BINARY_EXPECTED_SHA256', 'NFT_EXPECTED_VERSION', 'NFT_VALIDATOR_SOCKET'],
  };
  const mounts = {
    migrate: [['/run/sentinelflow-demo-history-capability-receipts', 'demo-history-capability-receipts', false]],
    'demo-activation-handoff': [[
      '/run/sentinelflow-demo-history-capability-receipts', 'demo-history-capability-receipts', false,
    ]],
    'demo-app': [['/var/lib/sentinelflow-auth-adapter', 'auth-state', true]],
    gateway: [
      ['/var/lib/sentinelflow-gateway', 'gateway-state', true],
      ['/run/sentinelflow-ready', 'executor-readiness', false],
    ],
    executor: [['/run/secrets/sentinelflow', 'executor-secrets', false],
      ['/run/sentinelflow-executor', 'executor-socket', true],
      ['/run/sentinelflow-ready', 'executor-readiness', true],
      ['/var/lib/sentinelflow-executor', 'executor-state', true]],
    validator: [['/run/sentinelflow-validator', 'validator-socket', true]],
    'demo-activator': [
      ['/run/secrets/sentinelflow-demo-history-analysis', 'demo-history-analysis-activation', false],
      ['/run/secrets/sentinelflow-demo-history-validation', 'demo-history-validation-activation', false],
    ],
    stubworker: [[
      '/run/secrets/sentinelflow-demo-history-analysis', 'demo-history-analysis-activation', false,
    ]],
    validationworker: [
      ['/run/secrets/sentinelflow-demo-history-validation', 'demo-history-validation-activation', false],
      ['/run/sentinelflow-validator', 'validator-socket', false],
    ],
    dispatcher: [['/run/secrets/sentinelflow', 'dispatcher-secrets', false],
      ['/run/sentinelflow-executor', 'executor-socket', false]],
    'secret-init': [
      ['/source', null, false], ['/volumes/auth-state', 'auth-state', true],
      ['/volumes/dispatcher-secrets', 'dispatcher-secrets', true],
      ['/volumes/executor-secrets', 'executor-secrets', true],
      ['/volumes/executor-socket', 'executor-socket', true],
      ['/volumes/executor-state', 'executor-state', true],
      ['/volumes/gateway-state', 'gateway-state', true],
      ['/volumes/readiness', 'executor-readiness', true],
      ['/volumes/validator-socket', 'validator-socket', true],
      ['/volumes/demo-history-capability-receipts', 'demo-history-capability-receipts', true],
      ['/volumes/demo-history-analysis-activation', 'demo-history-analysis-activation', true],
      ['/volumes/demo-history-validation-activation', 'demo-history-validation-activation', true],
    ],
  };
  const values = services.map((service, index) => ({
    Id: (index + 1).toString(16).padStart(64, '0'),
    Name: `/${project}-${service}-1`,
    Config: {
      Image: service === 'web' ? webImage : (['postgres', 'migrate', 'demo-activation-handoff'].includes(service) ? postgresImage :
        (service === 'prometheus' ? 'prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80' : backendImage)),
      Labels: { 'com.docker.compose.service': service, 'com.docker.compose.project': project },
      Env: ['PATH=/usr/bin', ...(sensitiveEnvironment[service] ?? []).map((key) => `${key}=redacted`)],
      User: users[service],
      Cmd: runtimeWrapperCommands[service] === undefined ? undefined : [...runtimeWrapperCommands[service]],
    },
    State: ['demo-activation-handoff', 'demo-activator', 'history-importer', 'migrate', 'secret-init'].includes(service) ?
      { Running: false, Status: 'exited', ExitCode: 0 } : { Running: true, Status: 'running', Health: { Status: 'healthy' } },
    HostConfig: {
      Binds: [], CapAdd: [], CapDrop: ['ALL'], DeviceRequests: [], Devices: [], NetworkMode: `${project}_default`,
      Privileged: false, ReadonlyRootfs: true, SecurityOpt: ['no-new-privileges:true'],
    },
    Mounts: (mounts[service] ?? []).map(([destination, source, rw]) => source === null ? {
      Type: 'bind', Destination: destination, Source: '/tmp/sentinelflow-demo-e2e.test/secrets', RW: rw,
    } : {
      Type: 'volume', Name: `${project}_${source}`, Destination: destination,
      Source: `/var/lib/docker/volumes/${project}_${source}/_data`, RW: rw,
    }),
    NetworkSettings: { Networks: Object.fromEntries(networks[service].map((network) => [`${project}_${network}`, {}])) },
  }));
  const gateway = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'gateway');
  const executor = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'executor');
  executor.HostConfig.CapAdd = ['NET_ADMIN'];
  executor.HostConfig.NetworkMode = `container:${gateway.Id}`;
  const validator = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'validator');
  const secretInit = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'secret-init');
  validator.HostConfig.CapAdd = ['NET_ADMIN'];
  validator.HostConfig.NetworkMode = 'none';
  secretInit.HostConfig.CapAdd = ['CHOWN', 'DAC_OVERRIDE', 'FOWNER'];
  secretInit.HostConfig.NetworkMode = 'none';
  const noneNetworkID = 'a'.repeat(64);
  const inertNoneNetwork = {
    IPAMConfig: null, Links: null, Aliases: null, DriverOpts: null, GwPriority: 0,
    NetworkID: noneNetworkID, EndpointID: '', Gateway: '', IPAddress: '', MacAddress: '', IPPrefixLen: 0,
    IPv6Gateway: '', GlobalIPv6Address: '', GlobalIPv6PrefixLen: 0, DNSNames: null,
  };
  secretInit.NetworkSettings.Networks = { none: structuredClone(inertNoneNetwork) };
  const noneNetworkInspection = { Id: noneNetworkID, Name: 'none', Driver: 'null', Containers: {} };
  const expected = { project, backendImage, postgresImage, webImage, noneNetworkID, noneNetworkInspection };
  assert.equal(validateRuntimeInspection(values, expected), true);
  for (const service of ['secret-init', 'gateway', 'executor', 'dispatcher']) {
    const wrapped = values.find(
      (value) => value.Config.Labels['com.docker.compose.service'] === service,
    );
    const original = [...wrapped.Config.Cmd];
    wrapped.Config.Cmd[1] = '-e';
    assert.throws(() => validateRuntimeInspection(values, expected), /runtime command drifted/);
    wrapped.Config.Cmd = [...original];
    wrapped.Config.Cmd[3] += 'exec /usr/local/bin/unreviewed\n';
    assert.throws(() => validateRuntimeInspection(values, expected), /runtime command drifted/);
    wrapped.Config.Cmd = original;
  }
  const stubworker = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'stubworker');
  stubworker.Config.Env.push('DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE=/forbidden');
  assert.throws(() => validateRuntimeInspection(values, expected), /sensitive environment ownership drifted/);
  stubworker.Config.Env.pop();
  const stubAnalysisMount = stubworker.Mounts[0];
  const stubAnalysisDestination = stubAnalysisMount.Destination;
  stubAnalysisMount.Destination = '/run/secrets/unreviewed-analysis-copy';
  assert.throws(() => validateRuntimeInspection(values, expected), /unauthorized authority mount/);
  stubAnalysisMount.Destination = stubAnalysisDestination;
  const stubAnalysisName = stubAnalysisMount.Name;
  const stubAnalysisSource = stubAnalysisMount.Source;
  stubAnalysisMount.Name = `${project}_demo-history-validation-activation`;
  stubAnalysisMount.Source =
    `/var/lib/docker/volumes/${project}_demo-history-validation-activation/_data`;
  assert.throws(() => validateRuntimeInspection(values, expected), /authority mount source drifted/);
  stubAnalysisMount.Name = stubAnalysisName;
  stubAnalysisMount.Source = stubAnalysisSource;
  stubAnalysisMount.Name = `sf-demo-e2e-other_demo-history-analysis-activation`;
  assert.throws(() => validateRuntimeInspection(values, expected), /authority mount source drifted/);
  stubAnalysisMount.Name = stubAnalysisName;
  stubAnalysisMount.RW = true;
  assert.throws(() => validateRuntimeInspection(values, expected), /authority mount mode drifted/);
  stubAnalysisMount.RW = false;
  const demoApp = values.find((value) =>
    value.Config.Labels['com.docker.compose.service'] === 'demo-app');
  const authStateMount = demoApp.Mounts[0];
  const authStateDestination = authStateMount.Destination;
  authStateMount.Destination = '/var/lib/sentinelflow-auth-adapter-alias';
  assert.throws(() => validateRuntimeInspection(values, expected), /unauthorized authority mount/);
  authStateMount.Destination = authStateDestination;
  const authStateName = authStateMount.Name;
  const authStateSource = authStateMount.Source;
  authStateMount.Name = `${project}_gateway-state`;
  authStateMount.Source = `/var/lib/docker/volumes/${project}_gateway-state/_data`;
  assert.throws(() => validateRuntimeInspection(values, expected), /authority mount source drifted/);
  authStateMount.Name = authStateName;
  authStateMount.Source = authStateSource;
  authStateMount.RW = false;
  assert.throws(() => validateRuntimeInspection(values, expected), /authority mount mode drifted/);
  authStateMount.RW = true;
  const api = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'api');
  api.Mounts.push({
    Type: 'volume', Name: `${project}_auth-state`,
    Destination: '/var/lib/sentinelflow-auth-adapter-copy',
    Source: `/var/lib/docker/volumes/${project}_auth-state/_data`, RW: true,
  });
  assert.throws(() => validateRuntimeInspection(values, expected), /unauthorized authority mount/);
  api.Mounts.pop();
  api.Mounts.push({
    Type: 'volume', Name: `${project}_demo-history-analysis-activation`,
    Destination: '/run/secrets/unreviewed-analysis-copy',
    Source: `/var/lib/docker/volumes/${project}_demo-history-analysis-activation/_data`, RW: false,
  });
  assert.throws(() => validateRuntimeInspection(values, expected), /unauthorized authority mount/);
  api.Mounts.pop();
  const validationworker = values.find(
    (value) => value.Config.Labels['com.docker.compose.service'] === 'validationworker',
  );
  validationworker.Config.Env.push('DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE=/forbidden');
  assert.throws(() => validateRuntimeInspection(values, expected), /sensitive environment ownership drifted/);
  validationworker.Config.Env.pop();
  secretInit.NetworkSettings.Networks = {};
  assert.equal(validateRuntimeInspection(values, expected), true);
  secretInit.NetworkSettings.Networks = { none: structuredClone(inertNoneNetwork) };
  secretInit.NetworkSettings.Networks.none.NetworkID = '';
  assert.throws(() => validateRuntimeInspection(values, expected), /none network ID does not match the engine/);
  secretInit.NetworkSettings.Networks.none.NetworkID = noneNetworkID;
  const missingNoneNetworkID = { project, backendImage, postgresImage, webImage, noneNetworkInspection };
  assert.throws(() => validateRuntimeInspection(values, missingNoneNetworkID), /runtime expectation shape is invalid/);
  assert.throws(() => validateRuntimeInspection(values, { ...expected, noneNetworkID: 'b'.repeat(64) }),
    /none network identity drifted/);
  assert.throws(() => validateRuntimeInspection(values, { ...expected, noneNetworkID: 'bad' }),
    /runtime Docker none network ID is invalid/);

  const validatorEndpointID = 'b'.repeat(64);
  validator.NetworkSettings.Networks = {
    none: { ...structuredClone(inertNoneNetwork), EndpointID: validatorEndpointID },
  };
  noneNetworkInspection.Containers[validator.Id] = {
    Name: validator.Name.slice(1), EndpointID: validatorEndpointID,
    MacAddress: '', IPv4Address: '', IPv6Address: '',
  };
  assert.equal(validateRuntimeInspection(values, expected), true);
  noneNetworkInspection.Containers[validator.Id].EndpointID = 'c'.repeat(64);
  assert.throws(() => validateRuntimeInspection(values, expected), /membership is not inert or digest-bound/);
  noneNetworkInspection.Containers[validator.Id].EndpointID = validatorEndpointID;
  noneNetworkInspection.Containers[validator.Id].IPv4Address = '172.16.0.2/32';
  assert.throws(() => validateRuntimeInspection(values, expected), /membership is not inert or digest-bound/);
  noneNetworkInspection.Containers[validator.Id].IPv4Address = '';
  validator.NetworkSettings.Networks.none.EndpointID = 'B'.repeat(64);
  assert.throws(() => validateRuntimeInspection(values, expected), /endpoint ID is invalid/);
  validator.NetworkSettings.Networks.none.EndpointID = validatorEndpointID;
  secretInit.NetworkSettings.Networks.none.EndpointID = 'd'.repeat(64);
  assert.throws(() => validateRuntimeInspection(values, expected), /exited with a Docker none network endpoint/);
  secretInit.NetworkSettings.Networks.none.EndpointID = '';
  delete noneNetworkInspection.Containers[validator.Id];
  assert.throws(() => validateRuntimeInspection(values, expected), /endpoint membership is missing/);
  validator.NetworkSettings.Networks = {};
  assert.equal(validateRuntimeInspection(values, expected), true);

  for (const [field, invalidValue] of [
    ['Id', 'c'.repeat(64)], ['Name', 'bridge'], ['Driver', 'bridge'],
  ]) {
    const original = noneNetworkInspection[field];
    noneNetworkInspection[field] = invalidValue;
    assert.throws(() => validateRuntimeInspection(values, expected), /none network identity drifted/);
    noneNetworkInspection[field] = original;
  }

  const invalidNoneFields = {
    IPAMConfig: {}, Links: [], Aliases: [], DriverOpts: {}, GwPriority: 1,
    Gateway: '172.16.0.1',
    IPAddress: '172.16.0.2', MacAddress: '02:42:ac:10:00:02', IPPrefixLen: 24,
    IPv6Gateway: '2001:db8::1', GlobalIPv6Address: '2001:db8::2', GlobalIPv6PrefixLen: 64,
    DNSNames: ['secret-init'],
  };
  for (const [field, invalidValue] of Object.entries(invalidNoneFields)) {
    secretInit.NetworkSettings.Networks.none[field] = invalidValue;
    assert.throws(() => validateRuntimeInspection(values, expected), /inert none network is not empty/);
    secretInit.NetworkSettings.Networks.none[field] = inertNoneNetwork[field];
  }
  secretInit.NetworkSettings.Networks = { bridge: structuredClone(inertNoneNetwork) };
  assert.throws(() => validateRuntimeInspection(values, expected), /network isolation drifted/);
  secretInit.NetworkSettings.Networks = {
    none: structuredClone(inertNoneNetwork), unexpected: structuredClone(inertNoneNetwork),
  };
  assert.throws(() => validateRuntimeInspection(values, expected), /network isolation drifted/);
  secretInit.NetworkSettings.Networks = { none: { ...inertNoneNetwork, Unexpected: null } };
  assert.throws(() => validateRuntimeInspection(values, expected), /inert none network shape is invalid/);
  secretInit.NetworkSettings.Networks = { none: structuredClone(inertNoneNetwork) };

  gateway.HostConfig.CapAdd = ['NET_ADMIN'];
  assert.throws(() => validateRuntimeInspection(values, expected), /gateway added capabilities drifted/);
  gateway.HostConfig.CapAdd = [];
  api.HostConfig.NetworkMode = `container:${gateway.Id}`;
  assert.throws(() => validateRuntimeInspection(values, expected), /api network mode drifted/);
  api.HostConfig.NetworkMode = `${project}_default`;
  api.Config.Env.push('DISPATCHER_SIGNING_PRIVATE_KEY_FILE=/forbidden');
  assert.throws(() => validateRuntimeInspection(values, expected), /sensitive environment ownership drifted/);
  api.Config.Env.pop();
  api.Mounts.push({
    Type: 'bind', Destination: '/run/secrets/sentinelflow', Source: '/forbidden', RW: false,
  });
  assert.throws(() => validateRuntimeInspection(values, expected), /unauthorized authority mount/);
  api.Mounts.pop();
  validator.HostConfig.NetworkMode = `${project}_control`;
  assert.throws(() => validateRuntimeInspection(values, expected), /validator network isolation drifted/);
  validator.HostConfig.NetworkMode = 'none';
  const dispatcher = values.find((value) => value.Config.Labels['com.docker.compose.service'] === 'dispatcher');
  dispatcher.Config.Env = dispatcher.Config.Env.filter((entry) => !entry.startsWith('DISPATCHER_SIGNING_PRIVATE_KEY_FILE='));
  assert.throws(() => validateRuntimeInspection(values, expected), /sensitive environment ownership drifted/);
});

test('detection diagnostics expose only bounded source, worker, and aggregate summaries', () => {
  const sources = [
    '203.0.113.20', '203.0.113.21', '203.0.113.22', '203.0.113.23', '203.0.113.24',
  ].map((sourceIPv4) => ({
    source_ipv4: sourceIPv4,
    gateway_event_count: 0,
    auth_event_count: 0,
    suspicious_path_ids: [],
    gateway_batch_shapes: [],
    detect_outbox: [],
    signals: [],
    incidents: [],
    pipeline_incidents: [],
    evaluation_time: null,
    gateway_coverage_start: null,
    auth_coverage_start: null,
    exact_gateway_coverage_batch_count: 0,
  }));
  sources[2] = {
    ...sources[2],
    gateway_event_count: 8,
    suspicious_path_ids: [{ id: 'admin_console', count: 1 }],
    gateway_batch_shapes: [{ event_count: 100, has_exact_coverage: false, count: 1 }],
    detect_outbox: [{
      aggregate_type: 'ingest_batch', state: 'retry', attempts: 2, max_attempts: 8,
      last_error_code: 'detection_source_coverage_incomplete', count: 1,
    }],
    signals: [{ kind: 'path_scan', source_health_status: 'complete', count: 1 }],
    incidents: [{ kind: 'path_scan', state: 'review_ready', count: 1 }],
    pipeline_incidents: [],
    evaluation_time: '2026-07-18T23:16:35.123Z',
    gateway_coverage_start: '2026-07-18T23:16:00.000Z',
    auth_coverage_start: '2026-07-18T23:16:00.000Z',
    exact_gateway_coverage_batch_count: 1,
  };
  sources[2].pipeline_incidents = [{
    incident_id: uuid('200'),
    kind: 'path_scan',
    state: 'review_ready',
    version: 3,
    evidence_version: 1,
    analyze_outbox: [{
      job_id: uuid('201'), aggregate_version: 1, state: 'completed', attempts: 1,
      max_attempts: 8, last_error_code: null,
    }],
    analysis_attempts: [{
      analysis_id: uuid('202'), incident_version: 1, outbox_attempt: 1,
      claim_state: 'succeeded', claim_failure_code: null,
      result_state: 'succeeded', result_failure_code: null,
    }],
    validate_outbox: [{
      job_id: uuid('203'), aggregate_version: 1, state: 'completed', attempts: 1,
      max_attempts: 8, last_error_code: null,
    }],
    validation_attempts: [{
      validation_attempt_id: uuid('204'), incident_version: 1, outbox_attempt: 1,
      claim_state: 'valid', claim_failure_code: null,
      result_state: 'valid', result_failure_code: null, failed_gate: null,
    }],
    policies: [{
      policy_id: uuid('205'), version: 1, incident_version: 1, state: 'valid', state_revision: 3,
      validation_snapshots: [{
        validation_snapshot_id: uuid('206'), state: 'valid', failure_code: null,
        gates: [
          'structured_output', 'command_grammar', 'policy_evidence_command_consistency',
          'protected_network', 'owned_schema_syntax', 'historical_impact',
        ].map((name, index) => ({ order: index + 1, name, passed: true, result_code: 'ok' })),
      }],
    }],
  }];
  const database = {
    schema_version: 'sentinelflow-demo-e2e-detection-diagnostic-v3', sources,
  };
  const detector = { running: true, restart_count: 0 };
  const validationworker = { running: true, restart_count: 2 };
  const summary = validateDetectionDiagnostic(database, detector, validationworker, 'after-path_scan');
  assert.equal(summary.stage, 'after-path_scan');
  assert.deepEqual(summary.detector, detector);
  assert.deepEqual(summary.validationworker, validationworker);
  assert.equal(summary.sources[2].gateway_event_count, 8);
  assert.equal(summary.sources[2].pipeline_incidents[0].analysis_attempts[0].result_state, 'succeeded');
  assert.equal(summary.sources[2].pipeline_incidents[0].policies[0]
    .validation_snapshots[0].gates.length, 6);

  const leaked = structuredClone(database);
  leaked.sources[2].raw_headers = { authorization: 'forbidden' };
  assert.throws(() => validateDetectionDiagnostic(
    leaked, detector, validationworker, 'failure-approve'), /shape is invalid/);
  const badError = structuredClone(database);
  badError.sources[2].detect_outbox[0].last_error_code = 'secret=value';
  assert.throws(() => validateDetectionDiagnostic(
    badError, detector, validationworker, 'failure-approve'), /error code is invalid/);
  const leakedPipeline = structuredClone(database);
  leakedPipeline.sources[2].pipeline_incidents[0].analysis_attempts[0].raw_output = 'forbidden';
  assert.throws(() => validateDetectionDiagnostic(
    leakedPipeline, detector, validationworker, 'failure-approve'),
    /analysis attempts 0 shape is invalid/);
  const invalidGateCode = structuredClone(database);
  invalidGateCode.sources[2].pipeline_incidents[0].policies[0]
    .validation_snapshots[0].gates[5].result_code = 'reason=forbidden';
  assert.throws(() => validateDetectionDiagnostic(
    invalidGateCode, detector, validationworker, 'failure-approve'),
    /result code is invalid/);
  const excessiveAttempts = structuredClone(database);
  excessiveAttempts.sources[2].pipeline_incidents[0].analysis_attempts = Array.from(
    { length: 17 }, () => structuredClone(database.sources[2].pipeline_incidents[0].analysis_attempts[0]),
  );
  assert.throws(() => validateDetectionDiagnostic(
    excessiveAttempts, detector, validationworker, 'failure-approve'),
    /analysis attempts is invalid/);
  const unsortedIncidents = structuredClone(database);
  const secondIncident = structuredClone(unsortedIncidents.sources[2].pipeline_incidents[0]);
  secondIncident.incident_id = uuid('199');
  secondIncident.analyze_outbox = [];
  secondIncident.analysis_attempts = [];
  secondIncident.validate_outbox = [];
  secondIncident.validation_attempts = [];
  secondIncident.policies = [];
  unsortedIncidents.sources[2].pipeline_incidents.push(secondIncident);
  assert.throws(() => validateDetectionDiagnostic(
    unsortedIncidents, detector, validationworker, 'failure-approve'),
    /pipeline incidents IDs are not sorted and unique/);
  assert.throws(() => validateDetectionDiagnostic(
    database, { running: true, restart_count: -1 }, validationworker, 'failure-approve'),
    /restart count is invalid/);
  assert.throws(() => validateDetectionDiagnostic(
    database, detector, { running: true, restart_count: -1 }, 'failure-approve'),
  /validationworker restart count is invalid/);
  assert.throws(() => validateDetectionDiagnostic(
    database, detector, { ...validationworker, container_id: 'forbidden' }, 'failure-approve'),
  /validationworker shape is invalid/);
  assert.throws(() => validateDetectionDiagnostic(
    { ...database, schema_version: 'sentinelflow-demo-e2e-detection-diagnostic-v2' },
    detector, validationworker, 'failure-approve'),
  /schema drifted/);
});

test('detection pipeline diagnostics preserve bounded terminal failure codes without raw failure content', () => {
  const source = (sourceIPv4) => ({
    source_ipv4: sourceIPv4, gateway_event_count: 0, auth_event_count: 0,
    suspicious_path_ids: [], gateway_batch_shapes: [], detect_outbox: [], signals: [], incidents: [],
    pipeline_incidents: [], evaluation_time: null, gateway_coverage_start: null,
    auth_coverage_start: null, exact_gateway_coverage_batch_count: 0,
  });
  const sources = [
    '203.0.113.20', '203.0.113.21', '203.0.113.22', '203.0.113.23', '203.0.113.24',
  ].map(source);
  sources[4].pipeline_incidents = [{
    incident_id: uuid('220'), kind: 'brute_force', state: 'analysis_failed', version: 2,
    evidence_version: 1,
    analyze_outbox: [{
      job_id: uuid('221'), aggregate_version: 1, state: 'retry', attempts: 2,
      max_attempts: 8, last_error_code: 'analysis_timeout',
    }],
    analysis_attempts: [{
      analysis_id: uuid('222'), incident_version: 1, outbox_attempt: 2,
      claim_state: 'failed', claim_failure_code: null,
      result_state: 'failed', result_failure_code: 'timeout',
    }],
    validate_outbox: [{
      job_id: uuid('223'), aggregate_version: 1, state: 'dead', attempts: 8,
      max_attempts: 8, last_error_code: 'protected_network_denied',
    }],
    validation_attempts: [{
      validation_attempt_id: uuid('224'), incident_version: 1, outbox_attempt: 8,
      claim_state: 'invalid', claim_failure_code: 'protected_network_denied',
      result_state: 'invalid', result_failure_code: 'protected_network_denied',
      failed_gate: 'protected_network',
    }],
    policies: [{
      policy_id: uuid('225'), version: 1, incident_version: 1, state: 'invalid', state_revision: 3,
      validation_snapshots: [{
        validation_snapshot_id: uuid('226'), state: 'invalid',
        failure_code: 'protected_network_denied',
        gates: [
          { order: 1, name: 'structured_output', passed: true, result_code: 'ok' },
          { order: 2, name: 'command_grammar', passed: true, result_code: 'ok' },
          { order: 3, name: 'policy_evidence_command_consistency', passed: true, result_code: 'ok' },
          { order: 4, name: 'protected_network', passed: false, result_code: 'protected_network_denied' },
        ],
      }],
    }],
  }];
  const summary = validateDetectionDiagnostic({
    schema_version: 'sentinelflow-demo-e2e-detection-diagnostic-v3', sources,
  }, { running: true, restart_count: 0 }, { running: false, restart_count: 3 },
  'failure-validation');
  const pipeline = summary.sources[4].pipeline_incidents[0];
  assert.equal(pipeline.analysis_attempts[0].result_failure_code, 'timeout');
  assert.equal(pipeline.validation_attempts[0].failed_gate, 'protected_network');
  assert.equal(pipeline.policies[0].validation_snapshots[0].gates[3].result_code,
    'protected_network_denied');

  const reasonLeak = structuredClone({
    schema_version: 'sentinelflow-demo-e2e-detection-diagnostic-v3', sources,
  });
  reasonLeak.sources[4].pipeline_incidents[0].validation_attempts[0].failure_reason = 'raw text';
  assert.throws(() => validateDetectionDiagnostic(
    reasonLeak, { running: true, restart_count: 0 }, { running: false, restart_count: 3 },
    'failure-validation'),
  /validation attempts 0 shape is invalid/);
});

test('detection diagnostic SQL projects only bounded pipeline state and controlled failure codes', () => {
  const helperSource = readFileSync(new URL('./demo-e2e.mjs', import.meta.url), 'utf8');
  const start = helperSource.indexOf('const DETECTION_DIAGNOSTIC_SQL = `');
  const end = helperSource.indexOf('\n`;\n\nasync function readNDJSON', start);
  assert.ok(start >= 0 && end > start, 'detection diagnostic SQL must remain independently inspectable');
  const sql = helperSource.slice(start, end);
  for (const table of [
    'analysis_attempt_claims', 'analysis_attempt_results', 'validation_attempt_claims',
    'validation_attempt_results', 'policy_proposals', 'validation_snapshots', 'validation_gates',
  ]) {
    assert.match(sql, new RegExp(`sentinelflow\\.${table}`));
  }
  for (const field of [
    'analyze_outbox', 'analysis_attempts', 'validate_outbox', 'validation_attempts',
    'claim_failure_code', 'result_failure_code', 'failed_gate', 'validation_snapshots',
    'result_code',
  ]) {
    assert.match(sql, new RegExp(`'${field}'`));
  }
  assert.ok((sql.match(/LIMIT 16/g) ?? []).length >= 7,
    'every per-incident diagnostic collection must be bounded');
  assert.match(sql, /ORDER BY gate_order LIMIT 6/);
  assert.doesNotMatch(sql,
    /terminal_mutation|prepared_snapshot(?:_digest)?|provider_response_id|policy_output|command_candidate_output|rationale|generated_command|canonical_artifact|input_bytes|output_digest/);
});

test('evidence chain SQL uses a non-reserved authorization alias and unique signature fields', () => {
  const helperSource = readFileSync(new URL('./demo-e2e.mjs', import.meta.url), 'utf8');
  const start = helperSource.indexOf('const EVIDENCE_CHAIN_SQL = `');
  const end = helperSource.indexOf('\n`;\n\nconst COVERAGE_READINESS_SQL', start);
  assert.ok(start >= 0 && end > start, 'evidence chain SQL must remain independently inspectable');
  const sql = helperSource.slice(start, end);

  assert.match(sql, /\('add', :'add_job'::uuid\)/);
  assert.match(sql, /\('revoke', NULLIF\(:'revoke_job', ''\)::uuid\)/);
  assert.match(sql, /SELECT selector, job_id FROM candidates WHERE job_id IS NOT NULL/);
  assert.match(sql, /JOIN enforcement_authorizations authz\s+ON authz\.authorization_id/);
  assert.doesNotMatch(sql, /\bauthorization\./,
    'authorization is a PostgreSQL keyword and must not be used as an unquoted relation alias');

  const capabilityJSON = sql.slice(
    sql.indexOf("'capability', json_build_object("),
    sql.indexOf("'result', json_build_object("),
  );
  const resultJSON = sql.slice(
    sql.indexOf("'result', json_build_object("),
    sql.indexOf("'application', json_build_object("),
  );
  assert.equal((capabilityJSON.match(/'signature_bytes'/g) ?? []).length, 1);
  assert.equal((resultJSON.match(/'signature_bytes'/g) ?? []).length, 1);
});

test('frozen credential-stuffing source retains both signals and correlates to one mixed incident', () => {
  const helperSource = readFileSync(new URL('./demo-e2e.mjs', import.meta.url), 'utf8');
  assert.match(helperSource, /\['203\.0\.113\.20', 'mixed'\]/);
  assert.match(helperSource,
    /credential-stuffing plan crosses both exact-login brute-force[\s\S]*?without dropping either deterministic signal/);

  const diagnosticSource = (sourceIPv4) => ({
    source_ipv4: sourceIPv4,
    gateway_event_count: 0,
    auth_event_count: 0,
    suspicious_path_ids: [],
    gateway_batch_shapes: [],
    detect_outbox: [],
    signals: [],
    incidents: [],
    pipeline_incidents: [],
    evaluation_time: null,
    gateway_coverage_start: null,
    auth_coverage_start: null,
    exact_gateway_coverage_batch_count: 0,
  });
  const sources = [
    '203.0.113.20', '203.0.113.21', '203.0.113.22', '203.0.113.23', '203.0.113.24',
  ].map(diagnosticSource);
  sources[0].signals = [
    { kind: 'brute_force', source_health_status: 'complete', count: 1 },
    { kind: 'credential_stuffing', source_health_status: 'complete', count: 1 },
  ];
  sources[0].incidents = [{ kind: 'mixed', state: 'review_ready', count: 1 }];
  const summary = validateDetectionDiagnostic({
    schema_version: 'sentinelflow-demo-e2e-detection-diagnostic-v3', sources,
  }, { running: true, restart_count: 0 }, { running: true, restart_count: 0 },
  'after-credential-stuffing');
  assert.deepEqual(summary.sources[0].signals.map((signal) => signal.kind),
    ['brute_force', 'credential_stuffing']);
  assert.deepEqual(summary.sources[0].incidents, [{ kind: 'mixed', state: 'review_ready', count: 1 }]);
});

function readyDetectionStabilitySnapshot(observedAt) {
  const expectedKinds = new Map([
    ['203.0.113.20', 'mixed'],
    ['203.0.113.22', 'path_scan'],
    ['203.0.113.23', 'request_burst'],
    ['203.0.113.24', 'brute_force'],
  ]);
  let ordinal = 121;
  const sources = [
    '203.0.113.20', '203.0.113.21', '203.0.113.22', '203.0.113.23', '203.0.113.24',
  ].map((sourceIPv4) => {
    const kind = expectedKinds.get(sourceIPv4);
    if (kind === undefined) {
      return { source_ipv4: sourceIPv4, active_detect_jobs: 0, dead_detect_jobs: 0, incidents: [] };
    }
    const incidentID = uuid(String(ordinal));
    ordinal += 1;
    const policyID = uuid(String(ordinal));
    ordinal += 1;
    return {
      source_ipv4: sourceIPv4,
      active_detect_jobs: 0,
      dead_detect_jobs: 0,
      incidents: [{
        incident_id: incidentID,
        kind,
        state: 'review_ready',
        version: 4,
        evidence_version: 2,
        signal_count: kind === 'mixed' ? 2 : 1,
        policies: [{
          policy_id: policyID,
          version: 1,
          incident_version: 2,
          state: sourceIPv4 === '203.0.113.20' ? 'valid' : 'invalid',
          state_revision: 3,
          policy_digest: digest('d'),
          evidence_snapshot_digest: digest('e'),
        }],
      }],
    };
  });
  return {
    schema_version: 'sentinelflow-demo-e2e-detection-stability-v1',
    observed_at: observedAt,
    sources,
  };
}

test('detection stability requires drained jobs and unchanged current incident-policy bindings', () => {
  const first = readyDetectionStabilitySnapshot('2026-07-19T02:00:00.000Z');
  const second = readyDetectionStabilitySnapshot('2026-07-19T02:00:02.000Z');
  assert.equal(validateDetectionStability(first).ready, true);
  assert.equal(validateDetectionStability(first).failed, false);
  assert.equal(detectionStabilityAdvanced(first, second), true);
  assert.equal(detectionStabilityAdvanced(second, first), false);

  const pending = structuredClone(second);
  pending.sources[0].active_detect_jobs = 1;
  assert.equal(validateDetectionStability(pending).ready, false);
  assert.equal(detectionStabilityAdvanced(first, pending), false);

  const dead = structuredClone(second);
  dead.sources[0].dead_detect_jobs = 1;
  assert.equal(validateDetectionStability(dead).failed, true);
  assert.equal(validateDetectionStability(dead).ready, false);

  const lifecycleOnly = structuredClone(second);
  lifecycleOnly.sources[0].incidents[0].version += 1;
  assert.equal(validateDetectionStability(lifecycleOnly).ready, false);
  assert.equal(detectionStabilityAdvanced(first, lifecycleOnly), false);

  const lifecycleRollback = structuredClone(second);
  lifecycleRollback.sources[0].incidents[0].version -= 1;
  assert.equal(validateDetectionStability(lifecycleRollback).ready, false);
  assert.equal(detectionStabilityAdvanced(first, lifecycleRollback), false);

  const changedEvidence = structuredClone(second);
  changedEvidence.sources[0].incidents[0].version += 1;
  changedEvidence.sources[0].incidents[0].evidence_version += 1;
  changedEvidence.sources[0].incidents[0].policies[0].incident_version += 1;
  assert.equal(validateDetectionStability(changedEvidence).ready, true);
  assert.equal(detectionStabilityAdvanced(first, changedEvidence), false);

  const mismatchedPolicy = structuredClone(second);
  mismatchedPolicy.sources[0].incidents[0].evidence_version += 1;
  assert.throws(() => validateDetectionStability(mismatchedPolicy), /evidence version drifted/);

  const missingEvidenceVersion = structuredClone(second);
  missingEvidenceVersion.sources[0].incidents[0].evidence_version = null;
  missingEvidenceVersion.sources[0].incidents[0].policies = [];
  assert.equal(validateDetectionStability(missingEvidenceVersion).ready, false);

  const futureEvidenceVersion = structuredClone(second);
  futureEvidenceVersion.sources[0].incidents[0].evidence_version = 5;
  assert.throws(() => validateDetectionStability(futureEvidenceVersion), /evidence version is invalid/);

  const stalePolicy = structuredClone(second);
  stalePolicy.sources[0].incidents[0].policies[0].state = 'stale';
  assert.equal(validateDetectionStability(stalePolicy).ready, false);

  const unexpectedNormalIncident = structuredClone(second);
  unexpectedNormalIncident.sources[1].incidents = structuredClone(second.sources[0].incidents);
  assert.equal(validateDetectionStability(unexpectedNormalIncident).ready, false);

  const leaked = structuredClone(second);
  leaked.sources[0].raw_evidence = 'forbidden';
  assert.throws(() => validateDetectionStability(leaked), /shape is invalid/);
});

test('cold-start coverage readiness is watermark-bound and fails closed for every blocker', () => {
  const endpoint = (endpointKind, overrides = {}) => ({
    endpoint_kind: endpointKind,
    expected_source_count: 1,
    active_source_count: 1,
    represented_source_count: 1,
    rotation_source_count: 0,
    binding_digests: [digest(endpointKind === 'auth' ? 'a' : 'b')],
    current_binding_digests: [digest(endpointKind === 'auth' ? 'a' : 'b')],
    detector_coverage_start: '2026-07-19T01:00:00.000Z',
    latest_coverage_end: '2026-07-19T01:05:05.000Z',
    unresolved_gap_count: 0,
    blocking_health_count: 0,
    ready: true,
    ...overrides,
  });
  const ready = {
    schema_version: 'sentinelflow-demo-e2e-coverage-readiness-v2',
    service_label: 'demo-app',
    detector_window_seconds: 300,
    readiness_margin_seconds: 5,
    required_coverage_seconds: 305,
    common_watermark: '2026-07-19T01:05:05.000Z',
    required_coverage_start: '2026-07-19T01:00:00.000Z',
    endpoints: [endpoint('auth'), endpoint('gateway', {
      detector_coverage_start: '2026-07-19T00:59:59.000Z',
      latest_coverage_end: '2026-07-19T01:05:06.000Z',
    })],
    ready: true,
  };
  assert.equal(validateCoverageReadiness(ready).ready, true);

  const blockers = [
    ['binding rotation', { rotation_source_count: 1 }],
    ['multiple active bindings', {
      active_source_count: 2, represented_source_count: 2,
      binding_digests: [digest('a'), digest('c')], current_binding_digests: [digest('a'), digest('c')],
    }],
    ['partial multiple-source coverage', {
      active_source_count: 2, represented_source_count: 1,
      binding_digests: [digest('a'), digest('c')], current_binding_digests: [digest('a'), digest('c')],
      detector_coverage_start: null,
    }],
    ['current binding generation drift', { current_binding_digests: [digest('c')] }],
    ['missing binding', {
      active_source_count: 0, represented_source_count: 0,
      binding_digests: [], current_binding_digests: [],
      detector_coverage_start: null, latest_coverage_end: null,
    }],
    ['unresolved gap', { unresolved_gap_count: 1 }],
    ['blocking health', { blocking_health_count: 1 }],
    ['insufficient 305-second age', { detector_coverage_start: '2026-07-19T01:00:00.001Z' }],
  ];
  for (const [label, override] of blockers) {
    const waiting = structuredClone(ready);
    waiting.endpoints[0] = endpoint('auth', { ...override, ready: false });
    waiting.ready = false;
    assert.equal(validateCoverageReadiness(waiting).ready, false, label);
  }

  const inconsistent = structuredClone(ready);
  inconsistent.endpoints[0].unresolved_gap_count = 1;
  assert.throws(() => validateCoverageReadiness(inconsistent), /readiness is inconsistent/);
  const leaked = structuredClone(ready);
  leaked.endpoints[0].binding_id = uuid('120');
  assert.throws(() => validateCoverageReadiness(leaked), /shape is invalid/);
  const clockDerived = structuredClone(ready);
  clockDerived.required_coverage_start = '2026-07-19T01:00:00.001Z';
  assert.throws(() => validateCoverageReadiness(clockDerived), /window is invalid/);
  const unsortedBindings = structuredClone(ready);
  unsortedBindings.endpoints[0].binding_digests = [digest('c'), digest('a')];
  unsortedBindings.endpoints[0].active_source_count = 2;
  unsortedBindings.endpoints[0].represented_source_count = 2;
  unsortedBindings.endpoints[0].current_binding_digests = [digest('a'), digest('c')];
  unsortedBindings.endpoints[0].ready = false;
  unsortedBindings.ready = false;
  assert.throws(() => validateCoverageReadiness(unsortedBindings), /not sorted and unique/);
});

function readyCoverageSnapshot(watermark, overrides = {}) {
  const watermarkMS = Date.parse(watermark);
  const requiredStart = new Date(watermarkMS - 305_000).toISOString();
  const endpoint = (endpointKind) => {
    const binding = overrides[`${endpointKind}Binding`] ?? digest(endpointKind === 'auth' ? 'a' : 'b');
    return {
      endpoint_kind: endpointKind,
      expected_source_count: 1,
      active_source_count: 1,
      represented_source_count: 1,
      rotation_source_count: 0,
      binding_digests: [binding],
      current_binding_digests: [binding],
      detector_coverage_start: requiredStart,
      latest_coverage_end: overrides[`${endpointKind}End`] ?? watermark,
      unresolved_gap_count: 0,
      blocking_health_count: 0,
      ready: true,
    };
  };
  return {
    schema_version: 'sentinelflow-demo-e2e-coverage-readiness-v2',
    service_label: 'demo-app',
    detector_window_seconds: 300,
    readiness_margin_seconds: 5,
    required_coverage_seconds: 305,
    common_watermark: watermark,
    required_coverage_start: requiredStart,
    endpoints: [endpoint('auth'), endpoint('gateway')],
    ready: true,
  };
}

test('coverage freshness requires both endpoints and the common watermark to advance on one binding generation', () => {
  const first = readyCoverageSnapshot('2026-07-19T01:05:05.000Z');
  const advanced = readyCoverageSnapshot('2026-07-19T01:05:06.000Z');
  const regressed = readyCoverageSnapshot('2026-07-19T01:05:04.999Z');
  assert.equal(coverageReadinessAdvanced(first, advanced), true);
  assert.equal(coverageReadinessAdvanced(first, structuredClone(first)), false);
  assert.equal(coverageReadinessAdvanced(first, regressed), false);

  const firstWithGatewayAhead = readyCoverageSnapshot('2026-07-19T01:05:05.000Z', {
    gatewayEnd: '2026-07-19T01:05:20.000Z',
  });
  const onlyAuthAdvanced = readyCoverageSnapshot('2026-07-19T01:05:06.000Z', {
    gatewayEnd: '2026-07-19T01:05:20.000Z',
  });
  assert.equal(coverageReadinessAdvanced(firstWithGatewayAhead, onlyAuthAdvanced), false);
  const rotated = readyCoverageSnapshot('2026-07-19T01:05:06.000Z', { gatewayBinding: digest('c') });
  assert.equal(coverageReadinessAdvanced(first, rotated), false);

  const missing = structuredClone(advanced);
  missing.common_watermark = null;
  missing.required_coverage_start = null;
  missing.endpoints = missing.endpoints.map((endpoint) => ({
    ...endpoint, active_source_count: 0, represented_source_count: 0,
    binding_digests: [], current_binding_digests: [],
    detector_coverage_start: null, latest_coverage_end: null, ready: false,
  }));
  missing.ready = false;
  assert.equal(coverageReadinessAdvanced(first, missing), false);

  const malformed = structuredClone(advanced);
  malformed.endpoints[0].binding_id = uuid('121');
  assert.throws(() => coverageReadinessAdvanced(first, malformed), /shape is invalid/);
  const invalidTime = structuredClone(advanced);
  invalidTime.common_watermark = 'not-a-timestamp';
  assert.throws(() => coverageReadinessAdvanced(first, invalidTime), /common watermark is invalid/);
});

test('browser QA locator is exact, private, action-bound, and secret-free', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'sentinelflow-browser-qa-test.'));
  t.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const secrets = path.join(root, 'secrets');
  await mkdir(secrets, { mode: 0o700 });
  const credentialsFile = path.join(secrets, 'admin-credentials.json');
  const stateFile = path.join(root, 'e2e-state.json');
  const output = path.join(root, 'browser-qa-active-locator.json');
  const stopFile = path.join(root, 'browser-qa-active.stop');
  const credentialSecret = 'browser-qa-password-must-not-leak';
  await writeFile(credentialsFile, `${JSON.stringify({ username: 'admin', password: credentialSecret })}\n`, {
    mode: 0o600, flag: 'wx',
  });
  const state = journalFixtureState('release_expiry');
  await writeFile(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600, flag: 'wx' });
  const startedAt = Date.now();
  const locator = await writeBrowserQALocator({
    output, root, project: 'sf-demo-e2e-browserqa-1234', webPort: 4173,
    phase: 'active', credentialsFile, stateFile, holdSeconds: 60, stopFile,
  });
  const finishedAt = Date.now();
  const expected = {
    root, project: 'sf-demo-e2e-browserqa-1234', phase: 'active', web_port: 4173,
    credentials_file: credentialsFile, action_id: state.action.action_id,
    expected_action_state: 'active', deadline: locator.deadline, stop_file: stopFile,
  };
  assert.deepEqual(validateBrowserQALocator(locator, expected), locator);
  assert.ok(Date.parse(locator.deadline) >= startedAt + 60_000 &&
    Date.parse(locator.deadline) <= finishedAt + 60_000);
  const raw = await readFile(output, 'utf8');
  assert.equal(raw, `${canonicalJSON(locator)}\n`);
  assert.doesNotMatch(raw, new RegExp(credentialSecret));
  assert.deepEqual(Object.keys(locator).sort(), [
    'action_id', 'credentials_file', 'deadline', 'expected_action_state', 'phase', 'project',
    'schema_version', 'stop_file', 'web_url',
  ]);
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  const leaked = { ...locator, password: credentialSecret };
  assert.throws(() => validateBrowserQALocator(leaked, expected), /shape is invalid/);
  await assert.rejects(() => writeBrowserQALocator({
    output, root, project: 'sf-demo-e2e-browserqa-1234', webPort: 4173,
    phase: 'active', credentialsFile, stateFile, holdSeconds: 60, stopFile,
  }), /already exists/);
  const oldV1 = {
    schema_version: 'sentinelflow-browser-qa-locator-v1', project: locator.project,
    web_url: locator.web_url, credentials_file: credentialsFile, state_file: stateFile,
    active_action_id: state.action.action_id, revoked_action_id: uuid('999'),
    deadline: locator.deadline, stop_file: stopFile,
  };
  assert.throws(() => validateBrowserQALocator(oldV1, expected), /shape is invalid/);
  assert.throws(() => validateBrowserQALocator(
    { ...locator, phase: 'revoked' }, { ...expected, phase: 'revoked' },
  ), /phase and expected action state differ/);
  const revokedOutput = path.join(root, 'browser-qa-revoked-locator.json');
  const revokedStop = path.join(root, 'browser-qa-revoked.stop');
  await assert.rejects(() => writeBrowserQALocator({
    output: revokedOutput, root, project: 'sf-demo-e2e-browserqa-1234', webPort: 4173,
    phase: 'revoked', credentialsFile, stateFile, holdSeconds: 60, stopFile: revokedStop,
  }), /phase does not match/);
  const fastState = journalFixtureState('fast_revoke');
  await writeFile(stateFile, `${JSON.stringify(fastState)}\n`, { mode: 0o600 });
  const revokedLocator = await writeBrowserQALocator({
    output: revokedOutput, root, project: 'sf-demo-e2e-browserqa-1234', webPort: 4173,
    phase: 'revoked', credentialsFile, stateFile, holdSeconds: 60, stopFile: revokedStop,
  });
  assert.equal(revokedLocator.action_id, fastState.action.action_id);
  assert.equal(revokedLocator.expected_action_state, 'revoked');
  await assert.rejects(() => writeBrowserQALocator({
    output: path.join(root, 'nested', 'browser-qa-active-locator.json'), root,
    project: 'sf-demo-e2e-browserqa-1234', webPort: 4173, phase: 'active',
    credentialsFile, stateFile, holdSeconds: 60,
    stopFile: path.join(root, 'browser-qa-active-2.stop'),
  }), /phase paths are invalid/);
});

test('browser QA hold rejects unsafe shell arguments before Docker preflight', () => {
  const script = fileURLToPath(new URL('../check-demo-e2e.sh', import.meta.url));
  const cases = [
    { args: ['--browser-qa-hold-seconds'], message: 'Usage:' },
    { args: ['--fast', '--browser-qa-hold-seconds', '59'], message: 'integer from 60 through 900' },
    { args: ['--fast', '--browser-qa-hold-seconds', '901'], message: 'integer from 60 through 900' },
    { args: ['--fast', '--browser-qa-hold-seconds', '60s'], message: 'integer from 60 through 900' },
    { args: ['--fast', '--run-browser-qa'], message: 'requires --browser-qa-hold-seconds' },
    { args: ['--fast', '--run-browser-qa', '--run-browser-qa'], message: 'Usage:' },
    {
      args: ['--fast', '--browser-qa-hold-seconds', '60', '--browser-qa-hold-seconds', '60'],
      message: 'Usage:',
    },
  ];
  for (const value of cases) {
    const result = spawnSync('/bin/bash', [script, ...value.args], { encoding: 'utf8', timeout: 5_000 });
    assert.equal(result.status, 2, `args=${value.args.join(' ')} stderr=${result.stderr}`);
    assert.match(result.stderr, new RegExp(value.message));
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /Building pinned demo images|Starting the unique/);
  }
});

test('revoked automatic browser QA ages the shared pre-hash login window without retrying', () => {
  const source = readFileSync(new URL('../check-demo-e2e.sh', import.meta.url), 'utf8');
  assert.match(source, /browser_qa_revoked_login_window_seconds=61/);
  const waitStart = source.indexOf('wait_for_revoked_browser_qa_login_window() {');
  const waitEnd = source.indexOf('\n\nvalidate_persisted_evidence() {', waitStart);
  assert.ok(waitStart >= 0 && waitEnd > waitStart, 'revoked browser QA login-window wait is missing');
  const wait = source.slice(waitStart, waitEnd);
  assert.match(wait, /current_stage="browser-qa-revoked-login-window"/);
  assert.match(wait, /deadline=\$\(\(SECONDS \+ browser_qa_revoked_login_window_seconds\)\)/);
  assert.match(wait, /while \(\(SECONDS < deadline\)\); do\n    sleep 1/);
  assert.doesNotMatch(wait, /compose-browser-qa\.mjs|credentials_file|loginClient/);

  const holdStart = source.indexOf('hold_for_browser_qa() {');
  const holdEnd = source.indexOf('\n\nwait_for_revoked_browser_qa_login_window() {', holdStart);
  assert.ok(holdStart >= 0 && holdEnd > holdStart, 'browser QA hold must call the explicit wait');
  const hold = source.slice(holdStart, holdEnd);
  assert.match(
    hold,
    /if \[\[ "\$phase" == "revoked" && "\$browser_qa_runner" == true \]\]; then\n    wait_for_revoked_browser_qa_login_window\n  fi/,
  );
  assert.ok(
    hold.indexOf('wait_for_revoked_browser_qa_login_window') <
      hold.indexOf('node "$helper" write-browser-qa-locator'),
    'the revoked login window must clear before the runner locator is issued',
  );
});

test('cold-start deadline slices bound near-deadline work and reject nonpositive time', () => {
  const source = readFileSync(new URL('../check-demo-e2e.sh', import.meta.url), 'utf8');
  const functionStart = source.indexOf('deadline_slice_seconds() {');
  const functionEnd = source.indexOf('\n\npostgres_query_bounded() {', functionStart);
  assert.ok(functionStart >= 0 && functionEnd > functionStart, 'deadline slice helper is missing');
  const functionSource = source.slice(functionStart, functionEnd);
  const queryFunctionStart = source.indexOf('postgres_query_bounded() {', functionEnd);
  const queryFunctionEnd = source.indexOf('\n\npostgres_query() {', queryFunctionStart);
  assert.ok(queryFunctionStart >= 0 && queryFunctionEnd > queryFunctionStart,
    'bounded PostgreSQL helper is missing');
  const queryFunctionSource = source.slice(queryFunctionStart, queryFunctionEnd);
  assert.match(queryFunctionSource, /timeout_seconds < 1 \|\| timeout_seconds > 30/);
  assert.match(queryFunctionSource, /run_bounded "\$timeout_seconds" docker exec/);
  const invoke = (seconds, deadline, maximum) => spawnSync('/bin/bash', ['-c', `
${functionSource}
SECONDS=${seconds}
deadline_slice_seconds ${deadline} ${maximum}
`], { encoding: 'utf8', timeout: 5_000 });

  assert.deepEqual(
    { status: invoke(100, 130, 30).status, output: invoke(100, 130, 30).stdout.trim() },
    { status: 0, output: '30' },
  );
  const nearDeadline = invoke(100, 103, 30);
  assert.equal(nearDeadline.status, 0);
  assert.equal(nearDeadline.stdout.trim(), '3');
  const boundedSleep = invoke(100, 103, 2);
  assert.equal(boundedSleep.status, 0);
  assert.equal(boundedSleep.stdout.trim(), '2');
  for (const [deadline, maximum, expectedStatus] of [[100, 30, 1], [99, 30, 1], [103, 0, 2], [103, -1, 2]]) {
    const result = invoke(100, deadline, maximum);
    assert.equal(result.status, expectedStatus, `deadline=${deadline} maximum=${maximum}`);
    assert.equal(result.stdout, '');
  }
});

test('bounded command succeeds, rejects invalid invocations, and terminates overruns', async () => {
  assert.equal(await runBoundedCommand(5, [process.execPath, '-e', 'process.exit(0)']), true);
  await assert.rejects(() => runBoundedCommand(1, [process.execPath, '-e', 'setTimeout(() => {}, 5000)']), /timed out/);
  await assert.rejects(() => runBoundedCommand(1, ['bad command']), /executable is invalid/);
});

test('management client keeps its deadline through bounded body consumption', async () => {
  const server = createServer((request, response) => {
    if (request.url === '/api/v1/stall') {
      response.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        Connection: 'close',
      });
      response.write('{"partial":');
      const timer = setTimeout(() => response.end('true}'), 1_000);
      response.once('close', () => clearTimeout(timer));
      return;
    }
    const oversized = Buffer.alloc(65, 0x61);
    response.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(oversized.length),
      Connection: 'close',
    });
    response.end(oversized);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0 }, resolve);
  });
  try {
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const client = new ManagementClient(
      `http://127.0.0.1:${address.port}/`, `http://localhost:${address.port}/`,
      { requestTimeoutMS: 50, maximumResponseBytes: 64 },
    );
    const started = Date.now();
    await assert.rejects(() => client.request('/api/v1/stall'), /request was unavailable/);
    assert.ok(Date.now() - started < 750, 'stalled response body escaped the request deadline');
    await assert.rejects(() => client.request('/api/v1/oversized'), /response exceeded its bound/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

function activeAction() {
  return {
    action_id: uuid('1'), policy_id: uuid('2'), policy_version: 1,
    validation_snapshot_id: uuid('3'), evidence_snapshot_digest: digest('d'),
    target_ipv4: '203.0.113.20', canonical_artifact_digest: digest('a'), ttl_seconds: 1800,
    state: 'active', approved_at: '2026-07-19T00:59:58Z', queued_at: '2026-07-19T00:59:59Z',
    applied_at: '2026-07-19T01:00:00Z',
    expected_expires_at: '2026-07-19T01:30:00Z',
    version: 3, created_at: '2026-07-19T00:59:58Z', updated_at: '2026-07-19T01:00:00Z',
    latest_result: {
      result_id: uuid('4'),
      operation: 'add', classification: 'applied', readback_state: 'active',
      remaining_ttl_seconds: 1799, journal_sequence: 1, error_code: 'none', result_digest: digest('b'),
      persisted_at: '2026-07-19T01:00:00Z',
    },
  };
}

function actionEvidence(action = activeAction(), overrides = {}) {
  return {
    incident_id: uuid('5'), policy_id: action.policy_id, policy_version: action.policy_version,
    policy_digest: digest('e'), validation_snapshot_id: action.validation_snapshot_id,
    validation_snapshot_digest: digest('f'), evidence_snapshot_digest: action.evidence_snapshot_digest,
    action_id: action.action_id, action_version: action.version, target_ipv4: action.target_ipv4,
    ttl_seconds: action.ttl_seconds, generated_artifact_digest: digest('c'),
    canonical_artifact_digest: action.canonical_artifact_digest,
    approved_at: action.approved_at, queued_at: action.queued_at, applied_at: action.applied_at,
    expected_expires_at: action.expected_expires_at, add_result_id: action.latest_result.result_id,
    add_result_digest: action.latest_result.result_digest,
    add_journal_sequence: action.latest_result.journal_sequence,
    add_remaining_ttl_seconds: action.latest_result.remaining_ttl_seconds,
    add_authorization_digest: digest('6'), add_outbox_job_id: uuid('40'),
    ...overrides,
  };
}

const digestBuffer = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

function encodeFrame(type, sequence, payload) {
  const body = Buffer.from(canonicalJSON(payload));
  const header = Buffer.alloc(24);
  header.write('SFJNLv1\n', 0, 'ascii');
  header[8] = 1;
  header[9] = type;
  header.writeBigUInt64BE(BigInt(sequence), 12);
  header.writeUInt32BE(body.length, 20);
  return Buffer.concat([header, body, createHash('sha256').update(header).update(body).digest()]);
}

function journalFixture(
  state, includeInspect = false, duplicateAdd = false, rewriteFirstEnvelope = false,
  includeAbsentInspect = false,
) {
  const signature = Buffer.alloc(64, 7).toString('base64url');
  const rewrittenSignature = Buffer.alloc(64, 8).toString('base64url');
  const operations = [
    {
      operation: 'add', action: state.action, job: state.action.add_outbox_job_id,
      authorization: state.action.add_authorization_digest,
      result: state.action.add_result_id, resultDigest: state.action.add_result_digest,
      classification: 'applied', readback: 'active', ttl: 1799,
    },
    {
      operation: 'inspect', action: state.action, job: uuid('82'), authorization: digest('8'),
      result: uuid('83'), classification: 'inspect_active', readback: 'active', ttl: 1700,
    },
  ];
  if (state.mode === 'fast_revoke') {
    operations.push({
      operation: 'revoke', action: state.action, job: state.revocation.outbox_job_id,
      authorization: state.revocation.authorization_digest,
      result: state.revocation.result_id, resultDigest: state.revocation.result_digest,
      classification: 'revoked', readback: 'absent', ttl: null,
      artifactDigest: state.revocation.revoke_artifact_digest,
    });
  }
  if (includeInspect) {
    const postMutationIsAbsent = state.mode === 'fast_revoke';
    operations.push({
      operation: 'inspect', action: state.action, job: uuid('84'), authorization: digest('9'),
      result: uuid('85'),
      classification: postMutationIsAbsent ? 'inspect_absent' : 'inspect_active',
      readback: postMutationIsAbsent ? 'absent' : 'active',
      ttl: postMutationIsAbsent ? null : 1600,
    });
  }
  if (includeAbsentInspect) {
    operations.push({
      operation: 'inspect', action: state.action, job: uuid('90'), authorization: digest('b'),
      result: uuid('91'), classification: 'inspect_absent', readback: 'absent', ttl: null,
    });
  }
  if (duplicateAdd) {
    operations.push({
      operation: 'add', action: state.action, job: uuid('86'), authorization: digest('a'),
      result: uuid('87'), classification: 'applied', readback: 'active', ttl: 1500,
    });
  }
  const frames = [];
  let previous = null;
  let sequence = 1;
  for (const [index, item] of operations.entries()) {
    const envelopeSignature = rewriteFirstEnvelope && index === 0 ? rewrittenSignature : signature;
    const artifact = item.operation === 'add' ?
      Buffer.from(`add element inet sentinelflow blacklist_ipv4 { ${item.action.target_ipv4} timeout 30m }\n`) :
      (item.operation === 'revoke' ?
        Buffer.from(`delete element inet sentinelflow blacklist_ipv4 { ${item.action.target_ipv4} }\n`) :
        Buffer.from(canonicalJSON({
          action_id: item.action.action_id, operation: 'inspect',
          original_add_digest: item.action.canonical_artifact_digest,
          owned_schema_digest: digest('7'), purpose: 'reconciliation',
          schema_version: 'nft-inspect-v1', target_ipv4: item.action.target_ipv4,
        })));
    const artifactDigest = digestBuffer(artifact);
    if (item.operation === 'add' && index === 0) {
      item.action.canonical_artifact_digest = artifactDigest;
      item.action.add_journal_sequence = sequence;
    } else if (item.operation === 'revoke') {
      state.revocation.revoke_artifact_digest = artifactDigest;
    }
    const capability = {
      action_id: item.action.action_id, actor_id: 'admin-demo', artifact_digest: artifactDigest,
      authorization_digest: item.authorization, capability_id: uuid(String(60 + index)),
      evidence_snapshot_digest: item.action.evidence_snapshot_digest,
      expires_at: '2026-07-19T01:00:01.000Z', issued_at: '2026-07-19T01:00:00.000Z',
      job_id: item.job, nonce: Buffer.alloc(16, index + 1).toString('base64url'),
      not_before: '2026-07-19T01:00:00.000Z', operation: item.operation,
      original_add_digest: item.operation === 'add' ? null : item.action.canonical_artifact_digest,
      owned_schema_digest: digest('7'), policy_id: item.action.policy_id,
      policy_version: item.action.policy_version, reason_digest: digest('6'),
      schema_version: 'execution-capability-v1', target_ipv4: item.action.target_ipv4,
      validation_snapshot_digest: item.action.validation_snapshot_digest,
    };
    const capabilityBytes = Buffer.from(canonicalJSON(capability));
    const capabilityDigest = digestBuffer(capabilityBytes);
    if (item.operation === 'revoke') state.revocation.execution_capability_digest = capabilityDigest;
    const startPayload = {
      artifact_b64url: artifact.toString('base64url'), artifact_digest: artifactDigest,
      capability_digest: capabilityDigest, capability_id: capability.capability_id,
      capability_jcs_b64url: capabilityBytes.toString('base64url'),
      capability_signature_b64url: envelopeSignature, deadline: '2026-07-19T01:00:01.000Z',
      journal_sequence: sequence, operation: item.operation, owned_schema_digest: digest('7'),
      phase: 'started', previous_record_digest: previous, received_at: '2026-07-19T01:00:00.000Z',
      record_checksum: '', schema_version: 'executor-journal-record-v1', target_ipv4: item.action.target_ipv4,
      terminal_result_digest: null, terminal_result_jcs_b64url: null,
      terminal_result_signature_b64url: null,
    };
    const startChecksum = { ...startPayload };
    delete startChecksum.record_checksum;
    startPayload.record_checksum = digestJSON(startChecksum);
    const startBytes = Buffer.from(canonicalJSON(startPayload));
    frames.push(encodeFrame(1, sequence, startPayload));
    previous = digestBuffer(startBytes);
    const result = {
      action_id: item.action.action_id, artifact_digest: artifactDigest,
      capability_digest: capabilityDigest, capability_id: capability.capability_id,
      classification: item.classification, completed_at: '2026-07-19T01:00:00.100Z',
      element_handle: null, error_code: 'none', journal_sequence: sequence,
      nft_exit_class: 'success', operation: item.operation, owned_schema_digest: digest('7'),
      readback_state: item.readback, remaining_ttl_seconds: item.ttl,
      result_id: item.result, schema_version: 'execution-result-v1',
      started_at: '2026-07-19T01:00:00.000Z', target_ipv4: item.action.target_ipv4,
    };
    const resultBytes = Buffer.from(canonicalJSON(result));
    const resultDigest = digestBuffer(resultBytes);
    if (item.operation === 'add' && index === 0) {
      item.action.add_result_digest = resultDigest;
    } else if (item.operation === 'revoke') {
      state.revocation.result_digest = resultDigest;
      state.revocation.journal_sequence = sequence;
    }
    const terminalPayload = {
      ...startPayload, journal_sequence: sequence + 1, phase: 'terminal',
      previous_record_digest: previous, record_checksum: '', terminal_result_digest: resultDigest,
      terminal_result_jcs_b64url: resultBytes.toString('base64url'),
      terminal_result_signature_b64url: envelopeSignature,
    };
    const terminalChecksum = { ...terminalPayload };
    delete terminalChecksum.record_checksum;
    terminalPayload.record_checksum = digestJSON(terminalChecksum);
    const terminalBytes = Buffer.from(canonicalJSON(terminalPayload));
    frames.push(encodeFrame(2, sequence + 1, terminalPayload));
    previous = digestBuffer(terminalBytes);
    sequence += 2;
  }
  return Buffer.concat(frames);
}

function journalFixtureState(mode = 'fast_revoke') {
  const action = actionEvidence(activeAction(), {
    add_outbox_job_id: uuid('70'), add_result_id: uuid('71'), add_authorization_digest: digest('1'),
  });
  return {
    schema_version: 'sentinelflow-demo-e2e-state-v4', mode, action,
    revocation: mode === 'fast_revoke' ? {
      action_version_before: action.action_version,
      action_version_after: action.action_version + 1,
      challenge_id: uuid('77'), revoke_artifact_digest: digest('3'), decision_id: uuid('78'),
      decision_digest: digest('4'), reason_digest: digest('5'), revocation_id: uuid('79'),
      authorization_id: uuid('80'), authorization_digest: digest('6'), outbox_job_id: uuid('81'),
      audit_event_id: uuid('88'), execution_capability_digest: digest('7'), result_id: uuid('89'),
      result_digest: digest('8'), journal_sequence: 5, finished_at: '2026-07-19T01:05:01Z',
    } : null,
  };
}

function evidenceChainRow(selector, evidence, state, index) {
  const operationName = selector === 'revoke' ? 'revoke' : 'add';
  const authorizationID = operationName === 'revoke' ? state.revocation.authorization_id : uuid(String(100 + index));
  const decisionID = operationName === 'revoke' ? state.revocation.decision_id : uuid(String(110 + index));
  const challengeID = operationName === 'revoke' ? state.revocation.challenge_id : uuid(String(120 + index));
  const reasonID = uuid(String(130 + index));
  const capabilityID = uuid(String(140 + index));
  const capabilityDigest = operationName === 'revoke' ?
    state.revocation.execution_capability_digest : digest(String(index + 1));
  const jobID = operationName === 'revoke' ? state.revocation.outbox_job_id : evidence.add_outbox_job_id;
  const resultID = operationName === 'revoke' ? state.revocation.result_id : evidence.add_result_id;
  const resultDigest = operationName === 'revoke' ? state.revocation.result_digest : evidence.add_result_digest;
  const journalSequence = operationName === 'revoke' ? state.revocation.journal_sequence : evidence.add_journal_sequence;
  const artifactDigest = operationName === 'revoke' ? state.revocation.revoke_artifact_digest : evidence.canonical_artifact_digest;
  const authorizationDigest = operationName === 'revoke' ? state.revocation.authorization_digest : evidence.add_authorization_digest;
  const originalAddDigest = operationName === 'revoke' ? evidence.canonical_artifact_digest : null;
  const decisionOperation = operationName === 'revoke' ? 'revoke' : 'approve';
  const decisionValue = operationName === 'revoke' ? 'revoked' : 'approved';
  const resourceType = operationName === 'revoke' ? 'enforcement_action' : 'policy';
  const resourceID = operationName === 'revoke' ? evidence.action_id : evidence.policy_id;
  const resourceVersion = operationName === 'revoke' ? evidence.action_version : evidence.policy_version;
  const actionID = operationName === 'revoke' ? evidence.action_id : null;
  const nonceDigest = digest(String(5 + index));
  const idempotencyDigest = digest(['8', '9', 'a'][index]);
  const reasonDigest = operationName === 'revoke' ? state.revocation.reason_digest : digest(String(2 + index));
  const ownedDigest = digest('e');
  const classification = operationName === 'revoke' ? 'revoked' : 'applied';
  const readback = operationName === 'revoke' ? 'absent' : 'active';
  const resultingState = operationName === 'revoke' ? 'revoked' : 'active';
  const resultingVersion = operationName === 'revoke' ? state.revocation.action_version_after : evidence.action_version;
  const currentState = state.mode === 'fast_revoke' ? 'revoked' : 'active';
  const currentVersion = state.mode === 'fast_revoke' ?
    state.revocation.action_version_after : evidence.action_version;
  const addAuthorizationID = operationName === 'add' ? authorizationID : uuid('100');
  return {
    schema_version: 'sentinelflow-demo-e2e-evidence-chain-v1', selector,
    job: {
      job_id: jobID, kind: `dispatch_${operationName}`, operation: operationName, state: 'completed',
      aggregate_type: 'enforcement_action', aggregate_id: evidence.action_id, aggregate_version: evidence.action_version,
    },
    operation: {
      job_id: jobID, operation: operationName, action_id: evidence.action_id, policy_id: evidence.policy_id,
      policy_version: evidence.policy_version, target_ipv4: evidence.target_ipv4, artifact_digest: artifactDigest,
      original_add_digest: originalAddDigest, evidence_snapshot_digest: evidence.evidence_snapshot_digest,
      validation_snapshot_id: evidence.validation_snapshot_id,
      validation_snapshot_digest: evidence.validation_snapshot_digest, authorization_id: authorizationID,
      authorization_digest: authorizationDigest, actor_id: 'admin-demo', reason_digest: reasonDigest,
      owned_schema_digest: ownedDigest,
    },
    action: {
      action_id: evidence.action_id, policy_id: evidence.policy_id, policy_version: evidence.policy_version,
      add_authorization_id: addAuthorizationID, target_ipv4: evidence.target_ipv4,
      canonical_artifact_digest: evidence.canonical_artifact_digest, state: currentState, version: currentVersion,
    },
    authorization: {
      authorization_id: authorizationID, authorization_kind: operationName, action_id: evidence.action_id,
      policy_id: evidence.policy_id, policy_version: evidence.policy_version, decision_id: decisionID,
      decision: operationName === 'revoke' ? 'revoke' : 'approve', target_ipv4: evidence.target_ipv4,
      policy_digest: evidence.policy_digest,
      generated_artifact_digest: operationName === 'add' ? evidence.generated_artifact_digest : artifactDigest,
      canonical_artifact_digest: artifactDigest, original_add_digest: originalAddDigest,
      evidence_snapshot_digest: evidence.evidence_snapshot_digest,
      validation_snapshot_digest: evidence.validation_snapshot_digest, actor_id: 'admin-demo',
      reason_digest: reasonDigest, decision_nonce_digest: nonceDigest,
      idempotency_key_digest: idempotencyDigest, authorization_digest: authorizationDigest,
    },
    decision: {
      decision_id: decisionID, challenge_id: challengeID, operation: decisionOperation,
      decision: decisionValue, resource_type: resourceType, resource_id: resourceID,
      resource_version: resourceVersion, policy_id: evidence.policy_id, policy_version: evidence.policy_version,
      action_id: actionID, target_ipv4: evidence.target_ipv4, policy_digest: evidence.policy_digest,
      evidence_snapshot_digest: evidence.evidence_snapshot_digest,
      generated_artifact_digest: operationName === 'add' ? evidence.generated_artifact_digest : artifactDigest,
      canonical_artifact_digest: artifactDigest, original_add_digest: originalAddDigest,
      validation_snapshot_digest: evidence.validation_snapshot_digest, actor_id: 'admin-demo',
      reason_id: reasonID, reason_digest: reasonDigest, challenge_nonce_digest: nonceDigest,
      idempotency_key_digest: idempotencyDigest,
    },
    challenge: {
      challenge_id: challengeID, operation: decisionOperation, resource_type: resourceType,
      resource_id: resourceID, resource_version: resourceVersion, policy_id: evidence.policy_id,
      policy_version: evidence.policy_version, action_id: actionID, target_ipv4: evidence.target_ipv4,
      policy_digest: evidence.policy_digest, evidence_snapshot_digest: evidence.evidence_snapshot_digest,
      generated_artifact_digest: operationName === 'add' ? evidence.generated_artifact_digest : artifactDigest,
      canonical_artifact_digest: artifactDigest,
      original_add_digest: originalAddDigest, validation_snapshot_digest: evidence.validation_snapshot_digest,
      actor_id: 'admin-demo', nonce_digest: nonceDigest, idempotency_key_digest: idempotencyDigest,
      consumed_decision_id: decisionID,
    },
    reason: { reason_id: reasonID, operation: decisionOperation, actor_id: 'admin-demo', reason_digest: reasonDigest },
    revocation: operationName === 'add' ? null : {
      revocation_id: state.revocation.revocation_id, action_id: evidence.action_id,
      authorization_id: authorizationID, decision_id: decisionID, actor_id: 'admin-demo', reason_id: reasonID,
      reason_digest: reasonDigest, target_ipv4: evidence.target_ipv4,
      original_add_digest: evidence.canonical_artifact_digest, artifact_digest: artifactDigest, state: 'revoked',
    },
    capability: {
      capability_id: capabilityID, job_id: jobID, operation: operationName, action_id: evidence.action_id,
      policy_id: evidence.policy_id, policy_version: evidence.policy_version, target_ipv4: evidence.target_ipv4,
      artifact_digest: artifactDigest, original_add_digest: originalAddDigest,
      evidence_snapshot_digest: evidence.evidence_snapshot_digest,
      validation_snapshot_digest: evidence.validation_snapshot_digest, authorization_digest: authorizationDigest,
      actor_id: 'admin-demo', reason_digest: reasonDigest, owned_schema_digest: ownedDigest,
      capability_digest: capabilityDigest, signature_bytes: 64, consumed: true,
    },
    result: {
      result_id: resultID, capability_id: capabilityID, capability_digest: capabilityDigest,
      operation: operationName, action_id: evidence.action_id, artifact_digest: artifactDigest,
      target_ipv4: evidence.target_ipv4, classification, readback_state: readback,
      journal_sequence: journalSequence, error_code: 'none', owned_schema_digest: ownedDigest,
      result_digest: resultDigest, signature_bytes: 64,
    },
    application: {
      result_id: resultID, result_digest: resultDigest, action_id: evidence.action_id,
      operation: operationName, classification, resulting_state: resultingState,
      resulting_action_version: resultingVersion,
    },
    audit: {
      authorization_count: 1,
      authorization_event_id: operationName === 'revoke' ? state.revocation.audit_event_id : uuid(String(150 + index)),
      authorization_primary_digest: operationName === 'revoke' ? state.revocation.decision_digest : digest('f'),
      queue_count: operationName === 'add' ? 1 : 0, terminal_count: 1,
    },
  };
}

test('restart verification binds the exact once-only add and permits bounded inspect progress', () => {
  const action = activeAction();
  const evidence = actionEvidence(action);
  assert.deepEqual(validateActiveAction(action), action);
  assert.throws(() => validateActiveAction({ ...action, state: 'approved' }), /state is invalid/);
  assert.deepEqual(validateActiveAction(action, evidence), action);

  const inspected = structuredClone(action);
  inspected.latest_result = {
    result_id: uuid('6'), operation: 'inspect', classification: 'inspect_active', readback_state: 'active',
    remaining_ttl_seconds: 1700, journal_sequence: 2, error_code: 'none', result_digest: digest('c'),
    persisted_at: '2026-07-19T01:01:39Z',
  };
  assert.deepEqual(validateActiveAction(inspected, evidence), inspected);

  const replayed = structuredClone(action);
  replayed.latest_result.journal_sequence = 2;
  assert.throws(() => validateActiveAction(replayed, evidence), /changed or refreshed TTL/);

  inspected.latest_result.remaining_ttl_seconds = 1800;
  assert.throws(() => validateActiveAction(inspected, evidence), /changed or refreshed TTL/);
});

test('expiry requires signed absent inspection, terminal state, and later audit', () => {
  const active = activeAction();
  const state = actionEvidence(active);
  const expired = {
    ...active,
    state: 'expired', version: 4, finished_at: '2026-07-19T01:30:01Z',
    updated_at: '2026-07-19T01:30:01Z',
    latest_result: {
      result_id: uuid('7'),
      operation: 'inspect', classification: 'inspect_absent', readback_state: 'absent',
      journal_sequence: 2, error_code: 'none', result_digest: digest('c'),
      persisted_at: '2026-07-19T01:30:01Z',
    },
  };
  const audit = [{
    action: 'enforcement_expired', enforcement_action_id: active.action_id,
    recorded_at: '2026-07-19T01:30:01Z', outcome: 'succeeded',
    primary_digest: expired.latest_result.result_digest,
    secondary_digest: digest('9'),
  }];
  assert.equal(validateExpiredAction(expired, audit, state), true);
  assert.throws(() => validateExpiredAction(expired, [], state), /audit is missing/);
});

test('revoke requires a terminal signed result ordered after the add', () => {
  const active = activeAction();
  const state = actionEvidence(active);
  const revoked = {
    ...active,
    state: 'revoked', version: 4, finished_at: '2026-07-19T01:05:01Z',
    updated_at: '2026-07-19T01:05:01Z',
    latest_result: {
      result_id: uuid('8'), operation: 'revoke', classification: 'revoked', readback_state: 'absent',
      journal_sequence: 3, error_code: 'none', result_digest: digest('8'),
      persisted_at: '2026-07-19T01:05:01Z',
    },
  };
  const revocation = {
    action_version_before: 3, action_version_after: 4, challenge_id: uuid('9'),
    revoke_artifact_digest: digest('1'), decision_id: uuid('10'), decision_digest: digest('2'),
    reason_digest: digest('3'), revocation_id: uuid('11'), authorization_id: uuid('12'),
    authorization_digest: digest('4'), outbox_job_id: uuid('13'), audit_event_id: uuid('14'),
    execution_capability_digest: digest('5'), result_id: revoked.latest_result.result_id,
    result_digest: revoked.latest_result.result_digest, journal_sequence: 3,
    finished_at: revoked.finished_at,
  };
  assert.deepEqual(validateRevokedAction(revoked, state, revocation), revoked);
  const replayed = structuredClone(revoked);
  replayed.latest_result.journal_sequence = 4;
  assert.throws(() => validateRevokedAction(replayed, state, revocation), /changed across restart/);
});

test('structural binary journal parser rejects tamper and binds mutations before independent crypto verification', () => {
  const state = journalFixtureState();
  const beforeBytes = journalFixture(state);
  const before = parseJournalBuffer(beforeBytes);
  assert.equal(validateJournalSnapshot(before, state, 'revoked'), true);
  const afterBytes = journalFixture(state, true);
  const after = parseJournalBuffer(afterBytes);
  assert.equal(compareJournalSnapshots(before, after, state, 'revoked'), true);
  assert.equal(compareJournalBuffers(beforeBytes, afterBytes, state, 'revoked'), true);

  const corrupted = Buffer.from(beforeBytes);
  corrupted[corrupted.length - 1] ^= 1;
  assert.throws(() => parseJournalBuffer(corrupted), /checksum is invalid/);
  const duplicate = parseJournalBuffer(journalFixture(state, false, true));
  assert.throws(() => validateJournalSnapshot(duplicate, state, 'revoked'), /duplicate add/);
  const mismatch = structuredClone(before);
  mismatch.terminal_operations[1].classification = 'inspect_mismatch';
  mismatch.terminal_operations[1].readback_state = 'active';
  assert.throws(() => validateJournalSnapshot(mismatch, state, 'revoked'),
    /unsuccessful or inconsistent inspection/);
  const postRevokeActive = structuredClone(parseJournalBuffer(journalFixture(state, true)));
  postRevokeActive.terminal_operations.at(-1).classification = 'inspect_active';
  postRevokeActive.terminal_operations.at(-1).readback_state = 'active';
  assert.throws(() => validateJournalSnapshot(postRevokeActive, state, 'revoked'),
    /revoke ordering is invalid/);
  const foreignMutation = structuredClone(before);
  foreignMutation.frame_count += 2;
  foreignMutation.terminal_operations.push({
    ...foreignMutation.terminal_operations[0], action_id: uuid('88'), job_id: uuid('89'),
    capability_id: uuid('106'), result_id: uuid('107'), started_sequence: 7, terminal_sequence: 8,
  });
  assert.throws(() => validateJournalSnapshot(foreignMutation, state, 'revoked'), /foreign action/);
  const reordered = structuredClone(after);
  [reordered.terminal_operations[0], reordered.terminal_operations[1]] =
    [reordered.terminal_operations[1], reordered.terminal_operations[0]];
  assert.throws(() => compareJournalSnapshots(before, reordered, state, 'revoked'), /prefix changed/);
});

test('raw append-only gate rejects a rewritten prior envelope followed by a valid inspect append', () => {
  const state = journalFixtureState();
  const beforeBytes = journalFixture(state);
  const before = parseJournalBuffer(beforeBytes);
  const rewrittenWithInspect = journalFixture(state, true, false, true);
  const rewrittenSnapshot = parseJournalBuffer(rewrittenWithInspect);

  assert.equal(compareJournalSnapshots(before, rewrittenSnapshot, state, 'revoked'), true,
    'summary-only comparison intentionally demonstrates the prior blind spot');
  assert.throws(
    () => compareJournalBuffers(beforeBytes, rewrittenWithInspect, state, 'revoked'),
    /raw byte prefix changed across restart/,
  );
});

test('release journal phases require active inspection before signed absent expiry inspection', () => {
  const state = journalFixtureState('release_expiry');
  const active = parseJournalBuffer(journalFixture(state));
  assert.equal(validateJournalSnapshot(active, state, 'active'), true);
  assert.throws(() => validateJournalSnapshot(active, state, 'expired'), /revoke ordering is invalid/);
  const expired = parseJournalBuffer(journalFixture(state, false, false, false, true));
  assert.equal(validateJournalSnapshot(expired, state, 'expired'), true);
  const mismatch = structuredClone(expired);
  mismatch.terminal_operations.at(-1).classification = 'inspect_mismatch';
  assert.throws(() => validateJournalSnapshot(mismatch, state, 'expired'),
    /unsuccessful or inconsistent inspection/);
  const activeAfterAbsent = structuredClone(expired);
  const activeInspection = activeAfterAbsent.terminal_operations.find((item) =>
    item.classification === 'inspect_active');
  const absentInspection = activeAfterAbsent.terminal_operations.find((item) =>
    item.classification === 'inspect_absent');
  activeInspection.started_sequence = absentInspection.terminal_sequence + 1;
  activeInspection.terminal_sequence = absentInspection.terminal_sequence + 2;
  assert.throws(() => validateJournalSnapshot(activeAfterAbsent, state, 'expired'),
    /revoke ordering is invalid/);
  assert.throws(() => validateJournalSnapshot(expired, state, 'active'), /revoke ordering is invalid/);
  assert.throws(() => validateJournalSnapshot(expired, {
    ...state, mode: 'fast_revoke', revocation: null,
  }, 'expired'), /missing revocation evidence/);
});

test('Compose E2E captures DB before retained journals for convergent cryptographic reconciliation', () => {
  const source = readFileSync(new URL('../check-demo-e2e.sh', import.meta.url), 'utf8');
  assert.match(source, /validate-execution-artifacts/);
  assert.match(source, /validate-recovery-state/);
  assert.match(source, /--replay-journal "\$replay_journal"/);
  assert.match(source, /docker network inspect none --format '\{\{\.Id\}\}'/);
  assert.match(source, /check-none-network-id "\$none_network_id_file"/);
  assert.match(source, /--none-network-id "\$none_network_id"/);
  assert.match(source, /docker network inspect none \\\n+\s+--format '\{\"Id\":\{\{json \.Id\}\},\"Name\":\{\{json \.Name\}\},\"Driver\":\{\{json \.Driver\}\},\"Containers\":\{\{json \.Containers\}\}\}'/);
  assert.match(source, /--none-network-inspection "\$none_network_inspection_file"/);
  assert.match(source, /write-detection-diagnostic-sql --output "\$detection_diagnostic_sql_file"/);
  assert.match(source, /write-detection-stability-sql --output "\$detection_stability_sql_file"/);
  assert.match(source, /write-coverage-readiness-sql --output "\$coverage_readiness_sql_file"/);
  assert.match(source, /write-browser-qa-locator \\\n+\s+--output "\$locator_file"/);
  assert.match(source, /--phase "\$phase"/);
  assert.match(source, /\[\[ -f "\$stop_file" && ! -L "\$stop_file" \]\]/);
  assert.match(source, /browser QA %s hold deadline elapsed without a regular stop marker[\s\S]*?return 1/);
  assert.match(source, /capture_detection_diagnostics "after-scenarios"/);
  const lastScenario = source.indexOf('run_scenario credential-stuffing ');
  const stabilityGate = source.indexOf('\nwait_for_detection_stability\n', lastScenario);
  const approve = source.indexOf('\nrun_bounded 900 node "$helper" approve ', stabilityGate);
  assert.ok(lastScenario >= 0 && stabilityGate > lastScenario && approve > stabilityGate,
    'detection stability must gate HIL after every scenario');
  assert.match(source, /capture_detection_diagnostics "failure-\$current_stage"/);
  assert.match(source, /--format '\{\"running\":\{\{json \.State\.Running\}\},\"restart_count\":\{\{json \.RestartCount\}\}\}'/);
  assert.match(source, /--before-raw "\$journal_before_raw" --after-raw "\$journal_after_raw"/);
  assert.match(source, /capture_journal_snapshot "\$journal_snapshot" "\$replay_journal"/);
  assert.match(source, /validate_persisted_evidence \\\n\s+"\$evidence_before_file" "\$journal_before_snapshot" "\$journal_before_raw" \\\n\s+"\$validation_before_journal"/);
  assert.match(source, /validate_persisted_evidence \\\n\s+"\$evidence_after_file" "\$journal_after_snapshot" "\$journal_after_raw" \\\n\s+"\$validation_after_journal"/);
  const validationFunction = source.slice(
    source.indexOf('validate_persisted_evidence() {'),
    source.indexOf('\nwait_for_nft_active() {'),
  );
  const databaseSnapshot = validationFunction.indexOf(
    'postgres_query "$artifact_query_file" "$artifact_rows_file"',
  );
  const journalSnapshot = validationFunction.indexOf(
    'capture_journal_snapshot "$journal_snapshot" "$replay_journal"',
  );
  assert.ok(databaseSnapshot >= 0 && journalSnapshot > databaseSnapshot,
    'each retry must capture the database artifact snapshot before the append-only journal');
  const browserHold = source.indexOf('\nhold_for_browser_qa active\n');
  const firstEvidence = source.indexOf('\n  if ! validate_persisted_evidence \\', browserHold);
  const controlPlaneOutage = source.indexOf('\ncompose 60 stop --timeout 10 api detector', firstEvidence);
  assert.ok(browserHold >= 0 && firstEvidence > browserHold && controlPlaneOutage > firstEvidence,
    'active browser QA must precede exact evidence and the control-plane outage');
  assert.match(source, /coverage_readiness_detector_window_seconds=300/);
  assert.match(source, /coverage_readiness_margin_seconds=5/);
  assert.match(source, /coverage_readiness_required_seconds=305/);
  assert.doesNotMatch(source, /SENTINELFLOW_[A-Z0-9_]*COVERAGE_READINESS/);
  const originProof = source.indexOf("printf 'PASS: private origin is not directly reachable from edge.");
  const readinessGate = source.indexOf('\nwait_for_cold_start_coverage\n', originProof);
  const firstFrozenScenario = source.indexOf('\nrun_scenario normal ', readinessGate);
  assert.ok(originProof >= 0 && readinessGate > originProof && firstFrozenScenario > readinessGate,
    'cold-start readiness must be re-evaluated immediately before the first frozen scenario');
  const readinessFunction = source.slice(
    source.indexOf('wait_for_cold_start_coverage() {'),
    source.indexOf('\nhold_for_browser_qa() {'),
  );
  assert.match(readinessFunction, /install -m 0600 "\$coverage_readiness_last_file" "\$coverage_readiness_first_ready_file"/);
  assert.match(readinessFunction, /coverage-readiness-advance \\\n+\s+"\$coverage_readiness_first_ready_file" "\$coverage_readiness_last_file"/);
  assert.match(readinessFunction, /not-advanced\)\n\s+rm -f "\$coverage_readiness_first_ready_file"/);
  assert.match(readinessFunction, /query_timeout_seconds="\$\(deadline_slice_seconds "\$deadline" 30\)"/);
  assert.match(readinessFunction, /postgres_query_bounded "\$query_timeout_seconds" \\\n+\s+"\$coverage_readiness_sql_file" "\$coverage_readiness_db_file"/);
  assert.match(readinessFunction, /sleep_seconds="\$\(deadline_slice_seconds \\\n+\s+"\$deadline" "\$coverage_readiness_poll_seconds"\)"/);
  assert.match(readinessFunction, /sleep "\$sleep_seconds"/);
  assert.doesNotMatch(readinessFunction, /sleep "\$coverage_readiness_poll_seconds"/);
  assert.ok((readinessFunction.match(/if \(\(SECONDS >= deadline\)\); then\n\s+break/g) ?? []).length >= 2,
    'query results and final readiness success must both be rejected at the deadline');
  assert.match(readinessFunction,
    /current_stage="post-coverage-readiness"\n\s+if \(\(SECONDS >= deadline\)\); then\n\s+current_stage="coverage-readiness"\n\s+break\n\s+fi\n\s+return 0/);
  assert.match(readinessFunction, /malformed coverage readiness snapshot failed closed[\s\S]*?return 1/);
  const helperSource = readFileSync(new URL('./demo-e2e.mjs', import.meta.url), 'utf8');
  const readinessSQL = helperSource.slice(
    helperSource.indexOf('const COVERAGE_READINESS_SQL ='),
    helperSource.indexOf('const DETECTION_STABILITY_SQL ='),
  );
  assert.match(readinessSQL, /min\(latest\.coverage_end\)/);
  assert.match(readinessSQL, /detection_coverage_start/);
  assert.match(readinessSQL, /ingest_gap_lifecycle/);
  assert.match(readinessSQL,
    /int8range\(opened\.sequence_start, opened\.sequence_end, '\[\]'\) <@\s+range_agg/);
  assert.match(readinessSQL, /AND NOT COALESCE\(\(/);
  assert.match(readinessSQL, /terminal\.sequence_start >= opened\.sequence_start/);
  assert.match(readinessSQL, /terminal\.sequence_end <= opened\.sequence_end/);
  assert.doesNotMatch(readinessSQL, /terminal\.sequence_start = opened\.sequence_start/);
  assert.doesNotMatch(readinessSQL, /range_merge/);
  assert.match(readinessSQL, /source_health_intervals/);
  assert.match(readinessSQL, /min\(coverage\.covered_through_sequence\) AS segment_first_sequence/);
  assert.match(readinessSQL, /batch\.sequence >= latest\.segment_first_sequence/);
  assert.match(readinessSQL, /health\.state IN \('degraded', 'lost'\)/);
  assert.match(readinessSQL, /current_bindings AS MATERIALIZED/);
  assert.match(readinessSQL, /binding\.binding_digest/);
  assert.match(readinessSQL, /summary\.binding_digests = summary\.current_binding_digests/);
  assert.match(readinessSQL, /sentinelflow-demo-e2e-coverage-readiness-v2/);
  assert.match(readinessSQL, /interval '305 seconds'/);
  assert.doesNotMatch(readinessSQL, /clock_timestamp|statement_timestamp|transaction_timestamp|now\(\)/);
  const stabilitySQL = helperSource.slice(
    helperSource.indexOf('const DETECTION_STABILITY_SQL ='),
    helperSource.indexOf('const DETECTION_DIAGNOSTIC_SQL ='),
  );
  assert.match(stabilitySQL, /job\.state IN \('pending', 'leased', 'retry'\)/);
  assert.match(stabilitySQL, /job\.state = 'dead'/);
  assert.match(stabilitySQL, /policy\.incident_version = incident\.evidence_version/);
  assert.doesNotMatch(stabilitySQL, /policy\.incident_version = incident\.version/);
  const stabilityFunction = source.slice(
    source.indexOf('wait_for_detection_stability() {'),
    source.indexOf('\nhold_for_browser_qa() {'),
  );
  assert.match(stabilityFunction, /detection-stability-state/);
  assert.match(stabilityFunction, /detection-stability-advance/);
  assert.match(stabilityFunction, /capture_detection_diagnostics "detection-stability-timeout"/);
  assert.match(stabilityFunction, /deadline_slice_seconds "\$deadline" 30/);
  assert.doesNotMatch(source, /rm -f "\$journal_(?:before|after)_raw"/);
  for (const command of [
    'approve', 'verify-inspected', 'prove-revoke-negative', 'revoke', 'verify-restart', 'verify-expired',
  ]) {
    assert.match(source, new RegExp(`run_bounded [0-9]+ node "\\$helper" ${command}`));
  }
});

test('persisted evidence rows require exact outbox, HIL, capability, result, lifecycle, and audit joins', () => {
  const state = journalFixtureState('fast_revoke');
  assert.notEqual(state.action.generated_artifact_digest, state.action.canonical_artifact_digest,
    'the fixture must preserve the generated/canonical digest distinction');
  const rows = [
    evidenceChainRow('add', state.action, state, 0),
    evidenceChainRow('revoke', state.action, state, 1),
  ];
  assert.equal(validateEvidenceChainRows(rows, state, 'revoked'), true);
  for (const [component, message] of [
    ['decision', /add decision evidence binding is invalid/],
    ['challenge', /add challenge evidence binding is invalid/],
  ]) {
    const canonicalSubstitution = structuredClone(rows);
    canonicalSubstitution[0][component].generated_artifact_digest =
      state.action.canonical_artifact_digest;
    assert.throws(
      () => validateEvidenceChainRows(canonicalSubstitution, state, 'revoked'),
      message,
      `${component} must retain the original generated add digest`,
    );
  }
  const generatedMismatch = structuredClone(rows);
  generatedMismatch[0].authorization.generated_artifact_digest = state.action.canonical_artifact_digest;
  assert.throws(() => validateEvidenceChainRows(generatedMismatch, state, 'revoked'),
    /authorization evidence binding/);

  for (const [component, message] of [
    ['operation', /dispatch operation binding/],
    ['capability', /capability, result, lifecycle, or audit/],
    ['result', /capability, result, lifecycle, or audit/],
  ]) {
    const generatedArtifactAtExecutionBoundary = structuredClone(rows);
    generatedArtifactAtExecutionBoundary[0][component].artifact_digest =
      state.action.generated_artifact_digest;
    assert.throws(
      () => validateEvidenceChainRows(generatedArtifactAtExecutionBoundary, state, 'revoked'),
      message,
      `${component} must use the canonical add artifact digest`,
    );
  }
  const missingGenerated = structuredClone(state);
  delete missingGenerated.action.generated_artifact_digest;
  assert.throws(() => validateDemoState(missingGenerated), /shape is invalid/);
  const wrongTerminal = structuredClone(rows);
  wrongTerminal[1].audit.terminal_count = 0;
  assert.throws(() => validateEvidenceChainRows(wrongTerminal, state, 'revoked'), /capability, result, lifecycle, or audit/);
  const mutableCurrentStateSubstitution = structuredClone(rows);
  mutableCurrentStateSubstitution[0].application.resulting_state = 'revoked';
  assert.throws(() => validateEvidenceChainRows(mutableCurrentStateSubstitution, state, 'revoked'), /capability, result, lifecycle/);
  const crossedAuthorization = structuredClone(rows);
  crossedAuthorization[0].capability.authorization_digest = state.revocation.authorization_digest;
  assert.throws(() => validateEvidenceChainRows(crossedAuthorization, state, 'revoked'), /capability, result, lifecycle/);

  const release = journalFixtureState('release_expiry');
  const releaseRows = [evidenceChainRow('add', release.action, release, 0)];
  assert.equal(validateEvidenceChainRows(releaseRows, release, 'active'), true);
  const expiredRows = structuredClone(releaseRows);
  expiredRows[0].action.state = 'expired';
  expiredRows[0].action.version = release.action.action_version + 1;
  assert.equal(validateEvidenceChainRows(expiredRows, release, 'expired'), true);
  assert.throws(() => validateEvidenceChainRows(expiredRows, release, 'active'),
    /current action descendant is invalid/);
  assert.throws(() => validateEvidenceChainRows([...releaseRows, rows[1]], release, 'active'), /row count is invalid/);
  assert.throws(() => validateEvidenceChainRows([releaseRows[0]], {
    ...release, mode: 'fast_revoke', revocation: null,
  }, 'revoked'), /missing revocation evidence/);
});

test('v4 E2E state binds one .20 action and both artifact digests to an exact fast or release mode', () => {
  const state = journalFixtureState('release_expiry');
  assert.deepEqual(validateDemoState(state), state);
  assert.throws(
    () => validateDemoState({ ...state, extra: true }),
    /shape is invalid/,
  );
  assert.throws(
    () => validateDemoState({ ...state, action: { ...state.action, target_ipv4: '203.0.113.24' } }),
    /frozen demo source/,
  );
  assert.throws(() => validateDemoState({ ...state, mode: 'fast_revoke' }, true),
    /missing revocation evidence/);
  assert.throws(() => validateDemoState({
    ...journalFixtureState('fast_revoke'), mode: 'release_expiry',
  }), /cannot contain revocation authority/);
  const oldV2 = {
    schema_version: 'sentinelflow-demo-e2e-state-v2', revoke_action: state.action,
    expiry_action: state.action, revocation: null,
  };
  assert.throws(() => validateDemoState(oldV2), /shape is invalid/);
});

test('revocation challenge and decision bind exact JCS, nonce, reason, authority, and rotation', () => {
  const action = activeAction();
  const evidence = actionEvidence(action);
  const sourceSession = {
    actor_id: 'admin-demo', session_id: uuid('20'), authenticated_at: '2026-07-19T00:55:00Z',
    expires_at: '2026-07-19T08:55:00Z',
  };
  const nonce = Buffer.alloc(32, 7).toString('base64url');
  const nonceDigest = `sha256:${createHash('sha256').update(Buffer.alloc(32, 7)).digest('hex')}`;
  const artifact = `delete element inet sentinelflow blacklist_ipv4 { ${action.target_ipv4} }\n`;
  const artifactDigest = digestText(artifact);
  const challenge = {
    authenticated_at: sourceSession.authenticated_at,
    canonical_artifact_digest: artifactDigest,
    challenge_id: uuid('21'),
    evidence_snapshot_digest: evidence.evidence_snapshot_digest,
    expires_at: '2026-07-19T01:10:00Z',
    generated_artifact_digest: artifactDigest,
    issued_at: '2026-07-19T01:05:00Z',
    nonce_digest: nonceDigest,
    operation: 'revoke',
    original_add_digest: action.canonical_artifact_digest,
    policy_digest: evidence.policy_digest,
    reauth_required_after_seconds: 900,
    resource_id: action.action_id,
    resource_type: 'enforcement_action',
    resource_version: action.version,
    schema_version: 'hil-challenge-v1',
    session_digest: digest('6'),
    target_ipv4: action.target_ipv4,
    validation_snapshot_digest: evidence.validation_snapshot_digest,
    validation_valid_until: '2026-07-19T01:10:00Z',
  };
  const challengeEnvelope = {
    challenge,
    challenge_nonce: nonce,
    canonical_revoke_artifact: artifact,
    policy_id: action.policy_id,
    policy_version: action.policy_version,
  };
  const checkedChallenge = validateRevocationChallengeEnvelope(
    challengeEnvelope, action, evidence, sourceSession,
  );
  assert.equal(checkedChallenge.artifact_digest, artifactDigest);

  const reason = {
    schema_version: 'hil-reason-v1',
    reason_code: 'operator_request',
    reason_text: 'Remove the exact synthetic credential-stuffing block.',
  };
  const idempotencyKey = 'e2e.revoke.0123456789abcdef0123456789abcdef';
  const decision = {
    actor_id: sourceSession.actor_id,
    canonical_artifact_digest: artifactDigest,
    challenge_id: challenge.challenge_id,
    decided_at: '2026-07-19T01:06:00Z',
    decision: 'revoked',
    decision_id: uuid('22'),
    decision_valid_until: '2026-07-19T01:09:00Z',
    evidence_snapshot_digest: evidence.evidence_snapshot_digest,
    generated_artifact_digest: artifactDigest,
    idempotency_key_digest: digestText(idempotencyKey),
    nonce_digest: nonceDigest,
    operation: 'revoke',
    original_add_digest: action.canonical_artifact_digest,
    policy_digest: evidence.policy_digest,
    reason_digest: digestJSON(reason),
    resource_id: action.action_id,
    resource_type: 'enforcement_action',
    resource_version: action.version,
    schema_version: 'hil-decision-v1',
    session_digest: challenge.session_digest,
    target_ipv4: action.target_ipv4,
    validation_snapshot_digest: evidence.validation_snapshot_digest,
  };
  const ids = {
    revocation: uuid('23'), authorization: uuid('24'), outbox: uuid('25'), audit: uuid('26'),
  };
  const authorization = {
    action_id: decision.resource_id,
    actor_id: decision.actor_id,
    authorization_id: ids.authorization,
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
  const decisionEnvelope = {
    decision,
    revocation_id: ids.revocation,
    authorization_id: ids.authorization,
    authorization_digest: digestJSON(authorization),
    outbox_job_id: ids.outbox,
    audit_event_id: ids.audit,
    session: {
      actor_id: sourceSession.actor_id, session_id: uuid('27'),
      authenticated_at: sourceSession.authenticated_at, expires_at: sourceSession.expires_at,
    },
    csrf_token: Buffer.alloc(32, 8).toString('base64url'),
  };
  const checkedDecision = validateRevocationDecisionEnvelope(
    decisionEnvelope, checkedChallenge, action, evidence, reason, idempotencyKey, sourceSession,
  );
  assert.equal(checkedDecision.authorization_digest, decisionEnvelope.authorization_digest);

  const mismatched = structuredClone(decisionEnvelope);
  mismatched.decision.resource_version += 1;
  assert.throws(
    () => validateRevocationDecisionEnvelope(
      mismatched, checkedChallenge, action, evidence, reason, idempotencyKey, sourceSession,
    ),
    /binding is invalid/,
  );
  assert.throws(
    () => validateRevocationChallengeEnvelope(
      { ...challengeEnvelope, canonical_revoke_artifact: `${artifact} ` }, action, evidence, sourceSession,
    ),
    /binding is invalid/,
  );
});
