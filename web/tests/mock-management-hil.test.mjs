import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';
import {
  HIL_POLICY_ID,
  HIL_VALIDITY_MS,
  canonicalJSONString,
  computeValidationSnapshotDigest,
  createDecisionResponse,
  createHilAuthorizationStore,
  createHilScenario,
  createHilScenarioManager,
  sha256,
} from './mock-management-hil.mjs';

const baseline = Date.parse('2026-07-19T00:00:00.000Z');
const session = Object.freeze({
  actor_id: 'admin',
  session_id: '019b0000-0000-7000-8000-000000000001',
  authenticated_at: new Date(baseline - 60_000).toISOString(),
  expires_at: new Date(baseline + 8 * 60 * 60 * 1000).toISOString(),
});
const rotatedSession = Object.freeze({ ...session, session_id: 'rotated' });
const reason = Object.freeze({
  schema_version: 'hil-reason-v1',
  reason_code: 'threat_confirmed',
  reason_text: 'Synthetic test evidence reviewed.',
});
const command =
  'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n';
const testNamespaceHeader = 'X-SentinelFlow-Test-Namespace';

function binding(policy) {
  return {
    operation: 'approve',
    policy_version: policy.version,
    target_ipv4: policy.target_ipv4,
    ttl_seconds: policy.ttl_seconds,
    policy_digest: policy.policy_digest,
    generated_artifact_digest: policy.generated_artifact_digest,
    canonical_artifact_digest: policy.canonical_artifact_digest,
    evidence_snapshot_digest: policy.evidence_snapshot_digest,
    validation_snapshot_digest: policy.latest_validation.snapshot_digest,
  };
}

function decisionBody(policyBinding, envelope) {
  return {
    ...policyBinding,
    challenge: envelope.challenge,
    challenge_nonce: envelope.challenge_nonce,
    reason,
  };
}

test('controlled five- and eleven-minute replacements regenerate a digest-consistent lineage', () => {
  const scenarios = createHilScenarioManager(session);
  const first = scenarios.current(baseline);
  const coherentReload = scenarios.current(baseline + 60_000);
  const afterFiveMinutes = scenarios.current(baseline + HIL_VALIDITY_MS + 1);
  const afterElevenMinutes = scenarios.current(baseline + 11 * 60 * 1000);
  const generations = [first, afterFiveMinutes, afterElevenMinutes];

  assert.equal(
    coherentReload,
    first,
    'reads and challenge issue share one immutable unexpired scenario',
  );
  for (const scenario of generations) {
    assert.equal(
      Date.parse(scenario.challenge.expires_at) -
        Date.parse(scenario.challenge.issued_at),
      HIL_VALIDITY_MS,
    );
    assert.equal(
      scenario.policy.latest_validation.snapshot_digest,
      computeValidationSnapshotDigest(scenario.policy.latest_validation),
    );
    assert.equal(
      scenario.challenge.validation_snapshot_digest,
      scenario.policy.latest_validation.snapshot_digest,
    );
    assert.equal(
      scenario.challenge.nonce_digest,
      sha256(Buffer.from(scenario.challenge_nonce, 'base64url')),
    );
    assert.equal(scenario.challenge_nonce.length, 43);
    assert.equal(scenario.policy.generated_artifact_digest, sha256(command));
    assert.equal(scenario.policy.canonical_artifact_digest, sha256(command));
    assert.ok(Object.isFrozen(scenario));
    assert.ok(Object.isFrozen(scenario.policy.latest_validation));
  }

  for (const select of [
    (scenario) => scenario.policy.analysis_id,
    (scenario) => scenario.policy.command_candidate_id,
    (scenario) => scenario.policy.policy_digest,
    (scenario) => scenario.policy.evidence_snapshot_digest,
    (scenario) => scenario.policy.latest_validation.validation_snapshot_id,
    (scenario) => scenario.policy.latest_validation.snapshot_digest,
    (scenario) => scenario.challenge.challenge_id,
    (scenario) => scenario.challenge_nonce,
    (scenario) => scenario.challenge.nonce_digest,
    (scenario) => scenario.challenge.session_digest,
    (scenario) => scenario.challenge.issued_at,
    (scenario) => scenario.challenge.expires_at,
  ]) {
    assert.equal(new Set(generations.map(select)).size, generations.length);
  }
  assert.throws(() => {
    first.challenge.expires_at = afterFiveMinutes.challenge.expires_at;
  }, TypeError);
});

test('the decision stays bound to the immutable request-time scenario', () => {
  const scenario = createHilScenario(baseline, session);
  const response = createDecisionResponse({
    scenario,
    idempotencyKey: 'hil-00000000-0000-4000-8000-000000000001',
    reason,
    rotatedSession,
    now: baseline + 1000,
  });
  assert.equal(
    response.decision.decision_valid_until,
    scenario.challenge.validation_valid_until,
  );
  assert.equal(
    response.decision.validation_snapshot_digest,
    scenario.challenge.validation_snapshot_digest,
  );
  assert.equal(response.decision.nonce_digest, scenario.challenge.nonce_digest);
  assert.throws(
    () =>
      createDecisionResponse({
        scenario,
        idempotencyKey: 'hil-00000000-0000-4000-8000-000000000001',
        reason,
        rotatedSession,
        now: baseline + HIL_VALIDITY_MS,
      }),
    /challenge expired/,
  );
});

test('two concurrent idempotency keys consume one challenge only once', async () => {
  const scenario = createHilScenario(baseline, session);
  const store = createHilAuthorizationStore({ rotatedSession });
  const keys = [
    'hil-00000000-0000-4000-8000-000000000011',
    'hil-00000000-0000-4000-8000-000000000012',
  ];
  const challengeFingerprint = canonicalJSONString(binding(scenario.policy));
  for (const idempotencyKey of keys) {
    assert.equal(
      store.issue({
        scenario,
        idempotencyKey,
        requestFingerprint: challengeFingerprint,
      }).kind,
      'fresh',
    );
  }
  const requestFingerprint = canonicalJSONString({
    ...binding(scenario.policy),
    challenge: scenario.challenge,
    challenge_nonce: scenario.challenge_nonce,
    reason,
  });
  const outcomes = await Promise.all(
    keys.map((idempotencyKey) =>
      Promise.resolve().then(() =>
        store.consume({
          idempotencyKey,
          requestFingerprint,
          reason,
          now: baseline + 1000,
        }),
      ),
    ),
  );
  assert.deepEqual(outcomes.map((outcome) => outcome.kind).sort(), [
    'conflict',
    'fresh',
  ]);
  const winnerIndex = outcomes.findIndex((outcome) => outcome.kind === 'fresh');
  const winningKey = keys[winnerIndex];
  const fresh = outcomes[winnerIndex].response;
  const replay = store.consume({
    idempotencyKey: winningKey,
    requestFingerprint,
    reason,
    now: baseline + 2000,
  });
  assert.equal(replay.kind, 'replay');
  assert.equal(replay.response.replayed, true);
  assert.equal(
    replay.response.decision.decision_id,
    fresh.decision.decision_id,
  );
  assert.equal(replay.response.action_id, fresh.action_id);
  assert.equal(replay.response.outbox_job_id, fresh.outbox_job_id);
  assert.equal(
    replay.response.authorization_digest,
    fresh.authorization_digest,
  );
  assert.equal(
    store.consume({
      idempotencyKey: winningKey,
      requestFingerprint: `${requestFingerprint} `,
      reason,
      now: baseline + 2000,
    }).kind,
    'conflict',
  );
});

test('replacement scenarios produce unique decision, action, outbox, and decision dates', () => {
  const store = createHilAuthorizationStore({ rotatedSession });
  const scenarios = [
    createHilScenario(baseline, session, 0),
    createHilScenario(baseline + 11 * 60 * 1000, session, 1),
  ];
  const responses = scenarios.map((scenario, index) => {
    const idempotencyKey = `hil-00000000-0000-4000-8000-00000000002${index}`;
    const challengeFingerprint = canonicalJSONString(binding(scenario.policy));
    store.issue({
      scenario,
      idempotencyKey,
      requestFingerprint: challengeFingerprint,
    });
    const requestFingerprint = canonicalJSONString({
      ...binding(scenario.policy),
      challenge: scenario.challenge,
      challenge_nonce: scenario.challenge_nonce,
      reason,
    });
    const outcome = store.consume({
      idempotencyKey,
      requestFingerprint,
      reason,
      now: scenario.anchor + 1000,
    });
    assert.equal(outcome.kind, 'fresh');
    return outcome.response;
  });
  for (const select of [
    (response) => response.decision.decision_id,
    (response) => response.action_id,
    (response) => response.outbox_job_id,
    (response) => response.authorization_digest,
    (response) => response.decision.decided_at,
  ]) {
    assert.equal(new Set(responses.map(select)).size, responses.length);
  }
});

async function startMockServer(t) {
  const child = spawn(process.execPath, ['tests/mock-management-server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      SENTINELFLOW_MOCK_PORT: '0',
      SENTINELFLOW_MOCK_REPORT_PORT: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  const port = await new Promise((resolve, reject) => {
    let stdout = '';
    const timeout = setTimeout(
      () => reject(new Error(`mock server startup timed out: ${stderr}`)),
      10_000,
    );
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      const match = stdout.match(/SENTINELFLOW_MOCK_PORT=([0-9]+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(Number(match[1]));
      }
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      reject(
        new Error(
          `mock server exited before readiness (${code ?? signal}): ${stderr}`,
        ),
      );
    });
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await once(child, 'exit');
    }
  });
  return `http://127.0.0.1:${port}`;
}

function namespaceHeaders(namespace) {
  return namespace === undefined ? {} : { [testNamespaceHeader]: namespace };
}

async function fetchJSON(url, namespace) {
  return fetch(url, { headers: namespaceHeaders(namespace) });
}

async function postJSON(url, idempotencyKey, value, namespace) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      ...namespaceHeaders(namespace),
    },
    body: JSON.stringify(value),
  });
}

test('the HTTP mock server allows exactly one concurrent fresh authority', async (t) => {
  const origin = await startMockServer(t);
  const policyURL = `${origin}/api/v1/policies/${HIL_POLICY_ID}`;
  const policy = await fetch(policyURL).then((response) => response.json());
  const policyBinding = binding(policy);
  const keys = [
    'hil-00000000-0000-4000-8000-000000000031',
    'hil-00000000-0000-4000-8000-000000000032',
  ];
  const challengeURL = `${policyURL}/decision-challenges`;
  const challengeResponses = await Promise.all(
    keys.map((key) => postJSON(challengeURL, key, policyBinding)),
  );
  assert.deepEqual(
    challengeResponses.map((response) => response.status),
    [201, 201],
  );
  const envelopes = await Promise.all(
    challengeResponses.map((response) => response.json()),
  );
  assert.deepEqual(envelopes[0], envelopes[1]);

  const bodies = envelopes.map((envelope) =>
    decisionBody(policyBinding, envelope),
  );
  const decisionURL = `${policyURL}/decisions`;
  const decisionResponses = await Promise.all(
    keys.map((key, index) => postJSON(decisionURL, key, bodies[index])),
  );
  assert.deepEqual(
    decisionResponses.map((response) => response.status).sort(),
    [200, 409],
  );
  const winnerIndex = decisionResponses.findIndex(
    (response) => response.status === 200,
  );
  const loserIndex = winnerIndex === 0 ? 1 : 0;
  const fresh = await decisionResponses[winnerIndex].json();
  const conflict = await decisionResponses[loserIndex].json();
  assert.equal(Object.hasOwn(fresh, 'replayed'), false);
  assert.equal(conflict.code, 'idempotency_conflict');

  const committedPolicy = await fetch(policyURL).then((response) =>
    response.json(),
  );
  assert.equal(
    committedPolicy.latest_validation.validation_snapshot_id,
    policy.latest_validation.validation_snapshot_id,
  );
  assert.equal(
    committedPolicy.latest_validation.snapshot_digest,
    policy.latest_validation.snapshot_digest,
  );

  const replayResponse = await postJSON(
    decisionURL,
    keys[winnerIndex],
    bodies[winnerIndex],
  );
  assert.equal(replayResponse.status, 200);
  const replay = await replayResponse.json();
  assert.equal(replay.replayed, true);
  assert.equal(replay.decision.decision_id, fresh.decision.decision_id);
  assert.equal(replay.action_id, fresh.action_id);
  assert.equal(replay.outbox_job_id, fresh.outbox_job_id);
  assert.equal(replay.authorization_digest, fresh.authorization_digest);

  const secondPolicy = await fetch(policyURL).then((response) =>
    response.json(),
  );
  assert.notEqual(
    secondPolicy.latest_validation.validation_snapshot_id,
    policy.latest_validation.validation_snapshot_id,
  );
  assert.notEqual(
    secondPolicy.latest_validation.snapshot_digest,
    policy.latest_validation.snapshot_digest,
  );
});

test('the HTTP mock server isolates concurrent HIL state by namespace', async (t) => {
  const origin = await startMockServer(t);
  const policyURL = `${origin}/api/v1/policies/${HIL_POLICY_ID}`;
  const challengeURL = `${policyURL}/decision-challenges`;
  const decisionURL = `${policyURL}/decisions`;
  const namespaces = ['browser-project-a', 'browser-project-b'];
  const policies = await Promise.all(
    namespaces.map((namespace) =>
      fetchJSON(policyURL, namespace).then((response) => response.json()),
    ),
  );
  const idempotencyKey = 'hil-00000000-0000-4000-8000-000000000041';
  const challengeResponses = await Promise.all(
    namespaces.map((namespace, index) =>
      postJSON(
        challengeURL,
        idempotencyKey,
        binding(policies[index]),
        namespace,
      ),
    ),
  );
  assert.deepEqual(
    challengeResponses.map((response) => response.status),
    [201, 201],
  );
  const envelopes = await Promise.all(
    challengeResponses.map((response) => response.json()),
  );

  const firstDecision = await postJSON(
    decisionURL,
    idempotencyKey,
    decisionBody(binding(policies[0]), envelopes[0]),
    namespaces[0],
  );
  assert.equal(firstDecision.status, 200);
  const firstNamespaceRead = await fetchJSON(policyURL, namespaces[0]).then(
    (response) => response.json(),
  );
  const firstNamespaceReplacement = await fetchJSON(
    policyURL,
    namespaces[0],
  ).then((response) => response.json());
  const secondNamespaceRead = await fetchJSON(policyURL, namespaces[1]).then(
    (response) => response.json(),
  );
  assert.equal(
    firstNamespaceRead.latest_validation.snapshot_digest,
    policies[0].latest_validation.snapshot_digest,
  );
  assert.notEqual(
    firstNamespaceReplacement.latest_validation.snapshot_digest,
    policies[0].latest_validation.snapshot_digest,
  );
  assert.equal(
    secondNamespaceRead.latest_validation.snapshot_digest,
    policies[1].latest_validation.snapshot_digest,
  );

  const secondDecision = await postJSON(
    decisionURL,
    idempotencyKey,
    decisionBody(binding(policies[1]), envelopes[1]),
    namespaces[1],
  );
  assert.equal(secondDecision.status, 200);

  const malformed = await fetchJSON(policyURL, 'invalid namespace');
  assert.equal(malformed.status, 422);
  assert.equal((await malformed.json()).code, 'schema_invalid');
});
