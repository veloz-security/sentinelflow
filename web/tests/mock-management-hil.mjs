import crypto from 'node:crypto';

export const HIL_POLICY_ID = '019b0000-0000-7000-8000-000000000301';
export const HIL_VALIDITY_MS = 5 * 60 * 1000;

const command =
  'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n';

function deepFreeze(value) {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function timestamp(anchor, offset = 0) {
  return new Date(anchor + offset).toISOString();
}

export function canonicalJSONString(value) {
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'string'
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJSONString(item)).join(',')}]`;
  }
  if (typeof value === 'object' && value !== null) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJSONString(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('value is not canonical JSON data');
}

export function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function lineageDigest(lineage, domain, material = null) {
  return sha256(
    canonicalJSONString({
      domain,
      lineage,
      material,
      schema_version: 'mock-hil-lineage-v1',
    }),
  );
}

function uuidFromLineage(lineage, domain) {
  const bytes = crypto
    .createHash('sha256')
    .update(`mock-hil-uuid-v1\u0000${lineage}\u0000${domain}`)
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function nonceFromLineage(lineage) {
  return crypto
    .createHash('sha256')
    .update(`mock-hil-nonce-v1\u0000${lineage}`)
    .digest();
}

export function computeValidationSnapshotDigest(snapshot) {
  const { snapshot_digest: ignored, ...digestMaterial } = snapshot;
  void ignored;
  return sha256(canonicalJSONString(digestMaterial));
}

function createValidationSnapshot({ anchor, lineage, validUntil }) {
  const gates = [
    'structured_output',
    'command_grammar',
    'policy_evidence_command_consistency',
    'protected_network',
    'owned_schema_syntax',
    'historical_impact',
  ].map((name, index) => ({
    order: index + 1,
    name,
    passed: true,
    result_code: 'ok',
    input_digest: lineageDigest(lineage, `gate:${name}:input`),
    result_digest: lineageDigest(lineage, `gate:${name}:result`),
    checked_at: timestamp(anchor, -10 * 1000),
  }));
  const snapshot = {
    validation_snapshot_id: uuidFromLineage(lineage, 'validation-snapshot'),
    state: 'valid',
    source_health_status: 'complete',
    base_chain_contract_raw_digest: sha256('mock-base-chain-contract-v1'),
    live_owned_schema_digest: sha256('mock-live-owned-schema-v1'),
    protected_ipv4_static_digest: sha256('mock-protected-ipv4-static-v1'),
    protected_ipv4_effective_config_digest: sha256(
      'mock-protected-ipv4-effective-v1',
    ),
    historical_impact_digest: lineageDigest(lineage, 'historical-impact'),
    created_at: timestamp(anchor, -10 * 1000),
    valid_until: validUntil,
    gates,
  };
  return {
    ...snapshot,
    snapshot_digest: computeValidationSnapshotDigest(snapshot),
  };
}

export function createHilScenario(anchor, session, generation = 0) {
  if (!Number.isFinite(anchor)) throw new TypeError('anchor must be finite');
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new TypeError('generation must be a non-negative safe integer');
  }
  const sessionExpiry = Date.parse(session.expires_at);
  if (!Number.isFinite(sessionExpiry)) {
    throw new TypeError('session expiry must be a date-time');
  }
  const validUntil = Math.min(anchor + HIL_VALIDITY_MS, sessionExpiry);
  if (validUntil <= anchor) {
    throw new RangeError(
      'session expires before a HIL challenge can be issued',
    );
  }

  const lineage = sha256(
    canonicalJSONString({
      anchor,
      authenticated_at: session.authenticated_at,
      generation,
      session_id: session.session_id,
      schema_version: 'mock-hil-scenario-v1',
    }),
  );
  const analysisID = uuidFromLineage(lineage, 'analysis');
  const commandCandidateID = uuidFromLineage(lineage, 'command-candidate');
  const evidenceSnapshotDigest = lineageDigest(lineage, 'evidence-snapshot', {
    analysis_id: analysisID,
    signal_ids: ['mock-auth-failure-spread-v1'],
  });
  const generatedArtifactDigest = sha256(command);
  const canonicalArtifactDigest = sha256(command);
  const policyDigest = lineageDigest(lineage, 'policy', {
    analysis_id: analysisID,
    command_candidate_id: commandCandidateID,
    evidence_snapshot_digest: evidenceSnapshotDigest,
    target_ipv4: '203.0.113.20',
    ttl_seconds: 1800,
  });
  const validationValidUntil = timestamp(validUntil);
  const latestValidation = createValidationSnapshot({
    anchor,
    lineage,
    validUntil: validationValidUntil,
  });

  const policy = {
    policy_id: HIL_POLICY_ID,
    version: 1,
    incident_id: '019b0000-0000-7000-8000-000000000101',
    incident_version: 2,
    analysis_id: analysisID,
    command_candidate_id: commandCandidateID,
    state: 'valid',
    state_revision: generation + 3,
    target_ipv4: '203.0.113.20',
    action: 'block_ip',
    ttl_seconds: 1800,
    timeout_token: '30m',
    rationale: 'Synthetic evidence indicates a bounded browser test attack.',
    policy_digest: policyDigest,
    evidence_snapshot_digest: evidenceSnapshotDigest,
    generated_command: command,
    generated_artifact_digest: generatedArtifactDigest,
    canonical_command: command,
    canonical_artifact_digest: canonicalArtifactDigest,
    parse_state: 'valid',
    created_at: timestamp(anchor, -30 * 1000),
    updated_at: timestamp(anchor, -10 * 1000),
    latest_validation: latestValidation,
  };

  const challengeID = uuidFromLineage(lineage, 'challenge');
  const challengeNonceBytes = nonceFromLineage(lineage);
  const challengeNonce = challengeNonceBytes.toString('base64url');
  const challengeNonceDigest = sha256(challengeNonceBytes);
  const sessionDigest = lineageDigest(lineage, 'session-binding', {
    authenticated_at: session.authenticated_at,
    challenge_id: challengeID,
    nonce_digest: challengeNonceDigest,
    session_id: session.session_id,
    validation_snapshot_digest: latestValidation.snapshot_digest,
  });
  const challenge = {
    authenticated_at: session.authenticated_at,
    canonical_artifact_digest: canonicalArtifactDigest,
    challenge_id: challengeID,
    evidence_snapshot_digest: evidenceSnapshotDigest,
    expires_at: validationValidUntil,
    generated_artifact_digest: generatedArtifactDigest,
    issued_at: timestamp(anchor),
    nonce_digest: challengeNonceDigest,
    operation: 'approve',
    original_add_digest: null,
    policy_digest: policyDigest,
    reauth_required_after_seconds: 900,
    resource_id: HIL_POLICY_ID,
    resource_type: 'policy',
    resource_version: policy.version,
    schema_version: 'hil-challenge-v1',
    session_digest: sessionDigest,
    target_ipv4: policy.target_ipv4,
    validation_snapshot_digest: latestValidation.snapshot_digest,
    validation_valid_until: validationValidUntil,
  };

  return deepFreeze({
    anchor,
    generation,
    lineage,
    policy,
    challenge,
    challenge_nonce: challengeNonce,
  });
}

export function createHilScenarioManager(session) {
  let active = null;
  let generation = 0;
  let lastAnchor = Number.NEGATIVE_INFINITY;
  let retireAfterRead = null;
  function current(now) {
    if (active === null || Date.parse(active.challenge.expires_at) <= now) {
      const anchor = Math.max(now, lastAnchor + 1);
      active = createHilScenario(anchor, session, generation);
      lastAnchor = anchor;
      retireAfterRead = null;
      generation += 1;
    }
    return active;
  }
  return Object.freeze({
    current(now = Date.now()) {
      return current(now);
    },
    read(now = Date.now()) {
      const scenario = current(now);
      if (retireAfterRead === scenario) {
        active = null;
        retireAfterRead = null;
      }
      return scenario;
    },
    retireAfterNextRead(scenario) {
      if (active === scenario) retireAfterRead = scenario;
    },
    retire(scenario) {
      if (active === scenario) {
        active = null;
        retireAfterRead = null;
      }
    },
  });
}

function createFreshDecisionResponse({
  scenario,
  idempotencyKey,
  reason,
  rotatedSession,
  now,
}) {
  const expiresAt = Date.parse(scenario.challenge.expires_at);
  if (now >= expiresAt) throw new RangeError('challenge expired');
  const decidedAt = Math.max(now, Date.parse(scenario.challenge.issued_at));
  const authorityLineage = canonicalJSONString({
    challenge_id: scenario.challenge.challenge_id,
    decided_at: timestamp(decidedAt),
    idempotency_key_digest: sha256(idempotencyKey),
    schema_version: 'mock-hil-authority-v1',
  });
  const decision = {
    actor_id: 'admin',
    canonical_artifact_digest: scenario.policy.canonical_artifact_digest,
    challenge_id: scenario.challenge.challenge_id,
    decided_at: timestamp(decidedAt),
    decision: 'approved',
    decision_id: uuidFromLineage(authorityLineage, 'decision'),
    decision_valid_until: scenario.challenge.validation_valid_until,
    evidence_snapshot_digest: scenario.policy.evidence_snapshot_digest,
    generated_artifact_digest: scenario.policy.generated_artifact_digest,
    idempotency_key_digest: sha256(idempotencyKey),
    nonce_digest: scenario.challenge.nonce_digest,
    operation: 'approve',
    original_add_digest: null,
    policy_digest: scenario.policy.policy_digest,
    reason_digest: sha256(
      canonicalJSONString({
        reason_code: reason.reason_code,
        reason_text: reason.reason_text,
        schema_version: reason.schema_version,
      }),
    ),
    resource_id: HIL_POLICY_ID,
    resource_type: 'policy',
    resource_version: scenario.policy.version,
    schema_version: 'hil-decision-v1',
    session_digest: scenario.challenge.session_digest,
    target_ipv4: scenario.policy.target_ipv4,
    validation_snapshot_digest:
      scenario.policy.latest_validation.snapshot_digest,
  };
  const actionID = uuidFromLineage(authorityLineage, 'action');
  const outboxJobID = uuidFromLineage(authorityLineage, 'outbox-job');
  const authorizationDigest = sha256(
    canonicalJSONString({
      action_id: actionID,
      decision,
      outbox_job_id: outboxJobID,
      schema_version: 'mock-hil-authorization-v1',
    }),
  );
  return deepFreeze({
    decision,
    action_id: actionID,
    authorization_digest: authorizationDigest,
    outbox_job_id: outboxJobID,
    session: rotatedSession,
    csrf_token: 'b'.repeat(43),
  });
}

function createReplayDecisionResponse(response) {
  return deepFreeze({
    decision: response.decision,
    action_id: response.action_id,
    authorization_digest: response.authorization_digest,
    outbox_job_id: response.outbox_job_id,
    replayed: true,
    reauthentication_required: true,
  });
}

export function createDecisionResponse({
  scenario,
  idempotencyKey,
  reason,
  rotatedSession,
  replayed = false,
  now = Date.now(),
}) {
  const response = createFreshDecisionResponse({
    scenario,
    idempotencyKey,
    reason,
    rotatedSession,
    now,
  });
  return replayed ? createReplayDecisionResponse(response) : response;
}

export function createHilAuthorizationStore({ rotatedSession }) {
  const issuedByIdempotencyKey = new Map();
  const committedByChallenge = new Map();
  return Object.freeze({
    issue({ scenario, idempotencyKey, requestFingerprint }) {
      const issued = issuedByIdempotencyKey.get(idempotencyKey);
      if (issued !== undefined) {
        if (issued.requestFingerprint !== requestFingerprint) {
          return Object.freeze({ kind: 'conflict' });
        }
        return Object.freeze({
          kind: 'replay',
          scenario: issued.scenario,
        });
      }
      issuedByIdempotencyKey.set(idempotencyKey, {
        requestFingerprint,
        scenario,
      });
      return Object.freeze({ kind: 'fresh', scenario });
    },
    scenarioFor(idempotencyKey) {
      return issuedByIdempotencyKey.get(idempotencyKey)?.scenario ?? null;
    },
    consume({ idempotencyKey, requestFingerprint, reason, now = Date.now() }) {
      const issued = issuedByIdempotencyKey.get(idempotencyKey);
      if (issued === undefined) return Object.freeze({ kind: 'missing' });
      const challengeID = issued.scenario.challenge.challenge_id;
      const committed = committedByChallenge.get(challengeID);
      if (committed !== undefined) {
        if (
          committed.idempotencyKey === idempotencyKey &&
          committed.requestFingerprint === requestFingerprint
        ) {
          return Object.freeze({
            kind: 'replay',
            response: createReplayDecisionResponse(committed.response),
            scenario: issued.scenario,
          });
        }
        return Object.freeze({ kind: 'conflict', scenario: issued.scenario });
      }
      if (now >= Date.parse(issued.scenario.challenge.expires_at)) {
        return Object.freeze({ kind: 'expired', scenario: issued.scenario });
      }
      const response = createFreshDecisionResponse({
        scenario: issued.scenario,
        idempotencyKey,
        reason,
        rotatedSession,
        now,
      });
      committedByChallenge.set(challengeID, {
        idempotencyKey,
        requestFingerprint,
        response,
      });
      return Object.freeze({
        kind: 'fresh',
        response,
        scenario: issued.scenario,
      });
    },
  });
}
