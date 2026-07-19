import type {
  HILChallengeEnvelope,
  HILDecisionEnvelope,
  HILOperation,
  HILReason,
  HILReasonCode,
  PolicyArtifactBinding,
  PolicyDetail,
  SessionProjection,
} from './contracts';

const EXPECTED_GATES = [
  'structured_output',
  'command_grammar',
  'policy_evidence_command_consistency',
  'protected_network',
  'owned_schema_syntax',
  'historical_impact',
] as const;

export interface PolicyDecisionReadiness {
  readonly ready: boolean;
  readonly blockers: readonly string[];
}

export type PolicyCommandIntegrityStatus =
  'pending' | 'verified' | 'mismatch' | 'unavailable' | 'error';

export interface PolicyCommandIntegrityResult {
  readonly status: PolicyCommandIntegrityStatus;
  readonly verified: boolean;
  readonly blockers: readonly string[];
}

export type PolicyCommandIntegrityInput = Pick<
  PolicyDetail,
  | 'generated_command'
  | 'generated_artifact_digest'
  | 'canonical_command'
  | 'canonical_artifact_digest'
>;

export function policyArtifactBinding(
  policy: Readonly<PolicyDetail>,
  operation: HILOperation,
): Readonly<PolicyArtifactBinding> | null {
  if (!policy.latest_validation) {
    return null;
  }
  return Object.freeze({
    operation,
    policy_version: policy.version,
    target_ipv4: policy.target_ipv4,
    ttl_seconds: policy.ttl_seconds,
    policy_digest: policy.policy_digest,
    generated_artifact_digest: policy.generated_artifact_digest,
    canonical_artifact_digest: policy.canonical_artifact_digest,
    evidence_snapshot_digest: policy.evidence_snapshot_digest,
    validation_snapshot_digest: policy.latest_validation.snapshot_digest,
  });
}

export function policyDecisionReadiness(
  policy: Readonly<PolicyDetail>,
  csrfAvailable: boolean,
  now = Date.now(),
): PolicyDecisionReadiness {
  const blockers: string[] = [];
  if (!csrfAvailable) {
    blockers.push('The in-memory CSRF mutation guard is unavailable.');
  }
  if (policy.decision) {
    blockers.push('This policy version already has a final HIL decision.');
  }
  if (policy.state !== 'valid') {
    blockers.push('The immutable policy state is not valid.');
  }
  if (policy.parse_state !== 'valid') {
    blockers.push('The command candidate has not passed strict parsing.');
  }
  if (
    policy.latest_validation_attempt &&
    policy.latest_validation_attempt.state !== 'valid'
  ) {
    blockers.push('The latest validation attempt failed closed.');
  }
  const validation = policy.latest_validation;
  if (!validation) {
    blockers.push('No exact validation snapshot is available.');
  } else {
    if (validation.state !== 'valid') {
      blockers.push('The exact validation snapshot is not valid.');
    }
    if (validation.failure_code !== undefined) {
      blockers.push('The exact validation snapshot carries a failure result.');
    }
    if (validation.source_health_status !== 'complete') {
      blockers.push('Source coverage is incomplete.');
    }
    if (Date.parse(validation.valid_until) <= now) {
      blockers.push('The exact validation snapshot is stale.');
    }
    const gatesMatch =
      validation.gates.length === EXPECTED_GATES.length &&
      validation.gates.every(
        (gate, index) =>
          gate.order === index + 1 &&
          gate.name === EXPECTED_GATES[index] &&
          gate.passed &&
          gate.result_code === 'ok',
      );
    if (!gatesMatch) {
      blockers.push('All six ordered safety gates must pass exactly.');
    }
  }
  return Object.freeze({
    ready: blockers.length === 0,
    blockers: Object.freeze(blockers),
  });
}

export function reasonForDecision(
  reasonCode: HILReasonCode,
  reasonText: string,
): Readonly<HILReason> {
  return Object.freeze({
    schema_version: 'hil-reason-v1',
    reason_code: reasonCode,
    reason_text: reasonText.normalize('NFC'),
  });
}

export function validateDecisionReason(
  reason: Readonly<HILReason>,
): string | null {
  const byteLength = new TextEncoder().encode(reason.reason_text).byteLength;
  const runeLength = Array.from(reason.reason_text).length;
  if (
    reason.reason_text.length === 0 ||
    reason.reason_text.trim().length === 0
  ) {
    return 'A non-empty administrator reason is required.';
  }
  if (runeLength > 500 || byteLength > 4096) {
    return 'The reason must be at most 500 characters and 4096 UTF-8 bytes.';
  }
  if (
    [...reason.reason_text].some((character) => {
      const code = character.codePointAt(0) ?? 0;
      return (
        code <= 0x1f || code === 0x7f || (code >= 0xd800 && code <= 0xdfff)
      );
    })
  ) {
    return 'The reason cannot contain control characters, line breaks, or invalid Unicode.';
  }
  return null;
}

export function createHILIdempotencyKey(): string {
  if (!globalThis.crypto?.randomUUID) {
    throw new Error('secure browser entropy is unavailable');
  }
  return `hil-${globalThis.crypto.randomUUID()}`;
}

function decodeBase64URL(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    return null;
  }
  try {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/') + '=';
    const binary = globalThis.atob(normalized);
    const result = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    return result.byteLength === 32 ? result : null;
  } catch {
    return null;
  }
}

async function sha256(value: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('secure browser digest support is unavailable');
  }
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input.buffer);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')}`;
}

export async function verifyPolicyCommandIntegrity(
  policy: Readonly<PolicyCommandIntegrityInput>,
): Promise<Readonly<PolicyCommandIntegrityResult>> {
  if (!globalThis.crypto?.subtle) {
    return Object.freeze({
      status: 'unavailable',
      verified: false,
      blockers: Object.freeze([
        'Secure browser SHA-256 verification is unavailable.',
      ]),
    });
  }

  let generatedDigest: string;
  let canonicalDigest: string;
  try {
    [generatedDigest, canonicalDigest] = await Promise.all([
      sha256(new TextEncoder().encode(policy.generated_command)),
      sha256(new TextEncoder().encode(policy.canonical_command)),
    ]);
  } catch {
    return Object.freeze({
      status: 'error',
      verified: false,
      blockers: Object.freeze([
        'Secure browser SHA-256 verification could not be completed.',
      ]),
    });
  }

  const blockers: string[] = [];
  if (generatedDigest !== policy.generated_artifact_digest) {
    blockers.push(
      'The generated command does not match its declared SHA-256 digest.',
    );
  }
  if (canonicalDigest !== policy.canonical_artifact_digest) {
    blockers.push(
      'The canonical command does not match its declared SHA-256 digest.',
    );
  }
  return Object.freeze({
    status: blockers.length === 0 ? 'verified' : 'mismatch',
    verified: blockers.length === 0,
    blockers: Object.freeze(blockers),
  });
}

export async function challengeMatchesExactBinding(
  envelope: Readonly<HILChallengeEnvelope>,
  policyID: string,
  binding: Readonly<PolicyArtifactBinding>,
  session: Readonly<SessionProjection>,
): Promise<boolean> {
  const challenge = envelope.challenge;
  const nonce = decodeBase64URL(envelope.challenge_nonce);
  if (!nonce || (await sha256(nonce)) !== challenge.nonce_digest) {
    return false;
  }
  return (
    challenge.operation === binding.operation &&
    challenge.authenticated_at === session.authenticated_at &&
    Date.parse(challenge.expires_at) <= Date.parse(session.expires_at) &&
    challenge.resource_type === 'policy' &&
    challenge.resource_id === policyID &&
    challenge.resource_version === binding.policy_version &&
    challenge.target_ipv4 === binding.target_ipv4 &&
    challenge.policy_digest === binding.policy_digest &&
    challenge.generated_artifact_digest === binding.generated_artifact_digest &&
    challenge.canonical_artifact_digest === binding.canonical_artifact_digest &&
    challenge.evidence_snapshot_digest === binding.evidence_snapshot_digest &&
    challenge.validation_snapshot_digest ===
      binding.validation_snapshot_digest &&
    Date.parse(challenge.expires_at) <=
      Date.parse(challenge.validation_valid_until)
  );
}

export async function decisionMatchesExactBinding(
  envelope: Readonly<HILDecisionEnvelope>,
  challengeEnvelope: Readonly<HILChallengeEnvelope>,
  binding: Readonly<PolicyArtifactBinding>,
  reason: Readonly<HILReason>,
  idempotencyKey: string,
  actorID: string,
): Promise<boolean> {
  const decision = envelope.decision;
  const idempotencyDigest = await sha256(
    new TextEncoder().encode(idempotencyKey),
  );
  const reasonDigest = await sha256(
    new TextEncoder().encode(
      JSON.stringify({
        reason_code: reason.reason_code,
        reason_text: reason.reason_text,
        schema_version: reason.schema_version,
      }),
    ),
  );
  const challenge = challengeEnvelope.challenge;
  return (
    decision.actor_id === actorID &&
    decision.challenge_id === challenge.challenge_id &&
    decision.session_digest === challenge.session_digest &&
    decision.operation === binding.operation &&
    decision.decision ===
      (binding.operation === 'approve' ? 'approved' : 'rejected') &&
    decision.resource_id === challenge.resource_id &&
    decision.resource_version === binding.policy_version &&
    decision.target_ipv4 === binding.target_ipv4 &&
    decision.policy_digest === binding.policy_digest &&
    decision.generated_artifact_digest === binding.generated_artifact_digest &&
    decision.canonical_artifact_digest === binding.canonical_artifact_digest &&
    decision.evidence_snapshot_digest === binding.evidence_snapshot_digest &&
    decision.validation_snapshot_digest ===
      binding.validation_snapshot_digest &&
    decision.nonce_digest === challenge.nonce_digest &&
    decision.idempotency_key_digest === idempotencyDigest &&
    decision.reason_digest === reasonDigest &&
    Date.parse(decision.decided_at) >= Date.parse(challenge.issued_at) &&
    Date.parse(decision.decided_at) < Date.parse(challenge.expires_at) &&
    Date.parse(decision.decision_valid_until) <=
      Date.parse(challenge.expires_at) &&
    Date.parse(decision.decision_valid_until) <=
      Date.parse(challenge.validation_valid_until)
  );
}

export function policyBindingFingerprint(
  policy: Readonly<PolicyDetail>,
): string {
  return JSON.stringify([
    policy.policy_id,
    policy.version,
    policy.state,
    policy.state_revision,
    policy.target_ipv4,
    policy.ttl_seconds,
    policy.policy_digest,
    policy.generated_command,
    policy.generated_artifact_digest,
    policy.canonical_command,
    policy.canonical_artifact_digest,
    policy.evidence_snapshot_digest,
    policy.latest_validation?.snapshot_digest ?? '',
    policy.latest_validation?.valid_until ?? '',
    policy.decision?.decision_id ?? '',
  ]);
}
