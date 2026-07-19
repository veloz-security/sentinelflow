import type {
  EnforcementActionDetail,
  RevocationArtifactBinding,
  RevocationChallengeEnvelope,
  RevocationDecisionEnvelope,
  RevocationReason,
  RevocationReasonCode,
  SessionProjection,
} from './contracts';
import { validateDecisionReason } from './policyHil';

export interface RevocationReadiness {
  readonly ready: boolean;
  readonly blockers: readonly string[];
}

export const REVOCATION_BROWSER_CHECKED_FIELDS = Object.freeze([
  'canonical_revoke_artifact',
  'generated_artifact_digest',
  'canonical_artifact_digest',
  'challenge_nonce',
  'nonce_digest',
  'operation',
  'resource_type',
  'resource_id',
  'resource_version',
  'target_ipv4',
  'original_add_digest',
  'evidence_snapshot_digest',
  'policy_id',
  'policy_version',
  'authenticated_at',
  'expires_at',
] as const);

export const REVOCATION_SERVER_REVALIDATED_FIELDS = Object.freeze([
  'policy_digest',
  'validation_snapshot_digest',
  'session_digest',
] as const);

export type RevocationChallengeBrowserCheckStatus =
  'passed' | 'mismatch' | 'unavailable' | 'error';

export interface RevocationChallengeBrowserCheck {
  readonly status: RevocationChallengeBrowserCheckStatus;
  readonly passed: boolean;
  readonly blockers: readonly string[];
  readonly independentlyCheckedFields: typeof REVOCATION_BROWSER_CHECKED_FIELDS;
  readonly serverRevalidatedFields: typeof REVOCATION_SERVER_REVALIDATED_FIELDS;
}

function browserCheck(
  status: RevocationChallengeBrowserCheckStatus,
  passed: boolean,
  blockers: readonly string[],
): Readonly<RevocationChallengeBrowserCheck> {
  return Object.freeze({
    status,
    passed,
    blockers: Object.freeze([...blockers]),
    independentlyCheckedFields: REVOCATION_BROWSER_CHECKED_FIELDS,
    serverRevalidatedFields: REVOCATION_SERVER_REVALIDATED_FIELDS,
  });
}

export function revocationArtifactBinding(
  action: Readonly<EnforcementActionDetail>,
): Readonly<RevocationArtifactBinding> {
  return Object.freeze({
    action_version: action.version,
    target_ipv4: action.target_ipv4,
    original_add_digest: action.canonical_artifact_digest,
    policy_id: action.policy_id,
    policy_version: action.policy_version,
    evidence_snapshot_digest: action.evidence_snapshot_digest,
  });
}

export function revocationReadiness(
  action: Readonly<EnforcementActionDetail>,
  csrfAvailable: boolean,
): Readonly<RevocationReadiness> {
  const blockers: string[] = [];
  if (action.state !== 'active') {
    blockers.push('Only an active enforcement action can be revoked.');
  }
  if (!csrfAvailable) {
    blockers.push('The in-memory CSRF mutation guard is unavailable.');
  }
  return Object.freeze({
    ready: blockers.length === 0,
    blockers: Object.freeze(blockers),
  });
}

export function reasonForRevocation(
  reasonCode: RevocationReasonCode,
  reasonText: string,
): Readonly<RevocationReason> {
  return Object.freeze({
    schema_version: 'hil-reason-v1',
    reason_code: reasonCode,
    reason_text: reasonText.normalize('NFC'),
  });
}

export function validateRevocationReason(
  reason: Readonly<RevocationReason>,
): string | null {
  return validateDecisionReason(reason);
}

function decodeBase64URL(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  try {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/') + '=';
    const decoded = globalThis.atob(normalized);
    const bytes = Uint8Array.from(decoded, (character) =>
      character.charCodeAt(0),
    );
    return bytes.byteLength === 32 ? bytes : null;
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
  const result = await globalThis.crypto.subtle.digest('SHA-256', input.buffer);
  return `sha256:${Array.from(new Uint8Array(result), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')}`;
}

export async function checkRevocationChallengeInBrowser(
  envelope: Readonly<RevocationChallengeEnvelope>,
  actionID: string,
  binding: Readonly<RevocationArtifactBinding>,
  session: Readonly<SessionProjection>,
): Promise<Readonly<RevocationChallengeBrowserCheck>> {
  if (!globalThis.crypto?.subtle) {
    return browserCheck('unavailable', false, [
      'Secure browser SHA-256 verification is unavailable. Revocation remains disabled.',
    ]);
  }
  const nonce = decodeBase64URL(envelope.challenge_nonce);
  if (!nonce) {
    return browserCheck('mismatch', false, [
      'The revocation challenge nonce is not a canonical 256-bit value.',
    ]);
  }
  let artifactDigest: string;
  let nonceDigest: string;
  try {
    [artifactDigest, nonceDigest] = await Promise.all([
      sha256(new TextEncoder().encode(envelope.canonical_revoke_artifact)),
      sha256(nonce),
    ]);
  } catch {
    return browserCheck('error', false, [
      'Secure browser SHA-256 verification could not be completed. Revocation remains disabled.',
    ]);
  }

  const challenge = envelope.challenge;
  const blockers: string[] = [];
  if (
    artifactDigest !== challenge.generated_artifact_digest ||
    artifactDigest !== challenge.canonical_artifact_digest
  ) {
    blockers.push(
      'The exact delete artifact does not match both challenge SHA-256 digests.',
    );
  }
  if (nonceDigest !== challenge.nonce_digest) {
    blockers.push(
      'The challenge nonce does not match its bound SHA-256 digest.',
    );
  }
  if (
    challenge.operation !== 'revoke' ||
    challenge.resource_type !== 'enforcement_action' ||
    challenge.resource_id !== actionID ||
    challenge.resource_version !== binding.action_version ||
    challenge.target_ipv4 !== binding.target_ipv4 ||
    challenge.original_add_digest !== binding.original_add_digest ||
    challenge.evidence_snapshot_digest !== binding.evidence_snapshot_digest ||
    envelope.policy_id !== binding.policy_id ||
    envelope.policy_version !== binding.policy_version ||
    challenge.authenticated_at !== session.authenticated_at ||
    Date.parse(challenge.expires_at) > Date.parse(session.expires_at) ||
    Date.parse(challenge.expires_at) >
      Date.parse(challenge.validation_valid_until)
  ) {
    blockers.push(
      'The revocation challenge does not match the active action, policy, evidence, validation, or administrator session.',
    );
  }
  return browserCheck(
    blockers.length === 0 ? 'passed' : 'mismatch',
    blockers.length === 0,
    blockers,
  );
}

export async function revocationDecisionMatchesExactBinding(
  envelope: Readonly<RevocationDecisionEnvelope>,
  challengeEnvelope: Readonly<RevocationChallengeEnvelope>,
  binding: Readonly<RevocationArtifactBinding>,
  reason: Readonly<RevocationReason>,
  idempotencyKey: string,
  session: Readonly<SessionProjection>,
): Promise<boolean> {
  try {
    const decision = envelope.decision;
    const challenge = challengeEnvelope.challenge;
    const [idempotencyDigest, reasonDigest] = await Promise.all([
      sha256(new TextEncoder().encode(idempotencyKey)),
      sha256(
        new TextEncoder().encode(
          JSON.stringify({
            reason_code: reason.reason_code,
            reason_text: reason.reason_text,
            schema_version: reason.schema_version,
          }),
        ),
      ),
    ]);
    if (
      decision.actor_id !== session.actor_id ||
      decision.challenge_id !== challenge.challenge_id ||
      decision.session_digest !== challenge.session_digest ||
      decision.operation !== 'revoke' ||
      decision.decision !== 'revoked' ||
      decision.resource_type !== 'enforcement_action' ||
      decision.resource_id !== challenge.resource_id ||
      decision.resource_version !== binding.action_version ||
      decision.target_ipv4 !== binding.target_ipv4 ||
      decision.original_add_digest !== binding.original_add_digest ||
      decision.policy_digest !== challenge.policy_digest ||
      decision.generated_artifact_digest !==
        challenge.generated_artifact_digest ||
      decision.canonical_artifact_digest !==
        challenge.canonical_artifact_digest ||
      decision.evidence_snapshot_digest !==
        challenge.evidence_snapshot_digest ||
      decision.validation_snapshot_digest !==
        challenge.validation_snapshot_digest ||
      decision.nonce_digest !== challenge.nonce_digest ||
      decision.idempotency_key_digest !== idempotencyDigest ||
      decision.reason_digest !== reasonDigest ||
      challengeEnvelope.policy_id !== binding.policy_id ||
      challengeEnvelope.policy_version !== binding.policy_version ||
      Date.parse(decision.decided_at) < Date.parse(challenge.issued_at) ||
      Date.parse(decision.decided_at) >= Date.parse(challenge.expires_at) ||
      Date.parse(decision.decision_valid_until) >
        Date.parse(challenge.expires_at) ||
      Date.parse(decision.decision_valid_until) >
        Date.parse(challenge.validation_valid_until)
    ) {
      return false;
    }

    const authorizationDigest = await sha256(
      new TextEncoder().encode(
        JSON.stringify({
          action_id: decision.resource_id,
          actor_id: decision.actor_id,
          authorization_id: envelope.authorization_id,
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
          policy_id: challengeEnvelope.policy_id,
          policy_version: challengeEnvelope.policy_version,
          schema_version: 'enforcement-authorization-v1',
          target_ipv4: decision.target_ipv4,
          valid_until: decision.decision_valid_until,
        }),
      ),
    );
    if (authorizationDigest !== envelope.authorization_digest) return false;
    if ('replayed' in envelope) return envelope.replayed === true;
    return (
      envelope.session.actor_id === session.actor_id &&
      envelope.session.authenticated_at === session.authenticated_at &&
      envelope.session.session_id !== session.session_id
    );
  } catch {
    return false;
  }
}

export function revocationBindingFingerprint(
  action: Readonly<EnforcementActionDetail>,
): string {
  return JSON.stringify([
    action.action_id,
    action.version,
    action.state,
    action.target_ipv4,
    action.canonical_artifact_digest,
    action.policy_id,
    action.policy_version,
    action.validation_snapshot_id,
    action.evidence_snapshot_digest,
    action.updated_at,
  ]);
}
