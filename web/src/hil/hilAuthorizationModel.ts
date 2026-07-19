import type { ApiErrorV1 } from '../contracts/apiDtos';
import type {
  HilChallengeV1,
  HilDecisionV1,
  HilReasonCode,
  HilReasonV1,
  Rfc3339Timestamp,
  Sha256Digest,
  Uuid,
} from '../contracts/rootContracts';
import type { ValidationReviewView } from '../validation/validationReviewModel';

export type HilDecisionOperation = 'approve' | 'reject';
export type ChallengeUseState =
  'not-issued' | 'available' | 'consumed' | 'expired';
export type SessionRotationState = 'not-required' | 'required' | 'completed';

export interface HilSessionPresentation {
  readonly authenticatedAt: Rfc3339Timestamp;
  readonly authenticatedAgeSeconds: number;
  readonly reauthRequiredAfterSeconds: 900;
  readonly sessionRotation: SessionRotationState;
}

export interface HilAuthorizationView {
  readonly fixtureOnly: true;
  readonly operation: HilDecisionOperation;
  readonly validationReview: ValidationReviewView;
  readonly challenge: HilChallengeV1 | null;
  readonly challengeUse: ChallengeUseState;
  readonly challengeWindowSeconds: 300;
  readonly decision: HilDecisionV1 | null;
  readonly reason: HilReasonV1 | null;
  readonly actorId: string;
  readonly idempotencyKey: Uuid;
  readonly idempotencyKeyDigest: Sha256Digest;
  readonly session: HilSessionPresentation;
  readonly updatedAt: Rfc3339Timestamp;
}

export const HIL_AUTHORIZATION_STATE_NAMES = [
  'loading',
  'ready',
  'step-up-required',
  'step-up-complete',
  'challenge-issued',
  'reject-challenge-issued',
  'expired',
  'replayed',
  'stale',
  'mutation',
  'conflict',
  'permission-denied',
  'unauthorized',
  'rate-limited',
  'step-up-failed',
  'rejected',
  'approved',
] as const;
export type HilAuthorizationStateName =
  (typeof HIL_AUTHORIZATION_STATE_NAMES)[number];

export type HilAuthorizationErrorStateName = Extract<
  HilAuthorizationStateName,
  | 'expired'
  | 'replayed'
  | 'stale'
  | 'mutation'
  | 'conflict'
  | 'permission-denied'
  | 'unauthorized'
  | 'rate-limited'
  | 'step-up-failed'
>;

export type HilAuthorizationState =
  | { readonly kind: 'loading' }
  | {
      readonly kind:
        | 'ready'
        | 'step-up-required'
        | 'step-up-complete'
        | 'challenge-issued'
        | 'reject-challenge-issued'
        | 'rejected'
        | 'approved';
      readonly view: HilAuthorizationView;
    }
  | {
      readonly kind: HilAuthorizationErrorStateName;
      readonly view: HilAuthorizationView;
      readonly error: ApiErrorV1;
      readonly retryAfterSeconds?: number;
    };

export interface HilDecisionPreviewInput {
  readonly operation: HilDecisionOperation;
  readonly challengeId: Uuid;
  readonly idempotencyKey: Uuid;
  readonly confirmedExactArtifact: true;
  readonly reason: HilReasonV1;
}

/**
 * A presentation-only boundary. It does not define or call the future HIL API,
 * verify credentials, consume a nonce, persist a decision, or mint authority.
 */
export interface HilAuthorizationAdapter {
  readonly kind: 'fixture';
  load(signal?: AbortSignal): Promise<HilAuthorizationState>;
  previewChallenge(
    operation: HilDecisionOperation,
    signal?: AbortSignal,
  ): Promise<HilAuthorizationState>;
  previewStepUp(
    operation: HilDecisionOperation,
    signal?: AbortSignal,
  ): Promise<HilAuthorizationState>;
  previewDecision(
    input: HilDecisionPreviewInput,
    signal?: AbortSignal,
  ): Promise<HilAuthorizationState>;
}

function hasDisallowedReasonControl(value: string) {
  return Array.from(value).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return (
      code <= 0x08 ||
      code === 0x0b ||
      code === 0x0c ||
      (code >= 0x0e && code <= 0x1f) ||
      code === 0x7f
    );
  });
}

export function normalizeHilReason(
  reasonCode: HilReasonCode,
  reasonText: string,
): HilReasonV1 | null {
  const normalized = reasonText.normalize('NFC').trim();
  if (
    normalized.length < 1 ||
    normalized.length > 500 ||
    hasDisallowedReasonControl(normalized)
  ) {
    return null;
  }

  return {
    schema_version: 'hil-reason-v1',
    reason_code: reasonCode,
    reason_text: normalized,
  };
}

export function challengeMatchesExactView(view: HilAuthorizationView) {
  const challenge = view.challenge;
  const validation = view.validationReview.validation;
  const policy = view.validationReview.policy;
  return Boolean(
    challenge &&
    validation &&
    challenge.operation === view.operation &&
    challenge.resource_type === 'policy' &&
    challenge.resource_id === policy.policy_id &&
    challenge.resource_version === policy.policy_version &&
    challenge.target_ipv4 === policy.target_ipv4 &&
    challenge.policy_digest === validation.policy_digest &&
    challenge.generated_artifact_digest ===
      validation.generated_candidate_digest &&
    challenge.canonical_artifact_digest ===
      validation.canonical_artifact_digest &&
    challenge.evidence_snapshot_digest ===
      validation.evidence_snapshot_digest &&
    challenge.validation_valid_until === validation.valid_until &&
    challenge.authenticated_at === view.session.authenticatedAt &&
    challenge.reauth_required_after_seconds === 900,
  );
}
