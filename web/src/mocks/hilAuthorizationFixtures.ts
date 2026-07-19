import type { ApiErrorCode, ApiErrorV1 } from '../contracts/apiDtos';
import type {
  HilChallengeV1,
  HilDecisionV1,
  HilReasonV1,
  Sha256Digest,
  Uuid,
} from '../contracts/rootContracts';
import type {
  HilAuthorizationState,
  HilAuthorizationStateName,
  HilAuthorizationView,
  HilDecisionOperation,
} from '../hil/hilAuthorizationModel';
import { MOCK_HIL_REASON } from './contractFixtures';
import { MOCK_READY_VALIDATION_REVIEW } from './validationReviewFixtures';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const digest = (character: string) =>
  `sha256:${character.repeat(64)}` as Sha256Digest;
const uuid = (tail: string) =>
  `019b0000-0000-7000-8000-${tail.padStart(12, '0')}` as Uuid;

const validation = MOCK_READY_VALIDATION_REVIEW.validation!;
if (!validation)
  throw new Error('Ready validation fixture must have a snapshot');

const challengeIds = {
  fresh: {
    approve: uuid('711'),
    reject: uuid('712'),
  },
  steppedUp: {
    approve: uuid('717'),
    reject: uuid('718'),
  },
} as const;

function challenge(
  operation: HilDecisionOperation,
  steppedUp = false,
): HilChallengeV1 {
  return deepFreeze({
    schema_version: 'hil-challenge-v1',
    challenge_id: challengeIds[steppedUp ? 'steppedUp' : 'fresh'][operation],
    session_digest: digest(steppedUp ? 'c' : '2'),
    operation,
    resource_type: 'policy',
    resource_id: MOCK_READY_VALIDATION_REVIEW.policy.policy_id,
    resource_version: MOCK_READY_VALIDATION_REVIEW.policy.policy_version,
    target_ipv4: MOCK_READY_VALIDATION_REVIEW.policy.target_ipv4,
    policy_digest: validation.policy_digest,
    generated_artifact_digest: validation.generated_candidate_digest,
    canonical_artifact_digest: validation.canonical_artifact_digest,
    original_add_digest: null,
    evidence_snapshot_digest: validation.evidence_snapshot_digest,
    validation_snapshot_digest: digest('3'),
    validation_valid_until: validation.valid_until,
    nonce_digest: digest(
      steppedUp
        ? operation === 'approve'
          ? 'd'
          : 'e'
        : operation === 'approve'
          ? '4'
          : '7',
    ),
    authenticated_at: steppedUp
      ? '2026-07-18T02:00:15Z'
      : '2026-07-18T01:58:00Z',
    reauth_required_after_seconds: 900,
    issued_at: '2026-07-18T02:00:30Z',
    expires_at: '2026-07-18T02:05:30Z',
  });
}

export const MOCK_HIL_APPROVE_CHALLENGE = challenge('approve');
export const MOCK_HIL_REJECT_CHALLENGE = challenge('reject');
export const MOCK_HIL_STEP_UP_APPROVE_CHALLENGE = challenge('approve', true);
export const MOCK_HIL_STEP_UP_REJECT_CHALLENGE = challenge('reject', true);

export const MOCK_HIL_REJECT_REASON: HilReasonV1 = deepFreeze({
  schema_version: 'hil-reason-v1',
  reason_code: 'false_positive',
  reason_text: 'Evidence is insufficient for a temporary block.',
});

function decision(
  operation: HilDecisionOperation,
  reason: HilReasonV1,
  source: HilChallengeV1,
  steppedUp = false,
): HilDecisionV1 {
  return deepFreeze({
    schema_version: 'hil-decision-v1',
    decision_id: uuid(
      steppedUp
        ? operation === 'approve'
          ? '719'
          : '720'
        : operation === 'approve'
          ? '713'
          : '714',
    ),
    challenge_id: source.challenge_id,
    session_digest: source.session_digest,
    operation,
    decision: operation === 'approve' ? 'approved' : 'rejected',
    resource_type: source.resource_type,
    resource_id: source.resource_id,
    resource_version: source.resource_version,
    target_ipv4: source.target_ipv4,
    policy_digest: source.policy_digest,
    generated_artifact_digest: source.generated_artifact_digest,
    canonical_artifact_digest: source.canonical_artifact_digest,
    original_add_digest: null,
    evidence_snapshot_digest: source.evidence_snapshot_digest,
    validation_snapshot_digest: source.validation_snapshot_digest,
    actor_id: 'admin.demo',
    reason_digest: digest(
      reason.reason_code === 'threat_confirmed' ? '5' : '8',
    ),
    nonce_digest: source.nonce_digest,
    idempotency_key_digest: digest(
      steppedUp
        ? operation === 'approve'
          ? 'a'
          : 'b'
        : operation === 'approve'
          ? '6'
          : '9',
    ),
    decided_at: '2026-07-18T02:02:00Z',
    decision_valid_until: '2026-07-18T02:05:30Z',
  });
}

export const MOCK_HIL_APPROVED_DECISION = decision(
  'approve',
  MOCK_HIL_REASON,
  MOCK_HIL_APPROVE_CHALLENGE,
);
export const MOCK_HIL_REJECTED_DECISION = decision(
  'reject',
  MOCK_HIL_REJECT_REASON,
  MOCK_HIL_REJECT_CHALLENGE,
);
export const MOCK_HIL_STEP_UP_APPROVED_DECISION = decision(
  'approve',
  MOCK_HIL_REASON,
  MOCK_HIL_STEP_UP_APPROVE_CHALLENGE,
  true,
);
export const MOCK_HIL_STEP_UP_REJECTED_DECISION = decision(
  'reject',
  MOCK_HIL_REJECT_REASON,
  MOCK_HIL_STEP_UP_REJECT_CHALLENGE,
  true,
);

const idempotencyKeys = {
  approve: uuid('715'),
  reject: uuid('716'),
} as const;
const stepUpIdempotencyKeys = {
  approve: uuid('731'),
  reject: uuid('732'),
} as const;

function view(
  operation: HilDecisionOperation,
  patch: Partial<HilAuthorizationView> = {},
): HilAuthorizationView {
  return deepFreeze({
    fixtureOnly: true,
    operation,
    validationReview: MOCK_READY_VALIDATION_REVIEW,
    challenge: null,
    challengeUse: 'not-issued',
    challengeWindowSeconds: 300,
    decision: null,
    reason: null,
    actorId: 'admin.demo',
    idempotencyKey: idempotencyKeys[operation],
    idempotencyKeyDigest: digest(operation === 'approve' ? '6' : '9'),
    session: {
      authenticatedAt: '2026-07-18T01:58:00Z',
      authenticatedAgeSeconds: 150,
      reauthRequiredAfterSeconds: 900,
      sessionRotation: 'not-required',
    },
    updatedAt: '2026-07-18T02:00:30Z',
    ...patch,
  });
}

const approveChallengeView = view('approve', {
  challenge: MOCK_HIL_APPROVE_CHALLENGE,
  challengeUse: 'available',
  session: {
    authenticatedAt: MOCK_HIL_APPROVE_CHALLENGE.authenticated_at,
    authenticatedAgeSeconds: 150,
    reauthRequiredAfterSeconds: 900,
    sessionRotation: 'not-required',
  },
});

const rejectChallengeView = view('reject', {
  challenge: MOCK_HIL_REJECT_CHALLENGE,
  challengeUse: 'available',
  session: {
    authenticatedAt: MOCK_HIL_REJECT_CHALLENGE.authenticated_at,
    authenticatedAgeSeconds: 150,
    reauthRequiredAfterSeconds: 900,
    sessionRotation: 'not-required',
  },
});

const stepUpApproveChallengeView = view('approve', {
  challenge: MOCK_HIL_STEP_UP_APPROVE_CHALLENGE,
  challengeUse: 'available',
  idempotencyKey: stepUpIdempotencyKeys.approve,
  idempotencyKeyDigest: digest('a'),
  session: {
    authenticatedAt: MOCK_HIL_STEP_UP_APPROVE_CHALLENGE.authenticated_at,
    authenticatedAgeSeconds: 15,
    reauthRequiredAfterSeconds: 900,
    sessionRotation: 'completed',
  },
});

const stepUpRejectChallengeView = view('reject', {
  challenge: MOCK_HIL_STEP_UP_REJECT_CHALLENGE,
  challengeUse: 'available',
  idempotencyKey: stepUpIdempotencyKeys.reject,
  idempotencyKeyDigest: digest('b'),
  session: {
    authenticatedAt: MOCK_HIL_STEP_UP_REJECT_CHALLENGE.authenticated_at,
    authenticatedAgeSeconds: 15,
    reauthRequiredAfterSeconds: 900,
    sessionRotation: 'completed',
  },
});

const staleSessionView = view('approve', {
  session: {
    authenticatedAt: '2026-07-18T01:42:30Z',
    authenticatedAgeSeconds: 1080,
    reauthRequiredAfterSeconds: 900,
    sessionRotation: 'required',
  },
});

function error(
  code: ApiErrorCode,
  message: string,
  traceTail: string,
  details: ApiErrorV1['details'] = {},
): ApiErrorV1 {
  return deepFreeze({
    code,
    message,
    trace_id: uuid(traceTail),
    details,
  });
}

export const MOCK_HIL_STEP_UP_CHALLENGE_STATES: Readonly<
  Record<HilDecisionOperation, HilAuthorizationState>
> = deepFreeze({
  approve: { kind: 'step-up-complete', view: stepUpApproveChallengeView },
  reject: {
    kind: 'reject-challenge-issued',
    view: stepUpRejectChallengeView,
  },
});

export const MOCK_HIL_STEP_UP_DECISION_STATES: Readonly<
  Record<HilDecisionOperation, HilAuthorizationState>
> = deepFreeze({
  approve: {
    kind: 'approved',
    view: view('approve', {
      challenge: MOCK_HIL_STEP_UP_APPROVE_CHALLENGE,
      challengeUse: 'consumed',
      decision: MOCK_HIL_STEP_UP_APPROVED_DECISION,
      reason: MOCK_HIL_REASON,
      idempotencyKey: stepUpIdempotencyKeys.approve,
      idempotencyKeyDigest: digest('a'),
      session: stepUpApproveChallengeView.session,
      updatedAt: MOCK_HIL_STEP_UP_APPROVED_DECISION.decided_at,
    }),
  },
  reject: {
    kind: 'rejected',
    view: view('reject', {
      challenge: MOCK_HIL_STEP_UP_REJECT_CHALLENGE,
      challengeUse: 'consumed',
      decision: MOCK_HIL_STEP_UP_REJECTED_DECISION,
      reason: MOCK_HIL_REJECT_REASON,
      idempotencyKey: stepUpIdempotencyKeys.reject,
      idempotencyKeyDigest: digest('b'),
      session: stepUpRejectChallengeView.session,
      updatedAt: MOCK_HIL_STEP_UP_REJECTED_DECISION.decided_at,
    }),
  },
});

export const MOCK_HIL_AUTHORIZATION_STATES: Readonly<
  Record<HilAuthorizationStateName, HilAuthorizationState>
> = deepFreeze({
  loading: { kind: 'loading' },
  ready: { kind: 'ready', view: view('approve') },
  'step-up-required': {
    kind: 'step-up-required',
    view: staleSessionView,
  },
  'step-up-complete': MOCK_HIL_STEP_UP_CHALLENGE_STATES.approve,
  'challenge-issued': {
    kind: 'challenge-issued',
    view: approveChallengeView,
  },
  'reject-challenge-issued': {
    kind: 'reject-challenge-issued',
    view: rejectChallengeView,
  },
  expired: {
    kind: 'expired',
    view: view('approve', {
      challenge: MOCK_HIL_APPROVE_CHALLENGE,
      challengeUse: 'expired',
    }),
    error: error(
      'challenge_expired',
      'The five-minute challenge window elapsed. Request a new exact-artifact challenge.',
      '721',
    ),
  },
  replayed: {
    kind: 'replayed',
    view: view('approve', {
      challenge: MOCK_HIL_APPROVE_CHALLENGE,
      challengeUse: 'consumed',
    }),
    error: error(
      'challenge_consumed',
      'This single-use challenge was already consumed. It cannot be replayed.',
      '722',
    ),
  },
  stale: {
    kind: 'stale',
    view: approveChallengeView,
    error: error(
      'stale_version',
      'The policy version changed after challenge issuance. Revalidation and a new challenge are required.',
      '723',
    ),
  },
  mutation: {
    kind: 'mutation',
    view: approveChallengeView,
    error: error(
      'digest_mismatch',
      'An exact-artifact digest no longer matches the challenge. No decision was recorded.',
      '724',
    ),
  },
  conflict: {
    kind: 'conflict',
    view: approveChallengeView,
    error: error(
      'idempotency_conflict',
      'The idempotency key was reused with different decision bytes. The conflicting request was rejected.',
      '725',
    ),
  },
  'permission-denied': {
    kind: 'permission-denied',
    view: view('approve'),
    error: error(
      'permission_denied',
      'This administrator session cannot authorize policy decisions.',
      '726',
    ),
  },
  unauthorized: {
    kind: 'unauthorized',
    view: view('approve'),
    error: error(
      'authentication_required',
      'An authenticated administrator session is required.',
      '727',
    ),
  },
  'rate-limited': {
    kind: 'rate-limited',
    view: view('approve'),
    error: error(
      'rate_limited',
      'The per-session HIL decision limit was reached.',
      '728',
      { retry_after_seconds: 42 },
    ),
    retryAfterSeconds: 42,
  },
  'step-up-failed': {
    kind: 'step-up-failed',
    view: staleSessionView,
    error: error(
      'authentication_required',
      'Step-up authentication failed. No challenge was issued.',
      '729',
    ),
  },
  rejected: {
    kind: 'rejected',
    view: view('reject', {
      challenge: MOCK_HIL_REJECT_CHALLENGE,
      challengeUse: 'consumed',
      decision: MOCK_HIL_REJECTED_DECISION,
      reason: MOCK_HIL_REJECT_REASON,
      session: rejectChallengeView.session,
      updatedAt: MOCK_HIL_REJECTED_DECISION.decided_at,
    }),
  },
  approved: {
    kind: 'approved',
    view: view('approve', {
      challenge: MOCK_HIL_APPROVE_CHALLENGE,
      challengeUse: 'consumed',
      decision: MOCK_HIL_APPROVED_DECISION,
      reason: MOCK_HIL_REASON,
      session: approveChallengeView.session,
      updatedAt: MOCK_HIL_APPROVED_DECISION.decided_at,
    }),
  },
});
