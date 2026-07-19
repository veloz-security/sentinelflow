import {
  MOCK_HIL_APPROVE_CHALLENGE,
  MOCK_HIL_AUTHORIZATION_STATES,
  MOCK_HIL_REJECT_CHALLENGE,
  MOCK_HIL_STEP_UP_APPROVE_CHALLENGE,
  MOCK_HIL_STEP_UP_CHALLENGE_STATES,
  MOCK_HIL_STEP_UP_DECISION_STATES,
  MOCK_HIL_STEP_UP_REJECT_CHALLENGE,
} from '../mocks/hilAuthorizationFixtures';
import {
  normalizeHilReason,
  type HilAuthorizationAdapter,
  type HilAuthorizationState,
  type HilDecisionOperation,
  type HilDecisionPreviewInput,
} from './hilAuthorizationModel';

async function resolveFixture(
  state: HilAuthorizationState,
  signal?: AbortSignal,
) {
  await Promise.resolve();
  if (signal?.aborted) {
    throw new DOMException('Fixture preview aborted', 'AbortError');
  }
  return state;
}

function challengeState(operation: HilDecisionOperation) {
  return operation === 'approve'
    ? MOCK_HIL_AUTHORIZATION_STATES['challenge-issued']
    : MOCK_HIL_AUTHORIZATION_STATES['reject-challenge-issued'];
}

export const fixtureHilAuthorizationAdapter: HilAuthorizationAdapter = {
  kind: 'fixture',

  load(signal) {
    return resolveFixture(MOCK_HIL_AUTHORIZATION_STATES.ready, signal);
  },

  previewChallenge(operation, signal) {
    return resolveFixture(challengeState(operation), signal);
  },

  previewStepUp(operation, signal) {
    return resolveFixture(MOCK_HIL_STEP_UP_CHALLENGE_STATES[operation], signal);
  },

  previewDecision(input: HilDecisionPreviewInput, signal) {
    const freshChallenge =
      input.operation === 'approve'
        ? MOCK_HIL_APPROVE_CHALLENGE
        : MOCK_HIL_REJECT_CHALLENGE;
    const stepUpChallenge =
      input.operation === 'approve'
        ? MOCK_HIL_STEP_UP_APPROVE_CHALLENGE
        : MOCK_HIL_STEP_UP_REJECT_CHALLENGE;
    const isFresh = input.challengeId === freshChallenge.challenge_id;
    const isStepUp = input.challengeId === stepUpChallenge.challenge_id;
    const state = isStepUp
      ? MOCK_HIL_STEP_UP_CHALLENGE_STATES[input.operation]
      : challengeState(input.operation);
    const expectedKey =
      state.kind === 'loading' ? null : state.view.idempotencyKey;
    const reason = normalizeHilReason(
      input.reason.reason_code,
      input.reason.reason_text,
    );

    if (
      (!isFresh && !isStepUp) ||
      reason === null ||
      reason.reason_text !== input.reason.reason_text
    ) {
      return resolveFixture(MOCK_HIL_AUTHORIZATION_STATES.mutation, signal);
    }
    if (input.idempotencyKey !== expectedKey) {
      return resolveFixture(MOCK_HIL_AUTHORIZATION_STATES.conflict, signal);
    }

    const terminal = isStepUp
      ? MOCK_HIL_STEP_UP_DECISION_STATES[input.operation]
      : input.operation === 'approve'
        ? MOCK_HIL_AUTHORIZATION_STATES.approved
        : MOCK_HIL_AUTHORIZATION_STATES.rejected;
    return resolveFixture(terminal, signal);
  },
};
