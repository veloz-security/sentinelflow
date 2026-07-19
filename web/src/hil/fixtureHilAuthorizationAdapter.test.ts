import { describe, expect, it } from 'vitest';
import {
  MOCK_HIL_APPROVE_CHALLENGE,
  MOCK_HIL_AUTHORIZATION_STATES,
  MOCK_HIL_REJECT_CHALLENGE,
  MOCK_HIL_STEP_UP_CHALLENGE_STATES,
} from '../mocks/hilAuthorizationFixtures';
import { fixtureHilAuthorizationAdapter } from './fixtureHilAuthorizationAdapter';
import { normalizeHilReason } from './hilAuthorizationModel';

describe('fixture HIL authorization adapter', () => {
  it('loads and previews operation-specific frozen states', async () => {
    await expect(fixtureHilAuthorizationAdapter.load()).resolves.toEqual(
      MOCK_HIL_AUTHORIZATION_STATES.ready,
    );
    await expect(
      fixtureHilAuthorizationAdapter.previewChallenge('approve'),
    ).resolves.toEqual(MOCK_HIL_AUTHORIZATION_STATES['challenge-issued']);
    await expect(
      fixtureHilAuthorizationAdapter.previewChallenge('reject'),
    ).resolves.toEqual(
      MOCK_HIL_AUTHORIZATION_STATES['reject-challenge-issued'],
    );
  });

  it('honors cancellation on every presentation-only transition', async () => {
    const controller = new AbortController();
    const loading = fixtureHilAuthorizationAdapter.load(controller.signal);
    controller.abort();
    await expect(loading).rejects.toMatchObject({ name: 'AbortError' });

    const second = new AbortController();
    const preview = fixtureHilAuthorizationAdapter.previewChallenge(
      'approve',
      second.signal,
    );
    second.abort();
    await expect(preview).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('shows successful step-up as a rotated session with a new challenge', async () => {
    const state = await fixtureHilAuthorizationAdapter.previewStepUp('approve');
    expect(state).toEqual(MOCK_HIL_STEP_UP_CHALLENGE_STATES.approve);
    if (state.kind !== 'step-up-complete') throw new Error('fixture drift');
    expect(state.view.session.sessionRotation).toBe('completed');
    expect(state.view.challenge?.authenticated_at).toBe(
      state.view.session.authenticatedAt,
    );
    expect(state.view.challenge?.challenge_id).not.toBe(
      MOCK_HIL_APPROVE_CHALLENGE.challenge_id,
    );
  });

  it('previews exact approve and reject decisions without backend authority', async () => {
    const approveReason = normalizeHilReason(
      'threat_confirmed',
      'Verified evidence supports a temporary block.',
    );
    const rejectReason = normalizeHilReason(
      'false_positive',
      'Evidence is insufficient for a temporary block.',
    );
    if (!approveReason || !rejectReason)
      throw new Error('reason fixture drift');

    const approveState = MOCK_HIL_AUTHORIZATION_STATES['challenge-issued'];
    const rejectState =
      MOCK_HIL_AUTHORIZATION_STATES['reject-challenge-issued'];
    if (approveState.kind !== 'challenge-issued')
      throw new Error('fixture drift');
    if (rejectState.kind !== 'reject-challenge-issued')
      throw new Error('fixture drift');

    await expect(
      fixtureHilAuthorizationAdapter.previewDecision({
        operation: 'approve',
        challengeId: MOCK_HIL_APPROVE_CHALLENGE.challenge_id,
        idempotencyKey: approveState.view.idempotencyKey,
        confirmedExactArtifact: true,
        reason: approveReason,
      }),
    ).resolves.toEqual(MOCK_HIL_AUTHORIZATION_STATES.approved);

    await expect(
      fixtureHilAuthorizationAdapter.previewDecision({
        operation: 'reject',
        challengeId: MOCK_HIL_REJECT_CHALLENGE.challenge_id,
        idempotencyKey: rejectState.view.idempotencyKey,
        confirmedExactArtifact: true,
        reason: rejectReason,
      }),
    ).resolves.toEqual(MOCK_HIL_AUTHORIZATION_STATES.rejected);
  });

  it('fails closed for challenge mutation and idempotency conflict', async () => {
    const reason = normalizeHilReason('other', 'Synthetic fixture review.');
    if (!reason) throw new Error('reason fixture drift');
    const approveState = MOCK_HIL_AUTHORIZATION_STATES['challenge-issued'];
    if (approveState.kind !== 'challenge-issued')
      throw new Error('fixture drift');

    await expect(
      fixtureHilAuthorizationAdapter.previewDecision({
        operation: 'approve',
        challengeId: MOCK_HIL_REJECT_CHALLENGE.challenge_id,
        idempotencyKey: approveState.view.idempotencyKey,
        confirmedExactArtifact: true,
        reason,
      }),
    ).resolves.toEqual(MOCK_HIL_AUTHORIZATION_STATES.mutation);

    await expect(
      fixtureHilAuthorizationAdapter.previewDecision({
        operation: 'approve',
        challengeId: MOCK_HIL_APPROVE_CHALLENGE.challenge_id,
        idempotencyKey: MOCK_HIL_REJECT_CHALLENGE.challenge_id,
        confirmedExactArtifact: true,
        reason,
      }),
    ).resolves.toEqual(MOCK_HIL_AUTHORIZATION_STATES.conflict);
  });
});
