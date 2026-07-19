import { describe, expect, it } from 'vitest';
import { decodeContract } from '../contracts/registry';
import {
  HIL_AUTHORIZATION_STATE_NAMES,
  challengeMatchesExactView,
  normalizeHilReason,
} from './hilAuthorizationModel';
import {
  MOCK_HIL_APPROVED_DECISION,
  MOCK_HIL_APPROVE_CHALLENGE,
  MOCK_HIL_AUTHORIZATION_STATES,
  MOCK_HIL_REJECTED_DECISION,
  MOCK_HIL_REJECT_CHALLENGE,
  MOCK_HIL_REJECT_REASON,
  MOCK_HIL_STEP_UP_APPROVED_DECISION,
  MOCK_HIL_STEP_UP_APPROVE_CHALLENGE,
} from '../mocks/hilAuthorizationFixtures';
import { MOCK_HIL_REASON } from '../mocks/contractFixtures';

describe('HIL authorization presentation model', () => {
  it('normalizes a non-empty reason to NFC and rejects invalid text', () => {
    expect(normalizeHilReason('other', '  Cafe\u0301 review  ')).toEqual({
      schema_version: 'hil-reason-v1',
      reason_code: 'other',
      reason_text: 'Café review',
    });
    expect(normalizeHilReason('other', ' \n\t ')).toBeNull();
    expect(normalizeHilReason('other', 'unsafe\u0000reason')).toBeNull();
    expect(normalizeHilReason('other', 'x'.repeat(501))).toBeNull();
  });

  it('decodes the checked reason, challenge, and decision contracts', () => {
    for (const value of [
      MOCK_HIL_REASON,
      MOCK_HIL_REJECT_REASON,
      MOCK_HIL_APPROVE_CHALLENGE,
      MOCK_HIL_REJECT_CHALLENGE,
      MOCK_HIL_APPROVED_DECISION,
      MOCK_HIL_REJECTED_DECISION,
      MOCK_HIL_STEP_UP_APPROVE_CHALLENGE,
      MOCK_HIL_STEP_UP_APPROVED_DECISION,
    ]) {
      expect(decodeContract(value), value.schema_version).toMatchObject({
        ok: true,
      });
    }
  });

  it('binds each operation to a distinct exact-artifact challenge', () => {
    const approve = MOCK_HIL_AUTHORIZATION_STATES['challenge-issued'];
    const reject = MOCK_HIL_AUTHORIZATION_STATES['reject-challenge-issued'];
    if (approve.kind !== 'challenge-issued') throw new Error('fixture drift');
    if (reject.kind !== 'reject-challenge-issued')
      throw new Error('fixture drift');

    expect(challengeMatchesExactView(approve.view)).toBe(true);
    expect(challengeMatchesExactView(reject.view)).toBe(true);
    expect(approve.view.challenge?.challenge_id).not.toBe(
      reject.view.challenge?.challenge_id,
    );
    expect(approve.view.challenge?.operation).toBe('approve');
    expect(reject.view.challenge?.operation).toBe('reject');
    expect(approve.view.idempotencyKey).not.toBe(reject.view.idempotencyKey);
  });

  it('keeps challenge and decision validity within the frozen windows', () => {
    for (const challenge of [
      MOCK_HIL_APPROVE_CHALLENGE,
      MOCK_HIL_REJECT_CHALLENGE,
    ]) {
      const seconds =
        (Date.parse(challenge.expires_at) - Date.parse(challenge.issued_at)) /
        1000;
      expect(seconds).toBe(300);
      expect(challenge.reauth_required_after_seconds).toBe(900);
      expect(Date.parse(challenge.expires_at)).toBeLessThanOrEqual(
        Date.parse(challenge.validation_valid_until),
      );
    }

    for (const decision of [
      MOCK_HIL_APPROVED_DECISION,
      MOCK_HIL_REJECTED_DECISION,
    ]) {
      expect(Date.parse(decision.decision_valid_until)).toBeLessThanOrEqual(
        Date.parse('2026-07-18T02:05:30Z'),
      );
      expect(decision.idempotency_key_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });

  it('contains every required fail-closed state and no terminal decision in errors', () => {
    expect(HIL_AUTHORIZATION_STATE_NAMES).toEqual([
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
    ]);

    for (const name of [
      'expired',
      'replayed',
      'stale',
      'mutation',
      'conflict',
      'permission-denied',
      'unauthorized',
      'rate-limited',
      'step-up-failed',
    ] as const) {
      const state = MOCK_HIL_AUTHORIZATION_STATES[name];
      if (state.kind === 'loading') throw new Error('fixture drift');
      expect(state.view.decision, name).toBeNull();
    }
  });

  it('keeps passwords and raw challenge nonces out of every frozen fixture', () => {
    const serialized = JSON.stringify(
      MOCK_HIL_AUTHORIZATION_STATES,
    ).toLowerCase();
    expect(serialized).not.toContain('password');
    expect(serialized).not.toContain('raw_nonce');
    expect(serialized).not.toContain('challenge_nonce');
    expect(Object.isFrozen(MOCK_HIL_AUTHORIZATION_STATES)).toBe(true);
    const approved = MOCK_HIL_AUTHORIZATION_STATES.approved;
    if (approved.kind !== 'approved') throw new Error('fixture drift');
    expect(Object.isFrozen(approved.view)).toBe(true);
  });
});
