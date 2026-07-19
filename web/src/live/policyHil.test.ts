import { describe, expect, it } from 'vitest';
import {
  HIL_CHALLENGE_ENVELOPE,
  HIL_DECISION_ENVELOPE,
  HIL_IDEMPOTENCY_KEY,
  INVALID_VALIDATION_ATTEMPT,
  POLICY_DETAIL,
  POLICY_ID,
  SESSION_ENVELOPE,
} from './liveTestFixtures';
import {
  decodeHILChallengeEnvelope,
  decodeHILDecisionEnvelope,
  decodePolicyDetail,
} from './contracts';
import {
  challengeMatchesExactBinding,
  decisionMatchesExactBinding,
  policyArtifactBinding,
  policyDecisionReadiness,
  reasonForDecision,
  validateDecisionReason,
} from './policyHil';

const now = Date.parse('2026-07-18T01:03:30Z');

describe('exact policy HIL boundary', () => {
  it('opens only for a current exact six-gate valid artifact', () => {
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    expect(policyDecisionReadiness(policy, true, now)).toEqual({
      ready: true,
      blockers: [],
    });

    const stale = decodePolicyDetail({
      ...POLICY_DETAIL,
      latest_validation: {
        ...POLICY_DETAIL.latest_validation,
        valid_until: '2026-07-18T01:03:00Z',
      },
    });
    expect(policyDecisionReadiness(stale, true, now)).toMatchObject({
      ready: false,
      blockers: expect.arrayContaining([
        'The exact validation snapshot is stale.',
      ]),
    });

    const missingGate = {
      ...policy,
      latest_validation: {
        ...policy.latest_validation!,
        gates: policy.latest_validation!.gates.slice(0, 5),
      },
    };
    expect(policyDecisionReadiness(missingGate, true, now)).toMatchObject({
      ready: false,
      blockers: expect.arrayContaining([
        'All six ordered safety gates must pass exactly.',
      ]),
    });
  });

  it('defensively rejects contradictory terminal and gate results', () => {
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    const nonOKGate = {
      ...policy,
      latest_validation: {
        ...policy.latest_validation!,
        gates: policy.latest_validation!.gates.map((gate, index) =>
          index === 0
            ? { ...gate, result_code: 'history_demo_binding_mismatch' }
            : gate,
        ),
      },
    };
    expect(policyDecisionReadiness(nonOKGate, true, now)).toMatchObject({
      ready: false,
      blockers: expect.arrayContaining([
        'All six ordered safety gates must pass exactly.',
      ]),
    });

    const failureSnapshot = {
      ...policy,
      latest_validation: {
        ...policy.latest_validation!,
        failure_code: 'history_demo_binding_mismatch',
      },
    };
    expect(policyDecisionReadiness(failureSnapshot, true, now)).toMatchObject({
      ready: false,
      blockers: expect.arrayContaining([
        'The exact validation snapshot carries a failure result.',
      ]),
    });

    const invalidPayload = structuredClone(POLICY_DETAIL) as Record<
      string,
      unknown
    >;
    delete invalidPayload.latest_validation;
    invalidPayload.state = 'invalid';
    invalidPayload.latest_validation_attempt = structuredClone(
      INVALID_VALIDATION_ATTEMPT,
    );
    const invalidAttempt = decodePolicyDetail(invalidPayload);
    const contradictoryAttempt = {
      ...policy,
      latest_validation_attempt: invalidAttempt.latest_validation_attempt,
    };
    expect(
      policyDecisionReadiness(contradictoryAttempt, true, now),
    ).toMatchObject({
      ready: false,
      blockers: expect.arrayContaining([
        'The latest validation attempt failed closed.',
      ]),
    });
  });

  it('verifies the server nonce digest and every exact artifact binding', async () => {
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    const binding = policyArtifactBinding(policy, 'approve');
    expect(binding).not.toBeNull();
    const challenge = decodeHILChallengeEnvelope(
      structuredClone(HIL_CHALLENGE_ENVELOPE),
    );
    expect(
      await challengeMatchesExactBinding(
        challenge,
        POLICY_ID,
        binding as NonNullable<typeof binding>,
        SESSION_ENVELOPE.session,
      ),
    ).toBe(true);

    const mismatched = decodeHILChallengeEnvelope({
      ...HIL_CHALLENGE_ENVELOPE,
      challenge: {
        ...HIL_CHALLENGE_ENVELOPE.challenge,
        nonce_digest: `sha256:${'f'.repeat(64)}`,
      },
    });
    expect(
      await challengeMatchesExactBinding(
        mismatched,
        POLICY_ID,
        binding as NonNullable<typeof binding>,
        SESSION_ENVELOPE.session,
      ),
    ).toBe(false);
  });

  it('binds the rotated decision to the same nonce and idempotency key', async () => {
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    const binding = policyArtifactBinding(policy, 'approve');
    expect(binding).not.toBeNull();
    expect(
      await decisionMatchesExactBinding(
        decodeHILDecisionEnvelope(structuredClone(HIL_DECISION_ENVELOPE)),
        decodeHILChallengeEnvelope(structuredClone(HIL_CHALLENGE_ENVELOPE)),
        binding as NonNullable<typeof binding>,
        reasonForDecision('threat_confirmed', 'Confirmed synthetic attack'),
        HIL_IDEMPOTENCY_KEY,
        'admin',
      ),
    ).toBe(true);
    expect(
      await decisionMatchesExactBinding(
        decodeHILDecisionEnvelope(structuredClone(HIL_DECISION_ENVELOPE)),
        decodeHILChallengeEnvelope(structuredClone(HIL_CHALLENGE_ENVELOPE)),
        binding as NonNullable<typeof binding>,
        reasonForDecision('threat_confirmed', 'Confirmed synthetic attack'),
        `${HIL_IDEMPOTENCY_KEY}-different`,
        'admin',
      ),
    ).toBe(false);
    expect(
      await decisionMatchesExactBinding(
        decodeHILDecisionEnvelope(structuredClone(HIL_DECISION_ENVELOPE)),
        decodeHILChallengeEnvelope(structuredClone(HIL_CHALLENGE_ENVELOPE)),
        binding as NonNullable<typeof binding>,
        reasonForDecision('threat_confirmed', 'A different reason'),
        HIL_IDEMPOTENCY_KEY,
        'admin',
      ),
    ).toBe(false);

    for (const mutation of [
      { actor_id: 'different_admin' },
      { policy_digest: `sha256:${'f'.repeat(64)}` },
      { session_digest: `sha256:${'e'.repeat(64)}` },
      { decided_at: '2026-07-18T01:02:59Z' },
      { decision_valid_until: '2026-07-18T01:07:01Z' },
    ]) {
      const mismatchedDecision = decodeHILDecisionEnvelope({
        ...HIL_DECISION_ENVELOPE,
        decision: { ...HIL_DECISION_ENVELOPE.decision, ...mutation },
      });
      expect(
        await decisionMatchesExactBinding(
          mismatchedDecision,
          decodeHILChallengeEnvelope(structuredClone(HIL_CHALLENGE_ENVELOPE)),
          binding as NonNullable<typeof binding>,
          reasonForDecision('threat_confirmed', 'Confirmed synthetic attack'),
          HIL_IDEMPOTENCY_KEY,
          'admin',
        ),
      ).toBe(false);
    }
  });

  it('normalizes and bounds the human-authored reason without logging it', () => {
    const normalized = reasonForDecision(
      'threat_confirmed',
      'Cafe\u0301 attack',
    );
    expect(normalized.reason_text).toBe('Café attack');
    expect(validateDecisionReason(normalized)).toBeNull();
    expect(
      validateDecisionReason(reasonForDecision('other', 'bad\nline')),
    ).toMatch(/control characters/);
    expect(
      validateDecisionReason(reasonForDecision('other', 'bad\ud800value')),
    ).toMatch(/invalid Unicode/);
    expect(
      validateDecisionReason(reasonForDecision('other', ' '.repeat(8))),
    ).toMatch(/non-empty/);
  });
});
