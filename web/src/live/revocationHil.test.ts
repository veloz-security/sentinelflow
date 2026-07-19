import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  decodeEnforcementAction,
  decodeRevocationChallengeEnvelope,
  decodeRevocationDecisionEnvelope,
} from './contracts';
import {
  ACTIVE_ENFORCEMENT_ACTION,
  HIL_IDEMPOTENCY_KEY,
  REVOCATION_CHALLENGE_ENVELOPE,
  REVOCATION_DECISION_ENVELOPE,
  REVOCATION_REASON,
  SESSION_ENVELOPE,
} from './liveTestFixtures';
import {
  checkRevocationChallengeInBrowser,
  reasonForRevocation,
  REVOCATION_BROWSER_CHECKED_FIELDS,
  REVOCATION_SERVER_REVALIDATED_FIELDS,
  revocationArtifactBinding,
  revocationDecisionMatchesExactBinding,
  revocationReadiness,
  validateRevocationReason,
} from './revocationHil';

const action = decodeEnforcementAction(
  structuredClone(ACTIVE_ENFORCEMENT_ACTION),
);
const binding = revocationArtifactBinding(action);
const challenge = decodeRevocationChallengeEnvelope(
  structuredClone(REVOCATION_CHALLENGE_ENVELOPE),
);
const decision = decodeRevocationDecisionEnvelope(
  structuredClone(REVOCATION_DECISION_ENVELOPE),
);

describe('revocation HIL browser binding', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('passes independent checks for artifact, nonce, action, policy identity, evidence, and session timing', async () => {
    await expect(
      checkRevocationChallengeInBrowser(
        challenge,
        action.action_id,
        binding,
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toMatchObject({
      status: 'passed',
      passed: true,
      blockers: [],
      independentlyCheckedFields: REVOCATION_BROWSER_CHECKED_FIELDS,
      serverRevalidatedFields: REVOCATION_SERVER_REVALIDATED_FIELDS,
    });
  });

  it.each([
    'policy_digest',
    'validation_snapshot_digest',
    'session_digest',
  ] as const)(
    'keeps a valid-shaped %s substitution server-authoritative rather than calling it browser proof',
    async (field) => {
      const substituted = decodeRevocationChallengeEnvelope({
        ...REVOCATION_CHALLENGE_ENVELOPE,
        challenge: {
          ...REVOCATION_CHALLENGE_ENVELOPE.challenge,
          [field]: `sha256:${'f'.repeat(64)}`,
        },
      });
      const result = await checkRevocationChallengeInBrowser(
        substituted,
        action.action_id,
        binding,
        SESSION_ENVELOPE.session,
      );

      expect(result).toMatchObject({
        status: 'passed',
        passed: true,
        serverRevalidatedFields: REVOCATION_SERVER_REVALIDATED_FIELDS,
      });
      expect(result.independentlyCheckedFields).not.toContain(field);
    },
  );

  it('fails closed for digest and immutable action-binding mismatches', async () => {
    const digestMismatch = decodeRevocationChallengeEnvelope({
      ...REVOCATION_CHALLENGE_ENVELOPE,
      challenge: {
        ...REVOCATION_CHALLENGE_ENVELOPE.challenge,
        generated_artifact_digest: `sha256:${'f'.repeat(64)}`,
      },
    });
    await expect(
      checkRevocationChallengeInBrowser(
        digestMismatch,
        action.action_id,
        binding,
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toMatchObject({ status: 'mismatch', passed: false });

    await expect(
      checkRevocationChallengeInBrowser(
        challenge,
        action.action_id,
        { ...binding, action_version: binding.action_version + 1 },
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toMatchObject({ status: 'mismatch', passed: false });
  });

  it('distinguishes unavailable and failed Web Crypto without granting authority', async () => {
    vi.stubGlobal('crypto', {} as Crypto);
    await expect(
      checkRevocationChallengeInBrowser(
        challenge,
        action.action_id,
        binding,
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toMatchObject({ status: 'unavailable', passed: false });

    vi.stubGlobal('crypto', {
      subtle: { digest: vi.fn().mockRejectedValue(new Error('unavailable')) },
    } as unknown as Crypto);
    await expect(
      checkRevocationChallengeInBrowser(
        challenge,
        action.action_id,
        binding,
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toMatchObject({ status: 'error', passed: false });
  });

  it('verifies the exact decision, reason, idempotency, rotation, and authorization digest', async () => {
    await expect(
      revocationDecisionMatchesExactBinding(
        decision,
        challenge,
        binding,
        REVOCATION_REASON,
        HIL_IDEMPOTENCY_KEY,
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toBe(true);

    const changedAuthorization = decodeRevocationDecisionEnvelope({
      ...REVOCATION_DECISION_ENVELOPE,
      authorization_digest: `sha256:${'e'.repeat(64)}`,
    });
    await expect(
      revocationDecisionMatchesExactBinding(
        changedAuthorization,
        challenge,
        binding,
        REVOCATION_REASON,
        HIL_IDEMPOTENCY_KEY,
        SESSION_ENVELOPE.session,
      ),
    ).resolves.toBe(false);
  });

  it('normalizes and validates only revocation reason codes and disables non-active actions', () => {
    const normalized = reasonForRevocation(
      'operator_request',
      'Cafe\u0301 block',
    );
    expect(normalized.reason_text).toBe('Café block');
    expect(validateRevocationReason(normalized)).toBeNull();
    expect(revocationReadiness(action, true).ready).toBe(true);
    expect(
      revocationReadiness(
        decodeEnforcementAction({
          ...ACTIVE_ENFORCEMENT_ACTION,
          state: 'expired',
          finished_at: '2026-07-18T01:34:02Z',
        }),
        true,
      ),
    ).toMatchObject({ ready: false });
  });
});
