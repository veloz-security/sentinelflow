import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApiErrorV1 } from '../contracts/apiDtos';
import { ApiClientError } from './apiClient';
import {
  decodeHILChallengeEnvelope,
  decodeHILDecisionEnvelope,
  decodePolicyDetail,
  type HILChallengeEnvelope,
  type HILDecisionEnvelope,
} from './contracts';
import {
  HIL_CHALLENGE_ENVELOPE,
  HIL_DECISION_ENVELOPE,
  HIL_REPLAY_DECISION_ENVELOPE,
  POLICY_DETAIL,
  SESSION_ENVELOPE,
} from './liveTestFixtures';
import { PolicyDecisionPanel } from './PolicyDecisionPanel';
import { SessionContext, type SessionContextValue } from './sessionContext';

const fixedNow = () => Date.parse('2026-07-18T01:03:30Z');
const challenge = decodeHILChallengeEnvelope(
  structuredClone(HIL_CHALLENGE_ENVELOPE),
);
const decision = decodeHILDecisionEnvelope(
  structuredClone(HIL_DECISION_ENVELOPE),
);

function context(
  overrides: Partial<SessionContextValue> = {},
): SessionContextValue {
  return {
    phase: 'authenticated',
    session: SESSION_ENVELOPE.session,
    csrfAvailable: true,
    reauthenticationNotice: null,
    error: null,
    login: vi.fn(),
    logout: vi.fn(),
    stepUp: vi.fn(),
    issuePolicyChallenge: vi.fn().mockResolvedValue(challenge),
    decidePolicy: vi.fn().mockResolvedValue(decision),
    issueRevocationChallenge: vi.fn(),
    decideRevocation: vi.fn(),
    retryBootstrap: vi.fn(),
    invalidate: vi.fn(),
    ...overrides,
  };
}

function renderPanel(
  session = context(),
  policyValue: unknown = POLICY_DETAIL,
  now: () => number = fixedNow,
) {
  const policy = decodePolicyDetail(structuredClone(policyValue));
  return {
    session,
    ...render(
      <MemoryRouter>
        <SessionContext.Provider value={session}>
          <PolicyDecisionPanel policy={policy} now={now} />
        </SessionContext.Provider>
      </MemoryRouter>,
    ),
  };
}

async function completeReasonAndChallenge() {
  await waitForIntegrityReady();
  const user = userEvent.setup();
  await user.type(
    screen.getByLabelText(/Administrator reason/),
    'Confirmed synthetic attack',
  );
  await user.click(
    screen.getByRole('button', { name: 'Request exact challenge' }),
  );
  await screen.findByText('Single-use challenge');
  return user;
}

async function waitForIntegrityReady() {
  await waitFor(() =>
    expect(screen.getByLabelText(/Administrator reason/)).toBeEnabled(),
  );
}

function digestBytes(digest: string): ArrayBuffer {
  return Uint8Array.from(
    digest.slice('sha256:'.length).match(/.{2}/g) ?? [],
    (value) => Number.parseInt(value, 16),
  ).buffer;
}

function apiError(
  status: number,
  code: ApiErrorV1['code'],
  retryAfter: number | null = null,
) {
  return new ApiClientError(
    status,
    Object.freeze({
      code,
      message: `safe ${code} response`,
      trace_id: '019b0000-0000-4000-8000-000000000999',
      details: Object.freeze({}),
    }),
    retryAfter,
  );
}

describe('live exact-artifact HIL panel', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fails closed when CSRF, current validation, or exact gates are absent', () => {
    renderPanel(context({ csrfAvailable: false }), {
      ...POLICY_DETAIL,
      state: 'stale',
      latest_validation: {
        ...POLICY_DETAIL.latest_validation,
        state: 'stale',
        source_health_status: 'incomplete',
        gates: POLICY_DETAIL.latest_validation.gates.slice(0, 5),
      },
    });
    expect(screen.getByText('HIL decision is disabled')).toBeVisible();
    expect(
      screen.getByText('The in-memory CSRF mutation guard is unavailable.'),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    ).toBeDisabled();
  });

  it('shows loading, reviews exact bytes, and commits approval with one key', async () => {
    let release: ((value: Readonly<HILChallengeEnvelope>) => void) | undefined;
    const issue = vi.fn(
      (
        _policyID: string,
        _binding: Parameters<SessionContextValue['issuePolicyChallenge']>[1],
        _idempotencyKey: string,
      ) => {
        void _policyID;
        void _binding;
        void _idempotencyKey;
        return new Promise<Readonly<HILChallengeEnvelope>>((resolve) => {
          release = resolve;
        });
      },
    );
    const decide = vi.fn().mockResolvedValue(decision);
    renderPanel(context({ issuePolicyChallenge: issue, decidePolicy: decide }));
    await waitForIntegrityReady();
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Administrator reason/),
      'Confirmed synthetic attack',
    );
    await user.click(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    );
    expect(
      screen.getByRole('button', { name: 'Requesting challenge' }),
    ).toBeDisabled();
    release?.(challenge);
    await screen.findByText('Single-use challenge');
    expect(
      screen.getByLabelText('Exact command awaiting HIL decision'),
    ).toHaveTextContent(POLICY_DETAIL.canonical_command.trim());
    expect(screen.getByText(POLICY_DETAIL.policy_digest)).toBeVisible();
    expect(
      screen.queryByText(HIL_CHALLENGE_ENVELOPE.challenge_nonce),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(SESSION_ENVELOPE.csrf_token),
    ).not.toBeInTheDocument();

    await user.click(
      screen.getByLabelText(/I reviewed the exact target, TTL, command/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Approve exact artifact' }),
    );
    expect(await screen.findByText('Exact artifact approved')).toBeVisible();
    expect(decide).toHaveBeenCalledOnce();
    expect(decide.mock.calls[0][4]).toBe(issue.mock.calls[0][2]);
    expect(
      screen.getByRole('link', { name: 'Open queued enforcement action' }),
    ).toHaveAttribute(
      'href',
      `/enforcement-actions/${HIL_DECISION_ENVELOPE.action_id}`,
    );
  });

  it('supports rejection without fabricating enforcement authority', async () => {
    const rejectChallenge = {
      ...challenge,
      challenge: { ...challenge.challenge, operation: 'reject' },
    } as Readonly<HILChallengeEnvelope>;
    const rejectDecision = {
      ...decision,
      decision: {
        ...decision.decision,
        operation: 'reject',
        decision: 'rejected',
      },
      action_id: null,
      authorization_digest: null,
      outbox_job_id: null,
    } as Readonly<HILDecisionEnvelope>;
    const decide = vi.fn().mockResolvedValue(rejectDecision);
    renderPanel(
      context({
        issuePolicyChallenge: vi.fn().mockResolvedValue(rejectChallenge),
        decidePolicy: decide,
      }),
    );
    await waitForIntegrityReady();
    const user = userEvent.setup();
    await user.click(screen.getByLabelText('Reject artifact'));
    await user.type(
      screen.getByLabelText(/Administrator reason/),
      'Synthetic traffic is benign',
    );
    await user.click(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    );
    await screen.findByText('Single-use challenge');
    await user.click(
      screen.getByLabelText(/I reviewed the exact target, TTL, command/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Reject exact artifact' }),
    );
    expect(await screen.findByText('Exact artifact rejected')).toBeVisible();
    expect(
      screen.queryByRole('link', { name: 'Open queued enforcement action' }),
    ).not.toBeInTheDocument();
  });

  it('labels an exact replay as a prior result rather than new authority', async () => {
    const replay = decodeHILDecisionEnvelope(
      structuredClone(HIL_REPLAY_DECISION_ENVELOPE),
    );
    renderPanel(context({ decidePolicy: vi.fn().mockResolvedValue(replay) }));
    const user = await completeReasonAndChallenge();
    await user.click(
      screen.getByLabelText(/I reviewed the exact target, TTL, command/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Approve exact artifact' }),
    );
    expect(await screen.findByText('Exact artifact approved')).toBeVisible();
    expect(screen.getByText(/confirmed an exact prior result/)).toBeVisible();
    expect(screen.getByText(/No new authorization was created/)).toBeVisible();
  });

  it('performs conditional password step-up before issuing a new challenge', async () => {
    const issue = vi
      .fn()
      .mockRejectedValueOnce(apiError(401, 'step_up_required'))
      .mockResolvedValueOnce(challenge);
    const stepUp = vi.fn().mockResolvedValue(undefined);
    renderPanel(context({ issuePolicyChallenge: issue, stepUp }));
    await waitForIntegrityReady();
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Administrator reason/),
      'Confirmed synthetic attack',
    );
    await user.click(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    );
    expect(await screen.findByText('Password step-up required')).toBeVisible();
    await user.type(screen.getByLabelText(/Current password/), 'not-retained');
    await user.click(
      screen.getByRole('button', { name: 'Step up and retry challenge' }),
    );
    await screen.findByText('Single-use challenge');
    expect(stepUp).toHaveBeenCalledWith('not-retained');
    expect(issue).toHaveBeenCalledTimes(2);
    expect(issue.mock.calls[1][2]).toBe(issue.mock.calls[0][2]);
    expect(screen.queryByDisplayValue('not-retained')).not.toBeInTheDocument();
  });

  it.each([
    [409, 'stale_version', null],
    [403, 'permission_denied', null],
    [429, 'rate_limited', 7],
    [503, 'service_unavailable', null],
  ] as const)(
    'shows typed %s %s challenge failures without creating a nonce view',
    async (status, code, retryAfter) => {
      renderPanel(
        context({
          issuePolicyChallenge: vi
            .fn()
            .mockRejectedValue(apiError(status, code, retryAfter)),
        }),
      );
      await waitForIntegrityReady();
      const user = userEvent.setup();
      await user.type(
        screen.getByLabelText(/Administrator reason/),
        'Confirmed synthetic attack',
      );
      await user.click(
        screen.getByRole('button', { name: 'Request exact challenge' }),
      );
      expect(
        await screen.findByText(
          status === 403 ? 'Permission required' : `safe ${code} response`,
        ),
      ).toBeVisible();
      expect(screen.getByText(code)).toBeVisible();
      if (retryAfter) {
        expect(
          screen.getByText(`Retry after ${retryAfter} seconds.`),
        ).toBeVisible();
      }
      expect(
        screen.queryByText('Single-use challenge'),
      ).not.toBeInTheDocument();
    },
  );

  it('discards a consumed/replayed challenge and never auto-retries mutation', async () => {
    const decide = vi
      .fn()
      .mockRejectedValue(apiError(409, 'challenge_consumed'));
    renderPanel(context({ decidePolicy: decide }));
    const user = await completeReasonAndChallenge();
    await user.click(
      screen.getByLabelText(/I reviewed the exact target, TTL, command/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Approve exact artifact' }),
    );
    expect(
      await screen.findByText('safe challenge_consumed response'),
    ).toBeVisible();
    expect(screen.queryByText('Single-use challenge')).not.toBeInTheDocument();
    expect(decide).toHaveBeenCalledOnce();
  });

  it('fails closed when a displayed challenge expires before confirmation', async () => {
    let clock = fixedNow();
    const decide = vi.fn().mockResolvedValue(decision);
    renderPanel(context({ decidePolicy: decide }), POLICY_DETAIL, () => clock);
    const user = await completeReasonAndChallenge();
    clock = Date.parse(HIL_CHALLENGE_ENVELOPE.challenge.expires_at) + 1;
    await user.click(
      screen.getByLabelText(/I reviewed the exact target, TTL, command/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Approve exact artifact' }),
    );
    expect(
      await screen.findByText(
        'The exact challenge expired before the decision was submitted.',
      ),
    ).toBeVisible();
    expect(screen.queryByText('Single-use challenge')).not.toBeInTheDocument();
    expect(decide).not.toHaveBeenCalled();
  });

  it('invalidates an issued challenge when the immutable policy revision changes', async () => {
    const session = context();
    const view = renderPanel(session);
    await completeReasonAndChallenge();
    const changed = decodePolicyDetail({
      ...POLICY_DETAIL,
      state_revision: POLICY_DETAIL.state_revision + 1,
    });
    view.rerender(
      <MemoryRouter>
        <SessionContext.Provider value={session}>
          <PolicyDecisionPanel policy={changed} now={fixedNow} />
        </SessionContext.Provider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(
        screen.queryByText('Single-use challenge'),
      ).not.toBeInTheDocument(),
    );
  });

  it('keeps HIL disabled while both command digests are pending', async () => {
    const digest = vi.fn(() => new Promise<ArrayBuffer>(() => undefined));
    vi.stubGlobal('crypto', {
      subtle: { digest },
    } as unknown as Crypto);
    const session = context();
    renderPanel(session);

    expect(
      await screen.findByText(
        'Browser SHA-256 verification of both exact command artifacts is pending.',
      ),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    ).toBeDisabled();
    expect(session.issuePolicyChallenge).not.toHaveBeenCalled();
    expect(digest).toHaveBeenCalledTimes(2);
  });

  it('fails closed visibly when Web Crypto digest support is unavailable', async () => {
    vi.stubGlobal('crypto', {} as Crypto);
    const session = context();
    renderPanel(session);

    expect(
      await screen.findByText(
        'Secure browser SHA-256 verification is unavailable.',
      ),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    ).toBeDisabled();
    expect(session.issuePolicyChallenge).not.toHaveBeenCalled();
  });

  it('fails closed visibly when Web Crypto digest execution rejects', async () => {
    const digest = vi.fn().mockRejectedValue(new Error('digest unavailable'));
    vi.stubGlobal('crypto', {
      subtle: { digest },
    } as unknown as Crypto);
    const session = context();
    renderPanel(session);

    expect(
      await screen.findByText(
        'Secure browser SHA-256 verification could not be completed.',
      ),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    ).toBeDisabled();
    expect(session.issuePolicyChallenge).not.toHaveBeenCalled();
    expect(digest).toHaveBeenCalledTimes(2);
  });

  it('reports each exact command digest mismatch and never requests a challenge', async () => {
    const session = context();
    renderPanel(session, {
      ...POLICY_DETAIL,
      generated_artifact_digest: `sha256:${'f'.repeat(64)}`,
      canonical_artifact_digest: `sha256:${'e'.repeat(64)}`,
    });

    expect(
      await screen.findByText(
        'The generated command does not match its declared SHA-256 digest.',
      ),
    ).toBeVisible();
    expect(
      screen.getByText(
        'The canonical command does not match its declared SHA-256 digest.',
      ),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Request exact challenge' }),
    ).toBeDisabled();
    expect(session.issuePolicyChallenge).not.toHaveBeenCalled();
  });

  it('cancels stale digest results when the reviewed policy bytes change', async () => {
    const resolvers: Array<(value: ArrayBuffer) => void> = [];
    const digest = vi.fn(
      () =>
        new Promise<ArrayBuffer>((resolve) => {
          resolvers.push(resolve);
        }),
    );
    vi.stubGlobal('crypto', {
      subtle: { digest },
    } as unknown as Crypto);
    const session = context();
    const view = renderPanel(session);
    await waitFor(() => expect(digest).toHaveBeenCalledTimes(2));

    const replacementDigest = `sha256:${'b'.repeat(64)}`;
    const changed = decodePolicyDetail({
      ...POLICY_DETAIL,
      state_revision: POLICY_DETAIL.state_revision + 1,
      generated_command:
        'add element inet sentinelflow blacklist_ipv4 { 203.0.113.21 timeout 30m }\n',
      generated_artifact_digest: replacementDigest,
      canonical_command:
        'add element inet sentinelflow blacklist_ipv4 { 203.0.113.21 timeout 30m }\n',
      canonical_artifact_digest: replacementDigest,
    });
    view.rerender(
      <MemoryRouter>
        <SessionContext.Provider value={session}>
          <PolicyDecisionPanel policy={changed} now={fixedNow} />
        </SessionContext.Provider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(digest).toHaveBeenCalledTimes(4));

    await act(async () => {
      const oldDigest = digestBytes(POLICY_DETAIL.generated_artifact_digest);
      resolvers[0]?.(oldDigest);
      resolvers[1]?.(oldDigest);
      await Promise.resolve();
    });
    expect(
      screen.getByText(
        'Browser SHA-256 verification of both exact command artifacts is pending.',
      ),
    ).toBeVisible();
    expect(screen.getByLabelText(/Administrator reason/)).toBeDisabled();
    expect(session.issuePolicyChallenge).not.toHaveBeenCalled();

    await act(async () => {
      const replacementBytes = digestBytes(replacementDigest);
      resolvers[2]?.(replacementBytes);
      resolvers[3]?.(replacementBytes);
      await Promise.resolve();
    });
    await waitForIntegrityReady();
    expect(
      screen.queryByText(
        'Browser SHA-256 verification of both exact command artifacts is pending.',
      ),
    ).not.toBeInTheDocument();
  });
});
