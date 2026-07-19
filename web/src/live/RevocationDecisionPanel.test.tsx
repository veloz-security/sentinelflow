import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApiErrorV1 } from '../contracts/apiDtos';
import { ApiClientError } from './apiClient';
import { decodeEnforcementAction } from './contracts';
import type {
  EnforcementActionDetail,
  RevocationChallengeEnvelope,
  RevocationDecisionEnvelope,
} from './contracts';
import {
  ACTIVE_ENFORCEMENT_ACTION,
  REVOCATION_CHALLENGE_ENVELOPE,
  REVOCATION_DECISION_ENVELOPE,
  REVOCATION_REPLAY_DECISION_ENVELOPE,
  SESSION_ENVELOPE,
} from './liveTestFixtures';
import { RevocationDecisionPanel } from './RevocationDecisionPanel';
import { SessionContext, type SessionContextValue } from './sessionContext';

const fixedNow = () => Date.parse('2026-07-18T01:03:30Z');
const action = decodeEnforcementAction(
  structuredClone(ACTIVE_ENFORCEMENT_ACTION),
);
const challenge =
  REVOCATION_CHALLENGE_ENVELOPE as Readonly<RevocationChallengeEnvelope>;
const decision =
  REVOCATION_DECISION_ENVELOPE as Readonly<RevocationDecisionEnvelope>;

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
    issuePolicyChallenge: vi.fn(),
    decidePolicy: vi.fn(),
    issueRevocationChallenge: vi.fn().mockResolvedValue(challenge),
    decideRevocation: vi.fn().mockResolvedValue(decision),
    retryBootstrap: vi.fn(),
    invalidate: vi.fn(),
    ...overrides,
  };
}

function renderPanel(
  session = context(),
  actionValue: Readonly<EnforcementActionDetail> = action,
  onCommitted = vi.fn(),
) {
  return {
    session,
    onCommitted,
    ...render(
      <SessionContext.Provider value={session}>
        <RevocationDecisionPanel
          action={actionValue}
          now={fixedNow}
          onCommitted={onCommitted}
        />
      </SessionContext.Provider>,
    ),
  };
}

async function requestChallenge(user = userEvent.setup()) {
  await user.type(
    screen.getByLabelText(/Administrator revocation reason/),
    'Remove the synthetic block',
  );
  await user.click(
    screen.getByRole('button', { name: 'Request exact revoke challenge' }),
  );
  await screen.findByText('Browser checks passed');
  return user;
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

describe('active enforcement revocation panel', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('shows non-active and missing-CSRF states without a mutation affordance', () => {
    const expired = decodeEnforcementAction({
      ...ACTIVE_ENFORCEMENT_ACTION,
      state: 'expired',
      finished_at: '2026-07-18T01:34:02Z',
      version: 4,
      updated_at: '2026-07-18T01:34:02Z',
    });
    renderPanel(context({ csrfAvailable: false }), expired);

    expect(screen.getByText('Manual revocation is unavailable')).toBeVisible();
    expect(
      screen.getByText('Only an active enforcement action can be revoked.'),
    ).toBeVisible();
    expect(
      screen.getByText('The in-memory CSRF mutation guard is unavailable.'),
    ).toBeVisible();
    expect(
      screen.queryByRole('button', {
        name: 'Request exact revoke challenge',
      }),
    ).not.toBeInTheDocument();
  });

  it('keeps the action disabled while the exact browser checks are pending', async () => {
    let release:
      ((value: Readonly<RevocationChallengeEnvelope>) => void) | null = null;
    const issue = vi.fn(
      () =>
        new Promise<Readonly<RevocationChallengeEnvelope>>((resolve) => {
          release = resolve;
        }),
    );
    renderPanel(context({ issueRevocationChallenge: issue }));
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Administrator revocation reason/),
      'Remove the synthetic block',
    );
    await user.click(
      screen.getByRole('button', { name: 'Request exact revoke challenge' }),
    );
    expect(
      screen.getByRole('button', { name: 'Verifying exact revoke artifact' }),
    ).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Revoke exact active action' }),
    ).not.toBeInTheDocument();
    await act(async () => {
      release?.(challenge);
    });
    await screen.findByText('Browser checks passed');
  });

  it('displays exact server-derived bytes and records a confirmed revocation with one key', async () => {
    const issue = vi.fn().mockResolvedValue(challenge);
    const revoke = vi.fn().mockResolvedValue(decision);
    const onCommitted = vi.fn();
    renderPanel(
      context({
        issueRevocationChallenge: issue,
        decideRevocation: revoke,
      }),
      action,
      onCommitted,
    );
    const user = await requestChallenge();

    expect(screen.getByText('Browser assurance boundary')).toBeVisible();
    expect(
      screen.getByText(
        /Policy, validation, and session digests are displayed server-bound values, not independent browser proof/,
      ),
    ).toBeVisible();
    for (const label of [
      'Policy digest (server-bound)',
      'Validation digest (server-bound)',
      'Session digest (server-bound)',
    ]) {
      expect(screen.getByText(label)).toBeVisible();
    }
    expect(
      screen.getByText('Delete artifact digest (browser-recalculated)'),
    ).toBeVisible();
    expect(
      screen.queryByText('Verified single-use revoke challenge'),
    ).not.toBeInTheDocument();
    expect(
      screen.getByLabelText('Exact revoke artifact awaiting confirmation'),
    ).toHaveTextContent(
      'delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }',
    );
    expect(screen.getByText(challenge.policy_id)).toBeVisible();
    expect(screen.getByText(action.canonical_artifact_digest)).toBeVisible();
    expect(
      screen.queryByText(challenge.challenge_nonce),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(SESSION_ENVELOPE.csrf_token),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Revoke exact active action' }),
    ).toBeDisabled();

    await user.click(
      screen.getByLabelText(/I reviewed the exact delete artifact/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Revoke exact active action' }),
    );

    expect(await screen.findByText('Exact revocation recorded')).toBeVisible();
    expect(screen.getByText(decision.revocation_id)).toBeVisible();
    expect(revoke).toHaveBeenCalledOnce();
    expect(revoke.mock.calls[0][4]).toBe(issue.mock.calls[0][2]);
    expect(onCommitted).toHaveBeenCalledOnce();
  });

  it('uses the same idempotency key after conditional password step-up', async () => {
    const issue = vi
      .fn()
      .mockRejectedValueOnce(apiError(401, 'step_up_required'))
      .mockResolvedValueOnce(challenge);
    const stepUp = vi.fn().mockResolvedValue(undefined);
    renderPanel(context({ issueRevocationChallenge: issue, stepUp }));
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Administrator revocation reason/),
      'Remove the synthetic block',
    );
    await user.click(
      screen.getByRole('button', { name: 'Request exact revoke challenge' }),
    );
    expect(await screen.findByText('Password step-up required')).toBeVisible();
    await user.type(
      screen.getByLabelText(/Current password for revocation/),
      'not-retained',
    );
    await user.click(
      screen.getByRole('button', {
        name: 'Step up and retry revocation challenge',
      }),
    );
    await screen.findByText('Browser checks passed');

    expect(stepUp).toHaveBeenCalledWith('not-retained');
    expect(issue).toHaveBeenCalledTimes(2);
    expect(issue.mock.calls[1][2]).toBe(issue.mock.calls[0][2]);
    expect(screen.queryByDisplayValue('not-retained')).not.toBeInTheDocument();
  });

  it('invalidates exact confirmation when reason intent changes', async () => {
    const issue = vi.fn().mockResolvedValue(challenge);
    renderPanel(context({ issueRevocationChallenge: issue }));
    const user = await requestChallenge();
    await user.click(
      screen.getByLabelText(/I reviewed the exact delete artifact/),
    );
    expect(
      screen.getByRole('button', { name: 'Revoke exact active action' }),
    ).toBeEnabled();

    await user.type(
      screen.getByLabelText(/Administrator revocation reason/),
      ' changed',
    );
    expect(screen.queryByText('Browser checks passed')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Revoke exact active action' }),
    ).not.toBeInTheDocument();
  });

  it('discards a stale async challenge when the action version and state change', async () => {
    let release:
      ((value: Readonly<RevocationChallengeEnvelope>) => void) | null = null;
    const issue = vi.fn(
      () =>
        new Promise<Readonly<RevocationChallengeEnvelope>>((resolve) => {
          release = resolve;
        }),
    );
    const session = context({ issueRevocationChallenge: issue });
    const view = renderPanel(session);
    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Administrator revocation reason/),
      'Remove the synthetic block',
    );
    await user.click(
      screen.getByRole('button', { name: 'Request exact revoke challenge' }),
    );
    const revoked = decodeEnforcementAction({
      ...ACTIVE_ENFORCEMENT_ACTION,
      state: 'revoked',
      version: ACTIVE_ENFORCEMENT_ACTION.version + 1,
      finished_at: '2026-07-18T01:05:00Z',
      updated_at: '2026-07-18T01:05:00Z',
    });
    view.rerender(
      <SessionContext.Provider value={session}>
        <RevocationDecisionPanel action={revoked} now={fixedNow} />
      </SessionContext.Provider>,
    );
    await act(async () => {
      release?.(challenge);
      await Promise.resolve();
    });

    expect(screen.getByText('Manual revocation is unavailable')).toBeVisible();
    expect(screen.queryByText('Browser checks passed')).not.toBeInTheDocument();
  });

  it.each([
    [403, 'permission_denied', null, 'Permission required'],
    [409, 'stale_version', null, 'safe stale_version response'],
    [429, 'rate_limited', 7, 'safe rate_limited response'],
  ] as const)(
    'shows typed %s %s challenge failures without exposing authority',
    async (status, code, retryAfter, message) => {
      renderPanel(
        context({
          issueRevocationChallenge: vi
            .fn()
            .mockRejectedValue(apiError(status, code, retryAfter)),
        }),
      );
      const user = userEvent.setup();
      await user.type(
        screen.getByLabelText(/Administrator revocation reason/),
        'Remove the synthetic block',
      );
      await user.click(
        screen.getByRole('button', { name: 'Request exact revoke challenge' }),
      );
      expect(await screen.findByText(message)).toBeVisible();
      if (retryAfter) {
        expect(
          screen.getByText(`Retry after ${retryAfter} seconds.`),
        ).toBeVisible();
      }
      expect(
        screen.queryByText('Browser checks passed'),
      ).not.toBeInTheDocument();
    },
  );

  it('keeps the exact candidate for an uncertain commit retry and then presents historical success', async () => {
    const revoke = vi
      .fn()
      .mockRejectedValueOnce(apiError(503, 'service_unavailable'))
      .mockResolvedValueOnce(REVOCATION_REPLAY_DECISION_ENVELOPE);
    renderPanel(context({ decideRevocation: revoke }));
    const user = await requestChallenge();
    await user.click(
      screen.getByLabelText(/I reviewed the exact delete artifact/),
    );
    await user.click(
      screen.getByRole('button', { name: 'Revoke exact active action' }),
    );
    expect(
      await screen.findByText('safe service_unavailable response'),
    ).toBeVisible();
    expect(screen.getByText('Browser checks passed')).toBeVisible();

    await user.click(
      screen.getByRole('button', { name: 'Revoke exact active action' }),
    );
    expect(await screen.findByText('Exact revocation recorded')).toBeVisible();
    expect(screen.getByText(/exact historical result/)).toBeVisible();
    expect(revoke).toHaveBeenCalledTimes(2);
    expect(revoke.mock.calls[1][4]).toBe(revoke.mock.calls[0][4]);
  });

  it('expires a displayed challenge locally before mutation', async () => {
    let clock = fixedNow();
    const session = context();
    render(
      <SessionContext.Provider value={session}>
        <RevocationDecisionPanel action={action} now={() => clock} />
      </SessionContext.Provider>,
    );
    const user = await requestChallenge();
    await user.click(
      screen.getByLabelText(/I reviewed the exact delete artifact/),
    );
    clock = Date.parse(challenge.challenge.expires_at) + 1;
    await user.click(
      screen.getByRole('button', { name: 'Revoke exact active action' }),
    );
    expect(
      await screen.findByText(
        'The exact revocation challenge expired before submission.',
      ),
    ).toBeVisible();
    expect(session.decideRevocation).not.toHaveBeenCalled();
  });
});
