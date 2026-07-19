import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { JSON_CONTENT_TYPE, ManagementApiClient } from './apiClient';
import { SessionProvider } from './SessionProvider';
import { PolicyDecisionPanel } from './PolicyDecisionPanel';
import { useSession } from './sessionContext';
import {
  HIL_CHALLENGE_ENVELOPE,
  HIL_DECISION_ENVELOPE,
  HIL_REPLAY_DECISION_ENVELOPE,
  HIL_IDEMPOTENCY_KEY,
  ACTIVE_ENFORCEMENT_ACTION,
  POLICY_DETAIL,
  POLICY_ID,
  REVOCATION_CHALLENGE_ENVELOPE,
  REVOCATION_DECISION_ENVELOPE,
  REVOCATION_REASON,
  REVOCATION_REPLAY_DECISION_ENVELOPE,
  SESSION_ENVELOPE,
} from './liveTestFixtures';
import { decodeEnforcementAction, decodePolicyDetail } from './contracts';
import { policyArtifactBinding, reasonForDecision } from './policyHil';
import { revocationArtifactBinding } from './revocationHil';

function response(value: unknown) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': JSON_CONTENT_TYPE },
  });
}

function Probe() {
  const session = useSession();
  return (
    <div>
      <span>{session.phase}</span>
      <span>{session.csrfAvailable ? 'csrf-ready' : 'csrf-missing'}</span>
      <button onClick={() => void session.logout()}>logout</button>
    </div>
  );
}

function HILProbe() {
  const session = useSession();
  const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
  const binding = policyArtifactBinding(policy, 'approve');
  const decide = async () => {
    if (!binding) return;
    const challenge = await session.issuePolicyChallenge(
      POLICY_ID,
      binding,
      HIL_IDEMPOTENCY_KEY,
    );
    await session.decidePolicy(
      POLICY_ID,
      binding,
      challenge,
      reasonForDecision('threat_confirmed', 'Confirmed synthetic attack'),
      HIL_IDEMPOTENCY_KEY,
    );
  };
  return (
    <div>
      <span>{session.phase}</span>
      <span>{session.session?.session_id ?? 'session-cleared'}</span>
      <span>{session.reauthenticationNotice?.decision.decision_id}</span>
      <button onClick={() => void decide()}>decide</button>
    </div>
  );
}

function ChallengeOnlyProbe() {
  const session = useSession();
  const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
  const binding = policyArtifactBinding(policy, 'approve');
  return (
    <div>
      <span>{session.phase}</span>
      <button
        onClick={() => {
          if (binding) {
            void session
              .issuePolicyChallenge(POLICY_ID, binding, HIL_IDEMPOTENCY_KEY)
              .catch(() => undefined);
          }
        }}
      >
        challenge
      </button>
    </div>
  );
}

function RevocationProbe() {
  const session = useSession();
  const action = decodeEnforcementAction(
    structuredClone(ACTIVE_ENFORCEMENT_ACTION),
  );
  const binding = revocationArtifactBinding(action);
  const revoke = async () => {
    const challenge = await session.issueRevocationChallenge(
      action.action_id,
      binding,
      HIL_IDEMPOTENCY_KEY,
    );
    await session.decideRevocation(
      action.action_id,
      binding,
      challenge,
      REVOCATION_REASON,
      HIL_IDEMPOTENCY_KEY,
    );
  };
  return (
    <div>
      <span>{session.phase}</span>
      <span>{session.session?.session_id ?? 'session-cleared'}</span>
      <span>{session.reauthenticationNotice?.decision.decision_id}</span>
      <button onClick={() => void revoke().catch(() => undefined)}>
        revoke
      </button>
    </div>
  );
}

describe('SessionProvider', () => {
  it('bootstraps the safe projection and uses memory-only CSRF for logout', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <Probe />
      </SessionProvider>,
    );

    expect(await screen.findByText('csrf-ready')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'logout' }));
    await waitFor(() => expect(screen.getByText('anonymous')).toBeVisible());
    const [, init] = fetchMock.mock.calls[1];
    expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );
    expect(document.cookie).toBe('');
  });

  it('keeps a restored session read-only when CSRF is absent', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(response({ session: SESSION_ENVELOPE.session }));
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <Probe />
      </SessionProvider>,
    );
    expect(await screen.findByText('csrf-missing')).toBeVisible();
    expect(screen.getByText('authenticated')).toBeVisible();
  });

  it('accepts the exact decision response and rotates memory-only CSRF', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(HIL_CHALLENGE_ENVELOPE), {
          status: 201,
          headers: { 'Content-Type': JSON_CONTENT_TYPE },
        }),
      )
      .mockResolvedValueOnce(response(HIL_DECISION_ENVELOPE));
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <HILProbe />
      </SessionProvider>,
    );

    expect(
      await screen.findByText(SESSION_ENVELOPE.session.session_id),
    ).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'decide' }));
    expect(
      await screen.findByText(HIL_DECISION_ENVELOPE.session.session_id),
    ).toBeVisible();
    const [, decisionInit] = fetchMock.mock.calls[2];
    expect(new Headers(decisionInit?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );
    expect(String(decisionInit?.body)).not.toContain('"csrf_token"');
  });

  it('shows exact replay proof, clears local authority, and requires login', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(HIL_CHALLENGE_ENVELOPE), {
          status: 201,
          headers: { 'Content-Type': JSON_CONTENT_TYPE },
        }),
      )
      .mockResolvedValueOnce(response(HIL_REPLAY_DECISION_ENVELOPE));
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <HILProbe />
      </SessionProvider>,
    );

    expect(
      await screen.findByText(SESSION_ENVELOPE.session.session_id),
    ).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'decide' }));
    expect(await screen.findByText('anonymous')).toBeVisible();
    expect(screen.getByText('session-cleared')).toBeVisible();
    expect(
      screen.getByText(HIL_REPLAY_DECISION_ENVELOPE.decision.decision_id),
    ).toBeVisible();
    expect(
      screen.queryByText(HIL_DECISION_ENVELOPE.session.session_id),
    ).not.toBeInTheDocument();
  });

  it('invalidates the local session on an authentication-required mutation', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            code: 'authentication_required',
            message: 'authentication is required',
            trace_id: '019b0000-0000-4000-8000-000000000901',
            details: {},
          }),
          {
            status: 401,
            headers: { 'Content-Type': JSON_CONTENT_TYPE },
          },
        ),
      );
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <ChallengeOnlyProbe />
      </SessionProvider>,
    );
    expect(await screen.findByText('authenticated')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'challenge' }));
    expect(await screen.findByText('anonymous')).toBeVisible();
  });

  it('uses the synchronously accepted step-up session for the immediate challenge retry', async () => {
    const rotatedSessionEnvelope = {
      session: {
        ...SESSION_ENVELOPE.session,
        session_id: '019b0000-0000-7000-8000-000000000399',
        authenticated_at: '2026-07-18T01:02:30Z',
      },
      csrf_token: 'c'.repeat(43),
    };
    const rotatedChallengeEnvelope = {
      ...HIL_CHALLENGE_ENVELOPE,
      challenge: {
        ...HIL_CHALLENGE_ENVELOPE.challenge,
        authenticated_at: rotatedSessionEnvelope.session.authenticated_at,
      },
    };
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            code: 'step_up_required',
            message: 'password step-up is required',
            trace_id: '019b0000-0000-4000-8000-000000000902',
            details: {},
          }),
          {
            status: 401,
            headers: { 'Content-Type': JSON_CONTENT_TYPE },
          },
        ),
      )
      .mockResolvedValueOnce(response(rotatedSessionEnvelope))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(rotatedChallengeEnvelope), {
          status: 201,
          headers: { 'Content-Type': JSON_CONTENT_TYPE },
        }),
      );
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    render(
      <MemoryRouter>
        <SessionProvider client={new ManagementApiClient(fetchMock)}>
          <PolicyDecisionPanel
            policy={policy}
            now={() => Date.parse('2026-07-18T01:03:30Z')}
          />
        </SessionProvider>
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByLabelText(/Administrator reason/)).toBeEnabled(),
    );
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

    expect(await screen.findByText('Single-use challenge')).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(4);
    const [, stepUpInit] = fetchMock.mock.calls[2];
    expect(new Headers(stepUpInit?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );
    const [, retriedChallengeInit] = fetchMock.mock.calls[3];
    expect(new Headers(retriedChallengeInit?.headers).get('X-CSRF-Token')).toBe(
      rotatedSessionEnvelope.csrf_token,
    );
    expect(screen.queryByDisplayValue('not-retained')).not.toBeInTheDocument();
  });

  it('verifies revocation output before atomically accepting the rotated session and CSRF', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(REVOCATION_CHALLENGE_ENVELOPE), {
          status: 201,
          headers: { 'Content-Type': JSON_CONTENT_TYPE },
        }),
      )
      .mockResolvedValueOnce(response(REVOCATION_DECISION_ENVELOPE));
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <RevocationProbe />
      </SessionProvider>,
    );

    expect(
      await screen.findByText(SESSION_ENVELOPE.session.session_id),
    ).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'revoke' }));
    expect(
      await screen.findByText(REVOCATION_DECISION_ENVELOPE.session.session_id),
    ).toBeVisible();
    const [, challengeInit] = fetchMock.mock.calls[1];
    const [, decisionInit] = fetchMock.mock.calls[2];
    expect(new Headers(challengeInit?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );
    expect(new Headers(decisionInit?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );
    expect(String(decisionInit?.body)).not.toContain(
      REVOCATION_DECISION_ENVELOPE.csrf_token,
    );
  });

  it('clears all local authority after an exact historical revocation replay', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(REVOCATION_CHALLENGE_ENVELOPE), {
          status: 201,
          headers: { 'Content-Type': JSON_CONTENT_TYPE },
        }),
      )
      .mockResolvedValueOnce(response(REVOCATION_REPLAY_DECISION_ENVELOPE));
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <RevocationProbe />
      </SessionProvider>,
    );

    expect(
      await screen.findByText(SESSION_ENVELOPE.session.session_id),
    ).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'revoke' }));
    expect(await screen.findByText('anonymous')).toBeVisible();
    expect(screen.getByText('session-cleared')).toBeVisible();
    expect(
      screen.getByText(
        REVOCATION_REPLAY_DECISION_ENVELOPE.decision.decision_id,
      ),
    ).toBeVisible();
  });

  it('invalidates the session when a revocation authorization digest is changed', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(SESSION_ENVELOPE))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(REVOCATION_CHALLENGE_ENVELOPE), {
          status: 201,
          headers: { 'Content-Type': JSON_CONTENT_TYPE },
        }),
      )
      .mockResolvedValueOnce(
        response({
          ...REVOCATION_DECISION_ENVELOPE,
          authorization_digest: `sha256:${'f'.repeat(64)}`,
        }),
      );
    render(
      <SessionProvider client={new ManagementApiClient(fetchMock)}>
        <RevocationProbe />
      </SessionProvider>,
    );
    expect(
      await screen.findByText(SESSION_ENVELOPE.session.session_id),
    ).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'revoke' }));
    expect(await screen.findByText('anonymous')).toBeVisible();
    expect(screen.getByText('session-cleared')).toBeVisible();
  });
});
