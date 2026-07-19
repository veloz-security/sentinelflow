import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { LoginPage, SessionPage } from './AuthPages';
import { SessionContext, type SessionContextValue } from './sessionContext';
import { SESSION_ENVELOPE } from './liveTestFixtures';
import { HIL_REPLAY_DECISION_ENVELOPE } from './liveTestFixtures';
import { REVOCATION_REPLAY_DECISION_ENVELOPE } from './liveTestFixtures';

function context(overrides: Partial<SessionContextValue>): SessionContextValue {
  return {
    phase: 'anonymous',
    session: null,
    csrfAvailable: false,
    reauthenticationNotice: null,
    error: null,
    login: vi.fn(),
    logout: vi.fn(),
    stepUp: vi.fn(),
    issuePolicyChallenge: vi.fn(),
    decidePolicy: vi.fn(),
    issueRevocationChallenge: vi.fn(),
    decideRevocation: vi.fn(),
    retryBootstrap: vi.fn(),
    invalidate: vi.fn(),
    ...overrides,
  };
}

describe('administrator auth pages', () => {
  it('submits login through the session boundary and clears the password field', async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    render(
      <SessionContext.Provider value={context({ login })}>
        <LoginPage />
      </SessionContext.Provider>,
    );
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/Username/), 'admin');
    await user.type(screen.getByLabelText(/Password/), 'not-retained');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() =>
      expect(login).toHaveBeenCalledWith('admin', 'not-retained'),
    );
    expect(screen.getByLabelText(/Password/)).toHaveValue('');
  });

  it('shows an idempotent replay result while requiring a fresh sign-in', () => {
    render(
      <SessionContext.Provider
        value={context({
          reauthenticationNotice: HIL_REPLAY_DECISION_ENVELOPE,
        })}
      >
        <LoginPage />
      </SessionContext.Provider>,
    );

    expect(
      screen.getByText('Exact decision was already recorded'),
    ).toBeVisible();
    expect(screen.getByText(/This is not a new authorization/)).toBeVisible();
    expect(
      screen.getByText(HIL_REPLAY_DECISION_ENVELOPE.decision.decision_id),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeVisible();
  });

  it('shows a historical revocation result without restoring mutation credentials', () => {
    render(
      <SessionContext.Provider
        value={context({
          reauthenticationNotice: REVOCATION_REPLAY_DECISION_ENVELOPE,
        })}
      >
        <LoginPage />
      </SessionContext.Provider>,
    );

    expect(
      screen.getByText(REVOCATION_REPLAY_DECISION_ENVELOPE.revocation_id),
    ).toBeVisible();
    expect(
      screen.getByText(
        REVOCATION_REPLAY_DECISION_ENVELOPE.decision.resource_id,
      ),
    ).toBeVisible();
    expect(screen.getByText(/previous session was expired/)).toBeVisible();
    expect(screen.queryByText('d'.repeat(43))).not.toBeInTheDocument();
  });

  it('shows restored sessions without exposing CSRF and disables mutations when it is absent', () => {
    render(
      <SessionContext.Provider
        value={context({
          phase: 'authenticated',
          session: SESSION_ENVELOPE.session,
        })}
      >
        <SessionPage />
      </SessionContext.Provider>,
    );

    expect(screen.getByText('Read-only fallback')).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Verify password and rotate' }),
    ).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled();
    expect(
      screen.queryByText(SESSION_ENVELOPE.csrf_token),
    ).not.toBeInTheDocument();
  });
});
