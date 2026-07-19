import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { MOCK_HIL_AUTHORIZATION_STATES } from '../mocks/hilAuthorizationFixtures';
import { HilAuthorizationResults } from './HilAuthorizationResults';

describe('HilAuthorizationResults', () => {
  it('separates approval from rejection and shows exact binding evidence', async () => {
    const user = userEvent.setup();
    const onPreviewChallenge = vi.fn();
    const ready = MOCK_HIL_AUTHORIZATION_STATES.ready;
    if (ready.kind !== 'ready') throw new Error('fixture drift');
    render(
      <HilAuthorizationResults
        state={ready}
        onPreviewChallenge={onPreviewChallenge}
      />,
    );

    expect(
      screen.getByRole('heading', { name: 'HIL authorization review' }),
    ).toBeVisible();
    expect(screen.getByText(/Fixture-only preview/)).toBeVisible();
    expect(
      screen.getByRole('radio', { name: /Approve temporary block/ }),
    ).toBeChecked();
    expect(
      screen.getByRole('radio', { name: /Reject this artifact/ }),
    ).not.toBeChecked();
    expect(
      screen.getByText(
        ready.view.validationReview.validation!.canonical_artifact_digest,
      ),
    ).toBeVisible();

    await user.click(
      screen.getByRole('radio', { name: /Reject this artifact/ }),
    );
    await user.click(
      screen.getByRole('button', {
        name: 'Open reject challenge fixture',
      }),
    );
    expect(onPreviewChallenge).toHaveBeenCalledWith('reject');
  });

  it('requires NFC non-empty reason and exact-artifact confirmation', async () => {
    const user = userEvent.setup();
    const onPreviewDecision = vi.fn();
    render(
      <HilAuthorizationResults
        state={MOCK_HIL_AUTHORIZATION_STATES['challenge-issued']}
        onPreviewDecision={onPreviewDecision}
      />,
    );

    const submit = screen.getByRole('button', {
      name: 'Preview approval decision',
    });
    expect(submit).toBeDisabled();
    expect(screen.getByText('Exact binding matches')).toBeVisible();
    expect(screen.getByText('5m 0s')).toBeVisible();

    await user.type(
      screen.getByRole('textbox', { name: 'Decision reason' }),
      '  Cafe\u0301 review  ',
    );
    expect(submit).toBeDisabled();
    await user.click(
      screen.getByRole('checkbox', {
        name: /I confirm the exact approve operation/,
      }),
    );
    expect(submit).toBeEnabled();
    await user.click(submit);

    expect(onPreviewDecision).toHaveBeenCalledTimes(1);
    expect(onPreviewDecision.mock.calls[0]?.[0]).toMatchObject({
      operation: 'approve',
      confirmedExactArtifact: true,
      reason: {
        schema_version: 'hil-reason-v1',
        reason_code: 'threat_confirmed',
        reason_text: 'Café review',
      },
    });
  });

  it('clears the uncontrolled step-up password before invoking the callback', async () => {
    const user = userEvent.setup();
    let inputValueAtCallback = 'not-called';
    render(
      <HilAuthorizationResults
        state={MOCK_HIL_AUTHORIZATION_STATES['step-up-required']}
        onPreviewStepUp={() => {
          inputValueAtCallback = (
            screen.getByLabelText(/Administrator password/) as HTMLInputElement
          ).value;
        }}
      />,
    );

    const password = screen.getByLabelText(
      /Administrator password/,
    ) as HTMLInputElement;
    const ephemeralValue = crypto.randomUUID();
    await user.type(password, ephemeralValue);
    expect(password.value).toBe(ephemeralValue);
    await user.click(
      screen.getByRole('button', {
        name: 'Preview step-up and session rotation',
      }),
    );

    expect(inputValueAtCallback).toBe('');
    expect(password.value).toBe('');
    expect(document.body.textContent).not.toContain(ephemeralValue);
  });

  it.each([
    ['expired', 'Challenge window expired'],
    ['replayed', 'Single-use challenge already consumed'],
    ['stale', 'Policy version changed'],
    ['mutation', 'Exact artifact changed'],
    ['conflict', 'Conflicting decision bytes rejected'],
    ['permission-denied', 'Decision permission required'],
    ['unauthorized', 'Administrator session required'],
    ['rate-limited', 'Decision rate limit reached'],
    ['step-up-failed', 'Authentication was not refreshed'],
  ] as const)('renders %s fail-closed', (stateName, heading) => {
    render(
      <HilAuthorizationResults
        state={MOCK_HIL_AUTHORIZATION_STATES[stateName]}
      />,
    );

    expect(screen.getByRole('heading', { name: heading })).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Decision unavailable' }),
    ).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: /Preview approval decision/ }),
    ).not.toBeInTheDocument();
  });

  it('shows Retry-After without enabling a decision', () => {
    render(
      <HilAuthorizationResults
        state={MOCK_HIL_AUTHORIZATION_STATES['rate-limited']}
      />,
    );
    expect(screen.getByText('Retry-After: 42 seconds')).toBeVisible();
  });

  it.each([
    ['approved', 'Fixture approval recorded', 'Approval preview only'],
    ['rejected', 'Fixture rejection recorded', 'Rejected'],
  ] as const)(
    'renders terminal %s as non-executing',
    (stateName, title, badge) => {
      render(
        <HilAuthorizationResults
          state={MOCK_HIL_AUTHORIZATION_STATES[stateName]}
        />,
      );
      expect(screen.getByRole('heading', { name: title })).toBeVisible();
      expect(screen.getByText(badge)).toBeVisible();
      expect(
        screen.getByText(
          /created no authorized job|creates no firewall authority/,
        ),
      ).toBeVisible();
      expect(
        screen.queryByRole('button', { name: /Preview .* decision/ }),
      ).not.toBeInTheDocument();
    },
  );
});
