import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { HilAuthorizationAdapter } from '../hil/hilAuthorizationModel';
import { MOCK_HIL_AUTHORIZATION_STATES } from '../mocks/hilAuthorizationFixtures';
import { HilAuthorizationPage } from './HilAuthorizationPage';

describe('HilAuthorizationPage', () => {
  it('walks the fixture approve flow through the abort-aware boundary', async () => {
    const user = userEvent.setup();
    render(<HilAuthorizationPage />);

    expect(
      await screen.findByRole('heading', { name: 'HIL authorization review' }),
    ).toBeVisible();
    await user.click(
      screen.getByRole('button', {
        name: 'Open approve challenge fixture',
      }),
    );
    expect(await screen.findByText('Exact binding matches')).toBeVisible();

    await user.type(
      screen.getByRole('textbox', { name: 'Decision reason' }),
      'Reviewed evidence.',
    );
    await user.click(
      screen.getByRole('checkbox', {
        name: /I confirm the exact approve operation/,
      }),
    );
    await user.click(
      screen.getByRole('button', { name: 'Preview approval decision' }),
    );

    expect(
      await screen.findByRole('heading', { name: 'Fixture approval recorded' }),
    ).toBeVisible();
    expect(screen.getByText(/created no authorized job/)).toBeVisible();
  });

  it('maps an adapter failure to a safe exact-artifact mismatch state', async () => {
    const adapter: HilAuthorizationAdapter = {
      kind: 'fixture',
      async load() {
        throw new Error('private adapter detail');
      },
      async previewChallenge() {
        return MOCK_HIL_AUTHORIZATION_STATES.mutation;
      },
      async previewStepUp() {
        return MOCK_HIL_AUTHORIZATION_STATES.mutation;
      },
      async previewDecision() {
        return MOCK_HIL_AUTHORIZATION_STATES.mutation;
      },
    };
    render(<HilAuthorizationPage adapter={adapter} />);

    expect(
      await screen.findByRole('heading', { name: 'Exact artifact changed' }),
    ).toBeVisible();
    expect(
      screen.queryByText('private adapter detail'),
    ).not.toBeInTheDocument();
  });
});
