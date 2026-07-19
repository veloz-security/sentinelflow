import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  MOCK_PRESENTATION_STATES,
  PRESENTATION_STATE_ORDER,
} from '../mocks/presentationStates';
import { PresentationState } from './PresentationState';

describe('PresentationState', () => {
  it.each(PRESENTATION_STATE_ORDER)('renders the %s mock contract', (kind) => {
    const state = MOCK_PRESENTATION_STATES[kind];

    render(<PresentationState state={state} />);

    expect(screen.getByRole('heading', { name: state.title })).toBeVisible();
    expect(screen.getByText(state.message)).toBeVisible();
    expect(screen.getByText(state.detail ?? '')).toBeVisible();
  });

  it('exposes an accessible skeleton loading state', () => {
    render(<PresentationState state={MOCK_PRESENTATION_STATES.loading} />);

    expect(
      screen.getByRole('status', { name: 'Loading typed investigation' }),
    ).toHaveAttribute('aria-busy', 'true');
  });

  it('keeps the disabled mock action inoperable', () => {
    render(
      <PresentationState
        state={MOCK_PRESENTATION_STATES.disabled}
        onAction={() => undefined}
      />,
    );

    expect(
      screen.getByRole('button', { name: 'Approve action' }),
    ).toBeDisabled();
  });
});
