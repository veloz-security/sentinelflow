import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import {
  INCIDENT_DETAIL_STATE_NAMES,
  MOCK_INCIDENT_DETAIL_STATES,
  type IncidentDetailStateName,
} from '../mocks/incidentDetailFixtures';
import { IncidentDetailResults } from './IncidentDetailResults';

const headings: Readonly<Record<IncidentDetailStateName, string>> = {
  loading: 'Loading incident detail',
  unknown: 'Incident state unknown',
  'not-found': 'Incident not found',
  error: 'Incident detail unavailable',
  'permission-denied': 'Incident access required',
  degraded: 'Failed login activity',
  'analysis-failed': 'Failed login activity',
  complete: 'Failed login activity',
};

function renderState(state: IncidentDetailStateName, onRetry = vi.fn()) {
  render(
    <MemoryRouter>
      <IncidentDetailResults
        state={MOCK_INCIDENT_DETAIL_STATES[state]}
        onRetry={onRetry}
      />
    </MemoryRouter>,
  );
  return onRetry;
}

describe('IncidentDetailResults', () => {
  it.each(INCIDENT_DETAIL_STATE_NAMES)(
    'renders the %s state with one page heading',
    (state) => {
      renderState(state);

      expect(
        screen.getByRole('heading', { level: 1, name: headings[state] }),
      ).toBeVisible();
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
      expect(
        screen.getByRole('link', { name: 'Back to incidents' }),
      ).toHaveAttribute('href', '/fixtures/incidents');
    },
  );

  it('makes incomplete source coverage explicit', () => {
    renderState('degraded');

    expect(screen.getByRole('alert')).toHaveTextContent('sequence gap 42–45');
    expect(screen.getByText('Dropped records').parentElement).toHaveTextContent(
      '4',
    );
    expect(screen.getByText(/still open/)).toBeVisible();
  });

  it('keeps model failure distinct from deterministic evidence', () => {
    renderState('analysis-failed');

    expect(screen.getByRole('alert')).toHaveTextContent('timeout');
    expect(
      screen.getByRole('heading', {
        name: 'Deterministic evidence remains available',
      }),
    ).toBeVisible();
  });

  it('exposes a typed retry control only for the generic error state', async () => {
    const onRetry = renderState('error');
    const retry = screen.getByRole('button', {
      name: 'Retry incident detail',
    });

    retry.click();
    expect(onRetry).toHaveBeenCalledOnce();
  });
});
