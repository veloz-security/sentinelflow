import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { MOCK_INCIDENT_SUMMARY } from '../mocks/contractFixtures';
import { MOCK_INCIDENT_LIST_STATES } from '../mocks/incidentListStates';
import { IncidentListResults } from './IncidentListResults';

function renderState(state: keyof typeof MOCK_INCIDENT_LIST_STATES) {
  render(
    <MemoryRouter>
      <IncidentListResults
        state={MOCK_INCIDENT_LIST_STATES[state]}
        detailFixtureId={MOCK_INCIDENT_SUMMARY.incident_id}
      />
    </MemoryRouter>,
  );
}

describe('IncidentListResults', () => {
  it('renders a populated dense table and narrow list from the same records', () => {
    renderState('populated');

    expect(
      screen.getByRole('heading', { name: 'Result summary' }),
    ).toBeVisible();
    expect(
      screen.getByRole('table', { name: 'Filtered incidents' }),
    ).toBeVisible();
    expect(
      screen.getByRole('list', { name: 'Filtered incidents' }),
    ).toBeVisible();
    expect(screen.getAllByText('203.0.113.20').length).toBeGreaterThan(0);
    expect(
      screen.getAllByRole('link', { name: /Open fixture detail/ }).length,
    ).toBeGreaterThan(0);
  });

  it.each([
    ['loading', 'Loading incidents', 'status'],
    ['empty', 'No incidents match these filters', 'status'],
    ['error', 'Incident list unavailable', 'alert'],
    ['permission-denied', 'Incident access required', 'alert'],
  ] as const)(
    'renders the %s state with its semantic role',
    (state, heading, role) => {
      renderState(state);

      expect(screen.getByRole('heading', { name: heading })).toBeVisible();
      expect(screen.getByRole(role)).toBeVisible();
    },
  );
});
