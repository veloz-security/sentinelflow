import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { IncidentDetailAdapter } from '../incidents/incidentDetailModel';
import { MOCK_INCIDENT_SUMMARY } from '../mocks/contractFixtures';
import { MOCK_INCIDENT_DETAIL_STATES } from '../mocks/incidentDetailFixtures';
import { IncidentsPage } from './IncidentsPage';

function renderPage(path: string, adapter?: IncidentDetailAdapter) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/incidents/:incidentId"
          element={<IncidentsPage adapter={adapter} />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe('IncidentsPage', () => {
  it('loads the canonical frozen investigation through the adapter port', async () => {
    renderPage(`/incidents/${MOCK_INCIDENT_SUMMARY.incident_id}`);

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Failed login activity',
      }),
    ).toBeVisible();
    expect(
      screen.getByRole('list', { name: 'Evidence provenance layers' }),
    ).toBeVisible();
  });

  it('maps an unmatched safe identifier to a typed not-found state', async () => {
    renderPage('/incidents/019b0000-0000-7000-8000-000000000999');

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Incident not found',
      }),
    ).toBeVisible();
  });

  it('maps adapter rejection to a safe typed error', async () => {
    const adapter: IncidentDetailAdapter = {
      kind: 'fixture',
      async load() {
        throw new Error('private adapter diagnostic');
      },
    };
    renderPage(`/incidents/${MOCK_INCIDENT_SUMMARY.incident_id}`, adapter);

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Incident detail unavailable',
      }),
    ).toBeVisible();
    expect(
      screen.queryByText('private adapter diagnostic'),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeVisible();
  });

  it('renders a typed permission state supplied by an adapter', async () => {
    const adapter: IncidentDetailAdapter = {
      kind: 'fixture',
      async load() {
        return MOCK_INCIDENT_DETAIL_STATES['permission-denied'];
      },
    };
    renderPage(`/incidents/${MOCK_INCIDENT_SUMMARY.incident_id}`, adapter);

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Incident access required',
      }),
    ).toBeVisible();
  });
});
