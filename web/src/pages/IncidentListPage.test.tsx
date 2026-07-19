import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { IncidentListPage } from './IncidentListPage';

function LocationProbe() {
  const location = useLocation();
  return <output aria-label="Current search">{location.search}</output>;
}

function renderPage(initialEntry = '/incidents') {
  render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route
          path="/incidents"
          element={
            <>
              <IncidentListPage />
              <LocationProbe />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe('IncidentListPage', () => {
  it('writes applied filters to the URL and clears the cursor', async () => {
    const user = userEvent.setup();
    renderPage('/incidents?cursor=fixture-cursor-v1%3A4');
    await screen.findByText('5–8 of 8');

    const source = screen.getByRole('textbox', {
      name: 'Canonical source IPv4',
    });
    await user.type(source, '203.0.113.20');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));

    await waitFor(() =>
      expect(screen.getByLabelText('Current search')).toHaveTextContent(
        '?source=203.0.113.20',
      ),
    );
    expect(screen.getByLabelText('Current search')).not.toHaveTextContent(
      'cursor=',
    );
  });

  it('moves through pages using only the adapter cursor', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('1–4 of 8');

    await user.click(screen.getByRole('button', { name: 'Next' }));

    await screen.findByText('5–8 of 8');
    expect(screen.getByLabelText('Current search')).toHaveTextContent(
      'cursor=fixture-cursor-v1%3A4',
    );
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeEnabled();
  });
});
