import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { App } from './App';

describe('App', () => {
  it('renders the operations overview without a backend', async () => {
    render(
      <MemoryRouter initialEntries={['/fixtures']}>
        <App />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole(
        'heading',
        {
          name: 'Review queue',
        },
        { timeout: 5_000 },
      ),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Approve exact artifact' }),
    ).toBeDisabled();
  });

  it('navigates to every presentation state', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={['/fixtures']}>
        <App />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole('link', { name: 'State library' }));

    expect(
      await screen.findByRole(
        'heading',
        {
          name: 'Presentation state library',
        },
        { timeout: 5_000 },
      ),
    ).toBeVisible();
    expect(screen.getByText('Permission required')).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Approve action' }),
    ).toBeDisabled();
  });

  it.each([
    ['/fixtures/incidents', 'Incidents'],
    [
      '/fixtures/incidents/019b0000-0000-7000-8000-000000000601',
      'Failed login activity',
    ],
    ['/fixtures/validation', 'Validation review'],
    ['/fixtures/authorization', 'HIL authorization review'],
    ['/fixtures/enforcement', 'Temporary block history'],
    ['/states/enforcement/active', 'Temporary block history'],
  ])('renders the %s fixture route', async (path, heading) => {
    render(
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole(
        'heading',
        { level: 1, name: heading },
        { timeout: 5_000 },
      ),
    ).toBeVisible();
  });
});
