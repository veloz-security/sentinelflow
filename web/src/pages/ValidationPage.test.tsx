import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ValidationReviewAdapter } from '../validation/validationReviewModel';
import { MOCK_VALIDATION_REVIEW_STATES } from '../mocks/validationReviewFixtures';
import { ValidationPage } from './ValidationPage';

describe('ValidationPage', () => {
  it('loads the ready fixture through the frontend adapter port', async () => {
    render(<ValidationPage />);

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Validation review',
      }),
    ).toBeVisible();
    expect(
      screen.getByRole('list', { name: 'Five ordered validation results' }),
    ).toBeVisible();
  });

  it('renders a typed permission state supplied by the adapter', async () => {
    const adapter: ValidationReviewAdapter = {
      kind: 'fixture',
      async load() {
        return MOCK_VALIDATION_REVIEW_STATES['permission-denied'];
      },
    };
    render(<ValidationPage adapter={adapter} />);

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Validation access required',
      }),
    ).toBeVisible();
    expect(screen.getByRole('alert')).toBeVisible();
  });

  it('maps an adapter rejection to a safe failed presentation', async () => {
    const adapter: ValidationReviewAdapter = {
      kind: 'fixture',
      async load() {
        throw new Error('private adapter detail');
      },
    };
    render(<ValidationPage adapter={adapter} />);

    expect(
      await screen.findByText(
        'An ordered hard gate failed. Later results are blocked and no snapshot was produced.',
      ),
    ).toBeVisible();
    expect(
      screen.queryByText('private adapter detail'),
    ).not.toBeInTheDocument();
  });
});
