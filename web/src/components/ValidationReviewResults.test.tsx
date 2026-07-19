import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  MOCK_SIGNED_DEMO_HISTORY_FIXTURE,
  MOCK_VALIDATION_REVIEW_STATES,
  VALIDATION_REVIEW_STATE_NAMES,
  type ValidationReviewStateName,
} from '../mocks/validationReviewFixtures';
import { ValidationReviewResults } from './ValidationReviewResults';

const headings: Readonly<Record<ValidationReviewStateName, string>> = {
  loading: 'Loading validation review',
  missing: 'Validation review missing',
  gapped: 'Validation review',
  unsigned: 'Validation review',
  failed: 'Validation review',
  mismatch: 'Validation review',
  stale: 'Validation review',
  expired: 'Validation review',
  'permission-denied': 'Validation access required',
  ready: 'Validation review',
};

function renderState(name: ValidationReviewStateName) {
  render(
    <ValidationReviewResults state={MOCK_VALIDATION_REVIEW_STATES[name]} />,
  );
}

describe('ValidationReviewResults', () => {
  it.each(VALIDATION_REVIEW_STATE_NAMES)(
    'renders one page heading for the %s state',
    (state) => {
      renderState(state);

      expect(
        screen.getByRole('heading', { level: 1, name: headings[state] }),
      ).toBeVisible();
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    },
  );

  it('renders exactly five ordered results with consistency before protection', () => {
    renderState('ready');
    const results = screen.getByRole('list', {
      name: 'Five ordered validation results',
    });
    const items = within(results).getAllByRole('listitem');

    expect(items).toHaveLength(5);
    expect(items[0]).toHaveTextContent('Schema, grammar, and canonicalization');
    expect(items[1]).toHaveTextContent(
      'Policy, evidence, and command consistency',
    );
    expect(items[2]).toHaveTextContent('Protected target');
    expect(items[4]).toHaveTextContent('Historical impact');
  });

  it('shows explicit TTL equality and inert command provenance', () => {
    renderState('ready');

    expect(
      screen.getByText('1800 seconds = 30m = 1800 seconds.'),
    ).toBeVisible();
    expect(
      screen.getByRole('region', { name: 'Generated candidate' }),
    ).toHaveTextContent('timeout 1800s');
    expect(
      screen.getByRole('region', { name: 'Canonical artifact' }),
    ).toHaveTextContent('timeout 30m');
    expect(
      screen.getByText(/Nothing in this panel is sent to a shell/),
    ).toBeVisible();
  });

  it('shows source, history, protected, owned-schema, impact, and validity proof', () => {
    renderState('ready');

    expect(screen.getByText('Gateway complete')).toBeVisible();
    expect(screen.getByText('Auth complete')).toBeVisible();
    expect(screen.getByText('History verified')).toBeVisible();
    expect(screen.getByText('4m 0s remaining')).toBeVisible();
    expect(
      screen.getByText('of the fixed 5m 0s validation window'),
    ).toBeVisible();
    for (const label of [
      'Protected IPv4 static',
      'Protected IPv4 effective',
      'Owned base-chain raw',
      'Owned live structure',
    ]) {
      expect(screen.getByText(label)).toBeVisible();
    }
    expect(
      screen.getByText('Verified successful authentication seen'),
    ).toBeVisible();
  });

  it('never renders signature bytes or public key material as authority', () => {
    renderState('ready');

    expect(
      screen.queryByText(MOCK_SIGNED_DEMO_HISTORY_FIXTURE.signature_b64url),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(MOCK_SIGNED_DEMO_HISTORY_FIXTURE.public_key_b64url),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', {
        name: 'No authorization control in this view',
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole('heading', {
        name: 'Authorization is a separate surface',
      }),
    ).toBeVisible();
    expect(
      screen.getByText(/Server-side exact-artifact authorization exists/),
    ).toBeVisible();
    expect(
      screen.queryByText(/server authorization is not implemented/i),
    ).not.toBeInTheDocument();
  });

  it.each([
    ['gapped', 'Unresolved sequence range 42–45'],
    ['unsigned', 'Demo-history signature verification is absent'],
    ['failed', 'An ordered hard gate failed'],
    ['mismatch', '1800 seconds ≠ 29m (1740 seconds).'],
    ['stale', 'A dependent evidence version changed'],
    ['expired', 'The fixed five-minute validation window elapsed'],
  ] as const)('makes the %s state fail-closed', (state, message) => {
    renderState(state);

    expect(
      screen.getByText(
        new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      ),
    ).toBeVisible();
    expect(
      screen.getByRole('button', {
        name: 'No authorization control in this view',
      }),
    ).toBeDisabled();
  });

  it('uses semantic loading, missing, and permission feedback', () => {
    const { unmount } = render(
      <ValidationReviewResults state={MOCK_VALIDATION_REVIEW_STATES.loading} />,
    );
    expect(
      screen.getByRole('status', { name: 'Loading validation review' }),
    ).toHaveAttribute('aria-busy', 'true');
    unmount();

    renderState('missing');
    expect(screen.getByRole('status')).toBeVisible();
  });
});
