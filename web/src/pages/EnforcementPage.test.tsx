import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { EnforcementLifecycleAdapter } from '../enforcement/enforcementLifecycleModel';
import { EnforcementPage } from './EnforcementPage';

describe('EnforcementPage', () => {
  it('loads the fixture adapter without exposing an execution control', async () => {
    render(<EnforcementPage />);
    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Temporary block history',
      }),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Reapply action' }),
    ).toBeDisabled();
  });

  it('maps adapter failures to a safe typed error without leaking details', async () => {
    const adapter: EnforcementLifecycleAdapter = {
      kind: 'fixture',
      async load() {
        throw new Error('private adapter detail');
      },
    };
    render(<EnforcementPage adapter={adapter} />);
    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Enforcement lifecycle unavailable',
      }),
    ).toBeVisible();
    expect(
      screen.queryByText('private adapter detail'),
    ).not.toBeInTheDocument();
  });
});
