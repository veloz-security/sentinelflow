import { act, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useServerSampleCountdown } from '../enforcement/useServerSampleCountdown';
import { MOCK_ENFORCEMENT_LIFECYCLE_STATES } from '../mocks/enforcementLifecycleFixtures';
import { EnforcementLifecycleResults } from './EnforcementLifecycleResults';

describe('EnforcementLifecycleResults', () => {
  afterEach(() => vi.useRealTimers());

  it('renders active add and inspect evidence with inert authority boundaries', () => {
    const { container } = render(
      <EnforcementLifecycleResults
        state={MOCK_ENFORCEMENT_LIFECYCLE_STATES.active}
      />,
    );

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Temporary block history',
      }),
    ).toBeVisible();
    expect(screen.getByText(/Fixture-only lifecycle evidence/)).toBeVisible();

    const operations = screen.getByRole('list', {
      name: 'Enforcement operation history',
    });
    expect(within(operations).getAllByRole('listitem')).toHaveLength(2);
    expect(
      within(operations).getByText('Shell-free temporary add'),
    ).toBeVisible();
    expect(within(operations).getByText('Read-only inspect')).toBeVisible();
    expect(
      within(operations).getByText(/separately signed, typed operation/),
    ).toBeVisible();
    expect(screen.getByText('Automatic re-add: disabled')).toBeVisible();
    expect(screen.getByText('TTL refresh: disabled')).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Reapply action' }),
    ).toBeDisabled();
    expect(screen.getByText('Observed fact')).toBeVisible();
    expect(screen.getByText('Deterministic rule')).toBeVisible();
    expect(screen.getByText('AI generated')).toBeVisible();
    expect(screen.getByText('Canonicalized artifact')).toBeVisible();
    expect(screen.getAllByText('Human decision').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Dispatcher').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Executor result').length).toBeGreaterThan(0);
    expect(screen.getByText('Recovery')).toBeVisible();
    expect(container.textContent).not.toContain('signature_b64url');
    expect(container.textContent).not.toContain('private_key');
  });

  it('renders the complete add, inspect, and revoke operation history', () => {
    render(
      <EnforcementLifecycleResults
        state={MOCK_ENFORCEMENT_LIFECYCLE_STATES.revoked}
      />,
    );
    const operations = screen.getByRole('list', {
      name: 'Enforcement operation history',
    });
    expect(within(operations).getAllByRole('listitem')).toHaveLength(3);
    expect(within(operations).getByText('Deterministic revoke')).toBeVisible();
    expect(screen.getByText('Human revoke decision bound')).toBeVisible();
    expect(screen.getByText('Executor revoke result verified')).toBeVisible();
  });

  it.each([
    ['loading', 'Loading enforcement lifecycle'],
    ['empty', 'No enforcement lifecycle'],
    ['error', 'Enforcement lifecycle unavailable'],
    ['permission-denied', 'Enforcement access required'],
  ] as const)('renders the %s resource state', (stateName, heading) => {
    render(
      <EnforcementLifecycleResults
        state={MOCK_ENFORCEMENT_LIFECYCLE_STATES[stateName]}
      />,
    );
    expect(
      screen.getByRole('heading', { level: 1, name: heading }),
    ).toBeVisible();
  });

  it.each([
    ['pending', 'Pending result'],
    ['applied', 'applied'],
    ['expired', 'inspect absent'],
    ['failed', 'failed'],
    ['indeterminate', 'indeterminate'],
    ['recovered-active', 'Recovery remained read-only'],
    ['torn-journal', 'missing terminal'],
    ['corrupt-journal', 'checksum failed'],
  ] as const)('renders the %s lifecycle fixture', (stateName, evidence) => {
    render(
      <EnforcementLifecycleResults
        state={MOCK_ENFORCEMENT_LIFECYCLE_STATES[stateName]}
      />,
    );
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Temporary block history',
      }),
    ).toBeVisible();
    expect(screen.getAllByText(evidence).length).toBeGreaterThan(0);
  });

  it('counts down only from the server sample and stops at zero', () => {
    vi.useFakeTimers();
    function CountdownProbe() {
      return <output>{useServerSampleCountdown(2)}</output>;
    }
    render(<CountdownProbe />);
    expect(screen.getByText('2')).toBeVisible();
    act(() => vi.advanceTimersByTime(1_000));
    expect(screen.getByText('1')).toBeVisible();
    act(() => vi.advanceTimersByTime(5_000));
    expect(screen.getByText('0')).toBeVisible();
  });
});
