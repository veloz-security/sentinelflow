import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_INCIDENT_LIST_FILTERS } from '../incidents/incidentListSearch';
import { IncidentFilterBar } from './IncidentFilterBar';

describe('IncidentFilterBar', () => {
  it('rejects non-canonical source input and submits a canonical value', async () => {
    const user = userEvent.setup();
    const onApply = vi.fn();
    render(
      <IncidentFilterBar
        filters={DEFAULT_INCIDENT_LIST_FILTERS}
        services={['demo-app']}
        onApply={onApply}
        onReset={vi.fn()}
      />,
    );

    const source = screen.getByRole('textbox', {
      name: 'Canonical source IPv4',
    });
    const apply = screen.getByRole('button', { name: 'Apply filters' });

    await user.type(source, '203.000.113.20');
    expect(apply).toBeDisabled();
    expect(
      screen.getByText(
        'Use one canonical IPv4 address without leading zeroes.',
      ),
    ).toBeVisible();

    await user.clear(source);
    await user.type(source, '203.0.113.20');
    await user.click(apply);

    expect(onApply).toHaveBeenCalledWith({
      ...DEFAULT_INCIDENT_LIST_FILTERS,
      sourceIp: '203.0.113.20',
    });
  });
});
