import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  MOCK_ANALYSIS_FAILED_INVESTIGATION,
  MOCK_COMPLETE_INVESTIGATION,
  MOCK_DEGRADED_INVESTIGATION,
} from '../mocks/incidentDetailFixtures';
import { IncidentEvidenceLayers } from './IncidentEvidenceLayers';

describe('IncidentEvidenceLayers', () => {
  it('keeps observed facts, rule output, and AI interpretation separate', () => {
    render(<IncidentEvidenceLayers view={MOCK_COMPLETE_INVESTIGATION} />);

    const layers = screen.getByRole('list', {
      name: 'Evidence provenance layers',
    });
    expect(layers).toBeVisible();
    expect(layers.children).toHaveLength(3);
    expect(
      screen.getByRole('heading', { name: 'Observed facts' }),
    ).toBeVisible();
    expect(
      screen.getByRole('heading', { name: 'Deterministic signals' }),
    ).toBeVisible();
    expect(
      screen.getByRole('heading', { name: 'AI interpretation' }),
    ).toBeVisible();
    expect(screen.getByText('Direct-peer provenance')).toBeVisible();
    expect(screen.getByText('Binding verified')).toBeVisible();
    expect(screen.getAllByText('019b0000…000603')).toHaveLength(2);
    expect(screen.getAllByText('019b0000…000604')).toHaveLength(2);
    expect(screen.getByText('gpt-5.6-sol')).toBeVisible();
    expect(screen.getByText('sentinelflow_system_prompt_v1')).toBeVisible();
    expect(screen.getByText('sha256:77777777…77777777')).toBeVisible();
  });

  it('never renders the synthetic account relation material', () => {
    render(<IncidentEvidenceLayers view={MOCK_COMPLETE_INVESTIGATION} />);

    expect(screen.queryByText(/^hmac-sha256:/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/aaaaaaaaaaaaaaaa/i)).not.toBeInTheDocument();
  });

  it.each([
    ['degraded', MOCK_DEGRADED_INVESTIGATION],
    ['analysis failed', MOCK_ANALYSIS_FAILED_INVESTIGATION],
  ])('preserves deterministic evidence when analysis is %s', (_, view) => {
    render(<IncidentEvidenceLayers view={view} />);

    expect(
      screen.getByRole('heading', {
        name: 'Deterministic evidence remains available',
      }),
    ).toBeVisible();
    expect(screen.getByText('Analysis unavailable')).toBeVisible();
    expect(screen.queryByText('Analysis provenance')).not.toBeInTheDocument();
  });
});
