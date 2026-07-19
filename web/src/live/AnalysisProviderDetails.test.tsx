import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  OPENAI_ANALYSIS_SUMMARY,
  STUB_ANALYSIS_SUMMARY,
} from './liveTestFixtures';
import { AnalysisProviderDetails } from './AnalysisProviderDetails';

describe('AnalysisProviderDetails', () => {
  it('shows exact OpenAI Responses provenance', () => {
    render(<AnalysisProviderDetails analysis={OPENAI_ANALYSIS_SUMMARY} />);
    const region = screen.getByRole('region', {
      name: 'Analysis provider provenance',
    });

    expect(within(region).getAllByText('OpenAI Responses API')).toHaveLength(2);
    expect(within(region).getByText('openai-responses-v1')).toBeVisible();
    expect(within(region).getByText('gpt-5.6-sol')).toBeVisible();
    expect(within(region).getByText('medium')).toBeVisible();
    expect(within(region).getByText('openai-demo-2026-07-18')).toBeVisible();
  });

  it('shows only deterministic offline provenance for the stub', () => {
    render(<AnalysisProviderDetails analysis={STUB_ANALYSIS_SUMMARY} />);
    const region = screen.getByRole('region', {
      name: 'Analysis provider provenance',
    });

    expect(
      within(region).getAllByText('Deterministic offline stub'),
    ).toHaveLength(2);
    expect(
      within(region).getByText('sentinelflow-deterministic-ai-stub-v1'),
    ).toBeVisible();
    expect(
      within(region).getByText('Offline deterministic adapter'),
    ).toBeVisible();
    for (const forbidden of [
      'gpt-5.6-sol',
      'medium',
      'openai-demo-2026-07-18',
      'Rate card',
      'Model',
      'Token cost',
    ]) {
      expect(within(region).queryByText(forbidden)).not.toBeInTheDocument();
    }
  });
});
