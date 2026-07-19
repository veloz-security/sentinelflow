import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { decodePolicyDetail } from './contracts';
import {
  INTERRUPTED_VALIDATION_ATTEMPT,
  INVALID_VALIDATION_ATTEMPT,
  POLICY_DETAIL,
} from './liveTestFixtures';
import { policyDecisionReadiness } from './policyHil';
import { PolicyValidationEvidence } from './ReviewPages';

function policyWithAttempt(attempt: unknown) {
  const value = structuredClone(POLICY_DETAIL) as Record<string, unknown>;
  delete value.latest_validation;
  value.state = 'invalid';
  value.latest_validation_attempt = attempt;
  return decodePolicyDetail(value);
}

describe('policy validation-attempt evidence', () => {
  it('renders an invalid history-binding attempt as inert fail-closed evidence', () => {
    const policy = policyWithAttempt(
      structuredClone(INVALID_VALIDATION_ATTEMPT),
    );
    render(<PolicyValidationEvidence policy={policy} />);

    expect(
      screen.getByRole('heading', { name: 'Fail-closed validation attempt' }),
    ).toBeVisible();
    expect(
      screen.queryByText('No validation snapshot'),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('Failure history_demo_binding_mismatch'),
    ).toBeVisible();
    expect(screen.getByText('historical_impact')).toBeVisible();
    expect(
      screen.getByText(INVALID_VALIDATION_ATTEMPT.prepared_snapshot_digest),
    ).toBeVisible();
    expect(
      screen.getByText(INVALID_VALIDATION_ATTEMPT.terminal_mutation_digest),
    ).toBeVisible();

    const gateHeading = screen.getByRole('heading', {
      name: 'Ordered attempt gates',
    });
    const gateRegion = gateHeading.parentElement;
    expect(gateRegion).not.toBeNull();
    expect(
      within(gateRegion as HTMLElement).getByText('6. historical_impact'),
    ).toBeVisible();
    expect(screen.getAllByText('Passed')).toHaveLength(5);
    expect(screen.getByText('Failed')).toBeVisible();
    expect(policyDecisionReadiness(policy, true).ready).toBe(false);
  });

  it('never hides terminal fail-closed evidence behind a contradictory snapshot', () => {
    const valid = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    const invalid = policyWithAttempt(
      structuredClone(INVALID_VALIDATION_ATTEMPT),
    );
    render(
      <PolicyValidationEvidence
        policy={{
          ...valid,
          latest_validation_attempt: invalid.latest_validation_attempt,
        }}
      />,
    );

    expect(
      screen.getByRole('heading', { name: 'Fail-closed validation attempt' }),
    ).toBeVisible();
    expect(
      screen.getByText('Failure history_demo_binding_mismatch'),
    ).toBeVisible();
    expect(screen.queryByText('Source complete')).not.toBeInTheDocument();
  });

  it('renders interrupted prefix evidence without inventing a failed gate or terminal mutation', () => {
    const policy = policyWithAttempt(
      structuredClone(INTERRUPTED_VALIDATION_ATTEMPT),
    );
    render(<PolicyValidationEvidence policy={policy} />);

    expect(
      screen.getByText('Failure validation_attempt_timeout'),
    ).toBeVisible();
    expect(screen.getByText('none')).toBeVisible();
    expect(screen.getByText('not produced')).toBeVisible();
    expect(screen.getAllByText('Passed')).toHaveLength(3);
    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
  });

  it('preserves the authorizing validation snapshot presentation', () => {
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    render(<PolicyValidationEvidence policy={policy} />);

    expect(
      screen.queryByText('Fail-closed validation attempt'),
    ).not.toBeInTheDocument();
    expect(screen.getByText('Source complete')).toBeVisible();
    expect(screen.getAllByText('Passed')).toHaveLength(6);
    expect(
      screen.getByText(POLICY_DETAIL.latest_validation.snapshot_digest),
    ).toBeVisible();
  });
});
