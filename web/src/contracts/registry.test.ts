import { describe, expect, it } from 'vitest';
import {
  MOCK_AI_ANALYSIS,
  MOCK_API_ERRORS,
  MOCK_INCIDENT_DETAIL,
  MOCK_LIFECYCLE,
  MOCK_REGISTERED_CONTRACTS,
  MOCK_RESOURCE_STATES,
  MOCK_VALIDATION,
} from '../mocks/contractFixtures';
import { CONTRACT_REGISTRY, decodeApiError, decodeContract } from './registry';
import {
  AI_CLASSIFICATIONS,
  AUTH_EVENT_OUTCOMES,
  DETECTION_CLASSIFICATIONS,
  DETECTION_RULE_IDS,
  EXECUTION_CLASSIFICATIONS,
  EXECUTION_ERROR_CODES,
  EXECUTION_OPERATIONS,
  HIL_DECISIONS,
  HIL_OPERATIONS,
  HIL_REASON_CODES,
  SOURCE_HEALTH_CAUSES,
  SOURCE_HEALTH_DETAIL_CODES,
  SOURCE_HEALTH_STATES,
  SUSPICIOUS_PATH_IDS,
  VALIDATION_CHECK_IDS,
} from './rootContracts';
import { ROOT_CONTRACT_ENUM_SNAPSHOT } from './schemas';

describe('frontend contract registry', () => {
  it('accepts every deterministic registered fixture', () => {
    for (const fixture of MOCK_REGISTERED_CONTRACTS) {
      const result = decodeContract(fixture);
      expect(result, fixture.schema_version).toMatchObject({ ok: true });
    }
  });

  it('keeps root contract provenance explicit', () => {
    const rootEntries = Object.values(CONTRACT_REGISTRY).filter(
      (entry) => entry.ownership === 'root-contract',
    );

    expect(rootEntries.length).toBeGreaterThan(0);
    expect(
      rootEntries.every((entry) => entry.source.startsWith('contracts/')),
    ).toBe(true);
  });

  it('keeps frontend enum types byte-equal to checked-in root schemas', () => {
    const localEnums = {
      suspiciousPathIds: SUSPICIOUS_PATH_IDS,
      authEventOutcomes: AUTH_EVENT_OUTCOMES,
      sourceHealthCauses: SOURCE_HEALTH_CAUSES,
      sourceHealthStates: SOURCE_HEALTH_STATES,
      sourceHealthDetailCodes: SOURCE_HEALTH_DETAIL_CODES,
      detectionRuleIds: DETECTION_RULE_IDS,
      detectionClassifications: DETECTION_CLASSIFICATIONS,
      aiClassifications: AI_CLASSIFICATIONS,
      validationCheckIds: VALIDATION_CHECK_IDS,
      hilOperations: HIL_OPERATIONS,
      hilDecisions: HIL_DECISIONS,
      hilReasonCodes: HIL_REASON_CODES,
      executionOperations: EXECUTION_OPERATIONS,
      executionClassifications: EXECUTION_CLASSIFICATIONS,
      executionErrorCodes: EXECUTION_ERROR_CODES,
    };

    expect(localEnums).toEqual(ROOT_CONTRACT_ENUM_SNAPSHOT);
  });

  it('rejects unknown schema versions before interpretation', () => {
    const result = decodeContract({
      ...MOCK_INCIDENT_DETAIL,
      schema_version: 'incident-detail-v2',
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'unknown_schema_version',
      schemaVersion: 'incident-detail-v2',
    });
  });

  it('rejects unknown enums and additional fields', () => {
    const unknownState = decodeContract({
      ...MOCK_LIFECYCLE,
      state: 'paused',
    });
    const extraField = decodeContract({
      ...MOCK_LIFECYCLE,
      raw_command: 'must-not-enter-the-frontend-contract',
    });

    expect(unknownState).toMatchObject({
      ok: false,
      reason: 'shape_or_enum_mismatch',
    });
    expect(extraField).toMatchObject({
      ok: false,
      reason: 'shape_or_enum_mismatch',
    });
  });

  it('rejects reordered validation gates', () => {
    const result = decodeContract({
      ...MOCK_VALIDATION,
      checks: [...MOCK_VALIDATION.checks].reverse(),
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'shape_or_enum_mismatch',
      issues: [{ keyword: 'contractInvariant' }],
    });
  });

  it('rejects AI evidence arrays that are not byte-identical', () => {
    const result = decodeContract({
      ...MOCK_AI_ANALYSIS,
      policy: {
        ...MOCK_AI_ANALYSIS.policy,
        evidence_ids: ['019b0000-0000-7000-8000-000000000999'],
      },
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'shape_or_enum_mismatch',
      issues: [{ keyword: 'contractInvariant' }],
    });
  });

  it('validates exact typed API error envelopes', () => {
    const decoded = decodeApiError({
      ...MOCK_API_ERRORS.permissionDenied,
      details: { retryable: false },
    });
    expect(decoded).toMatchObject({
      ok: true,
    });
    if (decoded.ok) {
      expect(Object.isFrozen(decoded.value)).toBe(true);
      expect(Object.isFrozen(decoded.value.details)).toBe(true);
    }
    expect(
      decodeApiError({
        ...MOCK_API_ERRORS.permissionDenied,
        code: 'new_unreviewed_error',
      }),
    ).toMatchObject({ ok: false, reason: 'shape_or_enum_mismatch' });
  });

  it('deep-freezes contract and resource-state fixtures', () => {
    expect(Object.isFrozen(MOCK_INCIDENT_DETAIL)).toBe(true);
    expect(Object.isFrozen(MOCK_INCIDENT_DETAIL.gateway_events)).toBe(true);
    expect(Object.isFrozen(MOCK_INCIDENT_DETAIL.validation?.checks)).toBe(true);
    expect(Object.isFrozen(MOCK_RESOURCE_STATES.success)).toBe(true);
  });
});
