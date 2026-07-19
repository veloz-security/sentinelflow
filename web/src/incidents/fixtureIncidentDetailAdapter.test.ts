import { describe, expect, it } from 'vitest';
import { decodeContract } from '../contracts/registry';
import {
  MOCK_ANALYSIS_FAILED_INVESTIGATION,
  MOCK_COMPLETE_INVESTIGATION,
  MOCK_DEGRADED_INVESTIGATION,
  MOCK_INCIDENT_DETAIL_STATES,
} from '../mocks/incidentDetailFixtures';
import { fixtureIncidentDetailAdapter } from './fixtureIncidentDetailAdapter';

const forbiddenKeys = new Set([
  'path',
  'raw_path',
  'decoded_path',
  'exact_path',
  'query',
  'query_string',
  'body',
  'request_body',
  'response_body',
  'cookie',
  'cookies',
  'authorization',
  'headers',
  'raw_headers',
  'account_name',
  'username',
  'password',
]);

const forbiddenValuePatterns = [
  { label: 'absolute request target', pattern: /^\/(?!\/)/ },
  { label: 'encoded request target', pattern: /%2f/i },
  { label: 'query parameter', pattern: /(?:\?|&)[a-z0-9_.~-]+=/i },
  { label: 'authorization value', pattern: /\bbearer\s+[a-z0-9._~-]+/i },
  { label: 'authorization header', pattern: /authorization\s*:/i },
  { label: 'cookie header', pattern: /cookie\s*:/i },
  { label: 'credential assignment', pattern: /password\s*=/i },
] as const;

function expectPrivacyMinimized(value: unknown): void {
  if (typeof value === 'string') {
    for (const forbidden of forbiddenValuePatterns) {
      expect(
        forbidden.pattern.test(value),
        `${forbidden.label} entered a detail fixture: ${value}`,
      ).toBe(false);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(expectPrivacyMinimized);
    return;
  }
  if (typeof value !== 'object' || value === null) return;

  for (const [key, child] of Object.entries(value)) {
    expect(
      forbiddenKeys.has(key.toLowerCase()),
      `forbidden field entered a detail fixture: ${key}`,
    ).toBe(false);
    expectPrivacyMinimized(child);
  }
}

describe('fixture incident detail adapter', () => {
  it('resolves only the canonical frozen investigation', async () => {
    const incidentId = MOCK_COMPLETE_INVESTIGATION.detail.incident.incident_id;

    await expect(
      fixtureIncidentDetailAdapter.load(incidentId),
    ).resolves.toEqual(MOCK_INCIDENT_DETAIL_STATES.complete);
    await expect(
      fixtureIncidentDetailAdapter.load('019b0000-0000-7000-8000-000000000999'),
    ).resolves.toEqual(MOCK_INCIDENT_DETAIL_STATES['not-found']);
  });

  it('keeps auth evidence on its checked root contract boundary', () => {
    for (const auth of MOCK_COMPLETE_INVESTIGATION.authEvidence) {
      expect(decodeContract(auth.event)).toMatchObject({ ok: true });
    }
  });

  it('recursively excludes forbidden request fields and values', () => {
    for (const fixture of [
      MOCK_COMPLETE_INVESTIGATION,
      MOCK_DEGRADED_INVESTIGATION,
      MOCK_ANALYSIS_FAILED_INVESTIGATION,
    ]) {
      expectPrivacyMinimized(fixture);
    }
  });

  it('deep-freezes every detail state and nested presentation layer', () => {
    expect(Object.isFrozen(MOCK_COMPLETE_INVESTIGATION)).toBe(true);
    expect(Object.isFrozen(MOCK_COMPLETE_INVESTIGATION.authEvidence)).toBe(
      true,
    );
    expect(
      Object.isFrozen(MOCK_COMPLETE_INVESTIGATION.authEvidence[0]?.event),
    ).toBe(true);
    expect(Object.isFrozen(MOCK_DEGRADED_INVESTIGATION.detail)).toBe(true);
    expect(Object.isFrozen(MOCK_INCIDENT_DETAIL_STATES)).toBe(true);
  });

  it('honors an already-aborted request', async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(
      fixtureIncidentDetailAdapter.load(
        MOCK_COMPLETE_INVESTIGATION.detail.incident.incident_id,
        controller.signal,
      ),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });
});
