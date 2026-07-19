import { describe, expect, it } from 'vitest';
import { MOCK_API_ERRORS } from '../mocks/contractFixtures';
import { decodeApiError as decodeWithAjv } from './registry';
import { decodeApiError } from './apiErrorDecoder';

const valid = {
  ...MOCK_API_ERRORS.permissionDenied,
  details: {
    nullable: null,
    retryable: false,
    retry_after_seconds: 3,
    state: 'denied',
  },
};

const corpus: readonly unknown[] = Object.freeze([
  valid,
  null,
  [],
  'error',
  {},
  { ...valid, code: 'unknown_error' },
  { ...valid, message: '' },
  { ...valid, message: 'x'.repeat(501) },
  { ...valid, message: 5 },
  { ...valid, trace_id: 'ABCDEFAB-0000-0000-0000-000000000000' },
  { ...valid, details: [] },
  { ...valid, details: { nested: {} } },
  { ...valid, details: { nonfinite: Number.POSITIVE_INFINITY } },
  { ...valid, unexpected: true },
]);

describe('CSP-safe API error decoder', () => {
  it('has accept/reject parity with the canonical AJV schema corpus', () => {
    for (const value of corpus) {
      const expected = decodeWithAjv(value);
      const actual = decodeApiError(value);
      expect(actual.ok, JSON.stringify(value)).toBe(expected.ok);
      if (!actual.ok && !expected.ok) {
        expect(actual.reason).toBe(expected.reason);
      }
    }
  });

  it('returns an immutable exact error envelope', () => {
    const result = decodeApiError(valid);
    expect(result).toMatchObject({ ok: true });
    if (result.ok) {
      expect(Object.isFrozen(result.value)).toBe(true);
      expect(Object.isFrozen(result.value.details)).toBe(true);
    }
  });
});
