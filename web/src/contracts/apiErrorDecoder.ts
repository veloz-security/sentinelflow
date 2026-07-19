import { API_ERROR_CODES } from './apiDtos';
import type { ApiErrorV1 } from './apiDtos';
import { deepFreeze } from '../utils/deepFreeze';

export interface ApiErrorValidationIssue {
  readonly path: string;
  readonly keyword: string;
  readonly message: string;
}

export type ApiErrorDecodeResult =
  | { readonly ok: true; readonly value: ApiErrorV1 }
  | {
      readonly ok: false;
      readonly reason: 'not_an_object' | 'shape_or_enum_mismatch';
      readonly schemaVersion: null;
      readonly issues: readonly ApiErrorValidationIssue[];
    };

const requiredKeys = Object.freeze(['code', 'details', 'message', 'trace_id']);
const allowedCodes = new Set<string>(API_ERROR_CODES);
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDetailValue(value: unknown): boolean {
  return (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  );
}

function mismatch(
  path: string,
  keyword: string,
  message: string,
): ApiErrorDecodeResult {
  return {
    ok: false,
    reason: 'shape_or_enum_mismatch',
    schemaVersion: null,
    issues: Object.freeze([{ path, keyword, message }]),
  };
}

/**
 * Decode the one small server error envelope needed before the live UI loads.
 *
 * This deliberately avoids importing the AJV contract registry: AJV compiles
 * schemas with dynamic code generation, which a production strict CSP blocks.
 * The complete registry remains the canonical test-time parity oracle.
 */
export function decodeApiError(value: unknown): ApiErrorDecodeResult {
  if (!isObject(value)) {
    return {
      ok: false,
      reason: 'not_an_object',
      schemaVersion: null,
      issues: Object.freeze([]),
    };
  }

  const keys = Object.keys(value).sort();
  if (
    keys.length !== requiredKeys.length ||
    !keys.every((key, index) => key === requiredKeys[index])
  ) {
    return mismatch('/', 'required', 'error envelope keys do not match');
  }
  if (typeof value.code !== 'string' || !allowedCodes.has(value.code)) {
    return mismatch('/code', 'enum', 'unsupported API error code');
  }
  if (typeof value.message !== 'string') {
    return mismatch('/message', 'type', 'message must be a string');
  }
  const messageLength = Array.from(value.message).length;
  if (messageLength < 1 || messageLength > 500) {
    return mismatch('/message', 'length', 'message length is outside 1..500');
  }
  if (typeof value.trace_id !== 'string' || !uuidPattern.test(value.trace_id)) {
    return mismatch('/trace_id', 'pattern', 'trace_id is not canonical UUID');
  }
  if (!isObject(value.details)) {
    return mismatch('/details', 'type', 'details must be an object');
  }
  for (const detail of Object.values(value.details)) {
    if (!isDetailValue(detail)) {
      return mismatch(
        '/details',
        'additionalProperties',
        'details contain an unsupported value',
      );
    }
  }

  return { ok: true, value: deepFreeze(value as unknown as ApiErrorV1) };
}
