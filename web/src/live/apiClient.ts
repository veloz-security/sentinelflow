import type { ApiErrorV1 } from '../contracts/apiDtos';
import { decodeApiError } from '../contracts/apiErrorDecoder';
import { deepFreeze } from '../utils/deepFreeze';
import {
  decodeAuditPage,
  decodeEnforcementAction,
  decodeHILChallengeEnvelope,
  decodeHILDecisionEnvelope,
  decodeIncidentDetail,
  decodeIncidentEventPage,
  decodeIncidentPage,
  decodePolicyDetail,
  decodeRevocationChallengeEnvelope,
  decodeRevocationDecisionEnvelope,
  decodeSessionEnvelope,
  isCanonicalUUID,
  type AuditPage,
  type EnforcementActionDetail,
  type HILChallengeEnvelope,
  type HILDecisionEnvelope,
  type HILReason,
  type IncidentDetail,
  type IncidentEventPage,
  type IncidentPage,
  type PolicyDetail,
  type PolicyArtifactBinding,
  type RevocationArtifactBinding,
  type RevocationChallengeEnvelope,
  type RevocationDecisionEnvelope,
  type RevocationReason,
  type SessionEnvelope,
} from './contracts';

export const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
const SUCCESS_BODY_LIMIT = 1024 * 1024;
const ERROR_BODY_LIMIT = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

type Decoder<T> = (value: unknown) => Readonly<T>;
type FetchImplementation = typeof fetch;

export interface IncidentListQuery {
  readonly state?: string;
  readonly kind?: string;
  readonly source?: string;
  readonly service?: string;
  readonly from?: string;
  readonly until?: string;
  readonly cursor?: string;
  readonly limit?: number;
}

export interface AuditQuery {
  readonly incident_id?: string;
  readonly policy_id?: string;
  readonly action_id?: string;
  readonly actor_type?: string;
  readonly actor_id?: string;
  readonly object_type?: string;
  readonly object_id?: string;
  readonly trace_id?: string;
  readonly from?: string;
  readonly until?: string;
  readonly cursor?: string;
  readonly limit?: number;
}

export class ApiClientError extends Error {
  constructor(
    readonly status: number,
    readonly envelope: Readonly<ApiErrorV1>,
    readonly retryAfterSeconds: number | null,
  ) {
    super(envelope.message);
    this.name = 'ApiClientError';
  }
}

function localTraceID(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return '00000000-0000-4000-8000-000000000000';
  }
}

function localError(message: string): Readonly<ApiErrorV1> {
  return deepFreeze({
    code: 'internal_error',
    message,
    trace_id: localTraceID(),
    details: {},
  });
}

function parseRetryAfter(response: Response): number | null {
  const raw = response.headers.get('Retry-After');
  if (raw === null || !/^(?:[1-9]|[1-5][0-9]|60)$/.test(raw)) {
    return null;
  }
  return Number(raw);
}

export async function readBoundedResponse(
  response: Response,
  limit: number,
): Promise<string> {
  const length = response.headers.get('Content-Length');
  if (
    length !== null &&
    (!/^(?:0|[1-9][0-9]*)$/.test(length) || Number(length) > limit)
  ) {
    throw new Error('response body limit exceeded');
  }
  if (!response.body) {
    return '';
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      total += result.value.byteLength;
      if (total > limit) {
        throw new Error('response body limit exceeded');
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function skipJSONWhitespace(source: string, start: number): number {
  let index = start;
  while (
    index < source.length &&
    (source[index] === ' ' ||
      source[index] === '\n' ||
      source[index] === '\r' ||
      source[index] === '\t')
  ) {
    index += 1;
  }
  return index;
}

function scanJSONString(
  source: string,
  start: number,
): { readonly next: number; readonly value: string } {
  if (source[start] !== '"') throw new Error('invalid JSON string');
  let index = start + 1;
  while (index < source.length) {
    const character = source[index];
    if (character === '"') {
      const raw = source.slice(start, index + 1);
      const value = JSON.parse(raw) as unknown;
      if (typeof value !== 'string') throw new Error('invalid JSON string');
      return { next: index + 1, value };
    }
    if (character === '\\') {
      index += 1;
      if (index >= source.length) throw new Error('invalid JSON escape');
      if (source[index] === 'u') index += 4;
    }
    index += 1;
  }
  throw new Error('unterminated JSON string');
}

function scanJSONValue(source: string, start: number): number {
  let index = skipJSONWhitespace(source, start);
  const character = source[index];
  if (character === '{') {
    index = skipJSONWhitespace(source, index + 1);
    const keys = new Set<string>();
    if (source[index] === '}') return index + 1;
    while (index < source.length) {
      const key = scanJSONString(source, index);
      if (keys.has(key.value)) throw new Error('duplicate JSON member');
      keys.add(key.value);
      index = skipJSONWhitespace(source, key.next);
      if (source[index] !== ':') throw new Error('invalid JSON object');
      index = skipJSONWhitespace(source, scanJSONValue(source, index + 1));
      if (source[index] === '}') return index + 1;
      if (source[index] !== ',') throw new Error('invalid JSON object');
      index = skipJSONWhitespace(source, index + 1);
    }
    throw new Error('unterminated JSON object');
  }
  if (character === '[') {
    index = skipJSONWhitespace(source, index + 1);
    if (source[index] === ']') return index + 1;
    while (index < source.length) {
      index = skipJSONWhitespace(source, scanJSONValue(source, index));
      if (source[index] === ']') return index + 1;
      if (source[index] !== ',') throw new Error('invalid JSON array');
      index = skipJSONWhitespace(source, index + 1);
    }
    throw new Error('unterminated JSON array');
  }
  if (character === '"') return scanJSONString(source, index).next;
  const primitiveStart = index;
  while (
    index < source.length &&
    source[index] !== ',' &&
    source[index] !== ']' &&
    source[index] !== '}' &&
    source[index] !== ' ' &&
    source[index] !== '\n' &&
    source[index] !== '\r' &&
    source[index] !== '\t'
  ) {
    index += 1;
  }
  if (index === primitiveStart) throw new Error('invalid JSON value');
  return index;
}

function parseJSON(source: string): unknown {
  if (source.length === 0 || source.charCodeAt(0) === 0xfeff) {
    throw new Error('invalid JSON response');
  }
  const end = skipJSONWhitespace(source, scanJSONValue(source, 0));
  if (end !== source.length) throw new Error('invalid JSON response');
  return JSON.parse(source) as unknown;
}

function linkedAbort(
  external: AbortSignal | undefined,
  timeoutMs: number,
): { readonly signal: AbortSignal; readonly cleanup: () => void } {
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () =>
      controller.abort(
        new DOMException('management API timeout', 'TimeoutError'),
      ),
    timeoutMs,
  );
  const onAbort = () => controller.abort(external?.reason);
  if (external?.aborted) {
    onAbort();
  } else {
    external?.addEventListener('abort', onAbort, { once: true });
  }
  return {
    signal: controller.signal,
    cleanup: () => {
      window.clearTimeout(timeout);
      external?.removeEventListener('abort', onAbort);
    },
  };
}

function queryString(
  values: Record<string, string | number | undefined>,
): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== '') {
      query.set(key, String(value));
    }
  }
  const encoded = query.toString();
  return encoded.length > 0 ? `?${encoded}` : '';
}

function requireUUID(value: string): string {
  if (!isCanonicalUUID(value)) {
    throw new ApiClientError(
      400,
      localError('The resource identifier is invalid.'),
      null,
    );
  }
  return value;
}

function requireIdempotencyKey(value: string): string {
  const byteLength = new TextEncoder().encode(value).byteLength;
  if (
    byteLength < 16 ||
    byteLength > 256 ||
    !/^[A-Za-z0-9._:-]+$/.test(value)
  ) {
    throw new ApiClientError(
      400,
      localError('The idempotency key is invalid.'),
      null,
    );
  }
  return value;
}

export class ManagementApiClient {
  constructor(
    private readonly fetchImplementation: FetchImplementation = fetch,
    private readonly timeoutMs = DEFAULT_TIMEOUT_MS,
  ) {}

  private async request<T>(
    path: string,
    options: {
      readonly method?: 'GET' | 'POST';
      readonly body?: Readonly<Record<string, unknown>>;
      readonly csrfToken?: string;
      readonly idempotencyKey?: string;
      readonly expectedStatus?: 200 | 201 | 204;
      readonly decoder?: Decoder<T>;
      readonly signal?: AbortSignal;
    },
  ): Promise<Readonly<T> | undefined> {
    const method = options.method ?? 'GET';
    const expectedStatus = options.expectedStatus ?? 200;
    const headers = new Headers({ Accept: 'application/json' });
    let body: string | undefined;
    if (method === 'POST') {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(options.body ?? {});
      if (options.csrfToken) {
        headers.set('X-CSRF-Token', options.csrfToken);
      }
      if (options.idempotencyKey) {
        headers.set(
          'Idempotency-Key',
          requireIdempotencyKey(options.idempotencyKey),
        );
      }
    }
    const abort = linkedAbort(options.signal, this.timeoutMs);
    try {
      const fetchImplementation = this.fetchImplementation;
      const response = await fetchImplementation(path, {
        method,
        headers,
        ...(body ? { body } : {}),
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: abort.signal,
      });

      if (response.status !== expectedStatus) {
        let envelope = localError(
          'The management API returned an invalid error response.',
        );
        try {
          if (response.headers.get('Content-Type') !== JSON_CONTENT_TYPE) {
            throw new Error('invalid error content type');
          }
          const decoded = decodeApiError(
            parseJSON(await readBoundedResponse(response, ERROR_BODY_LIMIT)),
          );
          if (!decoded.ok) {
            throw new Error('invalid error contract');
          }
          envelope = decoded.value;
        } catch {
          // The opaque local error intentionally does not include response bytes.
        }
        throw new ApiClientError(
          response.status,
          envelope,
          parseRetryAfter(response),
        );
      }

      if (expectedStatus === 204) {
        if (response.headers.get('Content-Type') !== null) {
          throw new ApiClientError(
            502,
            localError(
              'The management API returned an invalid empty response.',
            ),
            null,
          );
        }
        const empty = await readBoundedResponse(response, 0);
        if (empty.length !== 0) {
          throw new ApiClientError(
            502,
            localError(
              'The management API returned an invalid empty response.',
            ),
            null,
          );
        }
        return undefined;
      }

      if (
        response.headers.get('Content-Type') !== JSON_CONTENT_TYPE ||
        !options.decoder
      ) {
        throw new ApiClientError(
          502,
          localError(
            'The management API returned an unsupported representation.',
          ),
          null,
        );
      }
      try {
        return options.decoder(
          parseJSON(await readBoundedResponse(response, SUCCESS_BODY_LIMIT)),
        );
      } catch {
        throw new ApiClientError(
          502,
          localError(
            'The management API response did not match the frozen contract.',
          ),
          null,
        );
      }
    } finally {
      abort.cleanup();
    }
  }

  async session(signal?: AbortSignal): Promise<Readonly<SessionEnvelope>> {
    return (await this.request('/api/v1/session', {
      decoder: decodeSessionEnvelope,
      signal,
    })) as Readonly<SessionEnvelope>;
  }

  async login(
    username: string,
    password: string,
    signal?: AbortSignal,
  ): Promise<Readonly<SessionEnvelope>> {
    return (await this.request('/api/v1/session/login', {
      method: 'POST',
      body: { username, password },
      decoder: decodeSessionEnvelope,
      signal,
    })) as Readonly<SessionEnvelope>;
  }

  async logout(csrfToken: string, signal?: AbortSignal): Promise<void> {
    await this.request('/api/v1/session/logout', {
      method: 'POST',
      body: {},
      csrfToken,
      expectedStatus: 204,
      signal,
    });
  }

  async stepUp(
    password: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<Readonly<SessionEnvelope>> {
    return (await this.request('/api/v1/session/step-up', {
      method: 'POST',
      body: { password },
      csrfToken,
      decoder: decodeSessionEnvelope,
      signal,
    })) as Readonly<SessionEnvelope>;
  }

  async incidents(
    query: IncidentListQuery = {},
    signal?: AbortSignal,
  ): Promise<Readonly<IncidentPage>> {
    return (await this.request(
      `/api/v1/incidents${queryString({ ...query })}`,
      {
        decoder: decodeIncidentPage,
        signal,
      },
    )) as Readonly<IncidentPage>;
  }

  async incident(
    incidentID: string,
    signal?: AbortSignal,
  ): Promise<Readonly<IncidentDetail>> {
    return (await this.request(`/api/v1/incidents/${requireUUID(incidentID)}`, {
      decoder: decodeIncidentDetail,
      signal,
    })) as Readonly<IncidentDetail>;
  }

  async incidentEvents(
    incidentID: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<Readonly<IncidentEventPage>> {
    return (await this.request(
      `/api/v1/incidents/${requireUUID(incidentID)}/events${queryString({ cursor, limit: 100 })}`,
      {
        decoder: decodeIncidentEventPage,
        signal,
      },
    )) as Readonly<IncidentEventPage>;
  }

  async policy(
    policyID: string,
    signal?: AbortSignal,
  ): Promise<Readonly<PolicyDetail>> {
    return (await this.request(`/api/v1/policies/${requireUUID(policyID)}`, {
      decoder: decodePolicyDetail,
      signal,
    })) as Readonly<PolicyDetail>;
  }

  async policyDecisionChallenge(
    policyID: string,
    binding: Readonly<PolicyArtifactBinding>,
    idempotencyKey: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<Readonly<HILChallengeEnvelope>> {
    return (await this.request(
      `/api/v1/policies/${requireUUID(policyID)}/decision-challenges`,
      {
        method: 'POST',
        body: binding,
        csrfToken,
        idempotencyKey,
        expectedStatus: 201,
        decoder: decodeHILChallengeEnvelope,
        signal,
      },
    )) as Readonly<HILChallengeEnvelope>;
  }

  async policyDecision(
    policyID: string,
    binding: Readonly<PolicyArtifactBinding>,
    challengeEnvelope: Readonly<HILChallengeEnvelope>,
    reason: Readonly<HILReason>,
    idempotencyKey: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<Readonly<HILDecisionEnvelope>> {
    return (await this.request(
      `/api/v1/policies/${requireUUID(policyID)}/decisions`,
      {
        method: 'POST',
        body: {
          ...binding,
          challenge: challengeEnvelope.challenge,
          challenge_nonce: challengeEnvelope.challenge_nonce,
          reason,
        },
        csrfToken,
        idempotencyKey,
        decoder: decodeHILDecisionEnvelope,
        signal,
      },
    )) as Readonly<HILDecisionEnvelope>;
  }

  async enforcementAction(
    actionID: string,
    signal?: AbortSignal,
  ): Promise<Readonly<EnforcementActionDetail>> {
    return (await this.request(
      `/api/v1/enforcement-actions/${requireUUID(actionID)}`,
      {
        decoder: decodeEnforcementAction,
        signal,
      },
    )) as Readonly<EnforcementActionDetail>;
  }

  async revocationChallenge(
    actionID: string,
    binding: Readonly<RevocationArtifactBinding>,
    idempotencyKey: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<Readonly<RevocationChallengeEnvelope>> {
    return (await this.request(
      `/api/v1/enforcement-actions/${requireUUID(actionID)}/revocation-challenges`,
      {
        method: 'POST',
        body: {
          action_version: binding.action_version,
          target_ipv4: binding.target_ipv4,
          original_add_digest: binding.original_add_digest,
        },
        csrfToken,
        idempotencyKey,
        expectedStatus: 201,
        decoder: decodeRevocationChallengeEnvelope,
        signal,
      },
    )) as Readonly<RevocationChallengeEnvelope>;
  }

  async revokeEnforcementAction(
    actionID: string,
    binding: Readonly<RevocationArtifactBinding>,
    challengeEnvelope: Readonly<RevocationChallengeEnvelope>,
    reason: Readonly<RevocationReason>,
    idempotencyKey: string,
    csrfToken: string,
    signal?: AbortSignal,
  ): Promise<Readonly<RevocationDecisionEnvelope>> {
    return (await this.request(
      `/api/v1/enforcement-actions/${requireUUID(actionID)}/revocations`,
      {
        method: 'POST',
        body: {
          action_version: binding.action_version,
          target_ipv4: binding.target_ipv4,
          original_add_digest: binding.original_add_digest,
          challenge: challengeEnvelope.challenge,
          challenge_nonce: challengeEnvelope.challenge_nonce,
          canonical_revoke_artifact:
            challengeEnvelope.canonical_revoke_artifact,
          policy_id: challengeEnvelope.policy_id,
          policy_version: challengeEnvelope.policy_version,
          reason,
        },
        csrfToken,
        idempotencyKey,
        decoder: decodeRevocationDecisionEnvelope,
        signal,
      },
    )) as Readonly<RevocationDecisionEnvelope>;
  }

  async audit(
    query: AuditQuery = {},
    signal?: AbortSignal,
  ): Promise<Readonly<AuditPage>> {
    return (await this.request(
      `/api/v1/audit-events${queryString({ ...query })}`,
      {
        decoder: decodeAuditPage,
        signal,
      },
    )) as Readonly<AuditPage>;
  }
}

export const managementApi = new ManagementApiClient();
