import { describe, expect, it, vi } from 'vitest';
import {
  API_ERROR,
  ACTIVE_ENFORCEMENT_ACTION,
  HIL_CHALLENGE_ENVELOPE,
  HIL_DECISION_ENVELOPE,
  HIL_REPLAY_DECISION_ENVELOPE,
  HIL_IDEMPOTENCY_KEY,
  INCIDENT_PAGE,
  POLICY_DETAIL,
  POLICY_ID,
  REVOCATION_CHALLENGE_ENVELOPE,
  REVOCATION_DECISION_ENVELOPE,
  REVOCATION_REASON,
  REVOCATION_REPLAY_DECISION_ENVELOPE,
  SESSION_ENVELOPE,
} from './liveTestFixtures';
import { decodeEnforcementAction, decodePolicyDetail } from './contracts';
import { policyArtifactBinding, reasonForDecision } from './policyHil';
import { revocationArtifactBinding } from './revocationHil';
import {
  ApiClientError,
  ManagementApiClient,
  JSON_CONTENT_TYPE,
} from './apiClient';

function jsonResponse(
  value: unknown,
  status = 200,
  extraHeaders: HeadersInit = {},
) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': JSON_CONTENT_TYPE, ...extraHeaders },
  });
}

describe('ManagementApiClient', () => {
  it('uses same-origin credentials and decodes a frozen session', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(SESSION_ENVELOPE));
    const client = new ManagementApiClient(fetchMock);

    const result = await client.session();
    expect(Object.isFrozen(result.session)).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe('/api/v1/session');
    expect(init).toMatchObject({
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    });
    expect(new Headers(init?.headers).get('Content-Type')).toBeNull();
  });

  it('sends exact JSON and CSRF headers for session mutations', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(SESSION_ENVELOPE))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const client = new ManagementApiClient(fetchMock);

    await client.stepUp('secret', SESSION_ENVELOPE.csrf_token);
    await client.logout(SESSION_ENVELOPE.csrf_token);

    const [, stepUp] = fetchMock.mock.calls[0];
    expect(stepUp?.body).toBe('{"password":"secret"}');
    expect(new Headers(stepUp?.headers).get('Content-Type')).toBe(
      'application/json',
    );
    expect(new Headers(stepUp?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );
    const [, logout] = fetchMock.mock.calls[1];
    expect(logout?.body).toBe('{}');
  });

  it('rejects non-exact representations and oversized responses', async () => {
    const wrongType = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(INCIDENT_PAGE), {
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    await expect(
      new ManagementApiClient(wrongType).incidents(),
    ).rejects.toMatchObject({
      status: 502,
    });

    const oversized = vi.fn<typeof fetch>().mockResolvedValue(
      new Response('{}', {
        headers: {
          'Content-Type': JSON_CONTENT_TYPE,
          'Content-Length': String(1024 * 1024 + 1),
        },
      }),
    );
    await expect(
      new ManagementApiClient(oversized).incidents(),
    ).rejects.toMatchObject({
      status: 502,
    });
  });

  it('decodes frozen safe errors and never accepts extra response fields', async () => {
    const limited = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(API_ERROR, 429, { 'Retry-After': '5' }));
    const client = new ManagementApiClient(limited);
    const caught = await client.incidents().catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(ApiClientError);
    expect(caught).toMatchObject({ status: 429, retryAfterSeconds: 5 });
    expect(Object.isFrozen((caught as ApiClientError).envelope)).toBe(true);

    const extra = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ ...INCIDENT_PAGE, total: 1 }));
    await expect(
      new ManagementApiClient(extra).incidents(),
    ).rejects.toMatchObject({
      status: 502,
    });
  });

  it('sends one exact idempotency and CSRF binding for challenge and decision', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(HIL_CHALLENGE_ENVELOPE, 201))
      .mockResolvedValueOnce(jsonResponse(HIL_DECISION_ENVELOPE));
    const client = new ManagementApiClient(fetchMock);
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    const binding = policyArtifactBinding(policy, 'approve');
    expect(binding).not.toBeNull();

    const challenge = await client.policyDecisionChallenge(
      POLICY_ID,
      binding as NonNullable<typeof binding>,
      HIL_IDEMPOTENCY_KEY,
      SESSION_ENVELOPE.csrf_token,
    );
    await client.policyDecision(
      POLICY_ID,
      binding as NonNullable<typeof binding>,
      challenge,
      reasonForDecision('threat_confirmed', 'Confirmed synthetic attack'),
      HIL_IDEMPOTENCY_KEY,
      SESSION_ENVELOPE.csrf_token,
    );

    const [challengePath, challengeInit] = fetchMock.mock.calls[0];
    expect(challengePath).toBe(
      `/api/v1/policies/${POLICY_ID}/decision-challenges`,
    );
    expect(challengeInit?.body).toBe(JSON.stringify(binding));
    expect(new Headers(challengeInit?.headers).get('Idempotency-Key')).toBe(
      HIL_IDEMPOTENCY_KEY,
    );
    expect(new Headers(challengeInit?.headers).get('X-CSRF-Token')).toBe(
      SESSION_ENVELOPE.csrf_token,
    );

    const [decisionPath, decisionInit] = fetchMock.mock.calls[1];
    expect(decisionPath).toBe(`/api/v1/policies/${POLICY_ID}/decisions`);
    expect(new Headers(decisionInit?.headers).get('Idempotency-Key')).toBe(
      HIL_IDEMPOTENCY_KEY,
    );
    const body = JSON.parse(String(decisionInit?.body)) as Record<
      string,
      unknown
    >;
    expect(body.challenge).toEqual(HIL_CHALLENGE_ENVELOPE.challenge);
    expect(body.challenge_nonce).toBe(HIL_CHALLENGE_ENVELOPE.challenge_nonce);
    expect(body).not.toHaveProperty('csrf_token');
    expect(String(decisionInit?.body)).not.toContain(
      SESSION_ENVELOPE.csrf_token,
    );
  });

  it('accepts exact replay proof and preserves the caller idempotency key', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(HIL_DECISION_ENVELOPE))
      .mockResolvedValueOnce(jsonResponse(HIL_REPLAY_DECISION_ENVELOPE));
    const client = new ManagementApiClient(fetchMock);
    const policy = decodePolicyDetail(structuredClone(POLICY_DETAIL));
    const binding = policyArtifactBinding(policy, 'approve');
    const reason = reasonForDecision(
      'threat_confirmed',
      'Confirmed synthetic attack',
    );
    const results = [];
    for (let attempt = 0; attempt < 2; attempt += 1) {
      results.push(
        await client.policyDecision(
          POLICY_ID,
          binding as NonNullable<typeof binding>,
          HIL_CHALLENGE_ENVELOPE,
          reason,
          HIL_IDEMPOTENCY_KEY,
          SESSION_ENVELOPE.csrf_token,
        ),
      );
    }
    expect('replayed' in results[0]).toBe(false);
    expect('replayed' in results[1] && results[1].replayed).toBe(true);
    expect('session' in results[1]).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [, init] of fetchMock.mock.calls) {
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(
        HIL_IDEMPOTENCY_KEY,
      );
    }
  });

  it('sends the exact revocation challenge and decision bodies with one idempotency key', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(REVOCATION_CHALLENGE_ENVELOPE, 201))
      .mockResolvedValueOnce(jsonResponse(REVOCATION_DECISION_ENVELOPE));
    const client = new ManagementApiClient(fetchMock);
    const action = decodeEnforcementAction(
      structuredClone(ACTIVE_ENFORCEMENT_ACTION),
    );
    const binding = revocationArtifactBinding(action);

    const challenge = await client.revocationChallenge(
      action.action_id,
      binding,
      HIL_IDEMPOTENCY_KEY,
      SESSION_ENVELOPE.csrf_token,
    );
    await client.revokeEnforcementAction(
      action.action_id,
      binding,
      challenge,
      REVOCATION_REASON,
      HIL_IDEMPOTENCY_KEY,
      SESSION_ENVELOPE.csrf_token,
    );

    const [challengePath, challengeInit] = fetchMock.mock.calls[0];
    expect(challengePath).toBe(
      `/api/v1/enforcement-actions/${action.action_id}/revocation-challenges`,
    );
    expect(JSON.parse(String(challengeInit?.body))).toEqual({
      action_version: action.version,
      target_ipv4: action.target_ipv4,
      original_add_digest: action.canonical_artifact_digest,
    });
    const [decisionPath, decisionInit] = fetchMock.mock.calls[1];
    expect(decisionPath).toBe(
      `/api/v1/enforcement-actions/${action.action_id}/revocations`,
    );
    expect(JSON.parse(String(decisionInit?.body))).toEqual({
      action_version: action.version,
      target_ipv4: action.target_ipv4,
      original_add_digest: action.canonical_artifact_digest,
      challenge: REVOCATION_CHALLENGE_ENVELOPE.challenge,
      challenge_nonce: REVOCATION_CHALLENGE_ENVELOPE.challenge_nonce,
      canonical_revoke_artifact:
        REVOCATION_CHALLENGE_ENVELOPE.canonical_revoke_artifact,
      policy_id: REVOCATION_CHALLENGE_ENVELOPE.policy_id,
      policy_version: REVOCATION_CHALLENGE_ENVELOPE.policy_version,
      reason: REVOCATION_REASON,
    });
    for (const [, init] of fetchMock.mock.calls) {
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(
        HIL_IDEMPOTENCY_KEY,
      );
      expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe(
        SESSION_ENVELOPE.csrf_token,
      );
    }
  });

  it('accepts historical revocation replay only without session credentials', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(REVOCATION_REPLAY_DECISION_ENVELOPE));
    const client = new ManagementApiClient(fetchMock);
    const action = decodeEnforcementAction(
      structuredClone(ACTIVE_ENFORCEMENT_ACTION),
    );
    const result = await client.revokeEnforcementAction(
      action.action_id,
      revocationArtifactBinding(action),
      REVOCATION_CHALLENGE_ENVELOPE,
      REVOCATION_REASON,
      HIL_IDEMPOTENCY_KEY,
      SESSION_ENVELOPE.csrf_token,
    );
    expect('replayed' in result && result.replayed).toBe(true);
    expect('session' in result).toBe(false);
    expect('csrf_token' in result).toBe(false);
  });

  it('rejects duplicate and escape-equivalent response member names before decoding', async () => {
    const projection = JSON.stringify(SESSION_ENVELOPE.session);
    const duplicate = `{"session":${projection},"se\\u0073sion":${projection},"csrf_token":"${SESSION_ENVELOPE.csrf_token}"}`;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(duplicate, {
        headers: { 'Content-Type': JSON_CONTENT_TYPE },
      }),
    );
    await expect(
      new ManagementApiClient(fetchMock).session(),
    ).rejects.toMatchObject({ status: 502 });
  });
});
