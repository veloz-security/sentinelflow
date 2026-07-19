import http from 'node:http';
import {
  HIL_POLICY_ID,
  canonicalJSONString,
  createHilAuthorizationStore,
  createHilScenarioManager,
} from './mock-management-hil.mjs';

const host = '127.0.0.1';
const port = Number(process.env.SENTINELFLOW_MOCK_PORT ?? '4180');
if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
  throw new Error('SENTINELFLOW_MOCK_PORT must be a valid TCP port');
}
const incidentId = '019b0000-0000-7000-8000-000000000101';
const stubIncidentId = '019b0000-0000-7000-8000-000000000107';
const signalId = '019b0000-0000-7000-8000-000000000102';
const eventId = '019b0000-0000-7000-8000-000000000103';
const incidentEventId = '019b0000-0000-7000-8000-000000000104';
const auditId = '019b0000-0000-7000-8000-000000000105';
const stubEventId = '019b0000-0000-7000-8000-000000000108';
const stubIncidentEventId = '019b0000-0000-7000-8000-000000000109';
const stubAuditId = '019b0000-0000-7000-8000-00000000010a';
const traceId = '019b0000-0000-4000-8000-000000000106';
const digest = (character) => `sha256:${character.repeat(64)}`;
const startedAt = Date.now();
const time = (milliseconds) => new Date(startedAt + milliseconds).toISOString();

const session = {
  actor_id: 'admin',
  session_id: '019b0000-0000-7000-8000-000000000001',
  authenticated_at: time(-60 * 1000),
  expires_at: time(8 * 60 * 60 * 1000),
};

const rotatedSession = {
  ...session,
  session_id: '019b0000-0000-7000-8000-000000000309',
};
const testNamespaceHeader = 'x-sentinelflow-test-namespace';
const defaultTestNamespace = 'default';
const maxTestNamespaces = 256;
const hilStates = new Map();

function namespaceFor(request) {
  const value = request.headers[testNamespaceHeader];
  if (value === undefined) return defaultTestNamespace;
  if (
    typeof value !== 'string' ||
    !/^[a-z0-9](?:[a-z0-9._-]{0,95})$/.test(value)
  ) {
    throw new Error('invalid test namespace');
  }
  return value;
}

function hilStateFor(request) {
  const namespace = namespaceFor(request);
  let state = hilStates.get(namespace);
  if (state !== undefined) return state;
  if (hilStates.size >= maxTestNamespaces) {
    throw new Error('test namespace capacity exceeded');
  }
  state = Object.freeze({
    authorizations: createHilAuthorizationStore({ rotatedSession }),
    scenarios: createHilScenarioManager(session),
  });
  hilStates.set(namespace, state);
  return state;
}

const incident = {
  incident_id: incidentId,
  kind: 'brute_force',
  state: 'open',
  source_ip: '203.0.113.20',
  service_label: 'demo_app',
  first_seen: time(-120 * 1000),
  last_seen: time(-60 * 1000),
  deterministic_score: '0.90000',
  version: 2,
  created_at: time(-120 * 1000),
  updated_at: time(-60 * 1000),
};

const stubIncident = {
  incident_id: stubIncidentId,
  kind: 'path_scan',
  state: 'review_ready',
  source_ip: '203.0.113.21',
  service_label: 'demo_app',
  first_seen: time(-110 * 1000),
  last_seen: time(-50 * 1000),
  deterministic_score: '0.80000',
  version: 2,
  created_at: time(-110 * 1000),
  updated_at: time(-50 * 1000),
};

const openAIAnalysis = {
  analysis_id: '019b0000-0000-7000-8000-000000000110',
  incident_version: 2,
  provider_kind: 'openai_responses',
  adapter_id: 'openai-responses-v1',
  model: 'gpt-5.6-sol',
  reasoning_effort: 'medium',
  rate_card_version: 'openai-demo-2026-07-18',
  result_state: 'succeeded',
  output_digest: digest('c'),
  summary: 'OpenAI Responses analysis of the bounded synthetic incident.',
  classification: 'brute_force',
  confidence: '0.94000',
  uncertainty: 'Synthetic demo traffic may not represent production traffic.',
  started_at: time(-45 * 1000),
  completed_at: time(-43 * 1000),
  false_positive_factors: ['Synthetic demo source range'],
};

const stubAnalysis = {
  analysis_id: '019b0000-0000-7000-8000-000000000111',
  incident_version: 2,
  provider_kind: 'deterministic_stub',
  adapter_id: 'sentinelflow-deterministic-ai-stub-v1',
  model: null,
  reasoning_effort: null,
  rate_card_version: null,
  result_state: 'succeeded',
  output_digest: digest('d'),
  summary: 'Deterministic offline analysis of the bounded synthetic incident.',
  classification: 'path_scan',
  confidence: '0.80000',
  uncertainty: 'Static deterministic adapter output for local verification.',
  started_at: time(-40 * 1000),
  completed_at: time(-40 * 1000),
  false_positive_factors: ['Static offline adapter'],
};

const audit = {
  sequence: 1,
  event_id: auditId,
  actor_type: 'system',
  actor_id: 'analysis_worker',
  action: 'incident_opened',
  object_type: 'incident',
  object_id: incidentId,
  incident_id: incidentId,
  trace_id: traceId,
  outcome: 'accepted',
  occurred_at: time(-60 * 1000),
  recorded_at: time(-59 * 1000),
};

function json(response, status, value, headers = {}) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...headers,
  });
  response.end(body);
}

function error(response, status, code) {
  json(
    response,
    status,
    {
      code,
      message:
        code === 'authentication_required'
          ? 'authentication is required'
          : code === 'digest_mismatch'
            ? 'artifact digest does not match'
            : 'resource was not found',
      trace_id: traceId,
      details: {},
    },
    status === 429 ? { 'Retry-After': '5' } : {},
  );
}

async function readJSON(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16 * 1024) throw new Error('body too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function exactBindingMatches(body, policy) {
  return (
    body.operation === 'approve' &&
    body.policy_version === policy.version &&
    body.target_ipv4 === policy.target_ipv4 &&
    body.ttl_seconds === policy.ttl_seconds &&
    body.policy_digest === policy.policy_digest &&
    body.generated_artifact_digest === policy.generated_artifact_digest &&
    body.canonical_artifact_digest === policy.canonical_artifact_digest &&
    body.evidence_snapshot_digest === policy.evidence_snapshot_digest &&
    body.validation_snapshot_digest === policy.latest_validation.snapshot_digest
  );
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? '/', `http://${host}:${port}`);
    if (url.pathname === '/__ready') {
      response.writeHead(204);
      response.end();
      return;
    }
    if (
      request.method === 'POST' &&
      url.pathname === `/api/v1/policies/${HIL_POLICY_ID}/decision-challenges`
    ) {
      const { authorizations, scenarios } = hilStateFor(request);
      const body = await readJSON(request);
      const idempotencyKey = request.headers['idempotency-key'];
      const scenario =
        typeof idempotencyKey === 'string'
          ? (authorizations.scenarioFor(idempotencyKey) ?? scenarios.current())
          : scenarios.current();
      if (
        typeof idempotencyKey !== 'string' ||
        idempotencyKey.length < 16 ||
        !exactBindingMatches(body, scenario.policy)
      ) {
        error(response, 409, 'digest_mismatch');
        return;
      }
      const issued = authorizations.issue({
        scenario,
        idempotencyKey,
        requestFingerprint: canonicalJSONString(body),
      });
      if (issued.kind === 'conflict') {
        error(response, 409, 'idempotency_conflict');
        return;
      }
      json(response, 201, {
        challenge: issued.scenario.challenge,
        challenge_nonce: issued.scenario.challenge_nonce,
      });
      return;
    }
    if (
      request.method === 'POST' &&
      url.pathname === `/api/v1/policies/${HIL_POLICY_ID}/decisions`
    ) {
      const { authorizations, scenarios } = hilStateFor(request);
      const body = await readJSON(request);
      const idempotencyKey = request.headers['idempotency-key'];
      const issuedScenario =
        typeof idempotencyKey === 'string'
          ? authorizations.scenarioFor(idempotencyKey)
          : null;
      if (
        !issuedScenario ||
        !exactBindingMatches(body, issuedScenario.policy) ||
        JSON.stringify(body.challenge) !==
          JSON.stringify(issuedScenario.challenge) ||
        body.challenge_nonce !== issuedScenario.challenge_nonce ||
        body.reason?.schema_version !== 'hil-reason-v1' ||
        typeof body.reason?.reason_text !== 'string' ||
        body.reason.reason_text.length === 0
      ) {
        error(response, 409, 'digest_mismatch');
        return;
      }
      const outcome = authorizations.consume({
        idempotencyKey,
        requestFingerprint: canonicalJSONString(body),
        reason: body.reason,
      });
      if (outcome.kind === 'expired') {
        error(response, 409, 'challenge_expired');
        return;
      }
      if (outcome.kind === 'conflict' || outcome.kind === 'missing') {
        error(response, 409, 'idempotency_conflict');
        return;
      }
      if (outcome.kind === 'fresh') {
        scenarios.retireAfterNextRead(issuedScenario);
      } else {
        scenarios.retire(issuedScenario);
      }
      json(
        response,
        200,
        outcome.response,
        outcome.kind === 'replay'
          ? {
              'Set-Cookie':
                'sentinelflow_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict',
            }
          : {},
      );
      return;
    }
    if (request.method !== 'GET') {
      error(response, 404, 'not_found');
      return;
    }
    if (url.pathname === '/api/v1/session') {
      json(response, 200, {
        session,
        csrf_token: 'a'.repeat(43),
      });
      return;
    }
    if (url.pathname === '/api/v1/incidents') {
      json(response, 200, { items: [incident, stubIncident] });
      return;
    }
    if (url.pathname === `/api/v1/incidents/${incidentId}`) {
      json(response, 200, {
        incident,
        signals: [
          {
            signal_id: signalId,
            rule_id: 'auth_failure_spread',
            rule_version: 1,
            kind: 'brute_force',
            window_start: time(-120 * 1000),
            window_end: time(-60 * 1000),
            observed_count: 20,
            distinct_count: 8,
            threshold_count: 20,
            threshold_distinct: 8,
            source_health_status: 'complete',
            evidence_digest: digest('a'),
          },
        ],
        signals_truncated: false,
        latest_analysis: openAIAnalysis,
        policies: [],
        policies_truncated: false,
      });
      return;
    }
    if (url.pathname === `/api/v1/incidents/${stubIncidentId}`) {
      json(response, 200, {
        incident: stubIncident,
        signals: [
          {
            signal_id: '019b0000-0000-7000-8000-000000000112',
            rule_id: 'suspicious_path_scan',
            rule_version: 1,
            kind: 'path_scan',
            window_start: time(-110 * 1000),
            window_end: time(-50 * 1000),
            observed_count: 8,
            threshold_count: 8,
            source_health_status: 'complete',
            evidence_digest: digest('b'),
          },
        ],
        signals_truncated: false,
        latest_analysis: stubAnalysis,
        policies: [],
        policies_truncated: false,
      });
      return;
    }
    if (url.pathname === `/api/v1/incidents/${incidentId}/events`) {
      json(response, 200, {
        items: [
          {
            incident_event_id: incidentEventId,
            event_id: eventId,
            incident_version: 2,
            kind: 'gateway',
            occurred_at: time(-90 * 1000),
            trace_id: traceId,
            source_ip: '203.0.113.20',
            service_label: 'demo_app',
            route_label: 'login',
            method: 'POST',
            status_code: 401,
            suspicious_path_id: 'none',
            trust_state: 'trusted',
            trust_reason: 'direct_peer',
            relation_reason: 'same_source_overlap',
          },
        ],
      });
      return;
    }
    if (url.pathname === `/api/v1/incidents/${stubIncidentId}/events`) {
      json(response, 200, {
        items: [
          {
            incident_event_id: stubIncidentEventId,
            event_id: stubEventId,
            incident_version: 2,
            kind: 'gateway',
            occurred_at: time(-80 * 1000),
            trace_id: traceId,
            source_ip: '203.0.113.21',
            service_label: 'demo_app',
            route_label: 'unknown',
            method: 'GET',
            status_code: 404,
            suspicious_path_id: 'admin_probe',
            trust_state: 'trusted',
            trust_reason: 'direct_peer',
            relation_reason: 'same_source_overlap',
          },
        ],
      });
      return;
    }
    if (url.pathname === `/api/v1/policies/${HIL_POLICY_ID}`) {
      json(response, 200, hilStateFor(request).scenarios.read().policy);
      return;
    }
    if (url.pathname === '/api/v1/audit-events') {
      if (url.searchParams.get('incident_id') === stubIncidentId) {
        json(response, 200, {
          items: [
            {
              ...audit,
              sequence: 2,
              event_id: stubAuditId,
              object_id: stubIncidentId,
              incident_id: stubIncidentId,
            },
          ],
        });
        return;
      }
      json(response, 200, { items: [audit] });
      return;
    }
    if (url.pathname === '/api/v1/events/stream') {
      response.writeHead(200, {
        'Cache-Control': 'no-store, no-transform',
        'Content-Type': 'text/event-stream; charset=utf-8',
        'X-Accel-Buffering': 'no',
        Connection: 'keep-alive',
      });
      response.write(': connected\n\n');
      const heartbeat = setInterval(
        () => response.write(': heartbeat\n\n'),
        1000,
      );
      request.on('close', () => clearInterval(heartbeat));
      return;
    }
    error(response, 404, 'not_found');
  } catch {
    error(response, 422, 'schema_invalid');
  }
});

server.listen(port, host, () => {
  if (process.env.SENTINELFLOW_MOCK_REPORT_PORT === '1') {
    const address = server.address();
    if (typeof address === 'object' && address !== null) {
      process.stdout.write(`SENTINELFLOW_MOCK_PORT=${address.port}\n`);
    }
  }
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
