import { describe, expect, it } from 'vitest';
import {
  HIL_CHALLENGE_ENVELOPE,
  HIL_DECISION_ENVELOPE,
  HIL_REPLAY_DECISION_ENVELOPE,
  INCIDENT_PAGE,
  INTERRUPTED_VALIDATION_ATTEMPT,
  INVALID_VALIDATION_ATTEMPT,
  OPENAI_ANALYSIS_SUMMARY,
  POLICY_DETAIL,
  SESSION_ENVELOPE,
  STUB_ANALYSIS_SUMMARY,
  STREAM_PAYLOAD,
  REVOCATION_CHALLENGE_ENVELOPE,
  REVOCATION_DECISION_ENVELOPE,
  REVOCATION_REPLAY_DECISION_ENVELOPE,
} from './liveTestFixtures';
import {
  decodeIncidentPage,
  decodeIncidentDetail,
  decodePolicyDetail,
  decodeHILChallengeEnvelope,
  decodeHILDecisionEnvelope,
  decodeRevocationChallengeEnvelope,
  decodeRevocationDecisionEnvelope,
  decodeSessionEnvelope,
  decodeStreamEvent,
} from './contracts';
import type { AnalysisSummary } from './contracts';

function incidentDetail(latestAnalysis: unknown) {
  return {
    incident: INCIDENT_PAGE.items[0],
    signals: [],
    signals_truncated: false,
    latest_analysis: latestAnalysis,
    policies: [],
    policies_truncated: false,
  };
}

const OPENAI_PROVENANCE = {
  provider_kind: 'openai_responses',
  adapter_id: 'openai-responses-v1',
  model: 'gpt-5.6-sol',
  reasoning_effort: 'medium',
  rate_card_version: 'openai-demo-2026-07-18',
} as const;

const STUB_PROVENANCE = {
  provider_kind: 'deterministic_stub',
  adapter_id: 'sentinelflow-deterministic-ai-stub-v1',
  model: null,
  reasoning_effort: null,
  rate_card_version: null,
} as const;

const STARTED_OPENAI_ANALYSIS = {
  analysis_id: '019b0000-0000-7000-8000-000000000112',
  incident_version: 2,
  ...OPENAI_PROVENANCE,
  result_state: 'started',
  started_at: '2026-07-18T01:03:00.000000002Z',
  false_positive_factors: ['Bounded synthetic fixture'],
} as const satisfies AnalysisSummary;

const STARTED_STUB_ANALYSIS = {
  analysis_id: '019b0000-0000-7000-8000-000000000113',
  incident_version: 2,
  ...STUB_PROVENANCE,
  result_state: 'started',
  started_at: '2026-07-18T01:03:00Z',
  false_positive_factors: [],
} as const satisfies AnalysisSummary;

const FAILED_OPENAI_ANALYSIS = {
  analysis_id: '019b0000-0000-7000-8000-000000000114',
  incident_version: 2,
  ...OPENAI_PROVENANCE,
  result_state: 'failed',
  failure_code: 'timeout',
  started_at: '2026-07-18T01:04:00Z',
  completed_at: '2026-07-18T01:04:30Z',
  false_positive_factors: [],
} as const satisfies AnalysisSummary;

const FAILED_STUB_ANALYSIS = {
  analysis_id: '019b0000-0000-7000-8000-000000000115',
  incident_version: 2,
  ...STUB_PROVENANCE,
  result_state: 'failed',
  failure_code: 'configuration_error',
  started_at: '2026-07-18T01:05:00Z',
  completed_at: '2026-07-18T01:05:00Z',
  false_positive_factors: [],
} as const satisfies AnalysisSummary;

function policyWithValidationAttempt(attempt: unknown) {
  const policy = structuredClone(POLICY_DETAIL) as Record<string, unknown>;
  delete policy.latest_validation;
  return {
    ...policy,
    state: 'invalid',
    latest_validation_attempt: attempt,
  };
}

function validValidationAttempt() {
  const attempt = structuredClone(INVALID_VALIDATION_ATTEMPT) as Record<
    string,
    unknown
  >;
  attempt.state = 'valid';
  delete attempt.failure_code;
  delete attempt.failed_gate;
  attempt.gates = INVALID_VALIDATION_ATTEMPT.gates.map((gate) => ({
    ...gate,
    state: 'passed',
    result_code: 'ok',
  }));
  return attempt;
}

describe('live management wire contracts', () => {
  it('decodes and recursively freezes actual session and incident DTOs', () => {
    const session = decodeSessionEnvelope(structuredClone(SESSION_ENVELOPE));
    const incidents = decodeIncidentPage(structuredClone(INCIDENT_PAGE));

    expect(Object.isFrozen(session)).toBe(true);
    expect(Object.isFrozen(session.session)).toBe(true);
    expect(Object.isFrozen(incidents.items)).toBe(true);
    expect(Object.isFrozen(incidents.items[0])).toBe(true);
  });

  it('decodes and freezes fail-closed validation-attempt evidence', () => {
    const policy = decodePolicyDetail(
      policyWithValidationAttempt(structuredClone(INVALID_VALIDATION_ATTEMPT)),
    );

    expect(policy.latest_validation).toBeUndefined();
    expect(policy.latest_validation_attempt).toMatchObject({
      state: 'invalid',
      failure_code: 'history_demo_binding_mismatch',
      failed_gate: 'historical_impact',
    });
    expect(policy.latest_validation_attempt?.gates).toHaveLength(6);
    expect(policy.latest_validation_attempt?.gates[5]).toMatchObject({
      order: 6,
      name: 'historical_impact',
      state: 'failed',
      result_code: 'history_demo_binding_mismatch',
    });
    expect(Object.isFrozen(policy.latest_validation_attempt)).toBe(true);
    expect(Object.isFrozen(policy.latest_validation_attempt?.gates)).toBe(true);
  });

  it('accepts an interrupted validation attempt with only a passed prefix', () => {
    const policy = decodePolicyDetail(
      policyWithValidationAttempt(
        structuredClone(INTERRUPTED_VALIDATION_ATTEMPT),
      ),
    );

    expect(policy.latest_validation_attempt).toMatchObject({
      state: 'interrupted',
      failure_code: 'validation_attempt_timeout',
    });
    expect(policy.latest_validation_attempt?.failed_gate).toBeUndefined();
    expect(
      policy.latest_validation_attempt?.terminal_mutation_digest,
    ).toBeUndefined();
    expect(
      policy.latest_validation_attempt?.gates.every(
        (gate) => gate.state === 'passed' && gate.result_code === 'ok',
      ),
    ).toBe(true);
  });

  it('accepts a valid attempt only with all six passed gates and a terminal digest', () => {
    const policy = decodePolicyDetail({
      ...structuredClone(POLICY_DETAIL),
      latest_validation_attempt: validValidationAttempt(),
    });
    expect(policy.latest_validation_attempt).toMatchObject({ state: 'valid' });
    expect(policy.latest_validation_attempt?.gates).toHaveLength(6);
  });

  it.each(['invalid', 'interrupted'] as const)(
    'rejects a %s latest attempt that coexists with HIL-authorizing validation',
    (state) => {
      const attempt =
        state === 'invalid'
          ? structuredClone(INVALID_VALIDATION_ATTEMPT)
          : structuredClone(INTERRUPTED_VALIDATION_ATTEMPT);
      expect(() =>
        decodePolicyDetail({
          ...structuredClone(POLICY_DETAIL),
          latest_validation_attempt: attempt,
        }),
      ).toThrow(/frozen contract/);
    },
  );

  it('requires a successful latest attempt to retain its exact validation snapshot', () => {
    const policy = structuredClone(POLICY_DETAIL) as Record<string, unknown>;
    delete policy.latest_validation;
    policy.latest_validation_attempt = validValidationAttempt();
    expect(() => decodePolicyDetail(policy)).toThrow(/frozen contract/);
  });

  it.each([
    'approved',
    'queued',
    'active',
    'expired',
    'failed',
    'revoked',
    'indeterminate',
  ] as const)(
    'retains a valid attempt through the %s lifecycle state with an approved decision',
    (state) => {
      const policy = decodePolicyDetail({
        ...structuredClone(POLICY_DETAIL),
        state,
        latest_validation_attempt: validValidationAttempt(),
        decision: {
          decision_id: '019b0000-0000-7000-8000-000000000390',
          decision: 'approved',
          actor_id: 'admin',
          reason_digest: `sha256:${'e'.repeat(64)}`,
          decided_at: '2026-07-18T01:03:00Z',
        },
      });
      expect(policy.state).toBe(state);
      expect(policy.decision?.decision).toBe('approved');
    },
  );

  it('retains a rejected policy with its valid attempt and rejected decision', () => {
    const policy = decodePolicyDetail({
      ...structuredClone(POLICY_DETAIL),
      state: 'rejected',
      latest_validation_attempt: validValidationAttempt(),
      decision: {
        decision_id: '019b0000-0000-7000-8000-000000000391',
        decision: 'rejected',
        actor_id: 'admin',
        reason_digest: `sha256:${'f'.repeat(64)}`,
        decided_at: '2026-07-18T01:03:00Z',
      },
    });
    expect(policy.decision?.decision).toBe('rejected');
  });

  it('retains a stale policy derived from a previously valid attempt', () => {
    const policy = decodePolicyDetail({
      ...structuredClone(POLICY_DETAIL),
      state: 'stale',
      latest_validation_attempt: validValidationAttempt(),
      latest_validation: {
        ...POLICY_DETAIL.latest_validation,
        state: 'stale',
      },
    });
    expect(policy.latest_validation_attempt?.state).toBe('valid');
    expect(policy.latest_validation?.state).toBe('stale');
  });

  it.each([
    [
      'passed gate with a failure result',
      {
        ...POLICY_DETAIL.latest_validation,
        gates: POLICY_DETAIL.latest_validation.gates.map((gate, index) =>
          index === 0
            ? { ...gate, result_code: 'history_demo_binding_mismatch' }
            : gate,
        ),
      },
    ],
    [
      'valid snapshot with a failure code',
      {
        ...POLICY_DETAIL.latest_validation,
        failure_code: 'history_demo_binding_mismatch',
      },
    ],
    [
      'noncanonical gate name',
      {
        ...POLICY_DETAIL.latest_validation,
        gates: POLICY_DETAIL.latest_validation.gates.map((gate, index) =>
          index === 1 ? { ...gate, name: 'unexpected_gate' } : gate,
        ),
      },
    ],
    [
      'incomplete source on a valid snapshot',
      {
        ...POLICY_DETAIL.latest_validation,
        source_health_status: 'incomplete',
      },
    ],
    [
      'nonpositive validity interval',
      {
        ...POLICY_DETAIL.latest_validation,
        valid_until: POLICY_DETAIL.latest_validation.created_at,
      },
    ],
  ])('rejects malformed validation snapshot: %s', (_name, validation) => {
    expect(() =>
      decodePolicyDetail({
        ...structuredClone(POLICY_DETAIL),
        latest_validation: validation,
      }),
    ).toThrow(/frozen contract/);
  });

  it('accepts an invalid validation snapshot only with one terminal failed gate', () => {
    const gates = POLICY_DETAIL.latest_validation.gates.map((gate, index) =>
      index === 5
        ? {
            ...gate,
            passed: false,
            result_code: 'history_demo_binding_mismatch',
          }
        : gate,
    );
    const policy = decodePolicyDetail({
      ...structuredClone(POLICY_DETAIL),
      state: 'invalid',
      latest_validation: {
        ...POLICY_DETAIL.latest_validation,
        state: 'invalid',
        failure_code: 'history_demo_binding_mismatch',
        gates,
      },
    });
    expect(policy.latest_validation).toMatchObject({
      state: 'invalid',
      failure_code: 'history_demo_binding_mismatch',
    });
  });

  it('accepts a stale validation snapshot with a safe passed prefix', () => {
    const policy = decodePolicyDetail({
      ...structuredClone(POLICY_DETAIL),
      state: 'stale',
      latest_validation: {
        ...POLICY_DETAIL.latest_validation,
        state: 'stale',
        source_health_status: 'incomplete',
        gates: POLICY_DETAIL.latest_validation.gates.slice(0, 3),
      },
    });
    expect(policy.latest_validation?.gates).toHaveLength(3);
  });

  it.each([
    ['policy_id', '019b0000-0000-7000-8000-000000000999'],
    ['analysis_id', '019b0000-0000-7000-8000-000000000999'],
    ['incident_id', '019b0000-0000-7000-8000-000000000999'],
    ['incident_version', 3],
  ])('rejects validation-attempt %s binding drift', (field, value) => {
    expect(() =>
      decodePolicyDetail(
        policyWithValidationAttempt({
          ...INVALID_VALIDATION_ATTEMPT,
          [field]: value,
        }),
      ),
    ).toThrow(/frozen contract/);
  });

  it.each([
    [
      'unknown field',
      { ...INVALID_VALIDATION_ATTEMPT, raw_snapshot: 'must-not-cross' },
    ],
    [
      'missing prepared digest',
      (() => {
        const value = structuredClone(INVALID_VALIDATION_ATTEMPT) as Record<
          string,
          unknown
        >;
        delete value.prepared_snapshot_digest;
        return value;
      })(),
    ],
    [
      'malformed prepared digest',
      { ...INVALID_VALIDATION_ATTEMPT, prepared_snapshot_digest: 'secret' },
    ],
    [
      'malformed gate digest',
      {
        ...INVALID_VALIDATION_ATTEMPT,
        gates: INVALID_VALIDATION_ATTEMPT.gates.map((gate, index) =>
          index === 2 ? { ...gate, artifact_digest: 'secret' } : gate,
        ),
      },
    ],
    [
      'out-of-order gate',
      {
        ...INVALID_VALIDATION_ATTEMPT,
        gates: INVALID_VALIDATION_ATTEMPT.gates.map((gate, index) =>
          index === 2 ? { ...gate, order: 4 } : gate,
        ),
      },
    ],
    [
      'wrong gate name',
      {
        ...INVALID_VALIDATION_ATTEMPT,
        gates: INVALID_VALIDATION_ATTEMPT.gates.map((gate, index) =>
          index === 2 ? { ...gate, name: 'historical_impact' } : gate,
        ),
      },
    ],
    [
      'passed gate with failure result',
      {
        ...INVALID_VALIDATION_ATTEMPT,
        gates: INVALID_VALIDATION_ATTEMPT.gates.map((gate, index) =>
          index === 2 ? { ...gate, result_code: 'unexpected' } : gate,
        ),
      },
    ],
    [
      'failed gate with ok result',
      {
        ...INVALID_VALIDATION_ATTEMPT,
        gates: INVALID_VALIDATION_ATTEMPT.gates.map((gate, index) =>
          index === 5 ? { ...gate, result_code: 'ok' } : gate,
        ),
      },
    ],
    [
      'failure code mismatch',
      { ...INVALID_VALIDATION_ATTEMPT, failure_code: 'different_failure' },
    ],
    [
      'failed gate mismatch',
      { ...INVALID_VALIDATION_ATTEMPT, failed_gate: 'protected_network' },
    ],
    [
      'invalid attempt missing terminal digest',
      (() => {
        const value = structuredClone(INVALID_VALIDATION_ATTEMPT) as Record<
          string,
          unknown
        >;
        delete value.terminal_mutation_digest;
        return value;
      })(),
    ],
    [
      'interrupted attempt with failed gate authority',
      {
        ...INTERRUPTED_VALIDATION_ATTEMPT,
        failed_gate: 'protected_network',
      },
    ],
    [
      'interrupted attempt with terminal mutation',
      {
        ...INTERRUPTED_VALIDATION_ATTEMPT,
        terminal_mutation_digest: `sha256:${'f'.repeat(64)}`,
      },
    ],
  ])('rejects malformed validation attempt: %s', (_name, attempt) => {
    expect(() =>
      decodePolicyDetail(policyWithValidationAttempt(attempt)),
    ).toThrow(/frozen contract/);
  });

  it('rejects additional fields and inconsistent incident state shapes', () => {
    expect(() =>
      decodeIncidentPage({
        ...INCIDENT_PAGE,
        raw_log: 'must not cross the management contract',
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeIncidentPage({
        items: [{ ...INCIDENT_PAGE.items[0], state: 'closed' }],
      }),
    ).toThrow(/frozen contract/);
  });

  it('decodes exact OpenAI Responses and deterministic stub provenance', () => {
    const openAI = decodeIncidentDetail(
      incidentDetail(structuredClone(OPENAI_ANALYSIS_SUMMARY)),
    );
    const stub = decodeIncidentDetail(
      incidentDetail(structuredClone(STUB_ANALYSIS_SUMMARY)),
    );

    expect(openAI.latest_analysis).toMatchObject({
      provider_kind: 'openai_responses',
      adapter_id: 'openai-responses-v1',
      model: 'gpt-5.6-sol',
      reasoning_effort: 'medium',
      rate_card_version: 'openai-demo-2026-07-18',
    });
    expect(stub.latest_analysis).toMatchObject({
      provider_kind: 'deterministic_stub',
      adapter_id: 'sentinelflow-deterministic-ai-stub-v1',
      model: null,
      reasoning_effort: null,
      rate_card_version: null,
    });
    expect(Object.isFrozen(openAI.latest_analysis)).toBe(true);
    expect(Object.isFrozen(stub.latest_analysis)).toBe(true);
  });

  it.each([
    ['started OpenAI', STARTED_OPENAI_ANALYSIS, 'started'],
    ['started stub', STARTED_STUB_ANALYSIS, 'started'],
    ['succeeded OpenAI', OPENAI_ANALYSIS_SUMMARY, 'succeeded'],
    ['succeeded stub', STUB_ANALYSIS_SUMMARY, 'succeeded'],
    ['failed OpenAI', FAILED_OPENAI_ANALYSIS, 'failed'],
    ['failed stub', FAILED_STUB_ANALYSIS, 'failed'],
  ] as const)(
    'decodes and deeply freezes the %s state variant',
    (_name, candidate, expectedState) => {
      const decoded = decodeIncidentDetail(
        incidentDetail(structuredClone(candidate)),
      );

      expect(decoded.latest_analysis?.result_state).toBe(expectedState);
      expect(Object.isFrozen(decoded.latest_analysis)).toBe(true);
      expect(
        Object.isFrozen(decoded.latest_analysis?.false_positive_factors),
      ).toBe(true);
    },
  );

  it.each([
    ['failure_code', 'timeout'],
    ['output_digest', `sha256:${'e'.repeat(64)}`],
    ['summary', 'A terminal summary must not exist yet.'],
    ['classification', 'brute_force'],
    ['confidence', '0.5'],
    ['uncertainty', 'No terminal uncertainty exists yet.'],
    ['completed_at', '2026-07-18T01:03:01Z'],
  ])('rejects the %s terminal field on a started analysis', (field, value) => {
    expect(() =>
      decodeIncidentDetail(
        incidentDetail({ ...STARTED_OPENAI_ANALYSIS, [field]: value }),
      ),
    ).toThrow(/frozen contract/);
  });

  it.each([
    ['output_digest', `sha256:${'e'.repeat(64)}`],
    ['summary', 'A failed analysis cannot carry a success summary.'],
    ['classification', 'brute_force'],
    ['confidence', '0.5'],
    ['uncertainty', 'A failed analysis cannot carry success uncertainty.'],
  ])('rejects the %s success field on a failed analysis', (field, value) => {
    expect(() =>
      decodeIncidentDetail(
        incidentDetail({ ...FAILED_OPENAI_ANALYSIS, [field]: value }),
      ),
    ).toThrow(/frozen contract/);
  });

  it('rejects a failure field on a succeeded analysis', () => {
    expect(() =>
      decodeIncidentDetail(
        incidentDetail({
          ...OPENAI_ANALYSIS_SUMMARY,
          failure_code: 'timeout',
        }),
      ),
    ).toThrow(/frozen contract/);
  });

  it.each(['failure_code', 'completed_at'])(
    'rejects a failed analysis missing %s',
    (field) => {
      const candidate = { ...FAILED_OPENAI_ANALYSIS } as Record<
        string,
        unknown
      >;
      delete candidate[field];
      expect(() => decodeIncidentDetail(incidentDetail(candidate))).toThrow(
        /frozen contract/,
      );
    },
  );

  it.each([
    'output_digest',
    'summary',
    'classification',
    'confidence',
    'uncertainty',
    'completed_at',
  ])('rejects a succeeded analysis missing %s', (field) => {
    const candidate = { ...OPENAI_ANALYSIS_SUMMARY } as Record<string, unknown>;
    delete candidate[field];
    expect(() => decodeIncidentDetail(incidentDetail(candidate))).toThrow(
      /frozen contract/,
    );
  });

  it.each([
    [
      'failed seconds ordering',
      { ...FAILED_OPENAI_ANALYSIS, completed_at: '2026-07-18T01:03:59Z' },
    ],
    [
      'succeeded seconds ordering',
      { ...OPENAI_ANALYSIS_SUMMARY, completed_at: '2026-07-18T01:00:59Z' },
    ],
    [
      'failed nanosecond ordering',
      {
        ...FAILED_OPENAI_ANALYSIS,
        started_at: '2026-07-18T01:04:00.000000002Z',
        completed_at: '2026-07-18T01:04:00.000000001Z',
      },
    ],
  ])('rejects %s when completed_at precedes started_at', (_name, candidate) => {
    expect(() => decodeIncidentDetail(incidentDetail(candidate))).toThrow(
      /frozen contract/,
    );
  });

  it('accepts the succeeded schema boundaries and equal completion time', () => {
    const candidate = {
      ...STUB_ANALYSIS_SUMMARY,
      confidence: `0.${'0'.repeat(62)}`,
      uncertainty: '',
      false_positive_factors: ['a', 'b', 'c', 'd', 'e'],
    };

    const decoded = decodeIncidentDetail(incidentDetail(candidate));
    expect(decoded.latest_analysis?.result_state).toBe('succeeded');
  });

  it.each([
    [
      'unknown provider',
      { ...OPENAI_ANALYSIS_SUMMARY, provider_kind: 'unknown_provider' },
    ],
    [
      'wrong OpenAI adapter',
      { ...OPENAI_ANALYSIS_SUMMARY, adapter_id: 'spoofed-adapter' },
    ],
    [
      'missing OpenAI rate card',
      { ...OPENAI_ANALYSIS_SUMMARY, rate_card_version: null },
    ],
    ['nullable OpenAI model', { ...OPENAI_ANALYSIS_SUMMARY, model: null }],
    [
      'nullable OpenAI reasoning effort',
      { ...OPENAI_ANALYSIS_SUMMARY, reasoning_effort: null },
    ],
    ['spoofed stub model', { ...STUB_ANALYSIS_SUMMARY, model: 'gpt-5.6-sol' }],
    [
      'spoofed stub reasoning',
      { ...STUB_ANALYSIS_SUMMARY, reasoning_effort: 'medium' },
    ],
    [
      'spoofed stub rate card',
      { ...STUB_ANALYSIS_SUMMARY, rate_card_version: 'fake-cost-v1' },
    ],
    ['spoofed stub token cost', { ...STUB_ANALYSIS_SUMMARY, input_tokens: 10 }],
    [
      'extra provider field',
      { ...OPENAI_ANALYSIS_SUMMARY, provider_label: 'OpenAI' },
    ],
  ])('rejects %s', (_name, candidate) => {
    expect(() => decodeIncidentDetail(incidentDetail(candidate))).toThrow(
      /frozen contract/,
    );
  });

  it.each([
    'provider_kind',
    'adapter_id',
    'model',
    'reasoning_effort',
    'rate_card_version',
  ])('rejects an omitted required analysis field: %s', (field) => {
    const candidate = { ...OPENAI_ANALYSIS_SUMMARY } as Record<string, unknown>;
    delete candidate[field];
    expect(() => decodeIncidentDetail(incidentDetail(candidate))).toThrow(
      /frozen contract/,
    );
  });

  it('binds SSE type, resource identity, canonical s1 ID, and payload', () => {
    const event = decodeStreamEvent(
      's1.0000000000000002',
      'incident.updated',
      structuredClone(STREAM_PAYLOAD),
    );
    expect(event.resource_version).toBe(2);
    expect(Object.isFrozen(event.summary)).toBe(true);

    expect(() =>
      decodeStreamEvent('s1.0000000000000002', 'incident.updated', {
        ...STREAM_PAYLOAD,
        resource_id: '019b0000-0000-7000-8000-000000000999',
      }),
    ).toThrow(/frozen contract/);
  });

  it('decodes exact HIL challenge, rotated decision, and replay envelopes', () => {
    const challenge = decodeHILChallengeEnvelope(
      structuredClone(HIL_CHALLENGE_ENVELOPE),
    );
    const decision = decodeHILDecisionEnvelope(
      structuredClone(HIL_DECISION_ENVELOPE),
    );
    const replay = decodeHILDecisionEnvelope(
      structuredClone(HIL_REPLAY_DECISION_ENVELOPE),
    );

    expect(Object.isFrozen(challenge.challenge)).toBe(true);
    expect(JSON.stringify(challenge.challenge)).toBe(
      JSON.stringify(HIL_CHALLENGE_ENVELOPE.challenge),
    );
    expect(decision.action_id).toBe(HIL_DECISION_ENVELOPE.action_id);
    expect('session' in decision && Object.isFrozen(decision.session)).toBe(
      true,
    );
    expect('replayed' in replay && replay.replayed).toBe(true);
    expect('session' in replay).toBe(false);
  });

  it('rejects HIL nonce, authority, and additional-field drift', () => {
    expect(() =>
      decodeHILChallengeEnvelope({
        ...HIL_CHALLENGE_ENVELOPE,
        challenge_nonce: 'short',
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILChallengeEnvelope({
        ...HIL_CHALLENGE_ENVELOPE,
        challenge: {
          ...HIL_CHALLENGE_ENVELOPE.challenge,
          browser_generated_digest: `sha256:${'f'.repeat(64)}`,
        },
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILDecisionEnvelope({
        ...HIL_DECISION_ENVELOPE,
        decision: {
          ...HIL_DECISION_ENVELOPE.decision,
          operation: 'reject',
          decision: 'rejected',
        },
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILDecisionEnvelope({
        ...HIL_REPLAY_DECISION_ENVELOPE,
        replayed: false,
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILDecisionEnvelope({
        ...HIL_REPLAY_DECISION_ENVELOPE,
        reauthentication_required: false,
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILDecisionEnvelope({
        ...HIL_REPLAY_DECISION_ENVELOPE,
        csrf_token: SESSION_ENVELOPE.csrf_token,
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILDecisionEnvelope({
        ...HIL_REPLAY_DECISION_ENVELOPE,
        session: SESSION_ENVELOPE.session,
      }),
    ).toThrow(/frozen contract/);
    expect(() =>
      decodeHILDecisionEnvelope({
        ...HIL_DECISION_ENVELOPE,
        replayed: true,
        reauthentication_required: true,
      }),
    ).toThrow(/frozen contract/);
  });

  it('decodes and freezes exact revocation challenge, rotation, and historical replay variants', () => {
    const challenge = decodeRevocationChallengeEnvelope(
      structuredClone(REVOCATION_CHALLENGE_ENVELOPE),
    );
    const decision = decodeRevocationDecisionEnvelope(
      structuredClone(REVOCATION_DECISION_ENVELOPE),
    );
    const replay = decodeRevocationDecisionEnvelope(
      structuredClone(REVOCATION_REPLAY_DECISION_ENVELOPE),
    );

    expect(Object.isFrozen(challenge.challenge)).toBe(true);
    expect(challenge.challenge.operation).toBe('revoke');
    expect(challenge.challenge.resource_type).toBe('enforcement_action');
    expect(challenge.canonical_revoke_artifact.endsWith('\n')).toBe(true);
    expect(decision.decision.decision).toBe('revoked');
    expect('session' in decision && Object.isFrozen(decision.session)).toBe(
      true,
    );
    expect('replayed' in replay && replay.replayed).toBe(true);
    expect('session' in replay).toBe(false);
    expect('csrf_token' in replay).toBe(false);
  });

  it.each([
    [
      'unknown challenge field',
      {
        ...REVOCATION_CHALLENGE_ENVELOPE,
        raw_signature: 'must-not-cross',
      },
      'challenge',
    ],
    [
      'wrong operation',
      {
        ...REVOCATION_CHALLENGE_ENVELOPE,
        challenge: {
          ...REVOCATION_CHALLENGE_ENVELOPE.challenge,
          operation: 'approve',
        },
      },
      'challenge',
    ],
    [
      'non-canonical delete bytes',
      {
        ...REVOCATION_CHALLENGE_ENVELOPE,
        canonical_revoke_artifact:
          REVOCATION_CHALLENGE_ENVELOPE.canonical_revoke_artifact.trimEnd(),
      },
      'challenge',
    ],
    [
      'fresh credentials in replay',
      {
        ...REVOCATION_REPLAY_DECISION_ENVELOPE,
        session: REVOCATION_DECISION_ENVELOPE.session,
        csrf_token: REVOCATION_DECISION_ENVELOPE.csrf_token,
      },
      'decision',
    ],
    [
      'replay marker in fresh result',
      {
        ...REVOCATION_DECISION_ENVELOPE,
        replayed: true,
        reauthentication_required: true,
      },
      'decision',
    ],
    [
      'additional decision field',
      {
        ...REVOCATION_DECISION_ENVELOPE,
        decision: {
          ...REVOCATION_DECISION_ENVELOPE.decision,
          capability_signature: 'must-not-cross',
        },
      },
      'decision',
    ],
  ] as const)('rejects revocation %s', (_name, candidate, decoder) => {
    expect(() =>
      decoder === 'challenge'
        ? decodeRevocationChallengeEnvelope(candidate)
        : decodeRevocationDecisionEnvelope(candidate),
    ).toThrow(/frozen contract/);
  });
});
