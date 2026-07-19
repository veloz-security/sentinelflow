import type { AnalysisSummary } from './contracts';

export const SESSION_ENVELOPE = Object.freeze({
  session: Object.freeze({
    actor_id: 'admin',
    session_id: '019b0000-0000-7000-8000-000000000001',
    authenticated_at: '2026-07-18T01:00:00Z',
    expires_at: '2026-07-18T09:00:00Z',
  }),
  csrf_token: 'a'.repeat(43),
});

export const INCIDENT_PAGE = Object.freeze({
  items: Object.freeze([
    Object.freeze({
      incident_id: '019b0000-0000-7000-8000-000000000101',
      kind: 'brute_force',
      state: 'open',
      source_ip: '203.0.113.20',
      service_label: 'demo_app',
      first_seen: '2026-07-18T01:00:00Z',
      last_seen: '2026-07-18T01:01:00Z',
      deterministic_score: '0.90000',
      version: 2,
      created_at: '2026-07-18T01:00:00Z',
      updated_at: '2026-07-18T01:01:00Z',
    }),
  ]),
  next_cursor: 'incident_cursor_2',
});

export const OPENAI_ANALYSIS_SUMMARY = Object.freeze({
  analysis_id: '019b0000-0000-7000-8000-000000000110',
  incident_version: 2,
  provider_kind: 'openai_responses',
  adapter_id: 'openai-responses-v1',
  model: 'gpt-5.6-sol',
  reasoning_effort: 'medium',
  rate_card_version: 'openai-demo-2026-07-18',
  result_state: 'succeeded',
  output_digest: `sha256:${'c'.repeat(64)}`,
  summary: 'OpenAI Responses analysis of the bounded synthetic incident.',
  classification: 'brute_force',
  confidence: '0.94000',
  uncertainty: 'Synthetic demo traffic may not represent production traffic.',
  started_at: '2026-07-18T01:01:00Z',
  completed_at: '2026-07-18T01:01:02Z',
  false_positive_factors: Object.freeze(['Synthetic demo source range']),
} satisfies AnalysisSummary);

export const STUB_ANALYSIS_SUMMARY = Object.freeze({
  analysis_id: '019b0000-0000-7000-8000-000000000111',
  incident_version: 2,
  provider_kind: 'deterministic_stub',
  adapter_id: 'sentinelflow-deterministic-ai-stub-v1',
  model: null,
  reasoning_effort: null,
  rate_card_version: null,
  result_state: 'succeeded',
  output_digest: `sha256:${'d'.repeat(64)}`,
  summary: 'Deterministic offline analysis of the bounded synthetic incident.',
  classification: 'path_scan',
  confidence: '0.80000',
  uncertainty: 'Static deterministic adapter output for local verification.',
  started_at: '2026-07-18T01:02:00Z',
  completed_at: '2026-07-18T01:02:00Z',
  false_positive_factors: Object.freeze(['Static offline adapter']),
} satisfies AnalysisSummary);

export const API_ERROR = Object.freeze({
  code: 'rate_limited',
  message: 'request rate limit exceeded',
  trace_id: '019b0000-0000-4000-8000-000000000201',
  details: Object.freeze({}),
});

export const STREAM_PAYLOAD = Object.freeze({
  resource_id: '019b0000-0000-7000-8000-000000000101',
  resource_version: 2,
  incident_id: '019b0000-0000-7000-8000-000000000101',
  occurred_at: '2026-07-18T01:01:00Z',
  trace_id: '019b0000-0000-4000-8000-000000000202',
  summary: Object.freeze({ code: 'incident_updated', outcome: 'open' }),
});

const digest = (character: string) => `sha256:${character.repeat(64)}`;

export const POLICY_ID = '019b0000-0000-7000-8000-000000000301';
export const ACTION_ID = '019b0000-0000-7000-8000-000000000302';
export const HIL_IDEMPOTENCY_KEY = 'hil-019b0000-0000-7000-8000-000000000777';

export const POLICY_DETAIL = Object.freeze({
  policy_id: POLICY_ID,
  version: 1,
  incident_id: INCIDENT_PAGE.items[0].incident_id,
  incident_version: 2,
  analysis_id: '019b0000-0000-7000-8000-000000000303',
  command_candidate_id: '019b0000-0000-7000-8000-000000000304',
  state: 'valid',
  state_revision: 3,
  target_ipv4: '203.0.113.20',
  action: 'block_ip',
  ttl_seconds: 1800,
  timeout_token: '30m',
  rationale: 'Synthetic evidence indicates a bounded test attack.',
  policy_digest: digest('1'),
  evidence_snapshot_digest: digest('2'),
  generated_command:
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n',
  generated_artifact_digest:
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
  canonical_command:
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n',
  canonical_artifact_digest:
    'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6',
  parse_state: 'valid',
  created_at: '2026-07-18T01:01:00Z',
  updated_at: '2026-07-18T01:02:00Z',
  latest_validation: Object.freeze({
    validation_snapshot_id: '019b0000-0000-7000-8000-000000000305',
    snapshot_digest: digest('5'),
    state: 'valid',
    source_health_status: 'complete',
    base_chain_contract_raw_digest: digest('6'),
    live_owned_schema_digest: digest('7'),
    protected_ipv4_static_digest: digest('8'),
    protected_ipv4_effective_config_digest: digest('9'),
    historical_impact_digest: digest('a'),
    created_at: '2026-07-18T01:02:00Z',
    valid_until: '2026-07-18T01:07:00Z',
    gates: Object.freeze(
      [
        'structured_output',
        'command_grammar',
        'policy_evidence_command_consistency',
        'protected_network',
        'owned_schema_syntax',
        'historical_impact',
      ].map((name, index) =>
        Object.freeze({
          order: index + 1,
          name,
          passed: true,
          result_code: 'ok',
          input_digest: digest(String((index + 1) % 10)),
          result_digest: digest(String((index + 2) % 10)),
          checked_at: '2026-07-18T01:02:00Z',
        }),
      ),
    ),
  }),
});

export const INVALID_VALIDATION_ATTEMPT = Object.freeze({
  validation_attempt_id: '019b0000-0000-7000-8000-000000000310',
  policy_id: POLICY_DETAIL.policy_id,
  analysis_id: POLICY_DETAIL.analysis_id,
  incident_id: POLICY_DETAIL.incident_id,
  incident_version: POLICY_DETAIL.incident_version,
  state: 'invalid',
  failure_code: 'history_demo_binding_mismatch',
  failed_gate: 'historical_impact',
  prepared_snapshot_digest: digest('b'),
  terminal_mutation_digest: digest('c'),
  completed_at: '2026-07-18T01:02:00Z',
  gates: Object.freeze(
    [
      'structured_output',
      'command_grammar',
      'policy_evidence_command_consistency',
      'protected_network',
      'owned_schema_syntax',
      'historical_impact',
    ].map((name, index) =>
      Object.freeze({
        order: index + 1,
        name,
        state: index === 5 ? 'failed' : 'passed',
        result_code: index === 5 ? 'history_demo_binding_mismatch' : 'ok',
        artifact_digest: digest(String((index + 3) % 10)),
      }),
    ),
  ),
});

export const INTERRUPTED_VALIDATION_ATTEMPT = Object.freeze({
  validation_attempt_id: '019b0000-0000-7000-8000-000000000311',
  policy_id: POLICY_DETAIL.policy_id,
  analysis_id: POLICY_DETAIL.analysis_id,
  incident_id: POLICY_DETAIL.incident_id,
  incident_version: POLICY_DETAIL.incident_version,
  state: 'interrupted',
  failure_code: 'validation_attempt_timeout',
  prepared_snapshot_digest: digest('d'),
  completed_at: '2026-07-18T01:02:00Z',
  gates: Object.freeze(
    INVALID_VALIDATION_ATTEMPT.gates.slice(0, 3).map((gate) =>
      Object.freeze({
        ...gate,
        state: 'passed',
        result_code: 'ok',
      }),
    ),
  ),
});

export const HIL_CHALLENGE_ENVELOPE = Object.freeze({
  challenge: Object.freeze({
    authenticated_at: '2026-07-18T01:00:00Z',
    canonical_artifact_digest: POLICY_DETAIL.canonical_artifact_digest,
    challenge_id: '019b0000-0000-7000-8000-000000000306',
    evidence_snapshot_digest: POLICY_DETAIL.evidence_snapshot_digest,
    expires_at: '2026-07-18T01:07:00Z',
    generated_artifact_digest: POLICY_DETAIL.generated_artifact_digest,
    issued_at: '2026-07-18T01:03:00Z',
    nonce_digest:
      'sha256:60bf07c488aad18fda339df07e4fbc47b4f00be71711936f18d04d352ad01890',
    operation: 'approve',
    original_add_digest: null,
    policy_digest: POLICY_DETAIL.policy_digest,
    reauth_required_after_seconds: 900,
    resource_id: POLICY_ID,
    resource_type: 'policy',
    resource_version: 1,
    schema_version: 'hil-challenge-v1',
    session_digest: digest('b'),
    target_ipv4: POLICY_DETAIL.target_ipv4,
    validation_snapshot_digest: POLICY_DETAIL.latest_validation.snapshot_digest,
    validation_valid_until: POLICY_DETAIL.latest_validation.valid_until,
  }),
  challenge_nonce: 'WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo',
});

export const HIL_DECISION_ENVELOPE = Object.freeze({
  decision: Object.freeze({
    actor_id: 'admin',
    canonical_artifact_digest: POLICY_DETAIL.canonical_artifact_digest,
    challenge_id: HIL_CHALLENGE_ENVELOPE.challenge.challenge_id,
    decided_at: '2026-07-18T01:04:00Z',
    decision: 'approved',
    decision_id: '019b0000-0000-7000-8000-000000000307',
    decision_valid_until: '2026-07-18T01:07:00Z',
    evidence_snapshot_digest: POLICY_DETAIL.evidence_snapshot_digest,
    generated_artifact_digest: POLICY_DETAIL.generated_artifact_digest,
    idempotency_key_digest:
      'sha256:b8dbee625fc2058e5cd3d1988767e9e93b8a6bfdc02b5369f0fdc7c975599b3e',
    nonce_digest: HIL_CHALLENGE_ENVELOPE.challenge.nonce_digest,
    operation: 'approve',
    original_add_digest: null,
    policy_digest: POLICY_DETAIL.policy_digest,
    reason_digest:
      'sha256:ac5aa056d44247403e7c2247696f87a73ac5cbf8b832c23239641f4cd2985603',
    resource_id: POLICY_ID,
    resource_type: 'policy',
    resource_version: 1,
    schema_version: 'hil-decision-v1',
    session_digest: HIL_CHALLENGE_ENVELOPE.challenge.session_digest,
    target_ipv4: POLICY_DETAIL.target_ipv4,
    validation_snapshot_digest: POLICY_DETAIL.latest_validation.snapshot_digest,
  }),
  action_id: ACTION_ID,
  authorization_digest: digest('e'),
  outbox_job_id: '019b0000-0000-7000-8000-000000000308',
  session: Object.freeze({
    ...SESSION_ENVELOPE.session,
    session_id: '019b0000-0000-7000-8000-000000000309',
  }),
  csrf_token: 'b'.repeat(43),
});

export const HIL_REPLAY_DECISION_ENVELOPE = Object.freeze({
  decision: HIL_DECISION_ENVELOPE.decision,
  action_id: HIL_DECISION_ENVELOPE.action_id,
  authorization_digest: HIL_DECISION_ENVELOPE.authorization_digest,
  outbox_job_id: HIL_DECISION_ENVELOPE.outbox_job_id,
  replayed: true,
  reauthentication_required: true,
});

export const ACTIVE_ENFORCEMENT_ACTION = Object.freeze({
  action_id: ACTION_ID,
  policy_id: POLICY_ID,
  policy_version: 1,
  validation_snapshot_id:
    POLICY_DETAIL.latest_validation.validation_snapshot_id,
  evidence_snapshot_digest: POLICY_DETAIL.evidence_snapshot_digest,
  target_ipv4: POLICY_DETAIL.target_ipv4,
  canonical_artifact_digest: POLICY_DETAIL.canonical_artifact_digest,
  ttl_seconds: POLICY_DETAIL.ttl_seconds,
  state: 'active',
  approved_at: '2026-07-18T01:04:00Z',
  queued_at: '2026-07-18T01:04:01Z',
  applied_at: '2026-07-18T01:04:02Z',
  expected_expires_at: '2026-07-18T01:34:02Z',
  version: 3,
  created_at: '2026-07-18T01:04:00Z',
  updated_at: '2026-07-18T01:04:02Z',
});

export const REVOCATION_ARTIFACT =
  'delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n';
export const REVOCATION_ARTIFACT_DIGEST =
  'sha256:85847c58f49d2e055c5547554fb78b1bfe370c826393cf705a3456d7ca2d1cd4';

export const REVOCATION_CHALLENGE_ENVELOPE = Object.freeze({
  challenge: Object.freeze({
    authenticated_at: SESSION_ENVELOPE.session.authenticated_at,
    canonical_artifact_digest: REVOCATION_ARTIFACT_DIGEST,
    challenge_id: '019b0000-0000-7000-8000-000000000401',
    evidence_snapshot_digest: POLICY_DETAIL.evidence_snapshot_digest,
    expires_at: '2026-07-18T01:07:00Z',
    generated_artifact_digest: REVOCATION_ARTIFACT_DIGEST,
    issued_at: '2026-07-18T01:03:00Z',
    nonce_digest:
      'sha256:60bf07c488aad18fda339df07e4fbc47b4f00be71711936f18d04d352ad01890',
    operation: 'revoke',
    original_add_digest: ACTIVE_ENFORCEMENT_ACTION.canonical_artifact_digest,
    policy_digest: POLICY_DETAIL.policy_digest,
    reauth_required_after_seconds: 900,
    resource_id: ACTION_ID,
    resource_type: 'enforcement_action',
    resource_version: ACTIVE_ENFORCEMENT_ACTION.version,
    schema_version: 'hil-challenge-v1',
    session_digest: digest('c'),
    target_ipv4: ACTIVE_ENFORCEMENT_ACTION.target_ipv4,
    validation_snapshot_digest: POLICY_DETAIL.latest_validation.snapshot_digest,
    validation_valid_until: POLICY_DETAIL.latest_validation.valid_until,
  }),
  challenge_nonce: HIL_CHALLENGE_ENVELOPE.challenge_nonce,
  canonical_revoke_artifact: REVOCATION_ARTIFACT,
  policy_id: POLICY_ID,
  policy_version: POLICY_DETAIL.version,
});

export const REVOCATION_REASON = Object.freeze({
  schema_version: 'hil-reason-v1',
  reason_code: 'operator_request',
  reason_text: 'Remove the synthetic block',
});

export const REVOCATION_DECISION_ENVELOPE = Object.freeze({
  decision: Object.freeze({
    actor_id: SESSION_ENVELOPE.session.actor_id,
    canonical_artifact_digest: REVOCATION_ARTIFACT_DIGEST,
    challenge_id: REVOCATION_CHALLENGE_ENVELOPE.challenge.challenge_id,
    decided_at: '2026-07-18T01:04:00Z',
    decision: 'revoked',
    decision_id: '019b0000-0000-7000-8000-000000000402',
    decision_valid_until: '2026-07-18T01:07:00Z',
    evidence_snapshot_digest: POLICY_DETAIL.evidence_snapshot_digest,
    generated_artifact_digest: REVOCATION_ARTIFACT_DIGEST,
    idempotency_key_digest:
      'sha256:b8dbee625fc2058e5cd3d1988767e9e93b8a6bfdc02b5369f0fdc7c975599b3e',
    nonce_digest: REVOCATION_CHALLENGE_ENVELOPE.challenge.nonce_digest,
    operation: 'revoke',
    original_add_digest: ACTIVE_ENFORCEMENT_ACTION.canonical_artifact_digest,
    policy_digest: POLICY_DETAIL.policy_digest,
    reason_digest:
      'sha256:458970a8a58a91a4e250acaee99356d160900b85fc2d8ded331278d6e344278e',
    resource_id: ACTION_ID,
    resource_type: 'enforcement_action',
    resource_version: ACTIVE_ENFORCEMENT_ACTION.version,
    schema_version: 'hil-decision-v1',
    session_digest: REVOCATION_CHALLENGE_ENVELOPE.challenge.session_digest,
    target_ipv4: ACTIVE_ENFORCEMENT_ACTION.target_ipv4,
    validation_snapshot_digest: POLICY_DETAIL.latest_validation.snapshot_digest,
  }),
  revocation_id: '019b0000-0000-7000-8000-000000000403',
  authorization_id: '019b0000-0000-7000-8000-000000000404',
  authorization_digest:
    'sha256:fc6bf1432fe08ce6a0c74e67dd11e82c4a05de74b93248a914939b957f29ac52',
  outbox_job_id: '019b0000-0000-7000-8000-000000000405',
  audit_event_id: '019b0000-0000-7000-8000-000000000406',
  session: Object.freeze({
    ...SESSION_ENVELOPE.session,
    session_id: '019b0000-0000-7000-8000-000000000407',
  }),
  csrf_token: 'd'.repeat(43),
});

export const REVOCATION_REPLAY_DECISION_ENVELOPE = Object.freeze({
  decision: REVOCATION_DECISION_ENVELOPE.decision,
  revocation_id: REVOCATION_DECISION_ENVELOPE.revocation_id,
  authorization_id: REVOCATION_DECISION_ENVELOPE.authorization_id,
  authorization_digest: REVOCATION_DECISION_ENVELOPE.authorization_digest,
  outbox_job_id: REVOCATION_DECISION_ENVELOPE.outbox_job_id,
  audit_event_id: REVOCATION_DECISION_ENVELOPE.audit_event_id,
  replayed: true,
  reauthentication_required: true,
});
