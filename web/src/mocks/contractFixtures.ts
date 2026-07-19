import type {
  AuditEventV1,
  ApiErrorV1,
  EnforcementLifecycleV1,
  HilReviewStateV1,
  IncidentDetailV1,
  IncidentSummaryV1,
} from '../contracts/apiDtos';
import type {
  ResourceState,
  ResourceStateKind,
} from '../contracts/resourceState';
import type {
  AuthEventV1,
  DeterministicSignalV1,
  ExecutionResultV1,
  GatewayHttpV1,
  HilChallengeV1,
  HilDecisionV1,
  HilReasonV1,
  ResponsePolicyV1,
  SentinelFlowAnalysisV1,
  Sha256Digest,
  SourceHealthV1,
  ValidationSnapshotV1,
} from '../contracts/rootContracts';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

const digest = (character: string) =>
  `sha256:${character.repeat(64)}` as Sha256Digest;

const ids = Object.freeze({
  incident: '019b0000-0000-7000-8000-000000000601',
  event: '019b0000-0000-7000-8000-000000000602',
  request: '019b0000-0000-7000-8000-000000000603',
  trace: '019b0000-0000-7000-8000-000000000604',
  signal: '019b0000-0000-7000-8000-000000000605',
  analysis: '019b0000-0000-7000-8000-000000000606',
  policy: '019b0000-0000-7000-8000-000000000607',
  validation: '019b0000-0000-7000-8000-000000000608',
  challenge: '019b0000-0000-7000-8000-000000000609',
  decision: '019b0000-0000-7000-8000-000000000610',
  action: '019b0000-0000-7000-8000-000000000611',
  resultAdd: '019b0000-0000-7000-8000-000000000612',
  capabilityAdd: '019b0000-0000-7000-8000-000000000613',
  audit: '019b0000-0000-7000-8000-000000000614',
  operationAdd: '019b0000-0000-7000-8000-000000000615',
  resultInspect: '019b0000-0000-7000-8000-000000000616',
  capabilityInspect: '019b0000-0000-7000-8000-000000000617',
  operationInspect: '019b0000-0000-7000-8000-000000000618',
  resultRevoke: '019b0000-0000-7000-8000-000000000619',
  capabilityRevoke: '019b0000-0000-7000-8000-000000000620',
  operationRevoke: '019b0000-0000-7000-8000-000000000621',
  authEvent: '019b0000-0000-7000-8000-000000000625',
});

export const MOCK_GATEWAY_EVENT: GatewayHttpV1 = deepFreeze({
  schema_version: 'gateway-http-v1',
  event_id: ids.event,
  request_id: ids.request,
  trace_id: ids.trace,
  idempotency_key: digest('1'),
  started_at: '2026-07-18T01:01:00Z',
  completed_at: '2026-07-18T01:01:00.025Z',
  source_ip: '203.0.113.20',
  method: 'GET',
  protocol: 'HTTP/1.1',
  route_label: 'login',
  path_catalog_version: 'path-catalog-v1',
  suspicious_path_id: 'none',
  host: 'demo.internal',
  service_label: 'demo-app',
  status_code: 401,
  request_bytes: 0,
  response_bytes: 128,
  latency_ms: 25,
});

export const MOCK_AUTH_EVENT: AuthEventV1 = deepFreeze({
  schema_version: 'auth-event-v1',
  event_id: ids.authEvent,
  gateway_request_id: ids.request,
  trace_id: ids.trace,
  idempotency_key: digest('d'),
  occurred_at: '2026-07-18T01:01:00.020Z',
  source_ip: '203.0.113.20',
  service_label: 'demo-app',
  route_label: 'login',
  account_hash: `hmac-sha256:${'a'.repeat(64)}`,
  outcome: 'failed',
});

export const MOCK_SOURCE_HEALTH: SourceHealthV1 = deepFreeze({
  schema_version: 'source-health-v1',
  event_id: '019b0000-0000-7000-8000-000000000622',
  idempotency_key: digest('2'),
  occurred_at: '2026-07-18T01:00:00Z',
  source_id: 'gateway.demo',
  cause: 'recovered',
  state: 'recovered',
  affected_sender_epoch: 'AAAAAAAAAAAAAAAAAAAAAA',
  sequence_start: null,
  sequence_end: null,
  interval_start: '2026-07-18T00:59:00Z',
  interval_end: '2026-07-18T01:00:00Z',
  dropped_count: 0,
  detail_code: 'delivery_restored',
});

export const MOCK_SIGNAL: DeterministicSignalV1 = deepFreeze({
  schema_version: 'deterministic-signal-view-v1',
  signal_id: ids.signal,
  rule_id: 'login_bruteforce.v1',
  classification: 'brute_force',
  window_start: '2026-07-18T01:00:00Z',
  window_end: '2026-07-18T01:01:00Z',
  event_count: 12,
  distinct_account_count: 1,
  distinct_suspicious_path_count: 0,
  evidence_digest: digest('3'),
});

export const MOCK_AI_ANALYSIS: SentinelFlowAnalysisV1 = deepFreeze({
  schema_version: 'sentinelflow_analysis_v1',
  incident_summary:
    'Repeated failed login requests matched a deterministic rule.',
  classification: 'brute_force',
  confidence: 0.84,
  uncertainty: 'The source may represent a shared test client.',
  false_positive_factors: [
    'Synthetic demo traffic may intentionally repeat logins.',
  ],
  evidence_ids: [ids.signal],
  policy: {
    schema_version: 'response-policy-v1',
    action: 'block_ip',
    target_ip: '203.0.113.20',
    ttl_seconds: 1800,
    evidence_ids: [ids.signal],
    rationale: 'Temporarily contain the source after deterministic validation.',
  },
  nftables_command_candidate: {
    schema_version: 'nft-blacklist-v1',
    target_ip: '203.0.113.20',
    timeout: '30m',
    evidence_ids: [ids.signal],
    command:
      'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
  },
});

export const MOCK_POLICY: ResponsePolicyV1 = deepFreeze({
  schema_version: 'response-policy-v1',
  policy_id: ids.policy,
  policy_version: 1,
  incident_id: ids.incident,
  analysis_id: ids.analysis,
  action: 'block_ip',
  target_ipv4: '203.0.113.20',
  ttl_seconds: 1800,
  evidence_snapshot_digest: digest('4'),
  evidence_ids: [ids.signal],
  rationale_digest: digest('5'),
  created_at: '2026-07-18T01:01:30Z',
});

export const MOCK_VALIDATION: ValidationSnapshotV1 = deepFreeze({
  schema_version: 'validation-snapshot-v1',
  validation_id: ids.validation,
  policy_digest: digest('6'),
  evidence_snapshot_digest: digest('4'),
  analysis_input_digest: digest('7'),
  analysis_output_schema_digest: digest('8'),
  prompt_digest: digest('9'),
  generated_candidate_digest: digest('a'),
  canonical_artifact_digest: digest('b'),
  grammar_version: 'nft-blacklist-v1',
  parser_version: 'parser-v1',
  validator_version: 'validator-v1',
  base_chain_contract_raw_digest: digest('c'),
  live_owned_schema_digest: digest('d'),
  protected_ipv4_static_digest: digest('e'),
  protected_ipv4_effective_config_digest: digest('f'),
  nft_binary_digest: digest('0'),
  nft_version: '1.1.1',
  historical_impact_digest: digest('1'),
  checks: [
    'structured_output',
    'command_grammar',
    'policy_evidence_command_consistency',
    'protected_network',
    'owned_schema_syntax',
    'historical_impact',
  ].map((check_id, index) => ({
    check_id: check_id as ValidationSnapshotV1['checks'][number]['check_id'],
    result: 'pass' as const,
    reason_code: 'ok' as const,
    input_digest: digest(String(index)),
  })),
  created_at: '2026-07-18T01:02:00Z',
  valid_until: '2026-07-18T01:07:00Z',
});

export const MOCK_HIL_CHALLENGE: HilChallengeV1 = deepFreeze({
  schema_version: 'hil-challenge-v1',
  challenge_id: ids.challenge,
  session_digest: digest('2'),
  operation: 'approve',
  resource_type: 'policy',
  resource_id: ids.policy,
  resource_version: 1,
  target_ipv4: '203.0.113.20',
  policy_digest: digest('6'),
  generated_artifact_digest: digest('a'),
  canonical_artifact_digest: digest('b'),
  original_add_digest: null,
  evidence_snapshot_digest: digest('4'),
  validation_snapshot_digest: digest('3'),
  validation_valid_until: '2026-07-18T01:07:00Z',
  nonce_digest: digest('4'),
  authenticated_at: '2026-07-18T01:00:00Z',
  reauth_required_after_seconds: 900,
  issued_at: '2026-07-18T01:02:30Z',
  expires_at: '2026-07-18T01:07:30Z',
});

export const MOCK_HIL_DECISION: HilDecisionV1 = deepFreeze({
  schema_version: 'hil-decision-v1',
  decision_id: ids.decision,
  challenge_id: ids.challenge,
  session_digest: digest('2'),
  operation: 'approve',
  decision: 'approved',
  resource_type: 'policy',
  resource_id: ids.policy,
  resource_version: 1,
  target_ipv4: '203.0.113.20',
  policy_digest: digest('6'),
  generated_artifact_digest: digest('a'),
  canonical_artifact_digest: digest('b'),
  original_add_digest: null,
  evidence_snapshot_digest: digest('4'),
  validation_snapshot_digest: digest('3'),
  actor_id: 'admin.demo',
  reason_digest: digest('5'),
  nonce_digest: digest('4'),
  idempotency_key_digest: digest('6'),
  decided_at: '2026-07-18T01:03:00Z',
  decision_valid_until: '2026-07-18T01:07:00Z',
});

export const MOCK_HIL_REASON: HilReasonV1 = deepFreeze({
  schema_version: 'hil-reason-v1',
  reason_code: 'threat_confirmed',
  reason_text: 'Verified evidence supports a temporary block.',
});

function executionResult(
  result: Omit<
    ExecutionResultV1,
    'schema_version' | 'action_id' | 'target_ipv4' | 'owned_schema_digest'
  >,
): ExecutionResultV1 {
  return deepFreeze({
    schema_version: 'execution-result-v1',
    action_id: ids.action,
    target_ipv4: '203.0.113.20',
    owned_schema_digest: digest('d'),
    ...result,
  });
}

export const MOCK_ADD_RESULT = executionResult({
  result_id: ids.resultAdd,
  capability_id: ids.capabilityAdd,
  capability_digest: digest('7'),
  operation: 'add',
  artifact_digest: digest('b'),
  classification: 'applied',
  nft_exit_class: 'success',
  readback_state: 'active',
  element_handle: null,
  remaining_ttl_seconds: 1800,
  started_at: '2026-07-18T01:03:05Z',
  completed_at: '2026-07-18T01:03:06Z',
  journal_sequence: 1,
  error_code: 'none',
});

export const MOCK_INSPECT_RESULT = executionResult({
  result_id: ids.resultInspect,
  capability_id: ids.capabilityInspect,
  capability_digest: digest('8'),
  operation: 'inspect',
  artifact_digest: digest('9'),
  classification: 'inspect_active',
  nft_exit_class: 'success',
  readback_state: 'active',
  element_handle: null,
  remaining_ttl_seconds: 1700,
  started_at: '2026-07-18T01:04:00Z',
  completed_at: '2026-07-18T01:04:01Z',
  journal_sequence: 2,
  error_code: 'none',
});

export const MOCK_REVOKE_RESULT = executionResult({
  result_id: ids.resultRevoke,
  capability_id: ids.capabilityRevoke,
  capability_digest: digest('a'),
  operation: 'revoke',
  artifact_digest: digest('b'),
  classification: 'revoked',
  nft_exit_class: 'success',
  readback_state: 'absent',
  element_handle: null,
  remaining_ttl_seconds: null,
  started_at: '2026-07-18T01:05:00Z',
  completed_at: '2026-07-18T01:05:01Z',
  journal_sequence: 3,
  error_code: 'none',
});

export const MOCK_HIL_REVIEW: HilReviewStateV1 = deepFreeze({
  schema_version: 'hil-review-state-v1',
  status: 'approved',
  challenge: MOCK_HIL_CHALLENGE,
  challenge_nonce_available: false,
  decision: MOCK_HIL_DECISION,
  can_request_challenge: false,
  can_submit_decision: false,
  updated_at: '2026-07-18T01:03:00Z',
});

export const MOCK_LIFECYCLE: EnforcementLifecycleV1 = deepFreeze({
  schema_version: 'enforcement-lifecycle-v1',
  action_id: ids.action,
  action_version: 3,
  policy_id: ids.policy,
  state: 'revoked',
  target_ipv4: '203.0.113.20',
  original_add_digest: digest('b'),
  approved_ttl_seconds: 1800,
  applied_at: '2026-07-18T01:03:06Z',
  expires_at: '2026-07-18T01:33:06Z',
  operations: [
    {
      operation_id: ids.operationAdd,
      operation: 'add',
      requested_at: '2026-07-18T01:03:04Z',
      signature_verification: 'verified',
      result: MOCK_ADD_RESULT,
    },
    {
      operation_id: ids.operationInspect,
      operation: 'inspect',
      requested_at: '2026-07-18T01:03:59Z',
      signature_verification: 'verified',
      result: MOCK_INSPECT_RESULT,
    },
    {
      operation_id: ids.operationRevoke,
      operation: 'revoke',
      requested_at: '2026-07-18T01:04:59Z',
      signature_verification: 'verified',
      result: MOCK_REVOKE_RESULT,
    },
  ],
  updated_at: '2026-07-18T01:05:01Z',
});

export const MOCK_AUDIT_EVENT: AuditEventV1 = deepFreeze({
  schema_version: 'audit-event-v1',
  audit_id: ids.audit,
  occurred_at: '2026-07-18T01:05:01Z',
  category: 'enforcement',
  event_type: 'enforcement.revoked',
  actor_kind: 'administrator',
  actor_id: 'admin.demo',
  object_type: 'enforcement_action',
  object_id: ids.action,
  outcome: 'succeeded',
  trace_id: ids.trace,
  correlation_id: ids.incident,
  safe_reason_code: 'operator_requested',
});

export const MOCK_INCIDENT_SUMMARY: IncidentSummaryV1 = deepFreeze({
  schema_version: 'incident-summary-v1',
  incident_id: ids.incident,
  incident_version: 3,
  state: 'review_ready',
  analysis_failure_reason: null,
  source_ip: '203.0.113.20',
  service_label: 'demo-app',
  signal_count: 1,
  first_seen_at: '2026-07-18T01:00:00Z',
  last_seen_at: '2026-07-18T01:01:00Z',
  updated_at: '2026-07-18T01:05:01Z',
});

export const MOCK_INCIDENT_DETAIL: IncidentDetailV1 = deepFreeze({
  schema_version: 'incident-detail-v1',
  incident: MOCK_INCIDENT_SUMMARY,
  gateway_events: [MOCK_GATEWAY_EVENT],
  source_health_events: [MOCK_SOURCE_HEALTH],
  deterministic_signals: [MOCK_SIGNAL],
  ai_analysis: MOCK_AI_ANALYSIS,
  policy: MOCK_POLICY,
  validation: MOCK_VALIDATION,
  hil_review: MOCK_HIL_REVIEW,
  enforcement: MOCK_LIFECYCLE,
  audit_events: [MOCK_AUDIT_EVENT],
});

export const MOCK_API_ERRORS: Readonly<
  Record<'serviceUnavailable' | 'permissionDenied', ApiErrorV1>
> = deepFreeze({
  serviceUnavailable: {
    code: 'service_unavailable',
    message: 'The typed incident endpoint is temporarily unavailable.',
    trace_id: '019b0000-0000-7000-8000-000000000623',
    details: { retryable: true },
  },
  permissionDenied: {
    code: 'permission_denied',
    message: 'The server denied access to this investigation.',
    trace_id: '019b0000-0000-7000-8000-000000000624',
    details: { resource: 'incident-detail' },
  },
});

export const MOCK_RESOURCE_STATES: Readonly<
  Record<ResourceStateKind, ResourceState<IncidentDetailV1>>
> = deepFreeze({
  loading: {
    resource: 'incident-detail',
    kind: 'loading',
    value: null,
    error: null,
    disabledReason: null,
  },
  empty: {
    resource: 'incident-detail',
    kind: 'empty',
    value: null,
    error: null,
    disabledReason: null,
  },
  error: {
    resource: 'incident-detail',
    kind: 'error',
    value: null,
    error: MOCK_API_ERRORS.serviceUnavailable,
    disabledReason: null,
  },
  'permission-denied': {
    resource: 'incident-detail',
    kind: 'permission-denied',
    value: null,
    error: MOCK_API_ERRORS.permissionDenied,
    disabledReason: null,
  },
  disabled: {
    resource: 'incident-detail',
    kind: 'disabled',
    value: null,
    error: null,
    disabledReason: 'The server did not mark this exact artifact as HIL-ready.',
  },
  success: {
    resource: 'incident-detail',
    kind: 'success',
    value: MOCK_INCIDENT_DETAIL,
    error: null,
    disabledReason: null,
  },
});

export const MOCK_REGISTERED_CONTRACTS = deepFreeze([
  MOCK_GATEWAY_EVENT,
  MOCK_AUTH_EVENT,
  MOCK_SOURCE_HEALTH,
  MOCK_SIGNAL,
  MOCK_INCIDENT_SUMMARY,
  MOCK_AI_ANALYSIS,
  MOCK_POLICY,
  MOCK_VALIDATION,
  MOCK_HIL_CHALLENGE,
  MOCK_HIL_DECISION,
  MOCK_HIL_REASON,
  MOCK_HIL_REVIEW,
  MOCK_ADD_RESULT,
  MOCK_INSPECT_RESULT,
  MOCK_REVOKE_RESULT,
  MOCK_LIFECYCLE,
  MOCK_AUDIT_EVENT,
  MOCK_INCIDENT_DETAIL,
] as const);
