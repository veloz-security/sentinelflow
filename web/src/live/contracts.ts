import { deepFreeze } from '../utils/deepFreeze';

export const INCIDENT_STATES = [
  'open',
  'analyzing',
  'review_ready',
  'analysis_failed',
  'closed',
] as const;

export const STREAM_EVENT_TYPES = [
  'incident.created',
  'incident.updated',
  'analysis.completed',
  'analysis.failed',
  'policy.validation_updated',
  'approval.recorded',
  'enforcement.updated',
  'source.degraded',
  'source.recovered',
] as const;

export type StreamEventType = (typeof STREAM_EVENT_TYPES)[number];
export type IncidentState = (typeof INCIDENT_STATES)[number];

export const ANALYSIS_PROVIDER_KINDS = [
  'openai_responses',
  'deterministic_stub',
] as const;
export type AnalysisProviderKind = (typeof ANALYSIS_PROVIDER_KINDS)[number];

const ANALYSIS_FAILURE_CODES = [
  'budget_exhausted',
  'input_too_large',
  'network_error',
  'http_408',
  'http_409',
  'rate_limited',
  'server_error',
  'timeout',
  'refused',
  'incomplete',
  'schema_invalid',
  'evidence_invalid',
  'unsupported_action',
  'cancelled',
  'configuration_error',
] as const;

const ANALYSIS_CLASSIFICATIONS = [
  'credential_stuffing',
  'brute_force',
  'path_scan',
  'request_burst',
  'mixed',
  'unknown',
] as const;

export interface SessionProjection {
  readonly actor_id: string;
  readonly session_id: string;
  readonly authenticated_at: string;
  readonly expires_at: string;
}

export interface SessionEnvelope {
  readonly session: SessionProjection;
  readonly csrf_token?: string;
}

export const HIL_OPERATIONS = ['approve', 'reject'] as const;
export const HIL_REASON_CODES = [
  'threat_confirmed',
  'false_positive',
  'business_exception',
  'emergency_revoke',
  'operator_request',
  'other',
] as const;

export type HILOperation = (typeof HIL_OPERATIONS)[number];
export type HILReasonCode = (typeof HIL_REASON_CODES)[number];

export interface PolicyArtifactBinding {
  readonly operation: HILOperation;
  readonly policy_version: number;
  readonly target_ipv4: string;
  readonly ttl_seconds: number;
  readonly policy_digest: string;
  readonly generated_artifact_digest: string;
  readonly canonical_artifact_digest: string;
  readonly evidence_snapshot_digest: string;
  readonly validation_snapshot_digest: string;
}

export interface HILReason {
  readonly schema_version: 'hil-reason-v1';
  readonly reason_code: HILReasonCode;
  readonly reason_text: string;
}

export interface HILChallenge {
  readonly authenticated_at: string;
  readonly canonical_artifact_digest: string;
  readonly challenge_id: string;
  readonly evidence_snapshot_digest: string;
  readonly expires_at: string;
  readonly generated_artifact_digest: string;
  readonly issued_at: string;
  readonly nonce_digest: string;
  readonly operation: HILOperation;
  readonly original_add_digest: null;
  readonly policy_digest: string;
  readonly reauth_required_after_seconds: 900;
  readonly resource_id: string;
  readonly resource_type: 'policy';
  readonly resource_version: number;
  readonly schema_version: 'hil-challenge-v1';
  readonly session_digest: string;
  readonly target_ipv4: string;
  readonly validation_snapshot_digest: string;
  readonly validation_valid_until: string;
}

export interface HILChallengeEnvelope {
  readonly challenge: HILChallenge;
  readonly challenge_nonce: string;
}

export interface HILDecision {
  readonly actor_id: string;
  readonly canonical_artifact_digest: string;
  readonly challenge_id: string;
  readonly decided_at: string;
  readonly decision: 'approved' | 'rejected';
  readonly decision_id: string;
  readonly decision_valid_until: string;
  readonly evidence_snapshot_digest: string;
  readonly generated_artifact_digest: string;
  readonly idempotency_key_digest: string;
  readonly nonce_digest: string;
  readonly operation: HILOperation;
  readonly original_add_digest: null;
  readonly policy_digest: string;
  readonly reason_digest: string;
  readonly resource_id: string;
  readonly resource_type: 'policy';
  readonly resource_version: number;
  readonly schema_version: 'hil-decision-v1';
  readonly session_digest: string;
  readonly target_ipv4: string;
  readonly validation_snapshot_digest: string;
}

interface HILDecisionEnvelopeBase {
  readonly decision: HILDecision;
  readonly action_id: string | null;
  readonly authorization_digest: string | null;
  readonly outbox_job_id: string | null;
}

export interface HILFreshDecisionEnvelope extends HILDecisionEnvelopeBase {
  readonly session: SessionProjection;
  readonly csrf_token: string;
  readonly replayed?: never;
  readonly reauthentication_required?: never;
}

export interface HILReplayDecisionEnvelope extends HILDecisionEnvelopeBase {
  readonly replayed: true;
  readonly reauthentication_required: true;
  readonly session?: never;
  readonly csrf_token?: never;
}

export type HILDecisionEnvelope =
  HILFreshDecisionEnvelope | HILReplayDecisionEnvelope;

export const REVOCATION_REASON_CODES = [
  'emergency_revoke',
  'operator_request',
  'other',
] as const;

export type RevocationReasonCode = (typeof REVOCATION_REASON_CODES)[number];

export interface RevocationArtifactBinding {
  readonly action_version: number;
  readonly target_ipv4: string;
  readonly original_add_digest: string;
  readonly policy_id: string;
  readonly policy_version: number;
  readonly evidence_snapshot_digest: string;
}

export interface RevocationReason {
  readonly schema_version: 'hil-reason-v1';
  readonly reason_code: RevocationReasonCode;
  readonly reason_text: string;
}

export interface RevocationChallenge {
  readonly authenticated_at: string;
  readonly canonical_artifact_digest: string;
  readonly challenge_id: string;
  readonly evidence_snapshot_digest: string;
  readonly expires_at: string;
  readonly generated_artifact_digest: string;
  readonly issued_at: string;
  readonly nonce_digest: string;
  readonly operation: 'revoke';
  readonly original_add_digest: string;
  readonly policy_digest: string;
  readonly reauth_required_after_seconds: 900;
  readonly resource_id: string;
  readonly resource_type: 'enforcement_action';
  readonly resource_version: number;
  readonly schema_version: 'hil-challenge-v1';
  readonly session_digest: string;
  readonly target_ipv4: string;
  readonly validation_snapshot_digest: string;
  readonly validation_valid_until: string;
}

export interface RevocationChallengeEnvelope {
  readonly challenge: RevocationChallenge;
  readonly challenge_nonce: string;
  readonly canonical_revoke_artifact: string;
  readonly policy_id: string;
  readonly policy_version: number;
}

export interface RevocationDecision {
  readonly actor_id: string;
  readonly canonical_artifact_digest: string;
  readonly challenge_id: string;
  readonly decided_at: string;
  readonly decision: 'revoked';
  readonly decision_id: string;
  readonly decision_valid_until: string;
  readonly evidence_snapshot_digest: string;
  readonly generated_artifact_digest: string;
  readonly idempotency_key_digest: string;
  readonly nonce_digest: string;
  readonly operation: 'revoke';
  readonly original_add_digest: string;
  readonly policy_digest: string;
  readonly reason_digest: string;
  readonly resource_id: string;
  readonly resource_type: 'enforcement_action';
  readonly resource_version: number;
  readonly schema_version: 'hil-decision-v1';
  readonly session_digest: string;
  readonly target_ipv4: string;
  readonly validation_snapshot_digest: string;
}

interface RevocationDecisionEnvelopeBase {
  readonly decision: RevocationDecision;
  readonly revocation_id: string;
  readonly authorization_id: string;
  readonly authorization_digest: string;
  readonly outbox_job_id: string;
  readonly audit_event_id: string;
}

export interface RevocationFreshDecisionEnvelope extends RevocationDecisionEnvelopeBase {
  readonly session: SessionProjection;
  readonly csrf_token: string;
  readonly replayed?: never;
  readonly reauthentication_required?: never;
}

export interface RevocationReplayDecisionEnvelope extends RevocationDecisionEnvelopeBase {
  readonly replayed: true;
  readonly reauthentication_required: true;
  readonly session?: never;
  readonly csrf_token?: never;
}

export type RevocationDecisionEnvelope =
  RevocationFreshDecisionEnvelope | RevocationReplayDecisionEnvelope;

export type ReauthenticationNotice =
  HILReplayDecisionEnvelope | RevocationReplayDecisionEnvelope;

export interface IncidentSummary {
  readonly incident_id: string;
  readonly kind: string;
  readonly state: IncidentState;
  readonly source_ip: string;
  readonly service_label: string;
  readonly first_seen: string;
  readonly last_seen: string;
  readonly closed_at?: string;
  readonly deterministic_score: string;
  readonly version: number;
  readonly analysis_failure_code?: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface IncidentPage {
  readonly items: readonly IncidentSummary[];
  readonly next_cursor?: string;
}

export interface SignalSummary {
  readonly signal_id: string;
  readonly rule_id: string;
  readonly rule_version: number;
  readonly kind: string;
  readonly window_start: string;
  readonly window_end: string;
  readonly observed_count: number;
  readonly distinct_count?: number;
  readonly threshold_count: number;
  readonly threshold_distinct?: number;
  readonly source_health_status: string;
  readonly evidence_digest: string;
}

interface AnalysisSummaryBase {
  readonly analysis_id: string;
  readonly incident_version: number;
  readonly started_at: string;
  readonly false_positive_factors: readonly string[];
}

interface OpenAIResponsesProvider {
  readonly provider_kind: 'openai_responses';
  readonly adapter_id: 'openai-responses-v1';
  readonly model: 'gpt-5.6-sol';
  readonly reasoning_effort: 'medium';
  readonly rate_card_version: string;
}

interface DeterministicStubProvider {
  readonly provider_kind: 'deterministic_stub';
  readonly adapter_id: 'sentinelflow-deterministic-ai-stub-v1';
  readonly model: null;
  readonly reasoning_effort: null;
  readonly rate_card_version: null;
}

type AnalysisProvider = OpenAIResponsesProvider | DeterministicStubProvider;

interface StartedAnalysisState {
  readonly result_state: 'started';
}

interface SucceededAnalysisState {
  readonly result_state: 'succeeded';
  readonly output_digest: string;
  readonly summary: string;
  readonly classification: (typeof ANALYSIS_CLASSIFICATIONS)[number];
  readonly confidence: string;
  readonly uncertainty: string;
  readonly completed_at: string;
}

interface FailedAnalysisState {
  readonly result_state: 'failed';
  readonly failure_code: (typeof ANALYSIS_FAILURE_CODES)[number];
  readonly completed_at: string;
}

export type AnalysisSummary = AnalysisSummaryBase &
  AnalysisProvider &
  (StartedAnalysisState | SucceededAnalysisState | FailedAnalysisState);

export interface PolicySummary {
  readonly policy_id: string;
  readonly version: number;
  readonly incident_version: number;
  readonly state: string;
  readonly state_revision: number;
  readonly target_ipv4: string;
  readonly ttl_seconds: number;
  readonly policy_digest: string;
  readonly evidence_snapshot_digest: string;
  readonly updated_at: string;
}

export interface IncidentDetail {
  readonly incident: IncidentSummary;
  readonly signals: readonly SignalSummary[];
  readonly signals_truncated: boolean;
  readonly latest_analysis?: AnalysisSummary;
  readonly policies: readonly PolicySummary[];
  readonly policies_truncated: boolean;
}

export interface IncidentEvent {
  readonly incident_event_id: string;
  readonly event_id: string;
  readonly incident_version: number;
  readonly kind: string;
  readonly occurred_at: string;
  readonly trace_id?: string;
  readonly source_ip?: string;
  readonly service_label?: string;
  readonly route_label?: string;
  readonly method?: string;
  readonly status_code?: number;
  readonly suspicious_path_id?: string;
  readonly auth_outcome?: string;
  readonly binding_state?: string;
  readonly health_state?: string;
  readonly health_cause?: string;
  readonly dropped_count?: number;
  readonly trust_state: string;
  readonly trust_reason: string;
  readonly relation_reason: string;
}

export interface IncidentEventPage {
  readonly items: readonly IncidentEvent[];
  readonly next_cursor?: string;
}

export interface ValidationGate {
  readonly order: number;
  readonly name: string;
  readonly passed: boolean;
  readonly result_code: string;
  readonly input_digest: string;
  readonly result_digest: string;
  readonly checked_at: string;
}

export interface ValidationSummary {
  readonly validation_snapshot_id: string;
  readonly snapshot_digest: string;
  readonly state: string;
  readonly failure_code?: string;
  readonly source_health_status: string;
  readonly base_chain_contract_raw_digest: string;
  readonly live_owned_schema_digest: string;
  readonly protected_ipv4_static_digest: string;
  readonly protected_ipv4_effective_config_digest: string;
  readonly historical_impact_digest: string;
  readonly history_dataset_digest?: string;
  readonly history_manifest_digest?: string;
  readonly created_at: string;
  readonly valid_until: string;
  readonly gates: readonly ValidationGate[];
}

const POLICY_STATES = [
  'draft',
  'validating',
  'valid',
  'invalid',
  'stale',
  'approved',
  'rejected',
  'queued',
  'active',
  'expired',
  'failed',
  'revoked',
  'indeterminate',
] as const;

export const VALIDATION_ATTEMPT_GATE_NAMES = [
  'structured_output',
  'command_grammar',
  'policy_evidence_command_consistency',
  'protected_network',
  'owned_schema_syntax',
  'historical_impact',
] as const;

export type ValidationAttemptState = 'valid' | 'invalid' | 'interrupted';
export type ValidationAttemptGateName =
  (typeof VALIDATION_ATTEMPT_GATE_NAMES)[number];

export interface ValidationAttemptGate {
  readonly order: number;
  readonly name: ValidationAttemptGateName;
  readonly state: 'passed' | 'failed';
  readonly result_code: string;
  readonly artifact_digest: string;
}

export interface ValidationAttemptSummary {
  readonly validation_attempt_id: string;
  readonly policy_id: string;
  readonly analysis_id: string;
  readonly incident_id: string;
  readonly incident_version: number;
  readonly state: ValidationAttemptState;
  readonly failure_code?: string;
  readonly failed_gate?: ValidationAttemptGateName;
  readonly prepared_snapshot_digest: string;
  readonly terminal_mutation_digest?: string;
  readonly completed_at: string;
  readonly gates: readonly ValidationAttemptGate[];
}

export interface DecisionSummary {
  readonly decision_id: string;
  readonly decision: string;
  readonly actor_id: string;
  readonly reason_digest: string;
  readonly decided_at: string;
}

export interface PolicyDetail {
  readonly policy_id: string;
  readonly version: number;
  readonly incident_id: string;
  readonly incident_version: number;
  readonly analysis_id: string;
  readonly command_candidate_id: string;
  readonly state: string;
  readonly state_revision: number;
  readonly target_ipv4: string;
  readonly action: string;
  readonly ttl_seconds: number;
  readonly timeout_token: string;
  readonly rationale: string;
  readonly policy_digest: string;
  readonly evidence_snapshot_digest: string;
  readonly generated_command: string;
  readonly generated_artifact_digest: string;
  readonly canonical_command: string;
  readonly canonical_artifact_digest: string;
  readonly parse_state: string;
  readonly parse_error_code?: string;
  readonly created_at: string;
  readonly updated_at: string;
  readonly latest_validation?: ValidationSummary;
  readonly latest_validation_attempt?: ValidationAttemptSummary;
  readonly decision?: DecisionSummary;
}

export interface ExecutionResultSummary {
  readonly result_id: string;
  readonly operation: string;
  readonly classification: string;
  readonly readback_state: string;
  readonly remaining_ttl_seconds?: number;
  readonly journal_sequence: number;
  readonly error_code: string;
  readonly result_digest: string;
  readonly persisted_at: string;
}

export interface EnforcementActionDetail {
  readonly action_id: string;
  readonly policy_id: string;
  readonly policy_version: number;
  readonly validation_snapshot_id: string;
  readonly evidence_snapshot_digest: string;
  readonly target_ipv4: string;
  readonly canonical_artifact_digest: string;
  readonly ttl_seconds: number;
  readonly state: string;
  readonly approved_at: string;
  readonly queued_at?: string;
  readonly applied_at?: string;
  readonly expected_expires_at?: string;
  readonly finished_at?: string;
  readonly version: number;
  readonly created_at: string;
  readonly updated_at: string;
  readonly latest_result?: ExecutionResultSummary;
}

export interface AuditEvent {
  readonly sequence: number;
  readonly event_id: string;
  readonly actor_type: string;
  readonly actor_id: string;
  readonly action: string;
  readonly object_type: string;
  readonly object_id?: string;
  readonly incident_id?: string;
  readonly policy_id?: string;
  readonly policy_version?: number;
  readonly enforcement_action_id?: string;
  readonly trace_id?: string;
  readonly primary_digest?: string;
  readonly secondary_digest?: string;
  readonly outcome: string;
  readonly occurred_at: string;
  readonly recorded_at: string;
}

export interface AuditPage {
  readonly items: readonly AuditEvent[];
  readonly next_cursor?: string;
}

export interface StreamEvent {
  readonly id: string;
  readonly type: StreamEventType;
  readonly resource_id: string;
  readonly resource_version: number;
  readonly incident_id?: string;
  readonly policy_id?: string;
  readonly action_id?: string;
  readonly occurred_at: string;
  readonly trace_id?: string;
  readonly summary: Readonly<{ code: string; outcome: string }>;
}

export class WireContractError extends Error {
  constructor(readonly path: string) {
    super(`management API response violated the frozen contract at ${path}`);
    this.name = 'WireContractError';
  }
}

type RecordValue = Record<string, unknown>;
type Frozen<T> = Readonly<T>;

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const ASCII_ID = /^[a-z0-9][a-z0-9_.:-]{0,127}$/;
const PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CURSOR = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const SSE_CURSOR = /^s1\.[0-9a-f]{16}$/;
const SCORE = /^(?:0(?:\.\d{1,5})?|1(?:\.0{1,5})?)$/;
const ANALYSIS_CONFIDENCE = /^(?:0(?:\.[0-9]+)?|1(?:\.0+)?)$/;

function record(
  value: unknown,
  path: string,
  required: readonly string[],
  optional: readonly string[] = [],
): RecordValue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new WireContractError(path);
  }
  const result = value as RecordValue;
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(result);
  if (
    keys.some((key) => !allowed.has(key)) ||
    required.some((key) => !Object.hasOwn(result, key))
  ) {
    throw new WireContractError(path);
  }
  return result;
}

function text(
  value: unknown,
  path: string,
  options: {
    readonly min?: number;
    readonly max?: number;
    readonly pattern?: RegExp;
  } = {},
): string {
  const min = options.min ?? 1;
  const max = options.max ?? 4096;
  if (
    typeof value !== 'string' ||
    value.length < min ||
    value.length > max ||
    value.trim() !== value ||
    (options.pattern && !options.pattern.test(value))
  ) {
    throw new WireContractError(path);
  }
  return value;
}

function uuid(value: unknown, path: string): string {
  return text(value, path, { max: 36, pattern: UUID });
}

function digest(value: unknown, path: string): string {
  return text(value, path, { max: 71, pattern: DIGEST });
}

function timestamp(value: unknown, path: string): string {
  const result = text(value, path, { max: 40, pattern: RFC3339_UTC });
  if (!Number.isFinite(Date.parse(result))) {
    throw new WireContractError(path);
  }
  return result;
}

function integer(
  value: unknown,
  path: string,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < min ||
    (value as number) > max
  ) {
    throw new WireContractError(path);
  }
  return value as number;
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') {
    throw new WireContractError(path);
  }
  return value;
}

function nullValue(value: unknown, path: string): null {
  if (value !== null) {
    throw new WireContractError(path);
  }
  return null;
}

function enumeration<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new WireContractError(path);
  }
  return value as T;
}

function list<T>(
  value: unknown,
  path: string,
  decode: (item: unknown, path: string) => T,
  max = 100,
): T[] {
  if (!Array.isArray(value) || value.length > max) {
    throw new WireContractError(path);
  }
  return value.map((item, index) => decode(item, `${path}/${index}`));
}

function optional<T>(
  source: RecordValue,
  key: string,
  decode: (value: unknown, path: string) => T,
  path: string,
): T | undefined {
  return Object.hasOwn(source, key)
    ? decode(source[key], `${path}/${key}`)
    : undefined;
}

function nullableText(
  value: unknown,
  path: string,
  options: Parameters<typeof text>[2] = {},
): string | null {
  return value === null ? null : text(value, path, options);
}

function ipv4(value: unknown, path: string): string {
  const source = text(value, path, { max: 15 });
  const octets = source.split('.');
  if (
    octets.length !== 4 ||
    octets.some(
      (octet) => !/^(?:0|[1-9][0-9]{0,2})$/.test(octet) || Number(octet) > 255,
    )
  ) {
    throw new WireContractError(path);
  }
  return source;
}

function commandText(value: unknown, path: string): string {
  if (
    typeof value !== 'string' ||
    value.length < 2 ||
    value.length > 512 ||
    !value.endsWith('\n') ||
    value.slice(0, -1).includes('\n') ||
    value.includes('\r') ||
    value.includes('\0')
  ) {
    throw new WireContractError(path);
  }
  return value;
}

function decodeSession(value: unknown, path: string): SessionProjection {
  const item = record(value, path, [
    'actor_id',
    'session_id',
    'authenticated_at',
    'expires_at',
  ]);
  const authenticatedAt = timestamp(
    item.authenticated_at,
    `${path}/authenticated_at`,
  );
  const expiresAt = timestamp(item.expires_at, `${path}/expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(authenticatedAt)) {
    throw new WireContractError(path);
  }
  return {
    actor_id: text(item.actor_id, `${path}/actor_id`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    session_id: uuid(item.session_id, `${path}/session_id`),
    authenticated_at: authenticatedAt,
    expires_at: expiresAt,
  };
}

function decodeIncidentSummaryAt(
  value: unknown,
  path: string,
): IncidentSummary {
  const item = record(
    value,
    path,
    [
      'incident_id',
      'kind',
      'state',
      'source_ip',
      'service_label',
      'first_seen',
      'last_seen',
      'deterministic_score',
      'version',
      'created_at',
      'updated_at',
    ],
    ['closed_at', 'analysis_failure_code'],
  );
  const state = enumeration(item.state, `${path}/state`, INCIDENT_STATES);
  const closedAt = optional(item, 'closed_at', timestamp, path);
  const failure = optional(
    item,
    'analysis_failure_code',
    (candidate, childPath) =>
      text(candidate, childPath, { max: 128, pattern: ASCII_ID }),
    path,
  );
  if (
    (state === 'closed') !== (closedAt !== undefined) ||
    (state === 'analysis_failed') !== (failure !== undefined)
  ) {
    throw new WireContractError(path);
  }
  return {
    incident_id: uuid(item.incident_id, `${path}/incident_id`),
    kind: enumeration(item.kind, `${path}/kind`, [
      'credential_stuffing',
      'brute_force',
      'path_scan',
      'request_burst',
      'mixed',
      'unknown',
    ]),
    state,
    source_ip: ipv4(item.source_ip, `${path}/source_ip`),
    service_label: text(item.service_label, `${path}/service_label`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    first_seen: timestamp(item.first_seen, `${path}/first_seen`),
    last_seen: timestamp(item.last_seen, `${path}/last_seen`),
    ...(closedAt ? { closed_at: closedAt } : {}),
    deterministic_score: text(
      item.deterministic_score,
      `${path}/deterministic_score`,
      { max: 7, pattern: SCORE },
    ),
    version: integer(item.version, `${path}/version`, 1, 2_147_483_647),
    ...(failure ? { analysis_failure_code: failure } : {}),
    created_at: timestamp(item.created_at, `${path}/created_at`),
    updated_at: timestamp(item.updated_at, `${path}/updated_at`),
  };
}

function decodeSignal(value: unknown, path: string): SignalSummary {
  const item = record(
    value,
    path,
    [
      'signal_id',
      'rule_id',
      'rule_version',
      'kind',
      'window_start',
      'window_end',
      'observed_count',
      'threshold_count',
      'source_health_status',
      'evidence_digest',
    ],
    ['distinct_count', 'threshold_distinct'],
  );
  return {
    signal_id: uuid(item.signal_id, `${path}/signal_id`),
    rule_id: text(item.rule_id, `${path}/rule_id`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    rule_version: integer(
      item.rule_version,
      `${path}/rule_version`,
      1,
      2_147_483_647,
    ),
    kind: text(item.kind, `${path}/kind`, { max: 128, pattern: ASCII_ID }),
    window_start: timestamp(item.window_start, `${path}/window_start`),
    window_end: timestamp(item.window_end, `${path}/window_end`),
    observed_count: integer(
      item.observed_count,
      `${path}/observed_count`,
      0,
      2_147_483_647,
    ),
    ...(Object.hasOwn(item, 'distinct_count')
      ? {
          distinct_count: integer(
            item.distinct_count,
            `${path}/distinct_count`,
            0,
            2_147_483_647,
          ),
        }
      : {}),
    threshold_count: integer(
      item.threshold_count,
      `${path}/threshold_count`,
      1,
      2_147_483_647,
    ),
    ...(Object.hasOwn(item, 'threshold_distinct')
      ? {
          threshold_distinct: integer(
            item.threshold_distinct,
            `${path}/threshold_distinct`,
            1,
            2_147_483_647,
          ),
        }
      : {}),
    source_health_status: enumeration(
      item.source_health_status,
      `${path}/source_health_status`,
      ['complete', 'incomplete'],
    ),
    evidence_digest: digest(item.evidence_digest, `${path}/evidence_digest`),
  };
}

const ANALYSIS_COMMON_FIELDS = [
  'analysis_id',
  'incident_version',
  'provider_kind',
  'adapter_id',
  'model',
  'reasoning_effort',
  'rate_card_version',
  'result_state',
  'started_at',
  'false_positive_factors',
] as const;

function decodeAnalysisProvider(
  item: RecordValue,
  path: string,
): AnalysisProvider {
  const providerKind = enumeration(
    item.provider_kind,
    `${path}/provider_kind`,
    ANALYSIS_PROVIDER_KINDS,
  );
  const adapterID = text(item.adapter_id, `${path}/adapter_id`, {
    max: 64,
    pattern: PROVIDER_ID,
  });
  const model = nullableText(item.model, `${path}/model`, {
    max: 128,
    pattern: PROVIDER_ID,
  });
  const reasoningEffort = nullableText(
    item.reasoning_effort,
    `${path}/reasoning_effort`,
    { max: 64, pattern: PROVIDER_ID },
  );
  const rateCardVersion = nullableText(
    item.rate_card_version,
    `${path}/rate_card_version`,
    { max: 64, pattern: PROVIDER_ID },
  );
  if (
    (providerKind === 'openai_responses' &&
      (adapterID !== 'openai-responses-v1' ||
        model !== 'gpt-5.6-sol' ||
        reasoningEffort !== 'medium' ||
        rateCardVersion === null)) ||
    (providerKind === 'deterministic_stub' &&
      (adapterID !== 'sentinelflow-deterministic-ai-stub-v1' ||
        model !== null ||
        reasoningEffort !== null ||
        rateCardVersion !== null))
  ) {
    throw new WireContractError(`${path}/provider_kind`);
  }
  return providerKind === 'openai_responses'
    ? {
        provider_kind: 'openai_responses',
        adapter_id: 'openai-responses-v1',
        model: 'gpt-5.6-sol',
        reasoning_effort: 'medium',
        rate_card_version: rateCardVersion as string,
      }
    : {
        provider_kind: 'deterministic_stub',
        adapter_id: 'sentinelflow-deterministic-ai-stub-v1',
        model: null,
        reasoning_effort: null,
        rate_card_version: null,
      };
}

function decodeAnalysisCommon(
  item: RecordValue,
  path: string,
): AnalysisSummaryBase & AnalysisProvider {
  return {
    analysis_id: uuid(item.analysis_id, `${path}/analysis_id`),
    incident_version: integer(
      item.incident_version,
      `${path}/incident_version`,
      1,
      2_147_483_647,
    ),
    ...decodeAnalysisProvider(item, path),
    started_at: timestamp(item.started_at, `${path}/started_at`),
    false_positive_factors: list(
      item.false_positive_factors,
      `${path}/false_positive_factors`,
      (candidate, childPath) => text(candidate, childPath, { max: 240 }),
      5,
    ),
  };
}

function normalizedTimestamp(value: string, path: string): string {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(
    value,
  );
  if (!match) {
    throw new WireContractError(path);
  }
  return `${match[1]}.${(match[2] ?? '').padEnd(9, '0')}Z`;
}

function decodeAnalysis(value: unknown, path: string): AnalysisSummary {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new WireContractError(path);
  }
  const candidate = value as RecordValue;
  const resultState = enumeration(
    candidate.result_state,
    `${path}/result_state`,
    ['started', 'succeeded', 'failed'],
  );

  if (resultState === 'started') {
    const item = record(value, path, ANALYSIS_COMMON_FIELDS);
    return {
      ...decodeAnalysisCommon(item, path),
      result_state: 'started',
    };
  }

  if (resultState === 'failed') {
    const item = record(value, path, [
      ...ANALYSIS_COMMON_FIELDS,
      'failure_code',
      'completed_at',
    ]);
    const common = decodeAnalysisCommon(item, path);
    const completedAt = timestamp(item.completed_at, `${path}/completed_at`);
    if (
      normalizedTimestamp(completedAt, `${path}/completed_at`) <
      normalizedTimestamp(common.started_at, `${path}/started_at`)
    ) {
      throw new WireContractError(`${path}/completed_at`);
    }
    return {
      ...common,
      result_state: 'failed',
      failure_code: enumeration(
        item.failure_code,
        `${path}/failure_code`,
        ANALYSIS_FAILURE_CODES,
      ),
      completed_at: completedAt,
    };
  }

  const item = record(value, path, [
    ...ANALYSIS_COMMON_FIELDS,
    'output_digest',
    'summary',
    'classification',
    'confidence',
    'uncertainty',
    'completed_at',
  ]);
  const common = decodeAnalysisCommon(item, path);
  const completedAt = timestamp(item.completed_at, `${path}/completed_at`);
  if (
    normalizedTimestamp(completedAt, `${path}/completed_at`) <
    normalizedTimestamp(common.started_at, `${path}/started_at`)
  ) {
    throw new WireContractError(`${path}/completed_at`);
  }
  return {
    ...common,
    result_state: 'succeeded',
    output_digest: digest(item.output_digest, `${path}/output_digest`),
    summary: text(item.summary, `${path}/summary`, { max: 1600 }),
    classification: enumeration(
      item.classification,
      `${path}/classification`,
      ANALYSIS_CLASSIFICATIONS,
    ),
    confidence: text(item.confidence, `${path}/confidence`, {
      max: 64,
      pattern: ANALYSIS_CONFIDENCE,
    }),
    uncertainty: text(item.uncertainty, `${path}/uncertainty`, {
      min: 0,
      max: 800,
    }),
    completed_at: completedAt,
  };
}

function decodePolicySummary(value: unknown, path: string): PolicySummary {
  const item = record(value, path, [
    'policy_id',
    'version',
    'incident_version',
    'state',
    'state_revision',
    'target_ipv4',
    'ttl_seconds',
    'policy_digest',
    'evidence_snapshot_digest',
    'updated_at',
  ]);
  return {
    policy_id: uuid(item.policy_id, `${path}/policy_id`),
    version: integer(item.version, `${path}/version`, 1, 2_147_483_647),
    incident_version: integer(
      item.incident_version,
      `${path}/incident_version`,
      1,
      2_147_483_647,
    ),
    state: text(item.state, `${path}/state`, { max: 32, pattern: ASCII_ID }),
    state_revision: integer(item.state_revision, `${path}/state_revision`, 1),
    target_ipv4: ipv4(item.target_ipv4, `${path}/target_ipv4`),
    ttl_seconds: integer(item.ttl_seconds, `${path}/ttl_seconds`, 60, 86_400),
    policy_digest: digest(item.policy_digest, `${path}/policy_digest`),
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      `${path}/evidence_snapshot_digest`,
    ),
    updated_at: timestamp(item.updated_at, `${path}/updated_at`),
  };
}

function decodeIncidentEventAt(value: unknown, path: string): IncidentEvent {
  const item = record(
    value,
    path,
    [
      'incident_event_id',
      'event_id',
      'incident_version',
      'kind',
      'occurred_at',
      'trust_state',
      'trust_reason',
      'relation_reason',
    ],
    [
      'trace_id',
      'source_ip',
      'service_label',
      'route_label',
      'method',
      'status_code',
      'suspicious_path_id',
      'auth_outcome',
      'binding_state',
      'health_state',
      'health_cause',
      'dropped_count',
    ],
  );
  return {
    incident_event_id: uuid(
      item.incident_event_id,
      `${path}/incident_event_id`,
    ),
    event_id: uuid(item.event_id, `${path}/event_id`),
    incident_version: integer(
      item.incident_version,
      `${path}/incident_version`,
      1,
      2_147_483_647,
    ),
    kind: enumeration(item.kind, `${path}/kind`, [
      'gateway',
      'auth',
      'source_health',
    ]),
    occurred_at: timestamp(item.occurred_at, `${path}/occurred_at`),
    ...(Object.hasOwn(item, 'trace_id')
      ? { trace_id: uuid(item.trace_id, `${path}/trace_id`) }
      : {}),
    ...(Object.hasOwn(item, 'source_ip')
      ? { source_ip: ipv4(item.source_ip, `${path}/source_ip`) }
      : {}),
    ...(Object.hasOwn(item, 'service_label')
      ? {
          service_label: text(item.service_label, `${path}/service_label`, {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'route_label')
      ? {
          route_label: text(item.route_label, `${path}/route_label`, {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'method')
      ? {
          method: text(item.method, `${path}/method`, {
            max: 16,
            pattern: /^[A-Z]+$/,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'status_code')
      ? {
          status_code: integer(
            item.status_code,
            `${path}/status_code`,
            100,
            599,
          ),
        }
      : {}),
    ...(Object.hasOwn(item, 'suspicious_path_id')
      ? {
          suspicious_path_id: text(
            item.suspicious_path_id,
            `${path}/suspicious_path_id`,
            { max: 128, pattern: ASCII_ID },
          ),
        }
      : {}),
    ...(Object.hasOwn(item, 'auth_outcome')
      ? {
          auth_outcome: text(item.auth_outcome, `${path}/auth_outcome`, {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'binding_state')
      ? {
          binding_state: text(item.binding_state, `${path}/binding_state`, {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'health_state')
      ? {
          health_state: text(item.health_state, `${path}/health_state`, {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'health_cause')
      ? {
          health_cause: text(item.health_cause, `${path}/health_cause`, {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    ...(Object.hasOwn(item, 'dropped_count')
      ? {
          dropped_count: integer(
            item.dropped_count,
            `${path}/dropped_count`,
            0,
          ),
        }
      : {}),
    trust_state: text(item.trust_state, `${path}/trust_state`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    trust_reason: text(item.trust_reason, `${path}/trust_reason`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    relation_reason: text(item.relation_reason, `${path}/relation_reason`, {
      max: 128,
      pattern: ASCII_ID,
    }),
  };
}

function decodeGate(value: unknown, path: string): ValidationGate {
  const item = record(value, path, [
    'order',
    'name',
    'passed',
    'result_code',
    'input_digest',
    'result_digest',
    'checked_at',
  ]);
  return {
    order: integer(item.order, `${path}/order`, 1, 32),
    name: text(item.name, `${path}/name`, { max: 128, pattern: ASCII_ID }),
    passed: boolean(item.passed, `${path}/passed`),
    result_code: text(item.result_code, `${path}/result_code`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    input_digest: digest(item.input_digest, `${path}/input_digest`),
    result_digest: digest(item.result_digest, `${path}/result_digest`),
    checked_at: timestamp(item.checked_at, `${path}/checked_at`),
  };
}

function decodeValidation(value: unknown, path: string): ValidationSummary {
  const item = record(
    value,
    path,
    [
      'validation_snapshot_id',
      'snapshot_digest',
      'state',
      'source_health_status',
      'base_chain_contract_raw_digest',
      'live_owned_schema_digest',
      'protected_ipv4_static_digest',
      'protected_ipv4_effective_config_digest',
      'historical_impact_digest',
      'created_at',
      'valid_until',
      'gates',
    ],
    ['failure_code', 'history_dataset_digest', 'history_manifest_digest'],
  );
  const state = enumeration(item.state, `${path}/state`, [
    'draft',
    'valid',
    'invalid',
    'stale',
  ]);
  const failureCode = optional(
    item,
    'failure_code',
    (candidate, candidatePath) =>
      text(candidate, candidatePath, { max: 128, pattern: ASCII_ID }),
    path,
  );
  const sourceHealthStatus = enumeration(
    item.source_health_status,
    `${path}/source_health_status`,
    ['complete', 'incomplete'],
  );
  const createdAt = timestamp(item.created_at, `${path}/created_at`);
  const validUntil = timestamp(item.valid_until, `${path}/valid_until`);
  if (
    normalizedTimestamp(validUntil, `${path}/valid_until`) <=
    normalizedTimestamp(createdAt, `${path}/created_at`)
  ) {
    throw new WireContractError(`${path}/valid_until`);
  }
  const gates = list(
    item.gates,
    `${path}/gates`,
    decodeGate,
    VALIDATION_ATTEMPT_GATE_NAMES.length,
  );
  let failedIndex = -1;
  gates.forEach((gate, index) => {
    if (
      gate.order !== index + 1 ||
      gate.name !== VALIDATION_ATTEMPT_GATE_NAMES[index]
    ) {
      throw new WireContractError(`${path}/gates/${index}`);
    }
    if (gate.passed) {
      if (failedIndex >= 0 || gate.result_code !== 'ok') {
        throw new WireContractError(`${path}/gates/${index}`);
      }
      return;
    }
    if (
      gate.result_code === 'ok' ||
      index !== gates.length - 1 ||
      failedIndex >= 0
    ) {
      throw new WireContractError(`${path}/gates/${index}`);
    }
    failedIndex = index;
  });
  const failed = failedIndex >= 0;
  if (
    failed !== (failureCode !== undefined) ||
    (failed && failureCode !== gates[failedIndex]?.result_code) ||
    (state === 'valid' &&
      (failed ||
        failureCode !== undefined ||
        sourceHealthStatus !== 'complete' ||
        gates.length !== VALIDATION_ATTEMPT_GATE_NAMES.length)) ||
    (state === 'invalid' && !failed)
  ) {
    throw new WireContractError(path);
  }
  return {
    validation_snapshot_id: uuid(
      item.validation_snapshot_id,
      `${path}/validation_snapshot_id`,
    ),
    snapshot_digest: digest(item.snapshot_digest, `${path}/snapshot_digest`),
    state,
    ...(failureCode !== undefined ? { failure_code: failureCode } : {}),
    source_health_status: sourceHealthStatus,
    base_chain_contract_raw_digest: digest(
      item.base_chain_contract_raw_digest,
      `${path}/base_chain_contract_raw_digest`,
    ),
    live_owned_schema_digest: digest(
      item.live_owned_schema_digest,
      `${path}/live_owned_schema_digest`,
    ),
    protected_ipv4_static_digest: digest(
      item.protected_ipv4_static_digest,
      `${path}/protected_ipv4_static_digest`,
    ),
    protected_ipv4_effective_config_digest: digest(
      item.protected_ipv4_effective_config_digest,
      `${path}/protected_ipv4_effective_config_digest`,
    ),
    historical_impact_digest: digest(
      item.historical_impact_digest,
      `${path}/historical_impact_digest`,
    ),
    ...(Object.hasOwn(item, 'history_dataset_digest')
      ? {
          history_dataset_digest: digest(
            item.history_dataset_digest,
            `${path}/history_dataset_digest`,
          ),
        }
      : {}),
    ...(Object.hasOwn(item, 'history_manifest_digest')
      ? {
          history_manifest_digest: digest(
            item.history_manifest_digest,
            `${path}/history_manifest_digest`,
          ),
        }
      : {}),
    created_at: createdAt,
    valid_until: validUntil,
    gates,
  };
}

function decodeValidationAttemptGate(
  value: unknown,
  path: string,
): ValidationAttemptGate {
  const item = record(value, path, [
    'order',
    'name',
    'state',
    'result_code',
    'artifact_digest',
  ]);
  return {
    order: integer(item.order, `${path}/order`, 1, 6),
    name: enumeration(item.name, `${path}/name`, VALIDATION_ATTEMPT_GATE_NAMES),
    state: enumeration(item.state, `${path}/state`, ['passed', 'failed']),
    result_code: text(item.result_code, `${path}/result_code`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    artifact_digest: digest(item.artifact_digest, `${path}/artifact_digest`),
  };
}

function decodeValidationAttempt(
  value: unknown,
  path: string,
): ValidationAttemptSummary {
  const item = record(
    value,
    path,
    [
      'validation_attempt_id',
      'policy_id',
      'analysis_id',
      'incident_id',
      'incident_version',
      'state',
      'prepared_snapshot_digest',
      'completed_at',
      'gates',
    ],
    ['failure_code', 'failed_gate', 'terminal_mutation_digest'],
  );
  const state = enumeration(item.state, `${path}/state`, [
    'valid',
    'invalid',
    'interrupted',
  ]);
  const failureCode = optional(
    item,
    'failure_code',
    (candidate, candidatePath) =>
      text(candidate, candidatePath, { max: 128, pattern: ASCII_ID }),
    path,
  );
  const failedGate = optional(
    item,
    'failed_gate',
    (candidate, candidatePath) =>
      enumeration(candidate, candidatePath, VALIDATION_ATTEMPT_GATE_NAMES),
    path,
  );
  const terminalMutationDigest = optional(
    item,
    'terminal_mutation_digest',
    digest,
    path,
  );
  const gates = list(
    item.gates,
    `${path}/gates`,
    decodeValidationAttemptGate,
    VALIDATION_ATTEMPT_GATE_NAMES.length,
  );
  let failedIndex = -1;
  gates.forEach((gate, index) => {
    if (
      gate.order !== index + 1 ||
      gate.name !== VALIDATION_ATTEMPT_GATE_NAMES[index]
    ) {
      throw new WireContractError(`${path}/gates/${index}`);
    }
    if (gate.state === 'passed') {
      if (failedIndex >= 0 || gate.result_code !== 'ok') {
        throw new WireContractError(`${path}/gates/${index}`);
      }
      return;
    }
    if (
      gate.result_code === 'ok' ||
      index !== gates.length - 1 ||
      failedIndex >= 0
    ) {
      throw new WireContractError(`${path}/gates/${index}`);
    }
    failedIndex = index;
  });

  if (
    (state === 'valid' &&
      (gates.length !== VALIDATION_ATTEMPT_GATE_NAMES.length ||
        failedIndex >= 0 ||
        failureCode !== undefined ||
        failedGate !== undefined ||
        terminalMutationDigest === undefined)) ||
    (state === 'invalid' &&
      (failedIndex < 0 ||
        failureCode === undefined ||
        failedGate === undefined ||
        terminalMutationDigest === undefined ||
        failureCode !== gates[failedIndex]?.result_code ||
        failedGate !== gates[failedIndex]?.name)) ||
    (state === 'interrupted' &&
      (failedIndex >= 0 ||
        failureCode === undefined ||
        failedGate !== undefined ||
        terminalMutationDigest !== undefined))
  ) {
    throw new WireContractError(path);
  }

  return {
    validation_attempt_id: uuid(
      item.validation_attempt_id,
      `${path}/validation_attempt_id`,
    ),
    policy_id: uuid(item.policy_id, `${path}/policy_id`),
    analysis_id: uuid(item.analysis_id, `${path}/analysis_id`),
    incident_id: uuid(item.incident_id, `${path}/incident_id`),
    incident_version: integer(
      item.incident_version,
      `${path}/incident_version`,
      1,
      2_147_483_647,
    ),
    state,
    ...(failureCode !== undefined ? { failure_code: failureCode } : {}),
    ...(failedGate !== undefined ? { failed_gate: failedGate } : {}),
    prepared_snapshot_digest: digest(
      item.prepared_snapshot_digest,
      `${path}/prepared_snapshot_digest`,
    ),
    ...(terminalMutationDigest !== undefined
      ? { terminal_mutation_digest: terminalMutationDigest }
      : {}),
    completed_at: timestamp(item.completed_at, `${path}/completed_at`),
    gates,
  };
}

function decodeDecision(value: unknown, path: string): DecisionSummary {
  const item = record(value, path, [
    'decision_id',
    'decision',
    'actor_id',
    'reason_digest',
    'decided_at',
  ]);
  return {
    decision_id: uuid(item.decision_id, `${path}/decision_id`),
    decision: enumeration(item.decision, `${path}/decision`, [
      'approved',
      'rejected',
      'revoked',
    ]),
    actor_id: text(item.actor_id, `${path}/actor_id`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    reason_digest: digest(item.reason_digest, `${path}/reason_digest`),
    decided_at: timestamp(item.decided_at, `${path}/decided_at`),
  };
}

function validPolicyTerminalBinding(
  policyState: (typeof POLICY_STATES)[number],
  validation: ValidationSummary | undefined,
  attempt: ValidationAttemptSummary | undefined,
  decision: DecisionSummary | undefined,
): boolean {
  if (!attempt) {
    return true;
  }
  if (attempt.state === 'invalid') {
    return (
      policyState === 'invalid' &&
      validation === undefined &&
      decision === undefined
    );
  }
  if (attempt.state === 'interrupted') {
    return (
      (policyState === 'invalid' || policyState === 'stale') &&
      validation === undefined &&
      decision === undefined
    );
  }
  if (!validation) {
    return false;
  }
  if (policyState === 'stale') {
    if (validation.state !== 'valid' && validation.state !== 'stale') {
      return false;
    }
  } else if (validation.state !== 'valid') {
    return false;
  }
  switch (policyState) {
    case 'valid':
      return decision === undefined;
    case 'rejected':
      return decision?.decision === 'rejected';
    case 'approved':
    case 'queued':
    case 'active':
    case 'expired':
    case 'failed':
    case 'revoked':
    case 'indeterminate':
      return decision?.decision === 'approved';
    case 'stale':
      return decision === undefined || decision.decision === 'approved';
    default:
      return false;
  }
}

function decodeResult(value: unknown, path: string): ExecutionResultSummary {
  const item = record(
    value,
    path,
    [
      'result_id',
      'operation',
      'classification',
      'readback_state',
      'journal_sequence',
      'error_code',
      'result_digest',
      'persisted_at',
    ],
    ['remaining_ttl_seconds'],
  );
  return {
    result_id: uuid(item.result_id, `${path}/result_id`),
    operation: enumeration(item.operation, `${path}/operation`, [
      'add',
      'revoke',
      'inspect',
    ]),
    classification: text(item.classification, `${path}/classification`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    readback_state: text(item.readback_state, `${path}/readback_state`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    ...(Object.hasOwn(item, 'remaining_ttl_seconds')
      ? {
          remaining_ttl_seconds: integer(
            item.remaining_ttl_seconds,
            `${path}/remaining_ttl_seconds`,
            0,
            86_400,
          ),
        }
      : {}),
    journal_sequence: integer(
      item.journal_sequence,
      `${path}/journal_sequence`,
      1,
    ),
    error_code: text(item.error_code, `${path}/error_code`, {
      min: 0,
      max: 128,
      pattern: /^(?:|[a-z0-9][a-z0-9_.:-]{0,127})$/,
    }),
    result_digest: digest(item.result_digest, `${path}/result_digest`),
    persisted_at: timestamp(item.persisted_at, `${path}/persisted_at`),
  };
}

function decodeAuditEvent(value: unknown, path: string): AuditEvent {
  const item = record(
    value,
    path,
    [
      'sequence',
      'event_id',
      'actor_type',
      'actor_id',
      'action',
      'object_type',
      'outcome',
      'occurred_at',
      'recorded_at',
    ],
    [
      'object_id',
      'incident_id',
      'policy_id',
      'policy_version',
      'enforcement_action_id',
      'trace_id',
      'primary_digest',
      'secondary_digest',
    ],
  );
  return {
    sequence: integer(item.sequence, `${path}/sequence`, 1),
    event_id: uuid(item.event_id, `${path}/event_id`),
    actor_type: enumeration(item.actor_type, `${path}/actor_type`, [
      'administrator',
      'system',
      'dispatcher',
      'executor',
    ]),
    actor_id: text(item.actor_id, `${path}/actor_id`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    action: text(item.action, `${path}/action`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    object_type: text(item.object_type, `${path}/object_type`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    ...(Object.hasOwn(item, 'object_id')
      ? { object_id: uuid(item.object_id, `${path}/object_id`) }
      : {}),
    ...(Object.hasOwn(item, 'incident_id')
      ? { incident_id: uuid(item.incident_id, `${path}/incident_id`) }
      : {}),
    ...(Object.hasOwn(item, 'policy_id')
      ? { policy_id: uuid(item.policy_id, `${path}/policy_id`) }
      : {}),
    ...(Object.hasOwn(item, 'policy_version')
      ? {
          policy_version: integer(
            item.policy_version,
            `${path}/policy_version`,
            1,
            2_147_483_647,
          ),
        }
      : {}),
    ...(Object.hasOwn(item, 'enforcement_action_id')
      ? {
          enforcement_action_id: uuid(
            item.enforcement_action_id,
            `${path}/enforcement_action_id`,
          ),
        }
      : {}),
    ...(Object.hasOwn(item, 'trace_id')
      ? { trace_id: uuid(item.trace_id, `${path}/trace_id`) }
      : {}),
    ...(Object.hasOwn(item, 'primary_digest')
      ? {
          primary_digest: digest(item.primary_digest, `${path}/primary_digest`),
        }
      : {}),
    ...(Object.hasOwn(item, 'secondary_digest')
      ? {
          secondary_digest: digest(
            item.secondary_digest,
            `${path}/secondary_digest`,
          ),
        }
      : {}),
    outcome: enumeration(item.outcome, `${path}/outcome`, [
      'accepted',
      'rejected',
      'succeeded',
      'failed',
      'indeterminate',
    ]),
    occurred_at: timestamp(item.occurred_at, `${path}/occurred_at`),
    recorded_at: timestamp(item.recorded_at, `${path}/recorded_at`),
  };
}

export function decodeSessionEnvelope(value: unknown): Frozen<SessionEnvelope> {
  const item = record(value, '/', ['session'], ['csrf_token']);
  const csrf = optional(
    item,
    'csrf_token',
    (candidate, path) =>
      text(candidate, path, { max: 128, pattern: /^[A-Za-z0-9_-]{43}$/ }),
    '/',
  );
  return deepFreeze({
    session: decodeSession(item.session, '/session'),
    ...(csrf ? { csrf_token: csrf } : {}),
  });
}

function decodeHILChallenge(value: unknown, path: string): HILChallenge {
  const item = record(value, path, [
    'authenticated_at',
    'canonical_artifact_digest',
    'challenge_id',
    'evidence_snapshot_digest',
    'expires_at',
    'generated_artifact_digest',
    'issued_at',
    'nonce_digest',
    'operation',
    'original_add_digest',
    'policy_digest',
    'reauth_required_after_seconds',
    'resource_id',
    'resource_type',
    'resource_version',
    'schema_version',
    'session_digest',
    'target_ipv4',
    'validation_snapshot_digest',
    'validation_valid_until',
  ]);
  const authenticatedAt = timestamp(
    item.authenticated_at,
    `${path}/authenticated_at`,
  );
  const issuedAt = timestamp(item.issued_at, `${path}/issued_at`);
  const expiresAt = timestamp(item.expires_at, `${path}/expires_at`);
  const validationValidUntil = timestamp(
    item.validation_valid_until,
    `${path}/validation_valid_until`,
  );
  if (
    Date.parse(authenticatedAt) > Date.parse(issuedAt) ||
    Date.parse(expiresAt) <= Date.parse(issuedAt) ||
    Date.parse(expiresAt) > Date.parse(validationValidUntil) ||
    Date.parse(expiresAt) - Date.parse(issuedAt) > 5 * 60 * 1000
  ) {
    throw new WireContractError(path);
  }
  // Keep this insertion order identical to the server's RFC 8785/JCS bytes.
  // The exact object is serialized back once when the nonce is consumed.
  return {
    authenticated_at: authenticatedAt,
    canonical_artifact_digest: digest(
      item.canonical_artifact_digest,
      `${path}/canonical_artifact_digest`,
    ),
    challenge_id: uuid(item.challenge_id, `${path}/challenge_id`),
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      `${path}/evidence_snapshot_digest`,
    ),
    expires_at: expiresAt,
    generated_artifact_digest: digest(
      item.generated_artifact_digest,
      `${path}/generated_artifact_digest`,
    ),
    issued_at: issuedAt,
    nonce_digest: digest(item.nonce_digest, `${path}/nonce_digest`),
    operation: enumeration(item.operation, `${path}/operation`, HIL_OPERATIONS),
    original_add_digest: nullValue(
      item.original_add_digest,
      `${path}/original_add_digest`,
    ),
    policy_digest: digest(item.policy_digest, `${path}/policy_digest`),
    reauth_required_after_seconds: integer(
      item.reauth_required_after_seconds,
      `${path}/reauth_required_after_seconds`,
      900,
      900,
    ) as 900,
    resource_id: uuid(item.resource_id, `${path}/resource_id`),
    resource_type: enumeration(item.resource_type, `${path}/resource_type`, [
      'policy',
    ] as const),
    resource_version: integer(
      item.resource_version,
      `${path}/resource_version`,
      1,
      2_147_483_647,
    ),
    schema_version: enumeration(item.schema_version, `${path}/schema_version`, [
      'hil-challenge-v1',
    ] as const),
    session_digest: digest(item.session_digest, `${path}/session_digest`),
    target_ipv4: ipv4(item.target_ipv4, `${path}/target_ipv4`),
    validation_snapshot_digest: digest(
      item.validation_snapshot_digest,
      `${path}/validation_snapshot_digest`,
    ),
    validation_valid_until: validationValidUntil,
  };
}

export function decodeHILChallengeEnvelope(
  value: unknown,
): Frozen<HILChallengeEnvelope> {
  const item = record(value, '/', ['challenge', 'challenge_nonce']);
  return deepFreeze({
    challenge: decodeHILChallenge(item.challenge, '/challenge'),
    challenge_nonce: text(item.challenge_nonce, '/challenge_nonce', {
      max: 43,
      pattern: /^[A-Za-z0-9_-]{43}$/,
    }),
  });
}

function decodeHILDecision(value: unknown, path: string): HILDecision {
  const item = record(value, path, [
    'actor_id',
    'canonical_artifact_digest',
    'challenge_id',
    'decided_at',
    'decision',
    'decision_id',
    'decision_valid_until',
    'evidence_snapshot_digest',
    'generated_artifact_digest',
    'idempotency_key_digest',
    'nonce_digest',
    'operation',
    'original_add_digest',
    'policy_digest',
    'reason_digest',
    'resource_id',
    'resource_type',
    'resource_version',
    'schema_version',
    'session_digest',
    'target_ipv4',
    'validation_snapshot_digest',
  ]);
  const operation = enumeration(
    item.operation,
    `${path}/operation`,
    HIL_OPERATIONS,
  );
  const decision = enumeration(item.decision, `${path}/decision`, [
    'approved',
    'rejected',
  ] as const);
  if (
    (operation === 'approve' && decision !== 'approved') ||
    (operation === 'reject' && decision !== 'rejected')
  ) {
    throw new WireContractError(path);
  }
  const decidedAt = timestamp(item.decided_at, `${path}/decided_at`);
  const decisionValidUntil = timestamp(
    item.decision_valid_until,
    `${path}/decision_valid_until`,
  );
  if (
    Date.parse(decisionValidUntil) <= Date.parse(decidedAt) ||
    Date.parse(decisionValidUntil) - Date.parse(decidedAt) > 5 * 60 * 1000
  ) {
    throw new WireContractError(path);
  }
  return {
    actor_id: text(item.actor_id, `${path}/actor_id`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    canonical_artifact_digest: digest(
      item.canonical_artifact_digest,
      `${path}/canonical_artifact_digest`,
    ),
    challenge_id: uuid(item.challenge_id, `${path}/challenge_id`),
    decided_at: decidedAt,
    decision,
    decision_id: uuid(item.decision_id, `${path}/decision_id`),
    decision_valid_until: decisionValidUntil,
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      `${path}/evidence_snapshot_digest`,
    ),
    generated_artifact_digest: digest(
      item.generated_artifact_digest,
      `${path}/generated_artifact_digest`,
    ),
    idempotency_key_digest: digest(
      item.idempotency_key_digest,
      `${path}/idempotency_key_digest`,
    ),
    nonce_digest: digest(item.nonce_digest, `${path}/nonce_digest`),
    operation,
    original_add_digest: nullValue(
      item.original_add_digest,
      `${path}/original_add_digest`,
    ),
    policy_digest: digest(item.policy_digest, `${path}/policy_digest`),
    reason_digest: digest(item.reason_digest, `${path}/reason_digest`),
    resource_id: uuid(item.resource_id, `${path}/resource_id`),
    resource_type: enumeration(item.resource_type, `${path}/resource_type`, [
      'policy',
    ] as const),
    resource_version: integer(
      item.resource_version,
      `${path}/resource_version`,
      1,
      2_147_483_647,
    ),
    schema_version: enumeration(item.schema_version, `${path}/schema_version`, [
      'hil-decision-v1',
    ] as const),
    session_digest: digest(item.session_digest, `${path}/session_digest`),
    target_ipv4: ipv4(item.target_ipv4, `${path}/target_ipv4`),
    validation_snapshot_digest: digest(
      item.validation_snapshot_digest,
      `${path}/validation_snapshot_digest`,
    ),
  };
}

export function decodeHILDecisionEnvelope(
  value: unknown,
): Frozen<HILDecisionEnvelope> {
  const discriminator = record(
    value,
    '/',
    ['decision', 'action_id', 'authorization_digest', 'outbox_job_id'],
    ['session', 'csrf_token', 'replayed', 'reauthentication_required'],
  );
  const replayed = Object.hasOwn(discriminator, 'replayed');
  const item = replayed
    ? record(value, '/', [
        'decision',
        'action_id',
        'authorization_digest',
        'outbox_job_id',
        'replayed',
        'reauthentication_required',
      ])
    : record(value, '/', [
        'decision',
        'action_id',
        'authorization_digest',
        'outbox_job_id',
        'session',
        'csrf_token',
      ]);
  const decision = decodeHILDecision(item.decision, '/decision');
  const actionID =
    item.action_id === null ? null : uuid(item.action_id, '/action_id');
  const authorizationDigest =
    item.authorization_digest === null
      ? null
      : digest(item.authorization_digest, '/authorization_digest');
  const outboxJobID =
    item.outbox_job_id === null
      ? null
      : uuid(item.outbox_job_id, '/outbox_job_id');
  const hasAuthority =
    actionID !== null && authorizationDigest !== null && outboxJobID !== null;
  if (
    (decision.operation === 'approve' && !hasAuthority) ||
    (decision.operation === 'reject' &&
      (actionID !== null ||
        authorizationDigest !== null ||
        outboxJobID !== null))
  ) {
    throw new WireContractError('/');
  }
  const authority = {
    decision,
    action_id: actionID,
    authorization_digest: authorizationDigest,
    outbox_job_id: outboxJobID,
  };
  if (replayed) {
    if (
      boolean(item.replayed, '/replayed') !== true ||
      boolean(item.reauthentication_required, '/reauthentication_required') !==
        true
    ) {
      throw new WireContractError('/');
    }
    return deepFreeze({
      ...authority,
      replayed: true,
      reauthentication_required: true,
    });
  }
  return deepFreeze({
    ...authority,
    session: decodeSession(item.session, '/session'),
    csrf_token: text(item.csrf_token, '/csrf_token', {
      max: 128,
      pattern: /^[A-Za-z0-9_-]{43}$/,
    }),
  });
}

function decodeRevocationChallenge(
  value: unknown,
  path: string,
): RevocationChallenge {
  const item = record(value, path, [
    'authenticated_at',
    'canonical_artifact_digest',
    'challenge_id',
    'evidence_snapshot_digest',
    'expires_at',
    'generated_artifact_digest',
    'issued_at',
    'nonce_digest',
    'operation',
    'original_add_digest',
    'policy_digest',
    'reauth_required_after_seconds',
    'resource_id',
    'resource_type',
    'resource_version',
    'schema_version',
    'session_digest',
    'target_ipv4',
    'validation_snapshot_digest',
    'validation_valid_until',
  ]);
  const authenticatedAt = timestamp(
    item.authenticated_at,
    `${path}/authenticated_at`,
  );
  const issuedAt = timestamp(item.issued_at, `${path}/issued_at`);
  const expiresAt = timestamp(item.expires_at, `${path}/expires_at`);
  const validationValidUntil = timestamp(
    item.validation_valid_until,
    `${path}/validation_valid_until`,
  );
  if (
    Date.parse(authenticatedAt) > Date.parse(issuedAt) ||
    Date.parse(expiresAt) <= Date.parse(issuedAt) ||
    Date.parse(expiresAt) > Date.parse(validationValidUntil) ||
    Date.parse(expiresAt) - Date.parse(issuedAt) > 5 * 60 * 1000
  ) {
    throw new WireContractError(path);
  }
  return {
    authenticated_at: authenticatedAt,
    canonical_artifact_digest: digest(
      item.canonical_artifact_digest,
      `${path}/canonical_artifact_digest`,
    ),
    challenge_id: uuid(item.challenge_id, `${path}/challenge_id`),
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      `${path}/evidence_snapshot_digest`,
    ),
    expires_at: expiresAt,
    generated_artifact_digest: digest(
      item.generated_artifact_digest,
      `${path}/generated_artifact_digest`,
    ),
    issued_at: issuedAt,
    nonce_digest: digest(item.nonce_digest, `${path}/nonce_digest`),
    operation: enumeration(item.operation, `${path}/operation`, [
      'revoke',
    ] as const),
    original_add_digest: digest(
      item.original_add_digest,
      `${path}/original_add_digest`,
    ),
    policy_digest: digest(item.policy_digest, `${path}/policy_digest`),
    reauth_required_after_seconds: integer(
      item.reauth_required_after_seconds,
      `${path}/reauth_required_after_seconds`,
      900,
      900,
    ) as 900,
    resource_id: uuid(item.resource_id, `${path}/resource_id`),
    resource_type: enumeration(item.resource_type, `${path}/resource_type`, [
      'enforcement_action',
    ] as const),
    resource_version: integer(
      item.resource_version,
      `${path}/resource_version`,
      1,
      2_147_483_647,
    ),
    schema_version: enumeration(item.schema_version, `${path}/schema_version`, [
      'hil-challenge-v1',
    ] as const),
    session_digest: digest(item.session_digest, `${path}/session_digest`),
    target_ipv4: ipv4(item.target_ipv4, `${path}/target_ipv4`),
    validation_snapshot_digest: digest(
      item.validation_snapshot_digest,
      `${path}/validation_snapshot_digest`,
    ),
    validation_valid_until: validationValidUntil,
  };
}

function revocationArtifactText(
  value: unknown,
  path: string,
  targetIPv4: string,
): string {
  const artifact = commandText(value, path);
  if (
    artifact !==
    `delete element inet sentinelflow blacklist_ipv4 { ${targetIPv4} }\n`
  ) {
    throw new WireContractError(path);
  }
  return artifact;
}

export function decodeRevocationChallengeEnvelope(
  value: unknown,
): Frozen<RevocationChallengeEnvelope> {
  const item = record(value, '/', [
    'challenge',
    'challenge_nonce',
    'canonical_revoke_artifact',
    'policy_id',
    'policy_version',
  ]);
  const challenge = decodeRevocationChallenge(item.challenge, '/challenge');
  return deepFreeze({
    challenge,
    challenge_nonce: text(item.challenge_nonce, '/challenge_nonce', {
      max: 43,
      pattern: /^[A-Za-z0-9_-]{43}$/,
    }),
    canonical_revoke_artifact: revocationArtifactText(
      item.canonical_revoke_artifact,
      '/canonical_revoke_artifact',
      challenge.target_ipv4,
    ),
    policy_id: uuid(item.policy_id, '/policy_id'),
    policy_version: integer(
      item.policy_version,
      '/policy_version',
      1,
      2_147_483_647,
    ),
  });
}

function decodeRevocationDecision(
  value: unknown,
  path: string,
): RevocationDecision {
  const item = record(value, path, [
    'actor_id',
    'canonical_artifact_digest',
    'challenge_id',
    'decided_at',
    'decision',
    'decision_id',
    'decision_valid_until',
    'evidence_snapshot_digest',
    'generated_artifact_digest',
    'idempotency_key_digest',
    'nonce_digest',
    'operation',
    'original_add_digest',
    'policy_digest',
    'reason_digest',
    'resource_id',
    'resource_type',
    'resource_version',
    'schema_version',
    'session_digest',
    'target_ipv4',
    'validation_snapshot_digest',
  ]);
  const decidedAt = timestamp(item.decided_at, `${path}/decided_at`);
  const decisionValidUntil = timestamp(
    item.decision_valid_until,
    `${path}/decision_valid_until`,
  );
  if (
    Date.parse(decisionValidUntil) <= Date.parse(decidedAt) ||
    Date.parse(decisionValidUntil) - Date.parse(decidedAt) > 5 * 60 * 1000
  ) {
    throw new WireContractError(path);
  }
  return {
    actor_id: text(item.actor_id, `${path}/actor_id`, {
      max: 128,
      pattern: ASCII_ID,
    }),
    canonical_artifact_digest: digest(
      item.canonical_artifact_digest,
      `${path}/canonical_artifact_digest`,
    ),
    challenge_id: uuid(item.challenge_id, `${path}/challenge_id`),
    decided_at: decidedAt,
    decision: enumeration(item.decision, `${path}/decision`, [
      'revoked',
    ] as const),
    decision_id: uuid(item.decision_id, `${path}/decision_id`),
    decision_valid_until: decisionValidUntil,
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      `${path}/evidence_snapshot_digest`,
    ),
    generated_artifact_digest: digest(
      item.generated_artifact_digest,
      `${path}/generated_artifact_digest`,
    ),
    idempotency_key_digest: digest(
      item.idempotency_key_digest,
      `${path}/idempotency_key_digest`,
    ),
    nonce_digest: digest(item.nonce_digest, `${path}/nonce_digest`),
    operation: enumeration(item.operation, `${path}/operation`, [
      'revoke',
    ] as const),
    original_add_digest: digest(
      item.original_add_digest,
      `${path}/original_add_digest`,
    ),
    policy_digest: digest(item.policy_digest, `${path}/policy_digest`),
    reason_digest: digest(item.reason_digest, `${path}/reason_digest`),
    resource_id: uuid(item.resource_id, `${path}/resource_id`),
    resource_type: enumeration(item.resource_type, `${path}/resource_type`, [
      'enforcement_action',
    ] as const),
    resource_version: integer(
      item.resource_version,
      `${path}/resource_version`,
      1,
      2_147_483_647,
    ),
    schema_version: enumeration(item.schema_version, `${path}/schema_version`, [
      'hil-decision-v1',
    ] as const),
    session_digest: digest(item.session_digest, `${path}/session_digest`),
    target_ipv4: ipv4(item.target_ipv4, `${path}/target_ipv4`),
    validation_snapshot_digest: digest(
      item.validation_snapshot_digest,
      `${path}/validation_snapshot_digest`,
    ),
  };
}

export function decodeRevocationDecisionEnvelope(
  value: unknown,
): Frozen<RevocationDecisionEnvelope> {
  const discriminator = record(
    value,
    '/',
    [
      'decision',
      'revocation_id',
      'authorization_id',
      'authorization_digest',
      'outbox_job_id',
      'audit_event_id',
    ],
    ['session', 'csrf_token', 'replayed', 'reauthentication_required'],
  );
  const replayed = Object.hasOwn(discriminator, 'replayed');
  const common = [
    'decision',
    'revocation_id',
    'authorization_id',
    'authorization_digest',
    'outbox_job_id',
    'audit_event_id',
  ] as const;
  const item = replayed
    ? record(value, '/', [...common, 'replayed', 'reauthentication_required'])
    : record(value, '/', [...common, 'session', 'csrf_token']);
  const result = {
    decision: decodeRevocationDecision(item.decision, '/decision'),
    revocation_id: uuid(item.revocation_id, '/revocation_id'),
    authorization_id: uuid(item.authorization_id, '/authorization_id'),
    authorization_digest: digest(
      item.authorization_digest,
      '/authorization_digest',
    ),
    outbox_job_id: uuid(item.outbox_job_id, '/outbox_job_id'),
    audit_event_id: uuid(item.audit_event_id, '/audit_event_id'),
  };
  if (replayed) {
    if (
      boolean(item.replayed, '/replayed') !== true ||
      boolean(item.reauthentication_required, '/reauthentication_required') !==
        true
    ) {
      throw new WireContractError('/');
    }
    return deepFreeze({
      ...result,
      replayed: true,
      reauthentication_required: true,
    });
  }
  return deepFreeze({
    ...result,
    session: decodeSession(item.session, '/session'),
    csrf_token: text(item.csrf_token, '/csrf_token', {
      max: 128,
      pattern: /^[A-Za-z0-9_-]{43}$/,
    }),
  });
}

export function decodeIncidentPage(value: unknown): Frozen<IncidentPage> {
  const item = record(value, '/', ['items'], ['next_cursor']);
  const cursor = optional(
    item,
    'next_cursor',
    (candidate, path) => text(candidate, path, { max: 128, pattern: CURSOR }),
    '/',
  );
  return deepFreeze({
    items: list(item.items, '/items', decodeIncidentSummaryAt),
    ...(cursor ? { next_cursor: cursor } : {}),
  });
}

export function decodeIncidentDetail(value: unknown): Frozen<IncidentDetail> {
  const item = record(
    value,
    '/',
    [
      'incident',
      'signals',
      'signals_truncated',
      'policies',
      'policies_truncated',
    ],
    ['latest_analysis'],
  );
  return deepFreeze({
    incident: decodeIncidentSummaryAt(item.incident, '/incident'),
    signals: list(item.signals, '/signals', decodeSignal),
    signals_truncated: boolean(item.signals_truncated, '/signals_truncated'),
    ...(Object.hasOwn(item, 'latest_analysis')
      ? {
          latest_analysis: decodeAnalysis(
            item.latest_analysis,
            '/latest_analysis',
          ),
        }
      : {}),
    policies: list(item.policies, '/policies', decodePolicySummary),
    policies_truncated: boolean(item.policies_truncated, '/policies_truncated'),
  });
}

export function decodeIncidentEventPage(
  value: unknown,
): Frozen<IncidentEventPage> {
  const item = record(value, '/', ['items'], ['next_cursor']);
  const cursor = optional(
    item,
    'next_cursor',
    (candidate, path) => text(candidate, path, { max: 128, pattern: CURSOR }),
    '/',
  );
  return deepFreeze({
    items: list(item.items, '/items', decodeIncidentEventAt),
    ...(cursor ? { next_cursor: cursor } : {}),
  });
}

export function decodePolicyDetail(value: unknown): Frozen<PolicyDetail> {
  const item = record(
    value,
    '/',
    [
      'policy_id',
      'version',
      'incident_id',
      'incident_version',
      'analysis_id',
      'command_candidate_id',
      'state',
      'state_revision',
      'target_ipv4',
      'action',
      'ttl_seconds',
      'timeout_token',
      'rationale',
      'policy_digest',
      'evidence_snapshot_digest',
      'generated_command',
      'generated_artifact_digest',
      'canonical_command',
      'canonical_artifact_digest',
      'parse_state',
      'created_at',
      'updated_at',
    ],
    [
      'parse_error_code',
      'latest_validation',
      'latest_validation_attempt',
      'decision',
    ],
  );
  const policyID = uuid(item.policy_id, '/policy_id');
  const incidentID = uuid(item.incident_id, '/incident_id');
  const incidentVersion = integer(
    item.incident_version,
    '/incident_version',
    1,
    2_147_483_647,
  );
  const analysisID = uuid(item.analysis_id, '/analysis_id');
  const policyState = enumeration(item.state, '/state', POLICY_STATES);
  const validation = Object.hasOwn(item, 'latest_validation')
    ? decodeValidation(item.latest_validation, '/latest_validation')
    : undefined;
  const validationAttempt = Object.hasOwn(item, 'latest_validation_attempt')
    ? decodeValidationAttempt(
        item.latest_validation_attempt,
        '/latest_validation_attempt',
      )
    : undefined;
  const decision = Object.hasOwn(item, 'decision')
    ? decodeDecision(item.decision, '/decision')
    : undefined;
  if (
    validationAttempt &&
    (validationAttempt.policy_id !== policyID ||
      validationAttempt.analysis_id !== analysisID ||
      validationAttempt.incident_id !== incidentID ||
      validationAttempt.incident_version !== incidentVersion)
  ) {
    throw new WireContractError('/latest_validation_attempt');
  }
  if (
    !validPolicyTerminalBinding(
      policyState,
      validation,
      validationAttempt,
      decision,
    )
  ) {
    throw new WireContractError('/latest_validation_attempt');
  }
  return deepFreeze({
    policy_id: policyID,
    version: integer(item.version, '/version', 1, 2_147_483_647),
    incident_id: incidentID,
    incident_version: incidentVersion,
    analysis_id: analysisID,
    command_candidate_id: uuid(
      item.command_candidate_id,
      '/command_candidate_id',
    ),
    state: policyState,
    state_revision: integer(item.state_revision, '/state_revision', 1),
    target_ipv4: ipv4(item.target_ipv4, '/target_ipv4'),
    action: enumeration(item.action, '/action', ['block_ip']),
    ttl_seconds: integer(item.ttl_seconds, '/ttl_seconds', 60, 86_400),
    timeout_token: text(item.timeout_token, '/timeout_token', {
      max: 16,
      pattern: /^[1-9][0-9]*(?:h|m|s)$/,
    }),
    rationale: text(item.rationale, '/rationale', { max: 800 }),
    policy_digest: digest(item.policy_digest, '/policy_digest'),
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      '/evidence_snapshot_digest',
    ),
    generated_command: commandText(
      item.generated_command,
      '/generated_command',
    ),
    generated_artifact_digest: digest(
      item.generated_artifact_digest,
      '/generated_artifact_digest',
    ),
    canonical_command: commandText(
      item.canonical_command,
      '/canonical_command',
    ),
    canonical_artifact_digest: digest(
      item.canonical_artifact_digest,
      '/canonical_artifact_digest',
    ),
    parse_state: text(item.parse_state, '/parse_state', {
      max: 32,
      pattern: ASCII_ID,
    }),
    ...(Object.hasOwn(item, 'parse_error_code')
      ? {
          parse_error_code: text(item.parse_error_code, '/parse_error_code', {
            max: 128,
            pattern: ASCII_ID,
          }),
        }
      : {}),
    created_at: timestamp(item.created_at, '/created_at'),
    updated_at: timestamp(item.updated_at, '/updated_at'),
    ...(validation ? { latest_validation: validation } : {}),
    ...(validationAttempt
      ? { latest_validation_attempt: validationAttempt }
      : {}),
    ...(decision ? { decision } : {}),
  });
}

export function decodeEnforcementAction(
  value: unknown,
): Frozen<EnforcementActionDetail> {
  const item = record(
    value,
    '/',
    [
      'action_id',
      'policy_id',
      'policy_version',
      'validation_snapshot_id',
      'evidence_snapshot_digest',
      'target_ipv4',
      'canonical_artifact_digest',
      'ttl_seconds',
      'state',
      'approved_at',
      'version',
      'created_at',
      'updated_at',
    ],
    [
      'queued_at',
      'applied_at',
      'expected_expires_at',
      'finished_at',
      'latest_result',
    ],
  );
  return deepFreeze({
    action_id: uuid(item.action_id, '/action_id'),
    policy_id: uuid(item.policy_id, '/policy_id'),
    policy_version: integer(
      item.policy_version,
      '/policy_version',
      1,
      2_147_483_647,
    ),
    validation_snapshot_id: uuid(
      item.validation_snapshot_id,
      '/validation_snapshot_id',
    ),
    evidence_snapshot_digest: digest(
      item.evidence_snapshot_digest,
      '/evidence_snapshot_digest',
    ),
    target_ipv4: ipv4(item.target_ipv4, '/target_ipv4'),
    canonical_artifact_digest: digest(
      item.canonical_artifact_digest,
      '/canonical_artifact_digest',
    ),
    ttl_seconds: integer(item.ttl_seconds, '/ttl_seconds', 60, 86_400),
    state: enumeration(item.state, '/state', [
      'approved',
      'queued',
      'active',
      'expired',
      'failed',
      'revoked',
      'indeterminate',
    ]),
    approved_at: timestamp(item.approved_at, '/approved_at'),
    ...(Object.hasOwn(item, 'queued_at')
      ? { queued_at: timestamp(item.queued_at, '/queued_at') }
      : {}),
    ...(Object.hasOwn(item, 'applied_at')
      ? { applied_at: timestamp(item.applied_at, '/applied_at') }
      : {}),
    ...(Object.hasOwn(item, 'expected_expires_at')
      ? {
          expected_expires_at: timestamp(
            item.expected_expires_at,
            '/expected_expires_at',
          ),
        }
      : {}),
    ...(Object.hasOwn(item, 'finished_at')
      ? { finished_at: timestamp(item.finished_at, '/finished_at') }
      : {}),
    version: integer(item.version, '/version', 1, 2_147_483_647),
    created_at: timestamp(item.created_at, '/created_at'),
    updated_at: timestamp(item.updated_at, '/updated_at'),
    ...(Object.hasOwn(item, 'latest_result')
      ? { latest_result: decodeResult(item.latest_result, '/latest_result') }
      : {}),
  });
}

export function decodeAuditPage(value: unknown): Frozen<AuditPage> {
  const item = record(value, '/', ['items'], ['next_cursor']);
  const cursor = optional(
    item,
    'next_cursor',
    (candidate, path) => text(candidate, path, { max: 128, pattern: CURSOR }),
    '/',
  );
  return deepFreeze({
    items: list(item.items, '/items', decodeAuditEvent),
    ...(cursor ? { next_cursor: cursor } : {}),
  });
}

function decodeStreamData(
  value: unknown,
  id: string,
  type: StreamEventType,
): StreamEvent {
  const item = record(
    value,
    '/',
    ['resource_id', 'resource_version', 'occurred_at', 'summary'],
    ['incident_id', 'policy_id', 'action_id', 'trace_id'],
  );
  const summary = record(item.summary, '/summary', ['code', 'outcome']);
  const event: StreamEvent = {
    id: text(id, '/id', { max: 19, pattern: SSE_CURSOR }),
    type,
    resource_id: uuid(item.resource_id, '/resource_id'),
    resource_version: integer(item.resource_version, '/resource_version', 1),
    ...(Object.hasOwn(item, 'incident_id')
      ? { incident_id: uuid(item.incident_id, '/incident_id') }
      : {}),
    ...(Object.hasOwn(item, 'policy_id')
      ? { policy_id: uuid(item.policy_id, '/policy_id') }
      : {}),
    ...(Object.hasOwn(item, 'action_id')
      ? { action_id: uuid(item.action_id, '/action_id') }
      : {}),
    occurred_at: timestamp(item.occurred_at, '/occurred_at'),
    ...(Object.hasOwn(item, 'trace_id')
      ? { trace_id: uuid(item.trace_id, '/trace_id') }
      : {}),
    summary: {
      code: text(summary.code, '/summary/code', {
        max: 128,
        pattern: ASCII_ID,
      }),
      outcome: text(summary.outcome, '/summary/outcome', {
        max: 128,
        pattern: ASCII_ID,
      }),
    },
  };
  const incidentIsResource = event.incident_id === event.resource_id;
  const policyIsResource = event.policy_id === event.resource_id;
  const actionIsResource = event.action_id === event.resource_id;
  const valid =
    ((type === 'incident.created' || type === 'incident.updated') &&
      incidentIsResource &&
      !event.policy_id &&
      !event.action_id) ||
    ((type === 'analysis.completed' || type === 'analysis.failed') &&
      Boolean(event.incident_id) &&
      !event.policy_id &&
      !event.action_id) ||
    (type === 'policy.validation_updated' &&
      Boolean(event.incident_id) &&
      policyIsResource &&
      !event.action_id) ||
    (type === 'approval.recorded' &&
      Boolean(event.incident_id) &&
      ((policyIsResource && !event.action_id) ||
        (actionIsResource && !event.policy_id))) ||
    (type === 'enforcement.updated' &&
      Boolean(event.incident_id) &&
      actionIsResource &&
      !event.policy_id) ||
    ((type === 'source.degraded' || type === 'source.recovered') &&
      !event.incident_id &&
      !event.policy_id &&
      !event.action_id);
  if (!valid) {
    throw new WireContractError('/');
  }
  const incidentOutcome = INCIDENT_STATES.includes(
    event.summary.outcome as IncidentState,
  );
  const validSummary =
    (type === 'incident.created' &&
      event.summary.code === 'incident_created' &&
      incidentOutcome) ||
    (type === 'incident.updated' &&
      event.summary.code === 'incident_updated' &&
      incidentOutcome) ||
    (type === 'analysis.completed' &&
      event.summary.code === 'analysis_completed' &&
      event.summary.outcome === 'succeeded') ||
    (type === 'analysis.failed' &&
      event.summary.code === 'analysis_failed' &&
      event.summary.outcome === 'failed') ||
    (type === 'policy.validation_updated' &&
      event.summary.code === 'policy_validation_updated' &&
      ['validating', 'valid', 'invalid', 'stale'].includes(
        event.summary.outcome,
      )) ||
    (type === 'approval.recorded' &&
      event.summary.code === 'approval_recorded' &&
      ['approved', 'rejected', 'revoked'].includes(event.summary.outcome)) ||
    (type === 'enforcement.updated' &&
      event.summary.code === 'enforcement_updated' &&
      [
        'approved',
        'queued',
        'active',
        'expired',
        'failed',
        'revoked',
        'indeterminate',
      ].includes(event.summary.outcome)) ||
    (type === 'source.degraded' &&
      event.summary.code === 'source_degraded' &&
      ['degraded', 'lost'].includes(event.summary.outcome)) ||
    (type === 'source.recovered' &&
      event.summary.code === 'source_recovered' &&
      event.summary.outcome === 'recovered');
  if (!validSummary) {
    throw new WireContractError('/summary');
  }
  return event;
}

export function decodeStreamEvent(
  id: string,
  type: string,
  value: unknown,
): Frozen<StreamEvent> {
  const eventType = enumeration(type, '/type', STREAM_EVENT_TYPES);
  return deepFreeze(decodeStreamData(value, id, eventType));
}

export function isCanonicalUUID(value: string): boolean {
  return UUID.test(value);
}
