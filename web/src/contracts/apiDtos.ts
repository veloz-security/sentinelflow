import type {
  DeterministicSignalV1,
  ExecutionResultV1,
  GatewayHttpV1,
  HilChallengeV1,
  HilDecisionV1,
  Ipv4Address,
  ResponsePolicyV1,
  Rfc3339Timestamp,
  SentinelFlowAnalysisV1,
  Sha256Digest,
  SourceHealthV1,
  Uuid,
  ValidationSnapshotV1,
} from './rootContracts';

export const INCIDENT_STATES = [
  'open',
  'analyzing',
  'review_ready',
  'closed',
  'analysis_failed',
] as const;
export type IncidentState = (typeof INCIDENT_STATES)[number];

export const ANALYSIS_FAILURE_REASONS = [
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
export type AnalysisFailureReason = (typeof ANALYSIS_FAILURE_REASONS)[number];

export interface IncidentSummaryV1 {
  readonly schema_version: 'incident-summary-v1';
  readonly incident_id: Uuid;
  readonly incident_version: number;
  readonly state: IncidentState;
  readonly analysis_failure_reason: AnalysisFailureReason | null;
  readonly source_ip: Ipv4Address;
  readonly service_label: string;
  readonly signal_count: number;
  readonly first_seen_at: Rfc3339Timestamp;
  readonly last_seen_at: Rfc3339Timestamp;
  readonly updated_at: Rfc3339Timestamp;
}

export const HIL_REVIEW_STATES = [
  'not_requested',
  'step_up_required',
  'challenge_issued',
  'approved',
  'rejected',
  'expired',
  'conflict',
  'rate_limited',
  'permission_denied',
] as const;
export type HilReviewStatus = (typeof HIL_REVIEW_STATES)[number];

export interface HilReviewStateV1 {
  readonly schema_version: 'hil-review-state-v1';
  readonly status: HilReviewStatus;
  readonly challenge: HilChallengeV1 | null;
  readonly challenge_nonce_available: boolean;
  readonly decision: HilDecisionV1 | null;
  readonly can_request_challenge: boolean;
  readonly can_submit_decision: boolean;
  readonly updated_at: Rfc3339Timestamp;
}

export const LIFECYCLE_STATES = [
  'pending',
  'applied',
  'active',
  'expired',
  'revoked',
  'failed',
  'indeterminate',
] as const;
export type LifecycleState = (typeof LIFECYCLE_STATES)[number];

export const SIGNATURE_VERIFICATION_STATES = [
  'verified',
  'invalid',
  'missing',
] as const;
export type SignatureVerificationState =
  (typeof SIGNATURE_VERIFICATION_STATES)[number];

export interface LifecycleOperationV1 {
  readonly operation_id: Uuid;
  readonly operation: 'add' | 'revoke' | 'inspect';
  readonly requested_at: Rfc3339Timestamp;
  readonly signature_verification: SignatureVerificationState;
  readonly result: ExecutionResultV1 | null;
}

export interface EnforcementLifecycleV1 {
  readonly schema_version: 'enforcement-lifecycle-v1';
  readonly action_id: Uuid;
  readonly action_version: number;
  readonly policy_id: Uuid;
  readonly state: LifecycleState;
  readonly target_ipv4: Ipv4Address;
  readonly original_add_digest: Sha256Digest;
  readonly approved_ttl_seconds: number;
  readonly applied_at: Rfc3339Timestamp | null;
  readonly expires_at: Rfc3339Timestamp | null;
  readonly operations: readonly LifecycleOperationV1[];
  readonly updated_at: Rfc3339Timestamp;
}

export const AUDIT_CATEGORIES = [
  'observation',
  'analysis',
  'validation',
  'authorization',
  'enforcement',
  'source_health',
] as const;
export type AuditCategory = (typeof AUDIT_CATEGORIES)[number];

export const AUDIT_ACTOR_KINDS = [
  'administrator',
  'system',
  'service',
] as const;
export type AuditActorKind = (typeof AUDIT_ACTOR_KINDS)[number];

export const AUDIT_OBJECT_TYPES = [
  'incident',
  'analysis',
  'policy',
  'validation',
  'hil_decision',
  'enforcement_action',
  'source',
] as const;
export type AuditObjectType = (typeof AUDIT_OBJECT_TYPES)[number];

export const AUDIT_OUTCOMES = [
  'recorded',
  'succeeded',
  'failed',
  'denied',
  'indeterminate',
] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

export interface AuditEventV1 {
  readonly schema_version: 'audit-event-v1';
  readonly audit_id: Uuid;
  readonly occurred_at: Rfc3339Timestamp;
  readonly category: AuditCategory;
  readonly event_type: string;
  readonly actor_kind: AuditActorKind;
  readonly actor_id: string;
  readonly object_type: AuditObjectType;
  readonly object_id: Uuid;
  readonly outcome: AuditOutcome;
  readonly trace_id: Uuid;
  readonly correlation_id: Uuid | null;
  readonly safe_reason_code: string | null;
}

export interface IncidentDetailV1 {
  readonly schema_version: 'incident-detail-v1';
  readonly incident: IncidentSummaryV1;
  readonly gateway_events: readonly GatewayHttpV1[];
  readonly source_health_events: readonly SourceHealthV1[];
  readonly deterministic_signals: readonly DeterministicSignalV1[];
  readonly ai_analysis: SentinelFlowAnalysisV1 | null;
  readonly policy: ResponsePolicyV1 | null;
  readonly validation: ValidationSnapshotV1 | null;
  readonly hil_review: HilReviewStateV1;
  readonly enforcement: EnforcementLifecycleV1 | null;
  readonly audit_events: readonly AuditEventV1[];
}

export const API_ERROR_CODES = [
  'authentication_required',
  'permission_denied',
  'csrf_invalid',
  'step_up_required',
  'rate_limited',
  'stale_version',
  'digest_mismatch',
  'challenge_expired',
  'challenge_consumed',
  'idempotency_conflict',
  'validation_failed',
  'schema_invalid',
  'not_found',
  'service_unavailable',
  'internal_error',
] as const;
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

export type ApiErrorDetail = string | number | boolean | null;

export interface ApiErrorV1 {
  readonly code: ApiErrorCode;
  readonly message: string;
  readonly trace_id: Uuid;
  readonly details: Readonly<Record<string, ApiErrorDetail>>;
}
