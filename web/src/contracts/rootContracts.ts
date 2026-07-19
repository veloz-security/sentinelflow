export type Uuid = string;
export type Sha256Digest = string;
export type Rfc3339Timestamp = string;
export type Ipv4Address = string;

export const SUSPICIOUS_PATH_IDS = [
  'none',
  'admin_console',
  'env_file',
  'git_config',
  'wp_admin',
  'phpmyadmin',
  'server_status',
  'actuator_env',
  'backup_archive',
] as const;
export type SuspiciousPathId = (typeof SUSPICIOUS_PATH_IDS)[number];

export interface GatewayHttpV1 {
  readonly schema_version: 'gateway-http-v1';
  readonly event_id: Uuid;
  readonly request_id: Uuid;
  readonly trace_id: Uuid;
  readonly idempotency_key: Sha256Digest;
  readonly started_at: Rfc3339Timestamp;
  readonly completed_at: Rfc3339Timestamp;
  readonly source_ip: Ipv4Address;
  readonly method: string;
  readonly protocol: 'HTTP/1.1';
  readonly route_label: string;
  readonly path_catalog_version: 'path-catalog-v1';
  readonly suspicious_path_id: SuspiciousPathId;
  readonly host: string;
  readonly service_label: string;
  readonly status_code: number;
  readonly request_bytes: number;
  readonly response_bytes: number;
  readonly latency_ms: number;
}

export const AUTH_EVENT_OUTCOMES = ['failed', 'succeeded'] as const;
export type AuthEventOutcome = (typeof AUTH_EVENT_OUTCOMES)[number];

export interface AuthEventV1 {
  readonly schema_version: 'auth-event-v1';
  readonly event_id: Uuid;
  readonly gateway_request_id: Uuid;
  readonly trace_id: Uuid;
  readonly idempotency_key: Sha256Digest;
  readonly occurred_at: Rfc3339Timestamp;
  readonly source_ip: Ipv4Address;
  readonly service_label: string;
  readonly route_label: string;
  readonly account_hash: string;
  readonly outcome: AuthEventOutcome;
}

export const SOURCE_HEALTH_CAUSES = [
  'queue_overflow',
  'delivery_outage',
  'rejected_batch',
  'sequence_gap',
  'permanent_loss',
  'unclean_restart',
  'unknown_loss',
  'recovered',
] as const;
export type SourceHealthCause = (typeof SOURCE_HEALTH_CAUSES)[number];

export const SOURCE_HEALTH_STATES = ['degraded', 'lost', 'recovered'] as const;
export type SourceHealthState = (typeof SOURCE_HEALTH_STATES)[number];

export const SOURCE_HEALTH_DETAIL_CODES = [
  'none',
  'known_range',
  'unknown_range',
  'receiver_rejected',
  'sender_restart',
  'delivery_restored',
] as const;
export type SourceHealthDetailCode =
  (typeof SOURCE_HEALTH_DETAIL_CODES)[number];

export interface SourceHealthV1 {
  readonly schema_version: 'source-health-v1';
  readonly event_id: Uuid;
  readonly idempotency_key: Sha256Digest;
  readonly occurred_at: Rfc3339Timestamp;
  readonly source_id: string;
  readonly cause: SourceHealthCause;
  readonly state: SourceHealthState;
  readonly affected_sender_epoch: string;
  readonly sequence_start: number | null;
  readonly sequence_end: number | null;
  readonly interval_start: Rfc3339Timestamp | null;
  readonly interval_end: Rfc3339Timestamp | null;
  readonly dropped_count: number;
  readonly detail_code: SourceHealthDetailCode;
}

export const DETECTION_RULE_IDS = [
  'path_scan.v1',
  'request_burst.v1',
  'login_bruteforce.v1',
  'credential_stuffing.v1',
] as const;
export type DetectionRuleId = (typeof DETECTION_RULE_IDS)[number];

export const DETECTION_CLASSIFICATIONS = [
  'path_scan',
  'request_burst',
  'brute_force',
  'credential_stuffing',
] as const;
export type DetectionClassification =
  (typeof DETECTION_CLASSIFICATIONS)[number];

export interface DeterministicSignalV1 {
  readonly schema_version: 'deterministic-signal-view-v1';
  readonly signal_id: Uuid;
  readonly rule_id: DetectionRuleId;
  readonly classification: DetectionClassification;
  readonly window_start: Rfc3339Timestamp;
  readonly window_end: Rfc3339Timestamp;
  readonly event_count: number;
  readonly distinct_account_count: number;
  readonly distinct_suspicious_path_count: number;
  readonly evidence_digest: Sha256Digest;
}

export const AI_CLASSIFICATIONS = [
  'credential_stuffing',
  'brute_force',
  'path_scan',
  'request_burst',
  'mixed',
  'unknown',
] as const;
export type AiClassification = (typeof AI_CLASSIFICATIONS)[number];

export interface AnalysisPolicyV1 {
  readonly schema_version: 'response-policy-v1';
  readonly action: 'block_ip';
  readonly target_ip: Ipv4Address;
  readonly ttl_seconds: number;
  readonly evidence_ids: readonly string[];
  readonly rationale: string;
}

export interface NftablesCommandCandidateV1 {
  readonly schema_version: 'nft-blacklist-v1';
  readonly target_ip: Ipv4Address;
  readonly timeout: string;
  readonly evidence_ids: readonly string[];
  readonly command: string;
}

export interface SentinelFlowAnalysisV1 {
  readonly schema_version: 'sentinelflow_analysis_v1';
  readonly incident_summary: string;
  readonly classification: AiClassification;
  readonly confidence: number;
  readonly uncertainty: string;
  readonly false_positive_factors: readonly string[];
  readonly evidence_ids: readonly string[];
  readonly policy: AnalysisPolicyV1;
  readonly nftables_command_candidate: NftablesCommandCandidateV1;
}

export interface ResponsePolicyV1 {
  readonly schema_version: 'response-policy-v1';
  readonly policy_id: Uuid;
  readonly policy_version: number;
  readonly incident_id: Uuid;
  readonly analysis_id: Uuid;
  readonly action: 'block_ip';
  readonly target_ipv4: Ipv4Address;
  readonly ttl_seconds: number;
  readonly evidence_snapshot_digest: Sha256Digest;
  readonly evidence_ids: readonly Uuid[];
  readonly rationale_digest: Sha256Digest;
  readonly created_at: Rfc3339Timestamp;
}

export const VALIDATION_CHECK_IDS = [
  'structured_output',
  'command_grammar',
  'policy_evidence_command_consistency',
  'protected_network',
  'owned_schema_syntax',
  'historical_impact',
] as const;
export type ValidationCheckId = (typeof VALIDATION_CHECK_IDS)[number];

export interface ValidationCheckV1 {
  readonly check_id: ValidationCheckId;
  readonly result: 'pass';
  readonly reason_code: 'ok';
  readonly input_digest: Sha256Digest;
}

export interface ValidationSnapshotV1 {
  readonly schema_version: 'validation-snapshot-v1';
  readonly validation_id: Uuid;
  readonly policy_digest: Sha256Digest;
  readonly evidence_snapshot_digest: Sha256Digest;
  readonly analysis_input_digest: Sha256Digest;
  readonly analysis_output_schema_digest: Sha256Digest;
  readonly prompt_digest: Sha256Digest;
  readonly generated_candidate_digest: Sha256Digest;
  readonly canonical_artifact_digest: Sha256Digest;
  readonly grammar_version: 'nft-blacklist-v1';
  readonly parser_version: string;
  readonly validator_version: string;
  readonly base_chain_contract_raw_digest: Sha256Digest;
  readonly live_owned_schema_digest: Sha256Digest;
  readonly protected_ipv4_static_digest: Sha256Digest;
  readonly protected_ipv4_effective_config_digest: Sha256Digest;
  readonly nft_binary_digest: Sha256Digest;
  readonly nft_version: string;
  readonly historical_impact_digest: Sha256Digest;
  readonly checks: readonly ValidationCheckV1[];
  readonly created_at: Rfc3339Timestamp;
  readonly valid_until: Rfc3339Timestamp;
}

export interface DemoHistoryManifestV1 {
  readonly schema_version: 'demo-history-v1';
  readonly manifest_id: Uuid;
  readonly profile: 'isolated-demo';
  readonly clock_at: Rfc3339Timestamp;
  readonly dataset_id: Uuid;
  readonly dataset_schema_version: 'demo-history-dataset-v1';
  readonly dataset_digest: Sha256Digest;
  readonly dataset_record_count: number;
  readonly import_id: Uuid;
  readonly coverage_start: Rfc3339Timestamp;
  readonly coverage_end: Rfc3339Timestamp;
  readonly path_catalog_version: 'path-catalog-v1';
  readonly source_health_digest: Sha256Digest;
  readonly issued_at: Rfc3339Timestamp;
}

export interface SignedDemoHistoryFixtureV1 {
  readonly schema_version: 'demo-history-signed-manifest-v1';
  readonly fixture_only: true;
  readonly key_scope: 'public-test-only; actual demo runs must generate a run-scoped key and manifest';
  readonly manifest: DemoHistoryManifestV1;
  readonly manifest_jcs_b64url: string;
  readonly manifest_digest: Sha256Digest;
  readonly signature_b64url: string;
  readonly public_key_b64url: string;
}

export const HIL_OPERATIONS = ['approve', 'reject', 'revoke'] as const;
export type HilOperation = (typeof HIL_OPERATIONS)[number];
export type HilResourceType = 'policy' | 'enforcement_action';

export interface HilChallengeV1 {
  readonly schema_version: 'hil-challenge-v1';
  readonly challenge_id: Uuid;
  readonly session_digest: Sha256Digest;
  readonly operation: HilOperation;
  readonly resource_type: HilResourceType;
  readonly resource_id: Uuid;
  readonly resource_version: number;
  readonly target_ipv4: Ipv4Address;
  readonly policy_digest: Sha256Digest;
  readonly generated_artifact_digest: Sha256Digest;
  readonly canonical_artifact_digest: Sha256Digest;
  readonly original_add_digest: Sha256Digest | null;
  readonly evidence_snapshot_digest: Sha256Digest;
  readonly validation_snapshot_digest: Sha256Digest;
  readonly validation_valid_until: Rfc3339Timestamp;
  readonly nonce_digest: Sha256Digest;
  readonly authenticated_at: Rfc3339Timestamp;
  readonly reauth_required_after_seconds: 900;
  readonly issued_at: Rfc3339Timestamp;
  readonly expires_at: Rfc3339Timestamp;
}

export const HIL_DECISIONS = ['approved', 'rejected', 'revoked'] as const;
export type HilDecision = (typeof HIL_DECISIONS)[number];

export const HIL_REASON_CODES = [
  'threat_confirmed',
  'false_positive',
  'business_exception',
  'emergency_revoke',
  'operator_request',
  'other',
] as const;
export type HilReasonCode = (typeof HIL_REASON_CODES)[number];

export interface HilReasonV1 {
  readonly schema_version: 'hil-reason-v1';
  readonly reason_code: HilReasonCode;
  readonly reason_text: string;
}

export interface HilDecisionV1 {
  readonly schema_version: 'hil-decision-v1';
  readonly decision_id: Uuid;
  readonly challenge_id: Uuid;
  readonly session_digest: Sha256Digest;
  readonly operation: HilOperation;
  readonly decision: HilDecision;
  readonly resource_type: HilResourceType;
  readonly resource_id: Uuid;
  readonly resource_version: number;
  readonly target_ipv4: Ipv4Address;
  readonly policy_digest: Sha256Digest;
  readonly generated_artifact_digest: Sha256Digest;
  readonly canonical_artifact_digest: Sha256Digest;
  readonly original_add_digest: Sha256Digest | null;
  readonly evidence_snapshot_digest: Sha256Digest;
  readonly validation_snapshot_digest: Sha256Digest;
  readonly actor_id: string;
  readonly reason_digest: Sha256Digest;
  readonly nonce_digest: Sha256Digest;
  readonly idempotency_key_digest: Sha256Digest;
  readonly decided_at: Rfc3339Timestamp;
  readonly decision_valid_until: Rfc3339Timestamp;
}

export const EXECUTION_OPERATIONS = ['add', 'revoke', 'inspect'] as const;
export type ExecutionOperation = (typeof EXECUTION_OPERATIONS)[number];

export const EXECUTION_CLASSIFICATIONS = [
  'applied',
  'recovered_active',
  'revoked',
  'inspect_active',
  'inspect_absent',
  'inspect_mismatch',
  'failed',
  'indeterminate',
] as const;
export type ExecutionClassification =
  (typeof EXECUTION_CLASSIFICATIONS)[number];

export const EXECUTION_ERROR_CODES = [
  'none',
  'capability_invalid',
  'artifact_mismatch',
  'schema_mismatch',
  'target_exists',
  'target_absent',
  'nft_failed',
  'readback_failed',
  'readback_mismatch',
  'journal_failed',
  'deadline_exceeded',
  'replay_conflict',
  'indeterminate',
] as const;
export type ExecutionErrorCode = (typeof EXECUTION_ERROR_CODES)[number];

export interface ExecutionResultV1 {
  readonly schema_version: 'execution-result-v1';
  readonly result_id: Uuid;
  readonly capability_id: Uuid;
  readonly capability_digest: Sha256Digest;
  readonly operation: ExecutionOperation;
  readonly action_id: Uuid;
  readonly artifact_digest: Sha256Digest;
  readonly target_ipv4: Ipv4Address;
  readonly classification: ExecutionClassification;
  readonly nft_exit_class:
    'success' | 'not_invoked' | 'nonzero' | 'timeout' | 'signaled' | null;
  readonly readback_state: 'active' | 'absent' | 'mismatch' | 'unavailable';
  readonly element_handle: null;
  readonly remaining_ttl_seconds: number | null;
  readonly owned_schema_digest: Sha256Digest;
  readonly started_at: Rfc3339Timestamp;
  readonly completed_at: Rfc3339Timestamp;
  readonly journal_sequence: number;
  readonly error_code: ExecutionErrorCode;
}
