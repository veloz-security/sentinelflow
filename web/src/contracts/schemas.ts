import analysisInputSchema from '../../../contracts/ai/sentinelflow_analysis_input_v1.schema.json' with { type: 'json' };
import analysisSchema from '../../../contracts/ai/sentinelflow_analysis_v1.schema.json' with { type: 'json' };
import demoHistoryManifestSchema from '../../../contracts/enforcement/demo_history_manifest_v1.schema.json' with { type: 'json' };
import executionResultSchema from '../../../contracts/enforcement/execution_result_v1.schema.json' with { type: 'json' };
import hilChallengeSchema from '../../../contracts/enforcement/hil_challenge_v1.schema.json' with { type: 'json' };
import hilDecisionSchema from '../../../contracts/enforcement/hil_decision_v1.schema.json' with { type: 'json' };
import hilReasonSchema from '../../../contracts/enforcement/hil_reason_v1.schema.json' with { type: 'json' };
import responsePolicySchema from '../../../contracts/enforcement/response_policy_v1.schema.json' with { type: 'json' };
import validationSnapshotSchema from '../../../contracts/enforcement/validation_snapshot_v1.schema.json' with { type: 'json' };
import authEventSchema from '../../../contracts/events/auth_event_v1.schema.json' with { type: 'json' };
import gatewayHttpSchema from '../../../contracts/events/gateway_http_v1.schema.json' with { type: 'json' };
import sourceHealthSchema from '../../../contracts/events/source_health_v1.schema.json' with { type: 'json' };
import signedDemoHistoryFixtureSchema from '../../../contracts/fixtures/demo_history_signed_manifest_v1.schema.json' with { type: 'json' };
import {
  ANALYSIS_FAILURE_REASONS,
  API_ERROR_CODES,
  AUDIT_ACTOR_KINDS,
  AUDIT_CATEGORIES,
  AUDIT_OBJECT_TYPES,
  AUDIT_OUTCOMES,
  HIL_REVIEW_STATES,
  INCIDENT_STATES,
  LIFECYCLE_STATES,
  SIGNATURE_VERIFICATION_STATES,
} from './apiDtos';
import {
  DETECTION_CLASSIFICATIONS,
  DETECTION_RULE_IDS,
  EXECUTION_OPERATIONS,
} from './rootContracts';

const uuidSchema = {
  type: 'string',
  pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
} as const;
const digestSchema = {
  type: 'string',
  pattern: '^sha256:[0-9a-f]{64}$',
} as const;
const timestampSchema = { type: 'string', format: 'date-time' } as const;
const ipv4Schema = { type: 'string', format: 'ipv4' } as const;
const labelSchema = {
  type: 'string',
  pattern: '^[a-z][a-z0-9_-]{0,63}$',
} as const;

export const ROOT_AI_ANALYSIS_SCHEMA_ID =
  'https://sentinelflow.example/contracts/ai/sentinelflow_analysis_v1.schema.json';

export const FRONTEND_SCHEMA_IDS = Object.freeze({
  deterministicSignal:
    'https://sentinelflow.example/contracts/frontend/deterministic_signal_view_v1.schema.json',
  incidentSummary:
    'https://sentinelflow.example/contracts/frontend/incident_summary_v1.schema.json',
  hilReviewState:
    'https://sentinelflow.example/contracts/frontend/hil_review_state_v1.schema.json',
  enforcementLifecycle:
    'https://sentinelflow.example/contracts/frontend/enforcement_lifecycle_v1.schema.json',
  auditEvent:
    'https://sentinelflow.example/contracts/frontend/audit_event_v1.schema.json',
  incidentDetail:
    'https://sentinelflow.example/contracts/frontend/incident_detail_v1.schema.json',
  apiError:
    'https://sentinelflow.example/contracts/frontend/api_error_v1.schema.json',
});

export const rootSchemas = Object.freeze([
  gatewayHttpSchema,
  authEventSchema,
  sourceHealthSchema,
  responsePolicySchema,
  validationSnapshotSchema,
  demoHistoryManifestSchema,
  signedDemoHistoryFixtureSchema,
  hilChallengeSchema,
  hilDecisionSchema,
  hilReasonSchema,
  executionResultSchema,
]);

export const ROOT_CONTRACT_ENUM_SNAPSHOT = Object.freeze({
  suspiciousPathIds: gatewayHttpSchema.properties.suspicious_path_id.enum,
  authEventOutcomes: authEventSchema.properties.outcome.enum,
  sourceHealthCauses: sourceHealthSchema.properties.cause.enum,
  sourceHealthStates: sourceHealthSchema.properties.state.enum,
  sourceHealthDetailCodes: sourceHealthSchema.properties.detail_code.enum,
  detectionRuleIds: analysisInputSchema.$defs.signal.properties.rule_id.enum,
  detectionClassifications:
    analysisInputSchema.$defs.signal.properties.classification.enum,
  aiClassifications: analysisSchema.properties.classification.enum,
  validationCheckIds:
    validationSnapshotSchema.$defs.check.properties.check_id.enum,
  hilOperations: hilChallengeSchema.properties.operation.enum,
  hilDecisions: hilDecisionSchema.properties.decision.enum,
  hilReasonCodes: hilReasonSchema.properties.reason_code.enum,
  executionOperations: executionResultSchema.properties.operation.enum,
  executionClassifications:
    executionResultSchema.properties.classification.enum,
  executionErrorCodes: executionResultSchema.properties.error_code.enum,
});

export const ROOT_AI_CONTRACT_VERSION_SNAPSHOT = Object.freeze({
  inputSchemaVersion: analysisInputSchema.properties.schema_version
    .const as 'sentinelflow_analysis_input_v1',
  promptVersion: analysisInputSchema.properties.prompt_version
    .const as 'sentinelflow_system_prompt_v1',
  outputSchemaVersion: analysisInputSchema.properties.output_schema_version
    .const as 'sentinelflow_analysis_v1',
});

export const deterministicSignalSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.deterministicSignal,
  type: 'object',
  additionalProperties: false,
  properties: {
    schema_version: { const: 'deterministic-signal-view-v1' },
    signal_id: uuidSchema,
    rule_id: { enum: DETECTION_RULE_IDS },
    classification: { enum: DETECTION_CLASSIFICATIONS },
    window_start: timestampSchema,
    window_end: timestampSchema,
    event_count: { type: 'integer', minimum: 1, maximum: 1_000_000 },
    distinct_account_count: {
      type: 'integer',
      minimum: 0,
      maximum: 1_000_000,
    },
    distinct_suspicious_path_count: {
      type: 'integer',
      minimum: 0,
      maximum: 8,
    },
    evidence_digest: digestSchema,
  },
  required: [
    'schema_version',
    'signal_id',
    'rule_id',
    'classification',
    'window_start',
    'window_end',
    'event_count',
    'distinct_account_count',
    'distinct_suspicious_path_count',
    'evidence_digest',
  ],
} as const;

export const incidentSummarySchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.incidentSummary,
  type: 'object',
  additionalProperties: false,
  properties: {
    schema_version: { const: 'incident-summary-v1' },
    incident_id: uuidSchema,
    incident_version: {
      type: 'integer',
      minimum: 1,
      maximum: 2_147_483_647,
    },
    state: { enum: INCIDENT_STATES },
    analysis_failure_reason: {
      anyOf: [{ enum: ANALYSIS_FAILURE_REASONS }, { type: 'null' }],
    },
    source_ip: ipv4Schema,
    service_label: labelSchema,
    signal_count: { type: 'integer', minimum: 0, maximum: 1_000_000 },
    first_seen_at: timestampSchema,
    last_seen_at: timestampSchema,
    updated_at: timestampSchema,
  },
  required: [
    'schema_version',
    'incident_id',
    'incident_version',
    'state',
    'analysis_failure_reason',
    'source_ip',
    'service_label',
    'signal_count',
    'first_seen_at',
    'last_seen_at',
    'updated_at',
  ],
} as const;

export const hilReviewStateSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.hilReviewState,
  type: 'object',
  additionalProperties: false,
  properties: {
    schema_version: { const: 'hil-review-state-v1' },
    status: { enum: HIL_REVIEW_STATES },
    challenge: {
      anyOf: [
        {
          $ref: 'https://sentinelflow.example/contracts/enforcement/hil_challenge_v1.schema.json',
        },
        { type: 'null' },
      ],
    },
    challenge_nonce_available: { type: 'boolean' },
    decision: {
      anyOf: [
        {
          $ref: 'https://sentinelflow.example/contracts/enforcement/hil_decision_v1.schema.json',
        },
        { type: 'null' },
      ],
    },
    can_request_challenge: { type: 'boolean' },
    can_submit_decision: { type: 'boolean' },
    updated_at: timestampSchema,
  },
  required: [
    'schema_version',
    'status',
    'challenge',
    'challenge_nonce_available',
    'decision',
    'can_request_challenge',
    'can_submit_decision',
    'updated_at',
  ],
} as const;

const lifecycleOperationSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    operation_id: uuidSchema,
    operation: { enum: EXECUTION_OPERATIONS },
    requested_at: timestampSchema,
    signature_verification: { enum: SIGNATURE_VERIFICATION_STATES },
    result: {
      anyOf: [
        {
          $ref: 'https://sentinelflow.example/contracts/enforcement/execution_result_v1.schema.json',
        },
        { type: 'null' },
      ],
    },
  },
  required: [
    'operation_id',
    'operation',
    'requested_at',
    'signature_verification',
    'result',
  ],
} as const;

export const enforcementLifecycleSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.enforcementLifecycle,
  type: 'object',
  additionalProperties: false,
  properties: {
    schema_version: { const: 'enforcement-lifecycle-v1' },
    action_id: uuidSchema,
    action_version: {
      type: 'integer',
      minimum: 1,
      maximum: 2_147_483_647,
    },
    policy_id: uuidSchema,
    state: { enum: LIFECYCLE_STATES },
    target_ipv4: ipv4Schema,
    original_add_digest: digestSchema,
    approved_ttl_seconds: { type: 'integer', minimum: 60, maximum: 86_400 },
    applied_at: { anyOf: [timestampSchema, { type: 'null' }] },
    expires_at: { anyOf: [timestampSchema, { type: 'null' }] },
    operations: { type: 'array', items: lifecycleOperationSchema },
    updated_at: timestampSchema,
  },
  required: [
    'schema_version',
    'action_id',
    'action_version',
    'policy_id',
    'state',
    'target_ipv4',
    'original_add_digest',
    'approved_ttl_seconds',
    'applied_at',
    'expires_at',
    'operations',
    'updated_at',
  ],
} as const;

export const auditEventSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.auditEvent,
  type: 'object',
  additionalProperties: false,
  properties: {
    schema_version: { const: 'audit-event-v1' },
    audit_id: uuidSchema,
    occurred_at: timestampSchema,
    category: { enum: AUDIT_CATEGORIES },
    event_type: { type: 'string', pattern: '^[a-z][a-z0-9._-]{0,127}$' },
    actor_kind: { enum: AUDIT_ACTOR_KINDS },
    actor_id: {
      type: 'string',
      pattern: '^[a-z0-9][a-z0-9._-]{0,127}$',
    },
    object_type: { enum: AUDIT_OBJECT_TYPES },
    object_id: uuidSchema,
    outcome: { enum: AUDIT_OUTCOMES },
    trace_id: uuidSchema,
    correlation_id: { anyOf: [uuidSchema, { type: 'null' }] },
    safe_reason_code: {
      anyOf: [
        { type: 'string', pattern: '^[a-z][a-z0-9._-]{0,127}$' },
        { type: 'null' },
      ],
    },
  },
  required: [
    'schema_version',
    'audit_id',
    'occurred_at',
    'category',
    'event_type',
    'actor_kind',
    'actor_id',
    'object_type',
    'object_id',
    'outcome',
    'trace_id',
    'correlation_id',
    'safe_reason_code',
  ],
} as const;

export const incidentDetailSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.incidentDetail,
  type: 'object',
  additionalProperties: false,
  properties: {
    schema_version: { const: 'incident-detail-v1' },
    incident: { $ref: FRONTEND_SCHEMA_IDS.incidentSummary },
    gateway_events: {
      type: 'array',
      items: {
        $ref: 'https://sentinelflow.example/contracts/events/gateway_http_v1.schema.json',
      },
    },
    source_health_events: {
      type: 'array',
      items: {
        $ref: 'https://sentinelflow.example/contracts/events/source_health_v1.schema.json',
      },
    },
    deterministic_signals: {
      type: 'array',
      items: { $ref: FRONTEND_SCHEMA_IDS.deterministicSignal },
    },
    ai_analysis: {
      anyOf: [{ $ref: ROOT_AI_ANALYSIS_SCHEMA_ID }, { type: 'null' }],
    },
    policy: {
      anyOf: [
        {
          $ref: 'https://sentinelflow.example/contracts/enforcement/response_policy_v1.schema.json',
        },
        { type: 'null' },
      ],
    },
    validation: {
      anyOf: [
        {
          $ref: 'https://sentinelflow.example/contracts/enforcement/validation_snapshot_v1.schema.json',
        },
        { type: 'null' },
      ],
    },
    hil_review: { $ref: FRONTEND_SCHEMA_IDS.hilReviewState },
    enforcement: {
      anyOf: [
        { $ref: FRONTEND_SCHEMA_IDS.enforcementLifecycle },
        { type: 'null' },
      ],
    },
    audit_events: {
      type: 'array',
      items: { $ref: FRONTEND_SCHEMA_IDS.auditEvent },
    },
  },
  required: [
    'schema_version',
    'incident',
    'gateway_events',
    'source_health_events',
    'deterministic_signals',
    'ai_analysis',
    'policy',
    'validation',
    'hil_review',
    'enforcement',
    'audit_events',
  ],
} as const;

export const apiErrorSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: FRONTEND_SCHEMA_IDS.apiError,
  type: 'object',
  additionalProperties: false,
  properties: {
    code: { enum: API_ERROR_CODES },
    message: { type: 'string', minLength: 1, maxLength: 500 },
    trace_id: uuidSchema,
    details: {
      type: 'object',
      additionalProperties: {
        anyOf: [
          { type: 'string' },
          { type: 'number' },
          { type: 'boolean' },
          { type: 'null' },
        ],
      },
    },
  },
  required: ['code', 'message', 'trace_id', 'details'],
} as const;

export const frontendSchemas = Object.freeze([
  deterministicSignalSchema,
  incidentSummarySchema,
  hilReviewStateSchema,
  enforcementLifecycleSchema,
  auditEventSchema,
  incidentDetailSchema,
]);

export const rootAnalysisSchema = analysisSchema;
