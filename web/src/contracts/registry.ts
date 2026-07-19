import type { ErrorObject, ValidateFunction } from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { VALIDATION_CHECK_IDS } from './rootContracts';
import type {
  AuditEventV1,
  ApiErrorV1,
  EnforcementLifecycleV1,
  HilReviewStateV1,
  IncidentDetailV1,
  IncidentSummaryV1,
} from './apiDtos';
import type {
  AuthEventV1,
  DemoHistoryManifestV1,
  DeterministicSignalV1,
  ExecutionResultV1,
  GatewayHttpV1,
  HilChallengeV1,
  HilDecisionV1,
  HilReasonV1,
  ResponsePolicyV1,
  SentinelFlowAnalysisV1,
  SignedDemoHistoryFixtureV1,
  SourceHealthV1,
  ValidationSnapshotV1,
} from './rootContracts';
import {
  apiErrorSchema,
  frontendSchemas,
  FRONTEND_SCHEMA_IDS,
  ROOT_AI_ANALYSIS_SCHEMA_ID,
  rootAnalysisSchema,
  rootSchemas,
} from './schemas';
import { deepFreeze } from '../utils/deepFreeze';

export interface ContractByVersion {
  readonly 'gateway-http-v1': GatewayHttpV1;
  readonly 'auth-event-v1': AuthEventV1;
  readonly 'source-health-v1': SourceHealthV1;
  readonly 'deterministic-signal-view-v1': DeterministicSignalV1;
  readonly 'incident-summary-v1': IncidentSummaryV1;
  readonly sentinelflow_analysis_v1: SentinelFlowAnalysisV1;
  readonly 'response-policy-v1': ResponsePolicyV1;
  readonly 'validation-snapshot-v1': ValidationSnapshotV1;
  readonly 'demo-history-v1': DemoHistoryManifestV1;
  readonly 'demo-history-signed-manifest-v1': SignedDemoHistoryFixtureV1;
  readonly 'hil-challenge-v1': HilChallengeV1;
  readonly 'hil-decision-v1': HilDecisionV1;
  readonly 'hil-reason-v1': HilReasonV1;
  readonly 'hil-review-state-v1': HilReviewStateV1;
  readonly 'execution-result-v1': ExecutionResultV1;
  readonly 'enforcement-lifecycle-v1': EnforcementLifecycleV1;
  readonly 'audit-event-v1': AuditEventV1;
  readonly 'incident-detail-v1': IncidentDetailV1;
}

export type SupportedSchemaVersion = keyof ContractByVersion;
export type RegisteredContract = ContractByVersion[SupportedSchemaVersion];

export interface ContractRegistryEntry {
  readonly schemaVersion: SupportedSchemaVersion;
  readonly schemaId: string;
  readonly source: string;
  readonly ownership: 'root-contract' | 'frontend-dto';
}

export const CONTRACT_REGISTRY: Readonly<
  Record<SupportedSchemaVersion, ContractRegistryEntry>
> = Object.freeze({
  'gateway-http-v1': {
    schemaVersion: 'gateway-http-v1',
    schemaId:
      'https://sentinelflow.example/contracts/events/gateway_http_v1.schema.json',
    source: 'contracts/events/gateway_http_v1.schema.json',
    ownership: 'root-contract',
  },
  'auth-event-v1': {
    schemaVersion: 'auth-event-v1',
    schemaId:
      'https://sentinelflow.example/contracts/events/auth_event_v1.schema.json',
    source: 'contracts/events/auth_event_v1.schema.json',
    ownership: 'root-contract',
  },
  'source-health-v1': {
    schemaVersion: 'source-health-v1',
    schemaId:
      'https://sentinelflow.example/contracts/events/source_health_v1.schema.json',
    source: 'contracts/events/source_health_v1.schema.json',
    ownership: 'root-contract',
  },
  'deterministic-signal-view-v1': {
    schemaVersion: 'deterministic-signal-view-v1',
    schemaId: FRONTEND_SCHEMA_IDS.deterministicSignal,
    source:
      'contracts/ai/sentinelflow_analysis_input_v1.schema.json#/$defs/signal',
    ownership: 'frontend-dto',
  },
  'incident-summary-v1': {
    schemaVersion: 'incident-summary-v1',
    schemaId: FRONTEND_SCHEMA_IDS.incidentSummary,
    source: 'web/src/contracts/schemas.ts',
    ownership: 'frontend-dto',
  },
  sentinelflow_analysis_v1: {
    schemaVersion: 'sentinelflow_analysis_v1',
    schemaId: ROOT_AI_ANALYSIS_SCHEMA_ID,
    source: 'contracts/ai/sentinelflow_analysis_v1.schema.json',
    ownership: 'root-contract',
  },
  'response-policy-v1': {
    schemaVersion: 'response-policy-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/response_policy_v1.schema.json',
    source: 'contracts/enforcement/response_policy_v1.schema.json',
    ownership: 'root-contract',
  },
  'validation-snapshot-v1': {
    schemaVersion: 'validation-snapshot-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/validation_snapshot_v1.schema.json',
    source: 'contracts/enforcement/validation_snapshot_v1.schema.json',
    ownership: 'root-contract',
  },
  'demo-history-v1': {
    schemaVersion: 'demo-history-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/demo_history_manifest_v1.schema.json',
    source: 'contracts/enforcement/demo_history_manifest_v1.schema.json',
    ownership: 'root-contract',
  },
  'demo-history-signed-manifest-v1': {
    schemaVersion: 'demo-history-signed-manifest-v1',
    schemaId:
      'https://sentinelflow.example/contracts/fixtures/demo_history_signed_manifest_v1.schema.json',
    source: 'contracts/fixtures/demo_history_signed_manifest_v1.schema.json',
    ownership: 'root-contract',
  },
  'hil-challenge-v1': {
    schemaVersion: 'hil-challenge-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/hil_challenge_v1.schema.json',
    source: 'contracts/enforcement/hil_challenge_v1.schema.json',
    ownership: 'root-contract',
  },
  'hil-decision-v1': {
    schemaVersion: 'hil-decision-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/hil_decision_v1.schema.json',
    source: 'contracts/enforcement/hil_decision_v1.schema.json',
    ownership: 'root-contract',
  },
  'hil-reason-v1': {
    schemaVersion: 'hil-reason-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/hil_reason_v1.schema.json',
    source: 'contracts/enforcement/hil_reason_v1.schema.json',
    ownership: 'root-contract',
  },
  'hil-review-state-v1': {
    schemaVersion: 'hil-review-state-v1',
    schemaId: FRONTEND_SCHEMA_IDS.hilReviewState,
    source: 'web/src/contracts/schemas.ts',
    ownership: 'frontend-dto',
  },
  'execution-result-v1': {
    schemaVersion: 'execution-result-v1',
    schemaId:
      'https://sentinelflow.example/contracts/enforcement/execution_result_v1.schema.json',
    source: 'contracts/enforcement/execution_result_v1.schema.json',
    ownership: 'root-contract',
  },
  'enforcement-lifecycle-v1': {
    schemaVersion: 'enforcement-lifecycle-v1',
    schemaId: FRONTEND_SCHEMA_IDS.enforcementLifecycle,
    source: 'web/src/contracts/schemas.ts',
    ownership: 'frontend-dto',
  },
  'audit-event-v1': {
    schemaVersion: 'audit-event-v1',
    schemaId: FRONTEND_SCHEMA_IDS.auditEvent,
    source: 'web/src/contracts/schemas.ts',
    ownership: 'frontend-dto',
  },
  'incident-detail-v1': {
    schemaVersion: 'incident-detail-v1',
    schemaId: FRONTEND_SCHEMA_IDS.incidentDetail,
    source: 'web/src/contracts/schemas.ts',
    ownership: 'frontend-dto',
  },
});

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

for (const schema of rootSchemas) {
  ajv.addSchema(schema);
}
ajv.addSchema(rootAnalysisSchema, ROOT_AI_ANALYSIS_SCHEMA_ID);
for (const schema of frontendSchemas) {
  ajv.addSchema(schema);
}
ajv.addSchema(apiErrorSchema);

const validators = Object.fromEntries(
  Object.values(CONTRACT_REGISTRY).map((entry) => {
    const validator = ajv.getSchema(entry.schemaId);
    if (!validator) {
      throw new Error(`Missing frontend contract validator: ${entry.schemaId}`);
    }
    return [entry.schemaVersion, validator];
  }),
) as Record<SupportedSchemaVersion, ValidateFunction>;

function requireValidator(schemaId: string): ValidateFunction {
  const validator = ajv.getSchema(schemaId);
  if (!validator) {
    throw new Error(`Missing frontend contract validator: ${schemaId}`);
  }
  return validator;
}

const apiErrorValidator = requireValidator(FRONTEND_SCHEMA_IDS.apiError);

export interface ContractValidationIssue {
  readonly path: string;
  readonly keyword: string;
  readonly message: string;
}

export type DecodeFailureReason =
  | 'not_an_object'
  | 'missing_schema_version'
  | 'unknown_schema_version'
  | 'shape_or_enum_mismatch';

export type DecodeResult<T> =
  | { readonly ok: true; readonly value: T }
  | {
      readonly ok: false;
      readonly reason: DecodeFailureReason;
      readonly schemaVersion: string | null;
      readonly issues: readonly ContractValidationIssue[];
    };

function issuesFrom(errors: ErrorObject[] | null | undefined) {
  return Object.freeze(
    (errors ?? []).map((error) => ({
      path: error.instancePath || '/',
      keyword: error.keyword,
      message: error.message ?? 'contract validation failed',
    })),
  );
}

function invariantIssue(message: string): readonly ContractValidationIssue[] {
  return Object.freeze([{ path: '/', keyword: 'contractInvariant', message }]);
}

function hasExactValidationOrder(value: ValidationSnapshotV1): boolean {
  return (
    value.checks.length === VALIDATION_CHECK_IDS.length &&
    value.checks.every(
      (check, index) => check.check_id === VALIDATION_CHECK_IDS[index],
    )
  );
}

function isSortedUnique(values: readonly string[]): boolean {
  return values.every(
    (value, index) => index === 0 || values[index - 1] < value,
  );
}

function hasExactAnalysisEvidence(value: SentinelFlowAnalysisV1): boolean {
  const evidence = value.evidence_ids;
  return (
    isSortedUnique(evidence) &&
    evidence.length === value.policy.evidence_ids.length &&
    evidence.length === value.nftables_command_candidate.evidence_ids.length &&
    evidence.every(
      (item, index) =>
        item === value.policy.evidence_ids[index] &&
        item === value.nftables_command_candidate.evidence_ids[index],
    )
  );
}

function contractInvariantFailure(
  value: RegisteredContract,
): readonly ContractValidationIssue[] | null {
  if (
    value.schema_version === 'validation-snapshot-v1' &&
    !hasExactValidationOrder(value)
  ) {
    return invariantIssue('validation checks are not in the frozen order');
  }
  if (
    value.schema_version === 'sentinelflow_analysis_v1' &&
    !hasExactAnalysisEvidence(value)
  ) {
    return invariantIssue(
      'analysis evidence arrays are not sorted and byte-identical',
    );
  }
  if (
    value.schema_version === 'incident-detail-v1' &&
    value.validation !== null &&
    !hasExactValidationOrder(value.validation)
  ) {
    return invariantIssue(
      'nested validation checks are not in the frozen order',
    );
  }
  if (
    value.schema_version === 'incident-detail-v1' &&
    value.ai_analysis !== null &&
    !hasExactAnalysisEvidence(value.ai_analysis)
  ) {
    return invariantIssue(
      'nested analysis evidence arrays are not sorted and byte-identical',
    );
  }
  return null;
}

export function decodeContract(
  value: unknown,
): DecodeResult<RegisteredContract> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return {
      ok: false,
      reason: 'not_an_object',
      schemaVersion: null,
      issues: Object.freeze([]),
    };
  }

  const schemaVersion = Reflect.get(value, 'schema_version');
  if (typeof schemaVersion !== 'string') {
    return {
      ok: false,
      reason: 'missing_schema_version',
      schemaVersion: null,
      issues: Object.freeze([]),
    };
  }

  if (!Object.hasOwn(CONTRACT_REGISTRY, schemaVersion)) {
    return {
      ok: false,
      reason: 'unknown_schema_version',
      schemaVersion,
      issues: Object.freeze([]),
    };
  }

  const validator = validators[schemaVersion as SupportedSchemaVersion];
  if (!validator(value)) {
    return {
      ok: false,
      reason: 'shape_or_enum_mismatch',
      schemaVersion,
      issues: issuesFrom(validator.errors),
    };
  }

  const decoded = value as RegisteredContract;
  const invariantFailure = contractInvariantFailure(decoded);
  if (invariantFailure) {
    return {
      ok: false,
      reason: 'shape_or_enum_mismatch',
      schemaVersion,
      issues: invariantFailure,
    };
  }

  return { ok: true, value: decoded };
}

export function decodeApiError(value: unknown): DecodeResult<ApiErrorV1> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return {
      ok: false,
      reason: 'not_an_object',
      schemaVersion: null,
      issues: Object.freeze([]),
    };
  }
  if (!apiErrorValidator(value)) {
    return {
      ok: false,
      reason: 'shape_or_enum_mismatch',
      schemaVersion: null,
      issues: issuesFrom(apiErrorValidator.errors),
    };
  }
  return { ok: true, value: deepFreeze(value as ApiErrorV1) };
}
