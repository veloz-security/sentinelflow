import type {
  ApiErrorV1,
  HilReviewStateV1,
  IncidentDetailV1,
} from '../contracts/apiDtos';
import type { Sha256Digest, SourceHealthV1 } from '../contracts/rootContracts';
import { ROOT_AI_CONTRACT_VERSION_SNAPSHOT } from '../contracts/schemas';
import type {
  AnalysisProvenancePresentation,
  AuthEvidencePresentation,
  IncidentDetailViewState,
  IncidentInvestigationView,
} from '../incidents/incidentDetailModel';
import {
  MOCK_AUTH_EVENT,
  MOCK_GATEWAY_EVENT,
  MOCK_INCIDENT_DETAIL,
  MOCK_VALIDATION,
} from './contractFixtures';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const noReview: HilReviewStateV1 = {
  schema_version: 'hil-review-state-v1',
  status: 'not_requested',
  challenge: null,
  challenge_nonce_available: false,
  decision: null,
  can_request_challenge: false,
  can_submit_decision: false,
  updated_at: '2026-07-18T01:05:01Z',
};

export const MOCK_AUTH_EVIDENCE_PRESENTATION: AuthEvidencePresentation =
  deepFreeze({
    event: MOCK_AUTH_EVENT,
    bindingState: 'verified',
    bindingReason: 'verified',
    boundGatewayEventId: MOCK_GATEWAY_EVENT.event_id,
  });

export const MOCK_ANALYSIS_PROVENANCE: AnalysisProvenancePresentation =
  deepFreeze({
    profileSource: 'frozen-fixture',
    model: 'gpt-5.6-sol',
    reasoningEffort: 'medium',
    inputSchemaVersion: ROOT_AI_CONTRACT_VERSION_SNAPSHOT.inputSchemaVersion,
    outputSchemaVersion: ROOT_AI_CONTRACT_VERSION_SNAPSHOT.outputSchemaVersion,
    promptVersion: ROOT_AI_CONTRACT_VERSION_SNAPSHOT.promptVersion,
    inputDigest: MOCK_VALIDATION.analysis_input_digest,
    outputSchemaDigest: MOCK_VALIDATION.analysis_output_schema_digest,
    promptDigest: MOCK_VALIDATION.prompt_digest,
  });

export const MOCK_DEGRADED_SOURCE_HEALTH: SourceHealthV1 = deepFreeze({
  schema_version: 'source-health-v1',
  event_id: '019b0000-0000-7000-8000-000000000901',
  idempotency_key: `sha256:${'8'.repeat(64)}` as Sha256Digest,
  occurred_at: '2026-07-18T01:01:10Z',
  source_id: 'gateway.demo',
  cause: 'sequence_gap',
  state: 'degraded',
  affected_sender_epoch: 'CCCCCCCCCCCCCCCCCCCCCC',
  sequence_start: 42,
  sequence_end: 45,
  interval_start: '2026-07-18T01:00:30Z',
  interval_end: null,
  dropped_count: 4,
  detail_code: 'known_range',
});

const degradedDetail: IncidentDetailV1 = {
  ...MOCK_INCIDENT_DETAIL,
  incident: {
    ...MOCK_INCIDENT_DETAIL.incident,
    incident_version: 4,
    state: 'open',
    updated_at: '2026-07-18T01:01:10Z',
  },
  source_health_events: [MOCK_DEGRADED_SOURCE_HEALTH],
  ai_analysis: null,
  policy: null,
  validation: null,
  hil_review: noReview,
  enforcement: null,
  audit_events: [],
};

const analysisFailedDetail: IncidentDetailV1 = {
  ...MOCK_INCIDENT_DETAIL,
  incident: {
    ...MOCK_INCIDENT_DETAIL.incident,
    incident_version: 5,
    state: 'analysis_failed',
    analysis_failure_reason: 'timeout',
    updated_at: '2026-07-18T01:05:30Z',
  },
  ai_analysis: null,
  policy: null,
  validation: null,
  hil_review: noReview,
  enforcement: null,
  audit_events: [],
};

export const MOCK_COMPLETE_INVESTIGATION: IncidentInvestigationView =
  deepFreeze({
    detail: MOCK_INCIDENT_DETAIL,
    authEvidence: [MOCK_AUTH_EVIDENCE_PRESENTATION],
    analysisProvenance: MOCK_ANALYSIS_PROVENANCE,
  });

export const MOCK_DEGRADED_INVESTIGATION: IncidentInvestigationView =
  deepFreeze({
    detail: degradedDetail,
    authEvidence: [MOCK_AUTH_EVIDENCE_PRESENTATION],
    analysisProvenance: null,
  });

export const MOCK_ANALYSIS_FAILED_INVESTIGATION: IncidentInvestigationView =
  deepFreeze({
    detail: analysisFailedDetail,
    authEvidence: [MOCK_AUTH_EVIDENCE_PRESENTATION],
    analysisProvenance: null,
  });

const errors: Readonly<
  Record<'notFound' | 'unavailable' | 'permission', ApiErrorV1>
> = deepFreeze({
  notFound: {
    code: 'not_found',
    message: 'No frozen incident detail matches this safe identifier.',
    trace_id: '019b0000-0000-7000-8000-000000000902',
    details: { resource: 'incident-detail' },
  },
  unavailable: {
    code: 'service_unavailable',
    message:
      'The future incident detail endpoint is unavailable in this state.',
    trace_id: '019b0000-0000-7000-8000-000000000903',
    details: { resource: 'incident-detail', retryable: true },
  },
  permission: {
    code: 'permission_denied',
    message: 'The adapter denied access to this incident detail.',
    trace_id: '019b0000-0000-7000-8000-000000000904',
    details: { resource: 'incident-detail' },
  },
});

export const INCIDENT_DETAIL_STATE_NAMES = [
  'loading',
  'unknown',
  'not-found',
  'error',
  'permission-denied',
  'degraded',
  'analysis-failed',
  'complete',
] as const;
export type IncidentDetailStateName =
  (typeof INCIDENT_DETAIL_STATE_NAMES)[number];

export const MOCK_INCIDENT_DETAIL_STATES: Readonly<
  Record<IncidentDetailStateName, IncidentDetailViewState>
> = deepFreeze({
  loading: {
    kind: 'loading',
    requestedId: MOCK_INCIDENT_DETAIL.incident.incident_id,
  },
  unknown: { kind: 'unknown', requestedId: null },
  'not-found': { kind: 'not-found', error: errors.notFound },
  error: { kind: 'error', error: errors.unavailable },
  'permission-denied': {
    kind: 'permission-denied',
    error: errors.permission,
  },
  degraded: { kind: 'degraded', view: MOCK_DEGRADED_INVESTIGATION },
  'analysis-failed': {
    kind: 'analysis-failed',
    view: MOCK_ANALYSIS_FAILED_INVESTIGATION,
  },
  complete: { kind: 'complete', view: MOCK_COMPLETE_INVESTIGATION },
});
