import type { ApiErrorV1, IncidentDetailV1 } from '../contracts/apiDtos';
import type {
  AuthEventV1,
  Sha256Digest,
  Uuid,
} from '../contracts/rootContracts';

export const AUTH_BINDING_STATES = [
  'pending',
  'verified',
  'untrusted',
] as const;
export type AuthBindingState = (typeof AUTH_BINDING_STATES)[number];

export const AUTH_BINDING_REASONS = [
  'awaiting_gateway_event',
  'verified',
  'request_mismatch',
  'trace_mismatch',
  'source_mismatch',
  'service_mismatch',
  'route_mismatch',
  'expired',
] as const;
export type AuthBindingReason = (typeof AUTH_BINDING_REASONS)[number];

/** Presentation metadata, not an M7-001 HTTP DTO. */
export interface AuthEvidencePresentation {
  readonly event: AuthEventV1;
  readonly bindingState: AuthBindingState;
  readonly bindingReason: AuthBindingReason;
  readonly boundGatewayEventId: Uuid | null;
}

/**
 * Combines checked validation digests with a labeled fixture execution profile.
 * It never represents live provider metadata.
 */
export interface AnalysisProvenancePresentation {
  readonly profileSource: 'frozen-fixture';
  readonly model: 'gpt-5.6-sol';
  readonly reasoningEffort: 'medium';
  readonly inputSchemaVersion: 'sentinelflow_analysis_input_v1';
  readonly outputSchemaVersion: 'sentinelflow_analysis_v1';
  readonly promptVersion: 'sentinelflow_system_prompt_v1';
  readonly inputDigest: Sha256Digest;
  readonly outputSchemaDigest: Sha256Digest;
  readonly promptDigest: Sha256Digest;
}

export interface IncidentInvestigationView {
  readonly detail: IncidentDetailV1;
  readonly authEvidence: readonly AuthEvidencePresentation[];
  readonly analysisProvenance: AnalysisProvenancePresentation | null;
}

export type IncidentDetailViewState =
  | { readonly kind: 'loading'; readonly requestedId: string | null }
  | { readonly kind: 'unknown'; readonly requestedId: string | null }
  | { readonly kind: 'not-found'; readonly error: ApiErrorV1 }
  | { readonly kind: 'error'; readonly error: ApiErrorV1 }
  | { readonly kind: 'permission-denied'; readonly error: ApiErrorV1 }
  | { readonly kind: 'degraded'; readonly view: IncidentInvestigationView }
  | {
      readonly kind: 'analysis-failed';
      readonly view: IncidentInvestigationView;
    }
  | { readonly kind: 'complete'; readonly view: IncidentInvestigationView };

export interface IncidentDetailAdapter {
  readonly kind: 'fixture' | 'http';
  load(
    incidentId: string,
    signal?: AbortSignal,
  ): Promise<IncidentDetailViewState>;
}

/** Marker only. M7-001 must provide the response decoder before implementation. */
export interface FutureHttpIncidentDetailAdapter extends IncidentDetailAdapter {
  readonly kind: 'http';
}
