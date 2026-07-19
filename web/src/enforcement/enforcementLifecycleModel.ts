import type {
  ApiErrorV1,
  AuditEventV1,
  EnforcementLifecycleV1,
} from '../contracts/apiDtos';
import type {
  ExecutionOperation,
  Rfc3339Timestamp,
  Sha256Digest,
  Uuid,
} from '../contracts/rootContracts';

export const ENFORCEMENT_LIFECYCLE_STATE_NAMES = [
  'loading',
  'empty',
  'error',
  'permission-denied',
  'pending',
  'applied',
  'active',
  'expired',
  'revoked',
  'failed',
  'indeterminate',
  'recovered-active',
  'torn-journal',
  'corrupt-journal',
] as const;

export type EnforcementLifecycleStateName =
  (typeof ENFORCEMENT_LIFECYCLE_STATE_NAMES)[number];

export const AUDIT_PROVENANCE_KINDS = [
  'fact',
  'deterministic-rule',
  'ai-generated',
  'canonicalized',
  'human-decision',
  'dispatcher',
  'executor-result',
  'recovery',
] as const;

export type AuditProvenanceKind = (typeof AUDIT_PROVENANCE_KINDS)[number];

export interface AuditTrailEntry {
  readonly event: AuditEventV1;
  readonly provenance: AuditProvenanceKind;
  readonly title: string;
  readonly detail: string;
}

export type JournalIntegrity = 'complete' | 'torn' | 'corrupt' | 'unknown';

export interface JournalRecordPresentation {
  readonly sequence: number;
  readonly operation: ExecutionOperation;
  readonly phase: 'started' | 'terminal';
  readonly integrity: 'verified' | 'missing-terminal' | 'checksum-failed';
  readonly recordedAt: Rfc3339Timestamp;
  readonly terminalResultId: Uuid | null;
  readonly terminalResultDigest: Sha256Digest | null;
}

export interface RecoveryPresentation {
  readonly integrity: JournalIntegrity;
  readonly mode: 'none' | 'read-only-inspect' | 'halted';
  readonly detail: string;
  readonly automaticReadd: false;
  readonly ttlRefresh: false;
}

export interface ServerClockPresentation {
  readonly serverNow: Rfc3339Timestamp;
  readonly remainingTtlSeconds: number | null;
}

/**
 * Frontend-only presentation metadata around frozen API DTOs. This does not
 * define, replace, or extend a server contract.
 */
export interface EnforcementLifecycleView {
  readonly lifecycle: EnforcementLifecycleV1;
  readonly resultDigests: Readonly<Record<Uuid, Sha256Digest>>;
  readonly journal: readonly JournalRecordPresentation[];
  readonly recovery: RecoveryPresentation;
  readonly serverClock: ServerClockPresentation;
  readonly auditTrail: readonly AuditTrailEntry[];
}

export type EnforcementLifecycleState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'empty' }
  | { readonly kind: 'error'; readonly error: ApiErrorV1 }
  | { readonly kind: 'permission-denied'; readonly error: ApiErrorV1 }
  | {
      readonly kind: 'ready';
      readonly fixtureName: Exclude<
        EnforcementLifecycleStateName,
        'loading' | 'empty' | 'error' | 'permission-denied'
      >;
      readonly view: EnforcementLifecycleView;
    };

export interface EnforcementLifecycleAdapter {
  readonly kind: 'fixture' | 'api';
  load(signal?: AbortSignal): Promise<EnforcementLifecycleState>;
}
