import type { ApiErrorV1 } from '../contracts/apiDtos';
import type {
  ResponsePolicyV1,
  Rfc3339Timestamp,
  Sha256Digest,
  ValidationCheckId,
  ValidationSnapshotV1,
} from '../contracts/rootContracts';

export const VALIDATION_REVIEW_GATE_IDS = [
  'schema-command',
  'consistency',
  'protected-target',
  'owned-schema-syntax',
  'historical-impact',
] as const;
export type ValidationReviewGateId =
  (typeof VALIDATION_REVIEW_GATE_IDS)[number];

export type ValidationReviewGateOutcome = 'pass' | 'fail' | 'blocked';

export interface ValidationReviewGate {
  readonly id: ValidationReviewGateId;
  readonly title: string;
  readonly outcome: ValidationReviewGateOutcome;
  readonly detail: string;
  readonly sourceCheckIds: readonly ValidationCheckId[];
  readonly inputDigests: readonly Sha256Digest[];
}

export type ValidationReviewGates = readonly [
  ValidationReviewGate,
  ValidationReviewGate,
  ValidationReviewGate,
  ValidationReviewGate,
  ValidationReviewGate,
];

export interface CommandComparisonPresentation {
  readonly renderMode: 'inert-text';
  readonly generatedCommand: string;
  readonly generatedTimeoutToken: string;
  readonly generatedParsedSeconds: number;
  readonly generatedDigest: Sha256Digest;
  readonly canonicalCommand: string;
  readonly canonicalTimeoutToken: string;
  readonly canonicalParsedSeconds: number;
  readonly canonicalDigest: Sha256Digest;
  readonly policyTtlSeconds: number;
  readonly ttlEquality: 'equal' | 'mismatch';
}

export type CoverageProofState = 'complete' | 'gapped' | 'missing';
export type HistorySignatureState =
  'verified' | 'unsigned' | 'invalid' | 'missing';

export interface SourceHealthProofPresentation {
  readonly gateway: CoverageProofState;
  readonly authentication: CoverageProofState;
  readonly digest: Sha256Digest | null;
  readonly unresolvedSequenceRange: string | null;
}

export interface DemoHistoryProofPresentation {
  readonly signatureVerification: HistorySignatureState;
  readonly fixtureOnly: true;
  readonly manifestId: string;
  readonly manifestDigest: Sha256Digest | null;
  readonly datasetId: string;
  readonly datasetDigest: Sha256Digest;
  readonly datasetRecordCount: number;
  readonly importId: string;
  readonly coverageStart: Rfc3339Timestamp;
  readonly coverageEnd: Rfc3339Timestamp;
  readonly sourceHealthDigest: Sha256Digest;
}

export interface HistoricalImpactPresentation {
  readonly coverage: CoverageProofState;
  readonly lookbackStart: Rfc3339Timestamp;
  readonly lookbackEnd: Rfc3339Timestamp;
  readonly successfulAuthenticationSeen: boolean | null;
  readonly result: 'no-verified-success' | 'blocked-by-gap' | 'unavailable';
  readonly impactDigest: Sha256Digest | null;
}

export interface ValidationValidityPresentation {
  readonly status: 'fresh' | 'stale' | 'expired' | 'missing';
  readonly windowSeconds: 300;
  readonly remainingSeconds: number;
  readonly serverEvaluatedAt: Rfc3339Timestamp;
  readonly createdAt: Rfc3339Timestamp | null;
  readonly validUntil: Rfc3339Timestamp | null;
  readonly reason: string;
}

export interface ValidationReviewView {
  readonly policy: ResponsePolicyV1;
  readonly validation: ValidationSnapshotV1 | null;
  readonly command: CommandComparisonPresentation;
  readonly gates: ValidationReviewGates;
  readonly sourceHealth: SourceHealthProofPresentation;
  readonly demoHistory: DemoHistoryProofPresentation;
  readonly impact: HistoricalImpactPresentation;
  readonly validity: ValidationValidityPresentation;
  readonly hilControls: 'not-implemented';
}

export type ValidationReviewState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'missing' }
  | { readonly kind: 'gapped'; readonly view: ValidationReviewView }
  | { readonly kind: 'unsigned'; readonly view: ValidationReviewView }
  | { readonly kind: 'failed'; readonly view: ValidationReviewView }
  | { readonly kind: 'mismatch'; readonly view: ValidationReviewView }
  | { readonly kind: 'stale'; readonly view: ValidationReviewView }
  | { readonly kind: 'expired'; readonly view: ValidationReviewView }
  | { readonly kind: 'permission-denied'; readonly error: ApiErrorV1 }
  | { readonly kind: 'ready'; readonly view: ValidationReviewView };

export interface ValidationReviewAdapter {
  readonly kind: 'fixture' | 'http';
  load(signal?: AbortSignal): Promise<ValidationReviewState>;
}

/** Marker only. M7-001 must supply and freeze an HTTP response contract. */
export interface FutureHttpValidationReviewAdapter extends ValidationReviewAdapter {
  readonly kind: 'http';
}
