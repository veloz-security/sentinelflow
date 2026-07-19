import signedDemoHistoryFixtureJson from '../../../contracts/fixtures/demo_history_manifest_v1.json' with { type: 'json' };
import type { ApiErrorV1 } from '../contracts/apiDtos';
import type {
  SentinelFlowAnalysisV1,
  SignedDemoHistoryFixtureV1,
  ValidationSnapshotV1,
} from '../contracts/rootContracts';
import {
  MOCK_AI_ANALYSIS,
  MOCK_POLICY,
  MOCK_VALIDATION,
} from './contractFixtures';
import type {
  ValidationReviewGate,
  ValidationReviewGates,
  ValidationReviewState,
  ValidationReviewView,
} from '../validation/validationReviewModel';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export const MOCK_SIGNED_DEMO_HISTORY_FIXTURE: SignedDemoHistoryFixtureV1 =
  deepFreeze(
    signedDemoHistoryFixtureJson as unknown as SignedDemoHistoryFixtureV1,
  );

export const MOCK_REVIEW_ANALYSIS: SentinelFlowAnalysisV1 = deepFreeze({
  ...MOCK_AI_ANALYSIS,
  nftables_command_candidate: {
    ...MOCK_AI_ANALYSIS.nftables_command_candidate,
    timeout: '1800s',
    command:
      'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }',
  },
});

export const MOCK_REVIEW_VALIDATION: ValidationSnapshotV1 = deepFreeze({
  ...MOCK_VALIDATION,
  created_at: '2026-07-18T02:00:30Z',
  valid_until: '2026-07-18T02:05:30Z',
});

const manifest = MOCK_SIGNED_DEMO_HISTORY_FIXTURE.manifest;
const checks = MOCK_REVIEW_VALIDATION.checks;

const readyGates: ValidationReviewGates = deepFreeze([
  {
    id: 'schema-command',
    title: 'Schema, grammar, and canonicalization',
    outcome: 'pass',
    detail:
      'Strict output and one bounded command parsed into a canonical artifact.',
    sourceCheckIds: ['structured_output', 'command_grammar'],
    inputDigests: [checks[0]!.input_digest, checks[1]!.input_digest],
  },
  {
    id: 'consistency',
    title: 'Policy, evidence, and command consistency',
    outcome: 'pass',
    detail: 'Target, TTL, and immutable evidence references agree.',
    sourceCheckIds: ['policy_evidence_command_consistency'],
    inputDigests: [checks[2]!.input_digest],
  },
  {
    id: 'protected-target',
    title: 'Protected target',
    outcome: 'pass',
    detail:
      'The documentation target passed the static and effective protection set check.',
    sourceCheckIds: ['protected_network'],
    inputDigests: [checks[3]!.input_digest],
  },
  {
    id: 'owned-schema-syntax',
    title: 'nft syntax and owned schema',
    outcome: 'pass',
    detail:
      'Syntax check and signed read-back matched the executor-owned table, set, chain, and rule shape.',
    sourceCheckIds: ['owned_schema_syntax'],
    inputDigests: [checks[4]!.input_digest],
  },
  {
    id: 'historical-impact',
    title: 'Historical impact',
    outcome: 'pass',
    detail:
      'Complete 24-hour demo coverage contained no verified successful authentication for the target.',
    sourceCheckIds: ['historical_impact'],
    inputDigests: [checks[5]!.input_digest],
  },
]);

function replaceGate(
  gates: ValidationReviewGates,
  id: ValidationReviewGate['id'],
  patch: Partial<ValidationReviewGate>,
): ValidationReviewGates {
  return gates.map((gate) =>
    gate.id === id ? { ...gate, ...patch } : gate,
  ) as unknown as ValidationReviewGates;
}

const readyView: ValidationReviewView = {
  policy: MOCK_POLICY,
  validation: MOCK_REVIEW_VALIDATION,
  command: {
    renderMode: 'inert-text',
    generatedCommand: MOCK_REVIEW_ANALYSIS.nftables_command_candidate.command,
    generatedTimeoutToken:
      MOCK_REVIEW_ANALYSIS.nftables_command_candidate.timeout,
    generatedParsedSeconds: 1800,
    generatedDigest: MOCK_REVIEW_VALIDATION.generated_candidate_digest,
    canonicalCommand:
      'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n',
    canonicalTimeoutToken: '30m',
    canonicalParsedSeconds: 1800,
    canonicalDigest: MOCK_REVIEW_VALIDATION.canonical_artifact_digest,
    policyTtlSeconds: MOCK_POLICY.ttl_seconds,
    ttlEquality: 'equal',
  },
  gates: readyGates,
  sourceHealth: {
    gateway: 'complete',
    authentication: 'complete',
    digest: manifest.source_health_digest,
    unresolvedSequenceRange: null,
  },
  demoHistory: {
    signatureVerification: 'verified',
    fixtureOnly: true,
    manifestId: manifest.manifest_id,
    manifestDigest: MOCK_SIGNED_DEMO_HISTORY_FIXTURE.manifest_digest,
    datasetId: manifest.dataset_id,
    datasetDigest: manifest.dataset_digest,
    datasetRecordCount: manifest.dataset_record_count,
    importId: manifest.import_id,
    coverageStart: manifest.coverage_start,
    coverageEnd: manifest.coverage_end,
    sourceHealthDigest: manifest.source_health_digest,
  },
  impact: {
    coverage: 'complete',
    lookbackStart: manifest.coverage_start,
    lookbackEnd: manifest.coverage_end,
    successfulAuthenticationSeen: false,
    result: 'no-verified-success',
    impactDigest: MOCK_REVIEW_VALIDATION.historical_impact_digest,
  },
  validity: {
    status: 'fresh',
    windowSeconds: 300,
    remainingSeconds: 240,
    serverEvaluatedAt: '2026-07-18T02:01:30Z',
    createdAt: MOCK_REVIEW_VALIDATION.created_at,
    validUntil: MOCK_REVIEW_VALIDATION.valid_until,
    reason: 'Server fixture reports an unchanged validation snapshot.',
  },
  hilControls: 'not-implemented',
};

export const MOCK_READY_VALIDATION_REVIEW: ValidationReviewView =
  deepFreeze(readyView);

export const MOCK_GAPPED_VALIDATION_REVIEW: ValidationReviewView = deepFreeze({
  ...readyView,
  validation: null,
  gates: replaceGate(readyGates, 'historical-impact', {
    outcome: 'fail',
    detail:
      'Gateway coverage has an unresolved sequence gap, so historical impact is incomplete.',
  }),
  sourceHealth: {
    ...readyView.sourceHealth,
    gateway: 'gapped',
    unresolvedSequenceRange: '42–45',
  },
  impact: {
    ...readyView.impact,
    coverage: 'gapped',
    successfulAuthenticationSeen: null,
    result: 'blocked-by-gap',
    impactDigest: null,
  },
  validity: {
    ...readyView.validity,
    status: 'missing',
    remainingSeconds: 0,
    createdAt: null,
    validUntil: null,
    reason: 'No validation snapshot exists for incomplete source coverage.',
  },
});

export const MOCK_UNSIGNED_VALIDATION_REVIEW: ValidationReviewView = deepFreeze(
  {
    ...readyView,
    validation: null,
    gates: replaceGate(readyGates, 'historical-impact', {
      outcome: 'fail',
      detail:
        'The demo-history manifest has no verified signature status, so coverage cannot support impact validation.',
    }),
    demoHistory: {
      ...readyView.demoHistory,
      signatureVerification: 'unsigned',
      manifestDigest: null,
    },
    impact: {
      ...readyView.impact,
      coverage: 'missing',
      successfulAuthenticationSeen: null,
      result: 'unavailable',
      impactDigest: null,
    },
    validity: {
      ...readyView.validity,
      status: 'missing',
      remainingSeconds: 0,
      createdAt: null,
      validUntil: null,
      reason: 'Unsigned history cannot produce a validation snapshot.',
    },
  },
);

export const MOCK_FAILED_VALIDATION_REVIEW: ValidationReviewView = deepFreeze({
  ...readyView,
  validation: null,
  gates: replaceGate(
    replaceGate(readyGates, 'owned-schema-syntax', {
      outcome: 'fail',
      detail: 'The reported live owned-schema digest did not match.',
    }),
    'historical-impact',
    {
      outcome: 'blocked',
      detail: 'Historical impact was not entered after the earlier failure.',
    },
  ),
  validity: {
    ...readyView.validity,
    status: 'missing',
    remainingSeconds: 0,
    createdAt: null,
    validUntil: null,
    reason: 'A failed gate cannot produce a validation snapshot.',
  },
});

export const MOCK_MISMATCH_VALIDATION_REVIEW: ValidationReviewView = deepFreeze(
  {
    ...readyView,
    validation: null,
    command: {
      ...readyView.command,
      canonicalCommand:
        'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 29m }\n',
      canonicalTimeoutToken: '29m',
      canonicalParsedSeconds: 1740,
      ttlEquality: 'mismatch',
    },
    gates: replaceGate(
      replaceGate(
        replaceGate(
          replaceGate(readyGates, 'consistency', {
            outcome: 'fail',
            detail:
              'Policy TTL and canonical artifact timeout do not represent equal seconds.',
          }),
          'protected-target',
          {
            outcome: 'blocked',
            detail: 'Not entered after consistency failure.',
          },
        ),
        'owned-schema-syntax',
        {
          outcome: 'blocked',
          detail: 'Not entered after consistency failure.',
        },
      ),
      'historical-impact',
      { outcome: 'blocked', detail: 'Not entered after consistency failure.' },
    ),
    validity: {
      ...readyView.validity,
      status: 'missing',
      remainingSeconds: 0,
      createdAt: null,
      validUntil: null,
      reason: 'Mismatched TTL values cannot produce a validation snapshot.',
    },
  },
);

export const MOCK_STALE_VALIDATION_REVIEW: ValidationReviewView = deepFreeze({
  ...readyView,
  validity: {
    ...readyView.validity,
    status: 'stale',
    remainingSeconds: 0,
    reason:
      'The evidence version changed after this snapshot was created. Revalidation is required.',
  },
});

const expiredValidation: ValidationSnapshotV1 = deepFreeze({
  ...MOCK_REVIEW_VALIDATION,
  created_at: '2026-07-18T01:50:00Z',
  valid_until: '2026-07-18T01:55:00Z',
});

export const MOCK_EXPIRED_VALIDATION_REVIEW: ValidationReviewView = deepFreeze({
  ...readyView,
  validation: expiredValidation,
  validity: {
    ...readyView.validity,
    status: 'expired',
    remainingSeconds: 0,
    createdAt: expiredValidation.created_at,
    validUntil: expiredValidation.valid_until,
    reason: 'The five-minute validation window has elapsed.',
  },
});

const permissionError: ApiErrorV1 = deepFreeze({
  code: 'permission_denied',
  message: 'The adapter denied access to validation review evidence.',
  trace_id: '019b0000-0000-7000-8000-000000000906',
  details: { resource: 'validation-review' },
});

export const VALIDATION_REVIEW_STATE_NAMES = [
  'loading',
  'missing',
  'gapped',
  'unsigned',
  'failed',
  'mismatch',
  'stale',
  'expired',
  'permission-denied',
  'ready',
] as const;
export type ValidationReviewStateName =
  (typeof VALIDATION_REVIEW_STATE_NAMES)[number];

export const MOCK_VALIDATION_REVIEW_STATES: Readonly<
  Record<ValidationReviewStateName, ValidationReviewState>
> = deepFreeze({
  loading: { kind: 'loading' },
  missing: { kind: 'missing' },
  gapped: { kind: 'gapped', view: MOCK_GAPPED_VALIDATION_REVIEW },
  unsigned: { kind: 'unsigned', view: MOCK_UNSIGNED_VALIDATION_REVIEW },
  failed: { kind: 'failed', view: MOCK_FAILED_VALIDATION_REVIEW },
  mismatch: { kind: 'mismatch', view: MOCK_MISMATCH_VALIDATION_REVIEW },
  stale: { kind: 'stale', view: MOCK_STALE_VALIDATION_REVIEW },
  expired: { kind: 'expired', view: MOCK_EXPIRED_VALIDATION_REVIEW },
  'permission-denied': {
    kind: 'permission-denied',
    error: permissionError,
  },
  ready: { kind: 'ready', view: MOCK_READY_VALIDATION_REVIEW },
});
