import type {
  ApiErrorV1,
  AuditEventV1,
  EnforcementLifecycleV1,
  LifecycleOperationV1,
  LifecycleState,
} from '../contracts/apiDtos';
import type {
  ExecutionClassification,
  ExecutionErrorCode,
  ExecutionOperation,
  ExecutionResultV1,
  Sha256Digest,
  Uuid,
} from '../contracts/rootContracts';
import type {
  AuditProvenanceKind,
  AuditTrailEntry,
  EnforcementLifecycleState,
  EnforcementLifecycleStateName,
  EnforcementLifecycleView,
  JournalIntegrity,
  JournalRecordPresentation,
  RecoveryPresentation,
} from '../enforcement/enforcementLifecycleModel';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const digest = (character: string) =>
  `sha256:${character.repeat(64)}` as Sha256Digest;

const uuid = (value: number) =>
  `019b0000-0000-7000-8000-${String(value).padStart(12, '0')}` as Uuid;

const ACTION_ID = uuid(200);
const POLICY_ID = uuid(201);
const INCIDENT_ID = uuid(202);
const ANALYSIS_ID = uuid(203);
const VALIDATION_ID = uuid(204);
const HIL_DECISION_ID = uuid(205);
const TRACE_ID = uuid(206);
const TARGET_IPV4 = '203.0.113.20';
const ORIGINAL_ADD_DIGEST =
  'sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6' as Sha256Digest;
const OWNED_SCHEMA_DIGEST =
  'sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997' as Sha256Digest;

interface ResultInput {
  readonly resultId: number;
  readonly capabilityId: number;
  readonly capabilityDigest: Sha256Digest;
  readonly operation: ExecutionOperation;
  readonly artifactDigest: Sha256Digest;
  readonly classification: ExecutionClassification;
  readonly nftExitClass: ExecutionResultV1['nft_exit_class'];
  readonly readbackState: ExecutionResultV1['readback_state'];
  readonly elementHandle: null;
  readonly remainingTtlSeconds: number | null;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly journalSequence: number;
  readonly errorCode: ExecutionErrorCode;
}

function executionResult(input: ResultInput): ExecutionResultV1 {
  return deepFreeze({
    schema_version: 'execution-result-v1',
    result_id: uuid(input.resultId),
    capability_id: uuid(input.capabilityId),
    capability_digest: input.capabilityDigest,
    operation: input.operation,
    action_id: ACTION_ID,
    artifact_digest: input.artifactDigest,
    target_ipv4: TARGET_IPV4,
    classification: input.classification,
    nft_exit_class: input.nftExitClass,
    readback_state: input.readbackState,
    element_handle: input.elementHandle,
    remaining_ttl_seconds: input.remainingTtlSeconds,
    owned_schema_digest: OWNED_SCHEMA_DIGEST,
    started_at: input.startedAt,
    completed_at: input.completedAt,
    journal_sequence: input.journalSequence,
    error_code: input.errorCode,
  });
}

export const ENFORCEMENT_ADD_RESULT = executionResult({
  resultId: 310,
  capabilityId: 210,
  capabilityDigest:
    'sha256:494841d948324186c6d005ce971bd8fbb990e9e2c67e1e723610b308c9e425d9',
  operation: 'add',
  artifactDigest: ORIGINAL_ADD_DIGEST,
  classification: 'applied',
  nftExitClass: 'success',
  readbackState: 'active',
  elementHandle: null,
  remainingTtlSeconds: 1799,
  startedAt: '2026-07-18T02:00:06.000Z',
  completedAt: '2026-07-18T02:00:06.050Z',
  journalSequence: 2,
  errorCode: 'none',
});

export const ENFORCEMENT_INSPECT_RESULT = executionResult({
  resultId: 330,
  capabilityId: 230,
  capabilityDigest: digest('9'),
  operation: 'inspect',
  artifactDigest: digest('e'),
  classification: 'inspect_active',
  nftExitClass: 'success',
  readbackState: 'active',
  elementHandle: null,
  remainingTtlSeconds: 1680,
  startedAt: '2026-07-18T02:02:06.000Z',
  completedAt: '2026-07-18T02:02:06.030Z',
  journalSequence: 3,
  errorCode: 'none',
});

export const ENFORCEMENT_INSPECT_ABSENT_RESULT = executionResult({
  resultId: 331,
  capabilityId: 231,
  capabilityDigest: digest('7'),
  operation: 'inspect',
  artifactDigest: digest('c'),
  classification: 'inspect_absent',
  nftExitClass: 'success',
  readbackState: 'absent',
  elementHandle: null,
  remainingTtlSeconds: null,
  startedAt: '2026-07-18T02:31:00.000Z',
  completedAt: '2026-07-18T02:31:00.030Z',
  journalSequence: 3,
  errorCode: 'none',
});

export const ENFORCEMENT_REVOKE_RESULT = executionResult({
  resultId: 320,
  capabilityId: 220,
  capabilityDigest:
    'sha256:cdfa0c8a7ac77b7818ee4d5e35bc990df8c0774de63d9a9e85ecfcb061a877a2',
  operation: 'revoke',
  artifactDigest:
    'sha256:85847b7a4eff0b9b9b34f4706f09f260671e09d37847bc82413751f579de5a25',
  classification: 'revoked',
  nftExitClass: 'success',
  readbackState: 'absent',
  elementHandle: null,
  remainingTtlSeconds: null,
  startedAt: '2026-07-18T02:10:01.000Z',
  completedAt: '2026-07-18T02:10:01.050Z',
  journalSequence: 5,
  errorCode: 'none',
});

export const ENFORCEMENT_FAILED_RESULT = executionResult({
  resultId: 340,
  capabilityId: 240,
  capabilityDigest: digest('4'),
  operation: 'add',
  artifactDigest: ORIGINAL_ADD_DIGEST,
  classification: 'failed',
  nftExitClass: 'nonzero',
  readbackState: 'absent',
  elementHandle: null,
  remainingTtlSeconds: null,
  startedAt: '2026-07-18T02:00:06.000Z',
  completedAt: '2026-07-18T02:00:06.050Z',
  journalSequence: 2,
  errorCode: 'nft_failed',
});

export const ENFORCEMENT_INDETERMINATE_RESULT = executionResult({
  resultId: 350,
  capabilityId: 250,
  capabilityDigest: digest('5'),
  operation: 'add',
  artifactDigest: ORIGINAL_ADD_DIGEST,
  classification: 'indeterminate',
  nftExitClass: 'success',
  readbackState: 'unavailable',
  elementHandle: null,
  remainingTtlSeconds: null,
  startedAt: '2026-07-18T02:00:06.000Z',
  completedAt: '2026-07-18T02:00:06.050Z',
  journalSequence: 2,
  errorCode: 'journal_failed',
});

const RESULT_DIGESTS: Readonly<Record<Uuid, Sha256Digest>> = deepFreeze({
  [ENFORCEMENT_ADD_RESULT.result_id]:
    'sha256:85b3a12fb58a706827bd9e44f5d590e9d8a27cac09603f9cc5894f5a13311128',
  [ENFORCEMENT_INSPECT_RESULT.result_id]:
    'sha256:d93d2297ad3a8e187616488a607e20f8c24ac95de19325b370cb952c2d6a6492',
  [ENFORCEMENT_INSPECT_ABSENT_RESULT.result_id]:
    'sha256:27508c8b5b1579c188147f29814758cf2233c318a9b33e297f27acc918e575c2',
  [ENFORCEMENT_REVOKE_RESULT.result_id]:
    'sha256:d4abacce79ef4a05ac6abe699b3a8394ea442adadad62e50b7cbaca209196982',
  [ENFORCEMENT_FAILED_RESULT.result_id]:
    'sha256:a410d636f0cac493684636440404358a31d1396fc74d866e2c6576ecae8e1b57',
  [ENFORCEMENT_INDETERMINATE_RESULT.result_id]:
    'sha256:d3d79c99240a755285a6d319266a6d044401d7d51faad0ac2981a8722f6bf5a4',
});

function operation(
  value: ExecutionOperation,
  id: number,
  requestedAt: string,
  result: ExecutionResultV1 | null,
  signatureVerification: LifecycleOperationV1['signature_verification'] = 'verified',
): LifecycleOperationV1 {
  return deepFreeze({
    operation_id: uuid(id),
    operation: value,
    requested_at: requestedAt,
    signature_verification: signatureVerification,
    result,
  });
}

const ADD_OPERATION = operation(
  'add',
  401,
  '2026-07-18T02:00:05.900Z',
  ENFORCEMENT_ADD_RESULT,
);
const INSPECT_OPERATION = operation(
  'inspect',
  402,
  '2026-07-18T02:02:05.900Z',
  ENFORCEMENT_INSPECT_RESULT,
);
const INSPECT_ABSENT_OPERATION = operation(
  'inspect',
  403,
  '2026-07-18T02:30:59.900Z',
  ENFORCEMENT_INSPECT_ABSENT_RESULT,
);
const REVOKE_OPERATION = operation(
  'revoke',
  404,
  '2026-07-18T02:10:00.900Z',
  ENFORCEMENT_REVOKE_RESULT,
);
const PENDING_ADD_OPERATION = operation(
  'add',
  405,
  '2026-07-18T02:00:05.900Z',
  null,
);
const FAILED_ADD_OPERATION = operation(
  'add',
  406,
  '2026-07-18T02:00:05.900Z',
  ENFORCEMENT_FAILED_RESULT,
);
const INDETERMINATE_ADD_OPERATION = operation(
  'add',
  407,
  '2026-07-18T02:00:05.900Z',
  ENFORCEMENT_INDETERMINATE_RESULT,
  'invalid',
);

interface AuditInput {
  readonly id: number;
  readonly occurredAt: string;
  readonly category: AuditEventV1['category'];
  readonly eventType: string;
  readonly actorKind: AuditEventV1['actor_kind'];
  readonly actorId: string;
  readonly objectType: AuditEventV1['object_type'];
  readonly objectId: Uuid;
  readonly outcome: AuditEventV1['outcome'];
  readonly reason: string | null;
  readonly provenance: AuditProvenanceKind;
  readonly title: string;
  readonly detail: string;
}

function auditEntry(input: AuditInput): AuditTrailEntry {
  return deepFreeze({
    event: {
      schema_version: 'audit-event-v1',
      audit_id: uuid(input.id),
      occurred_at: input.occurredAt,
      category: input.category,
      event_type: input.eventType,
      actor_kind: input.actorKind,
      actor_id: input.actorId,
      object_type: input.objectType,
      object_id: input.objectId,
      outcome: input.outcome,
      trace_id: TRACE_ID,
      correlation_id: INCIDENT_ID,
      safe_reason_code: input.reason,
    },
    provenance: input.provenance,
    title: input.title,
    detail: input.detail,
  });
}

export const ENFORCEMENT_AUDIT_TRAIL: readonly AuditTrailEntry[] = deepFreeze([
  auditEntry({
    id: 501,
    occurredAt: '2026-07-18T01:58:00.000Z',
    category: 'observation',
    eventType: 'gateway.fact.recorded',
    actorKind: 'service',
    actorId: 'gateway.demo',
    objectType: 'incident',
    objectId: INCIDENT_ID,
    outcome: 'recorded',
    reason: 'minimized_event',
    provenance: 'fact',
    title: 'Observed fact recorded',
    detail: 'Minimized gateway metadata entered the evidence chain.',
  }),
  auditEntry({
    id: 502,
    occurredAt: '2026-07-18T01:58:10.000Z',
    category: 'analysis',
    eventType: 'detector.rule.matched',
    actorKind: 'service',
    actorId: 'detector.demo',
    objectType: 'incident',
    objectId: INCIDENT_ID,
    outcome: 'recorded',
    reason: 'login_bruteforce_v1',
    provenance: 'deterministic-rule',
    title: 'Deterministic rule matched',
    detail: 'The fixed detector conclusion remains separate from AI analysis.',
  }),
  auditEntry({
    id: 503,
    occurredAt: '2026-07-18T01:58:30.000Z',
    category: 'analysis',
    eventType: 'ai.candidate.generated',
    actorKind: 'service',
    actorId: 'ai.worker.demo',
    objectType: 'analysis',
    objectId: ANALYSIS_ID,
    outcome: 'recorded',
    reason: 'structured_output',
    provenance: 'ai-generated',
    title: 'AI candidate generated',
    detail: 'Untrusted structured output proposed one evidence-bound action.',
  }),
  auditEntry({
    id: 504,
    occurredAt: '2026-07-18T01:59:00.000Z',
    category: 'validation',
    eventType: 'artifact.canonicalized',
    actorKind: 'service',
    actorId: 'validator.demo',
    objectType: 'validation',
    objectId: VALIDATION_ID,
    outcome: 'succeeded',
    reason: 'nft_blacklist_v1',
    provenance: 'canonicalized',
    title: 'Artifact canonicalized',
    detail: 'Strict parsing produced the exact digest later bound to approval.',
  }),
  auditEntry({
    id: 505,
    occurredAt: '2026-07-18T02:00:00.000Z',
    category: 'authorization',
    eventType: 'hil.decision.approved',
    actorKind: 'administrator',
    actorId: 'admin.demo',
    objectType: 'hil_decision',
    objectId: HIL_DECISION_ID,
    outcome: 'succeeded',
    reason: 'threat_confirmed',
    provenance: 'human-decision',
    title: 'Human decision bound',
    detail: 'The administrator approved only the exact artifact and version.',
  }),
  auditEntry({
    id: 506,
    occurredAt: '2026-07-18T02:00:05.900Z',
    category: 'enforcement',
    eventType: 'dispatcher.add.capability_issued',
    actorKind: 'service',
    actorId: 'dispatcher.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'recorded',
    reason: 'single_use_exact_artifact',
    provenance: 'dispatcher',
    title: 'Dispatcher issued add capability',
    detail:
      'A short-lived, single-use add capability was recorded server-side.',
  }),
  auditEntry({
    id: 507,
    occurredAt: '2026-07-18T02:00:06.050Z',
    category: 'enforcement',
    eventType: 'executor.add.result_recorded',
    actorKind: 'service',
    actorId: 'executor.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'succeeded',
    reason: 'signed_result_verified',
    provenance: 'executor-result',
    title: 'Executor add result verified',
    detail:
      'The digest-bound result and read-back classified the add as applied.',
  }),
  auditEntry({
    id: 508,
    occurredAt: '2026-07-18T02:02:05.900Z',
    category: 'enforcement',
    eventType: 'dispatcher.inspect.capability_issued',
    actorKind: 'service',
    actorId: 'dispatcher.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'recorded',
    reason: 'read_only_operation',
    provenance: 'dispatcher',
    title: 'Dispatcher issued inspect capability',
    detail: 'Inspect used separate, typed, read-only authority.',
  }),
  auditEntry({
    id: 509,
    occurredAt: '2026-07-18T02:02:06.030Z',
    category: 'enforcement',
    eventType: 'executor.inspect.result_recorded',
    actorKind: 'service',
    actorId: 'executor.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'succeeded',
    reason: 'active_readback',
    provenance: 'executor-result',
    title: 'Executor inspect result verified',
    detail:
      'Read-back observed the owned element without adding or extending it.',
  }),
  auditEntry({
    id: 510,
    occurredAt: '2026-07-18T02:02:06.040Z',
    category: 'enforcement',
    eventType: 'recovery.inspect.completed',
    actorKind: 'system',
    actorId: 'recovery.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'recorded',
    reason: 'no_reapply_no_ttl_refresh',
    provenance: 'recovery',
    title: 'Recovery remained read-only',
    detail:
      'Recovery accepted persisted bytes and inspect evidence; add was not invoked again.',
  }),
  auditEntry({
    id: 511,
    occurredAt: '2026-07-18T02:09:50.000Z',
    category: 'authorization',
    eventType: 'hil.revoke.approved',
    actorKind: 'administrator',
    actorId: 'admin.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'succeeded',
    reason: 'operator_requested',
    provenance: 'human-decision',
    title: 'Human revoke decision bound',
    detail:
      'Removal used a new deterministic artifact and administrator reason.',
  }),
  auditEntry({
    id: 512,
    occurredAt: '2026-07-18T02:10:00.900Z',
    category: 'enforcement',
    eventType: 'dispatcher.revoke.capability_issued',
    actorKind: 'service',
    actorId: 'dispatcher.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'recorded',
    reason: 'single_use_revoke',
    provenance: 'dispatcher',
    title: 'Dispatcher issued revoke capability',
    detail:
      'Revoke authority remained distinct from the original add approval.',
  }),
  auditEntry({
    id: 513,
    occurredAt: '2026-07-18T02:10:01.050Z',
    category: 'enforcement',
    eventType: 'executor.revoke.result_recorded',
    actorKind: 'service',
    actorId: 'executor.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome: 'succeeded',
    reason: 'absent_readback',
    provenance: 'executor-result',
    title: 'Executor revoke result verified',
    detail:
      'Read-back classified the element as absent after deterministic removal.',
  }),
]);

const FAILED_EXECUTOR_AUDIT = auditEntry({
  id: 520,
  occurredAt: '2026-07-18T02:00:06.050Z',
  category: 'enforcement',
  eventType: 'executor.add.result_recorded',
  actorKind: 'service',
  actorId: 'executor.demo',
  objectType: 'enforcement_action',
  objectId: ACTION_ID,
  outcome: 'failed',
  reason: 'nft_failed',
  provenance: 'executor-result',
  title: 'Executor add failed',
  detail:
    'The fixed invocation failed and read-back confirmed the target absent.',
});

const INDETERMINATE_EXECUTOR_AUDIT = auditEntry({
  id: 521,
  occurredAt: '2026-07-18T02:00:06.050Z',
  category: 'enforcement',
  eventType: 'executor.add.result_recorded',
  actorKind: 'service',
  actorId: 'executor.demo',
  objectType: 'enforcement_action',
  objectId: ACTION_ID,
  outcome: 'indeterminate',
  reason: 'journal_failed',
  provenance: 'executor-result',
  title: 'Executor result indeterminate',
  detail:
    'Mutation outcome cannot be trusted because terminal persistence failed.',
});

const EXPIRED_INSPECT_AUDIT = auditEntry({
  id: 522,
  occurredAt: '2026-07-18T02:31:00.030Z',
  category: 'enforcement',
  eventType: 'executor.inspect.result_recorded',
  actorKind: 'service',
  actorId: 'executor.demo',
  objectType: 'enforcement_action',
  objectId: ACTION_ID,
  outcome: 'succeeded',
  reason: 'absent_readback',
  provenance: 'executor-result',
  title: 'Executor inspect confirmed expiry',
  detail:
    'Separately authorized read-back found no owned element after native expiry.',
});

function haltedRecoveryAudit(
  id: number,
  outcome: AuditEventV1['outcome'],
  reason: string,
  title: string,
  detail: string,
) {
  return auditEntry({
    id,
    occurredAt: '2026-07-18T02:00:06.060Z',
    category: 'enforcement',
    eventType: 'recovery.journal.halted',
    actorKind: 'system',
    actorId: 'recovery.demo',
    objectType: 'enforcement_action',
    objectId: ACTION_ID,
    outcome,
    reason,
    provenance: 'recovery',
    title,
    detail,
  });
}

const INDETERMINATE_RECOVERY_AUDIT = haltedRecoveryAudit(
  523,
  'indeterminate',
  'readback_required',
  'Recovery halted mutation',
  'Only a new separately signed read-only inspect may classify the persisted action.',
);
const TORN_RECOVERY_AUDIT = haltedRecoveryAudit(
  524,
  'indeterminate',
  'torn_record',
  'Torn journal preserved',
  'The incomplete record remains visible; recovery neither truncates it nor invokes add.',
);
const CORRUPT_RECOVERY_AUDIT = haltedRecoveryAudit(
  525,
  'failed',
  'checksum_failed',
  'Corrupt journal rejected',
  'Checksum failure stopped recovery before any mutation or TTL change.',
);

const ADD_JOURNAL: readonly JournalRecordPresentation[] = deepFreeze([
  {
    sequence: 1,
    operation: 'add',
    phase: 'started',
    integrity: 'verified',
    recordedAt: '2026-07-18T02:00:06.000Z',
    terminalResultId: null,
    terminalResultDigest: null,
  },
  {
    sequence: 2,
    operation: 'add',
    phase: 'terminal',
    integrity: 'verified',
    recordedAt: '2026-07-18T02:00:06.050Z',
    terminalResultId: ENFORCEMENT_ADD_RESULT.result_id,
    terminalResultDigest: RESULT_DIGESTS[ENFORCEMENT_ADD_RESULT.result_id],
  },
]);

const INSPECT_JOURNAL: readonly JournalRecordPresentation[] = deepFreeze([
  ...ADD_JOURNAL,
  {
    sequence: 3,
    operation: 'inspect',
    phase: 'terminal',
    integrity: 'verified',
    recordedAt: '2026-07-18T02:02:06.030Z',
    terminalResultId: ENFORCEMENT_INSPECT_RESULT.result_id,
    terminalResultDigest: RESULT_DIGESTS[ENFORCEMENT_INSPECT_RESULT.result_id],
  },
]);

const REVOKE_JOURNAL: readonly JournalRecordPresentation[] = deepFreeze([
  ...INSPECT_JOURNAL,
  {
    sequence: 4,
    operation: 'revoke',
    phase: 'started',
    integrity: 'verified',
    recordedAt: '2026-07-18T02:10:01.000Z',
    terminalResultId: null,
    terminalResultDigest: null,
  },
  {
    sequence: 5,
    operation: 'revoke',
    phase: 'terminal',
    integrity: 'verified',
    recordedAt: '2026-07-18T02:10:01.050Z',
    terminalResultId: ENFORCEMENT_REVOKE_RESULT.result_id,
    terminalResultDigest: RESULT_DIGESTS[ENFORCEMENT_REVOKE_RESULT.result_id],
  },
]);

const RECOVERY_NONE: RecoveryPresentation = deepFreeze({
  integrity: 'complete',
  mode: 'none',
  detail: 'Journal records form a complete ordered chain.',
  automaticReadd: false,
  ttlRefresh: false,
});

const RECOVERY_READ_ONLY: RecoveryPresentation = deepFreeze({
  integrity: 'complete',
  mode: 'read-only-inspect',
  detail:
    'Recovery reverified persisted bytes and used a separately signed inspect. Add was not invoked again.',
  automaticReadd: false,
  ttlRefresh: false,
});

function haltedRecovery(integrity: JournalIntegrity): RecoveryPresentation {
  return deepFreeze({
    integrity,
    mode: 'halted',
    detail:
      integrity === 'torn'
        ? 'A started record has no terminal pair. Recovery is read-only and mutation remains halted.'
        : 'A checksum or sequence mismatch was detected. The record is preserved and mutation remains halted.',
    automaticReadd: false,
    ttlRefresh: false,
  });
}

interface ViewInput {
  readonly state: LifecycleState;
  readonly operations: readonly LifecycleOperationV1[];
  readonly journal: readonly JournalRecordPresentation[];
  readonly recovery?: RecoveryPresentation;
  readonly appliedAt?: string | null;
  readonly expiresAt?: string | null;
  readonly serverNow?: string;
  readonly remainingTtlSeconds?: number | null;
  readonly auditCount?: number;
  readonly auditTrail?: readonly AuditTrailEntry[];
}

function view(input: ViewInput): EnforcementLifecycleView {
  const lifecycle: EnforcementLifecycleV1 = deepFreeze({
    schema_version: 'enforcement-lifecycle-v1',
    action_id: ACTION_ID,
    action_version: 3,
    policy_id: POLICY_ID,
    state: input.state,
    target_ipv4: TARGET_IPV4,
    original_add_digest: ORIGINAL_ADD_DIGEST,
    approved_ttl_seconds: 1800,
    applied_at:
      input.appliedAt === undefined
        ? '2026-07-18T02:00:06.050Z'
        : input.appliedAt,
    expires_at:
      input.expiresAt === undefined
        ? '2026-07-18T02:30:06.050Z'
        : input.expiresAt,
    operations: input.operations,
    updated_at: input.serverNow ?? '2026-07-18T02:02:06.040Z',
  });

  return deepFreeze({
    lifecycle,
    resultDigests: RESULT_DIGESTS,
    journal: input.journal,
    recovery: input.recovery ?? RECOVERY_NONE,
    serverClock: {
      serverNow: input.serverNow ?? '2026-07-18T02:02:06.040Z',
      remainingTtlSeconds: input.remainingTtlSeconds ?? null,
    },
    auditTrail:
      input.auditTrail ??
      ENFORCEMENT_AUDIT_TRAIL.slice(0, input.auditCount ?? 10),
  });
}

const READY_VIEWS = deepFreeze({
  pending: view({
    state: 'pending',
    operations: [PENDING_ADD_OPERATION],
    journal: [],
    appliedAt: null,
    expiresAt: null,
    serverNow: '2026-07-18T02:00:05.950Z',
    auditCount: 6,
  }),
  applied: view({
    state: 'applied',
    operations: [ADD_OPERATION],
    journal: ADD_JOURNAL,
    remainingTtlSeconds: 1799,
    serverNow: '2026-07-18T02:00:06.050Z',
    auditCount: 7,
  }),
  active: view({
    state: 'active',
    operations: [ADD_OPERATION, INSPECT_OPERATION],
    journal: INSPECT_JOURNAL,
    remainingTtlSeconds: 1680,
    recovery: RECOVERY_READ_ONLY,
  }),
  expired: view({
    state: 'expired',
    operations: [ADD_OPERATION, INSPECT_ABSENT_OPERATION],
    journal: [
      ...ADD_JOURNAL,
      {
        sequence: 3,
        operation: 'inspect',
        phase: 'terminal',
        integrity: 'verified',
        recordedAt: '2026-07-18T02:31:00.030Z',
        terminalResultId: ENFORCEMENT_INSPECT_ABSENT_RESULT.result_id,
        terminalResultDigest:
          RESULT_DIGESTS[ENFORCEMENT_INSPECT_ABSENT_RESULT.result_id],
      },
    ],
    serverNow: '2026-07-18T02:31:00.030Z',
    remainingTtlSeconds: 0,
    auditTrail: [
      ...ENFORCEMENT_AUDIT_TRAIL.slice(0, 8),
      EXPIRED_INSPECT_AUDIT,
      ENFORCEMENT_AUDIT_TRAIL[9],
    ],
  }),
  revoked: view({
    state: 'revoked',
    operations: [ADD_OPERATION, INSPECT_OPERATION, REVOKE_OPERATION],
    journal: REVOKE_JOURNAL,
    serverNow: '2026-07-18T02:10:01.050Z',
    remainingTtlSeconds: null,
    auditCount: 13,
  }),
  failed: view({
    state: 'failed',
    operations: [FAILED_ADD_OPERATION],
    journal: [
      ADD_JOURNAL[0],
      {
        ...ADD_JOURNAL[1],
        terminalResultId: ENFORCEMENT_FAILED_RESULT.result_id,
        terminalResultDigest:
          RESULT_DIGESTS[ENFORCEMENT_FAILED_RESULT.result_id],
      },
    ],
    appliedAt: null,
    expiresAt: null,
    serverNow: '2026-07-18T02:00:06.050Z',
    auditTrail: [...ENFORCEMENT_AUDIT_TRAIL.slice(0, 6), FAILED_EXECUTOR_AUDIT],
  }),
  indeterminate: view({
    state: 'indeterminate',
    operations: [INDETERMINATE_ADD_OPERATION],
    journal: [
      ADD_JOURNAL[0],
      {
        ...ADD_JOURNAL[1],
        terminalResultId: ENFORCEMENT_INDETERMINATE_RESULT.result_id,
        terminalResultDigest:
          RESULT_DIGESTS[ENFORCEMENT_INDETERMINATE_RESULT.result_id],
      },
    ],
    recovery: haltedRecovery('unknown'),
    serverNow: '2026-07-18T02:00:06.050Z',
    auditTrail: [
      ...ENFORCEMENT_AUDIT_TRAIL.slice(0, 6),
      INDETERMINATE_EXECUTOR_AUDIT,
      INDETERMINATE_RECOVERY_AUDIT,
    ],
  }),
  'recovered-active': view({
    state: 'active',
    operations: [ADD_OPERATION, INSPECT_OPERATION],
    journal: INSPECT_JOURNAL,
    remainingTtlSeconds: 1680,
    recovery: RECOVERY_READ_ONLY,
  }),
  'torn-journal': view({
    state: 'indeterminate',
    operations: [INDETERMINATE_ADD_OPERATION],
    journal: [
      {
        ...ADD_JOURNAL[0],
        integrity: 'missing-terminal',
      },
    ],
    recovery: haltedRecovery('torn'),
    serverNow: '2026-07-18T02:00:06.050Z',
    auditTrail: [
      ...ENFORCEMENT_AUDIT_TRAIL.slice(0, 6),
      INDETERMINATE_EXECUTOR_AUDIT,
      TORN_RECOVERY_AUDIT,
    ],
  }),
  'corrupt-journal': view({
    state: 'indeterminate',
    operations: [INDETERMINATE_ADD_OPERATION],
    journal: [
      ADD_JOURNAL[0],
      {
        ...ADD_JOURNAL[1],
        integrity: 'checksum-failed',
        terminalResultId: ENFORCEMENT_INDETERMINATE_RESULT.result_id,
        terminalResultDigest:
          RESULT_DIGESTS[ENFORCEMENT_INDETERMINATE_RESULT.result_id],
      },
    ],
    recovery: haltedRecovery('corrupt'),
    serverNow: '2026-07-18T02:00:06.050Z',
    auditTrail: [
      ...ENFORCEMENT_AUDIT_TRAIL.slice(0, 6),
      INDETERMINATE_EXECUTOR_AUDIT,
      CORRUPT_RECOVERY_AUDIT,
    ],
  }),
});

const ERRORS: Readonly<Record<'error' | 'permission-denied', ApiErrorV1>> =
  deepFreeze({
    error: {
      code: 'service_unavailable',
      message: 'The lifecycle endpoint is temporarily unavailable.',
      trace_id: uuid(601),
      details: { retryable: true },
    },
    'permission-denied': {
      code: 'permission_denied',
      message: 'The server denied access to enforcement lifecycle evidence.',
      trace_id: uuid(602),
      details: { resource: 'enforcement-lifecycle' },
    },
  });

export const MOCK_ENFORCEMENT_LIFECYCLE_STATES: Readonly<
  Record<EnforcementLifecycleStateName, EnforcementLifecycleState>
> = deepFreeze({
  loading: { kind: 'loading' },
  empty: { kind: 'empty' },
  error: { kind: 'error', error: ERRORS.error },
  'permission-denied': {
    kind: 'permission-denied',
    error: ERRORS['permission-denied'],
  },
  pending: { kind: 'ready', fixtureName: 'pending', view: READY_VIEWS.pending },
  applied: { kind: 'ready', fixtureName: 'applied', view: READY_VIEWS.applied },
  active: { kind: 'ready', fixtureName: 'active', view: READY_VIEWS.active },
  expired: { kind: 'ready', fixtureName: 'expired', view: READY_VIEWS.expired },
  revoked: { kind: 'ready', fixtureName: 'revoked', view: READY_VIEWS.revoked },
  failed: { kind: 'ready', fixtureName: 'failed', view: READY_VIEWS.failed },
  indeterminate: {
    kind: 'ready',
    fixtureName: 'indeterminate',
    view: READY_VIEWS.indeterminate,
  },
  'recovered-active': {
    kind: 'ready',
    fixtureName: 'recovered-active',
    view: READY_VIEWS['recovered-active'],
  },
  'torn-journal': {
    kind: 'ready',
    fixtureName: 'torn-journal',
    view: READY_VIEWS['torn-journal'],
  },
  'corrupt-journal': {
    kind: 'ready',
    fixtureName: 'corrupt-journal',
    view: READY_VIEWS['corrupt-journal'],
  },
});
