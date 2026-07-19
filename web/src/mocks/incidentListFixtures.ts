import type {
  AnalysisFailureReason,
  IncidentState,
  IncidentSummaryV1,
} from '../contracts/apiDtos';
import type {
  DetectionClassification,
  DetectionRuleId,
  DeterministicSignalV1,
  Sha256Digest,
  SourceHealthCause,
  SourceHealthDetailCode,
  SourceHealthState,
  SourceHealthV1,
} from '../contracts/rootContracts';
import type { IncidentListViewItem } from '../incidents/incidentListModel';
import {
  MOCK_INCIDENT_SUMMARY,
  MOCK_SIGNAL,
  MOCK_SOURCE_HEALTH,
} from './contractFixtures';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const digest = (character: string) =>
  `sha256:${character.repeat(64)}` as Sha256Digest;

const ruleByScenario: Readonly<
  Record<DetectionClassification, DetectionRuleId>
> = {
  path_scan: 'path_scan.v1',
  request_burst: 'request_burst.v1',
  brute_force: 'login_bruteforce.v1',
  credential_stuffing: 'credential_stuffing.v1',
};

interface FixtureInput {
  readonly sequence: number;
  readonly sourceIp: string;
  readonly service: string;
  readonly state: IncidentState;
  readonly scenario: DetectionClassification;
  readonly health: SourceHealthState;
  readonly healthCause: SourceHealthCause;
  readonly healthDetail: SourceHealthDetailCode;
  readonly dropped: number;
  readonly lastSeenAt: string;
  readonly analysisFailureReason?: AnalysisFailureReason;
}

function createFixture(input: FixtureInput): IncidentListViewItem {
  const suffix = String(700 + input.sequence).padStart(12, '0');
  const minute = String(8 - input.sequence).padStart(2, '0');
  const incident: IncidentSummaryV1 = {
    schema_version: 'incident-summary-v1',
    incident_id: `019b0000-0000-7000-8000-${suffix}`,
    incident_version: input.state === 'closed' ? 4 : 2,
    state: input.state,
    analysis_failure_reason:
      input.state === 'analysis_failed'
        ? (input.analysisFailureReason ?? 'timeout')
        : null,
    source_ip: input.sourceIp,
    service_label: input.service,
    signal_count: input.scenario === 'credential_stuffing' ? 2 : 1,
    first_seen_at: `2026-07-18T00:${minute}:00Z`,
    last_seen_at: input.lastSeenAt,
    updated_at: input.lastSeenAt,
  };
  const signal: DeterministicSignalV1 = {
    schema_version: 'deterministic-signal-view-v1',
    signal_id: `019b0000-0000-7000-9000-${suffix}`,
    rule_id: ruleByScenario[input.scenario],
    classification: input.scenario,
    window_start: `2026-07-18T00:${minute}:00Z`,
    window_end: input.lastSeenAt,
    event_count: 10 + input.sequence,
    distinct_account_count: input.scenario === 'credential_stuffing' ? 8 : 1,
    distinct_suspicious_path_count: input.scenario === 'path_scan' ? 8 : 0,
    evidence_digest: digest(String(input.sequence)),
  };
  const sourceHealth: SourceHealthV1 = {
    schema_version: 'source-health-v1',
    event_id: `019b0000-0000-7000-a000-${suffix}`,
    idempotency_key: digest(String((input.sequence + 1) % 10)),
    occurred_at: input.lastSeenAt,
    source_id: `${input.service}.gateway`,
    cause: input.healthCause,
    state: input.health,
    affected_sender_epoch: 'BBBBBBBBBBBBBBBBBBBBBB',
    sequence_start: input.health === 'recovered' ? null : input.sequence * 100,
    sequence_end:
      input.health === 'recovered'
        ? null
        : input.sequence * 100 + Math.max(input.dropped - 1, 0),
    interval_start: `2026-07-18T00:${minute}:00Z`,
    interval_end: input.lastSeenAt,
    dropped_count: input.dropped,
    detail_code: input.healthDetail,
  };

  return deepFreeze({ incident, primarySignal: signal, sourceHealth });
}

export const MOCK_INCIDENT_LIST_RECORDS: readonly IncidentListViewItem[] =
  deepFreeze([
    {
      incident: MOCK_INCIDENT_SUMMARY,
      primarySignal: MOCK_SIGNAL,
      sourceHealth: MOCK_SOURCE_HEALTH,
    },
    createFixture({
      sequence: 1,
      sourceIp: '203.0.113.21',
      service: 'demo-app',
      state: 'open',
      scenario: 'credential_stuffing',
      health: 'degraded',
      healthCause: 'sequence_gap',
      healthDetail: 'known_range',
      dropped: 4,
      lastSeenAt: '2026-07-18T00:58:00Z',
    }),
    createFixture({
      sequence: 2,
      sourceIp: '198.51.100.10',
      service: 'catalog-api',
      state: 'analyzing',
      scenario: 'request_burst',
      health: 'recovered',
      healthCause: 'recovered',
      healthDetail: 'delivery_restored',
      dropped: 0,
      lastSeenAt: '2026-07-18T00:54:00Z',
    }),
    createFixture({
      sequence: 3,
      sourceIp: '192.0.2.44',
      service: 'docs-app',
      state: 'closed',
      scenario: 'path_scan',
      health: 'recovered',
      healthCause: 'recovered',
      healthDetail: 'delivery_restored',
      dropped: 0,
      lastSeenAt: '2026-07-18T00:49:00Z',
    }),
    createFixture({
      sequence: 4,
      sourceIp: '203.0.113.72',
      service: 'checkout-api',
      state: 'analysis_failed',
      scenario: 'request_burst',
      health: 'lost',
      healthCause: 'permanent_loss',
      healthDetail: 'known_range',
      dropped: 13,
      lastSeenAt: '2026-07-18T00:43:00Z',
      analysisFailureReason: 'timeout',
    }),
    createFixture({
      sequence: 5,
      sourceIp: '198.51.100.77',
      service: 'demo-app',
      state: 'review_ready',
      scenario: 'path_scan',
      health: 'degraded',
      healthCause: 'unclean_restart',
      healthDetail: 'sender_restart',
      dropped: 0,
      lastSeenAt: '2026-07-18T00:36:00Z',
    }),
    createFixture({
      sequence: 6,
      sourceIp: '192.0.2.92',
      service: 'identity-api',
      state: 'open',
      scenario: 'brute_force',
      health: 'recovered',
      healthCause: 'recovered',
      healthDetail: 'delivery_restored',
      dropped: 0,
      lastSeenAt: '2026-07-18T00:31:00Z',
    }),
    createFixture({
      sequence: 7,
      sourceIp: '203.0.113.88',
      service: 'catalog-api',
      state: 'closed',
      scenario: 'credential_stuffing',
      health: 'recovered',
      healthCause: 'recovered',
      healthDetail: 'delivery_restored',
      dropped: 0,
      lastSeenAt: '2026-07-18T00:24:00Z',
    }),
  ]);

export const MOCK_INCIDENT_SERVICES = deepFreeze(
  [
    ...new Set(
      MOCK_INCIDENT_LIST_RECORDS.map((item) => item.incident.service_label),
    ),
  ].sort(),
);
