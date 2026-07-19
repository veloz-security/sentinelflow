import type { ApiErrorV1 } from '../contracts/apiDtos';
import {
  INCIDENT_LIST_PAGE_SIZE,
  type IncidentListLoadState,
} from '../incidents/incidentListModel';
import { buildFixtureIncidentListPage } from '../incidents/fixtureIncidentListAdapter';
import { DEFAULT_INCIDENT_LIST_FILTERS } from '../incidents/incidentListSearch';

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const unavailable: ApiErrorV1 = {
  code: 'service_unavailable',
  message:
    'The future incident list endpoint is unavailable in this fixture state.',
  trace_id: '019b0000-0000-7000-8000-000000000801',
  details: { resource: 'incident-list', retryable: true },
};

const permissionDenied: ApiErrorV1 = {
  code: 'permission_denied',
  message: 'The adapter denied access to the incident collection.',
  trace_id: '019b0000-0000-7000-8000-000000000802',
  details: { resource: 'incident-list' },
};

export const INCIDENT_LIST_STATE_NAMES = [
  'loading',
  'empty',
  'error',
  'permission-denied',
  'populated',
] as const;
export type IncidentListStateName = (typeof INCIDENT_LIST_STATE_NAMES)[number];

export const MOCK_INCIDENT_LIST_STATES: Readonly<
  Record<IncidentListStateName, IncidentListLoadState>
> = deepFreeze({
  loading: { kind: 'loading' },
  empty: { kind: 'empty' },
  error: { kind: 'error', error: unavailable },
  'permission-denied': {
    kind: 'permission-denied',
    error: permissionDenied,
  },
  populated: {
    kind: 'populated',
    page: buildFixtureIncidentListPage({
      filters: DEFAULT_INCIDENT_LIST_FILTERS,
      cursor: null,
      pageSize: INCIDENT_LIST_PAGE_SIZE,
    }),
  },
});
