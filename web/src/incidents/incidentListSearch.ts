import { INCIDENT_STATES } from '../contracts/apiDtos';
import { DETECTION_CLASSIFICATIONS } from '../contracts/rootContracts';
import type { IncidentListFilters } from './incidentListModel';

export const DEFAULT_INCIDENT_LIST_FILTERS: IncidentListFilters = Object.freeze(
  {
    sourceIp: '',
    state: 'all',
    scenario: 'all',
    service: '',
    fromUtc: '',
    toUtc: '',
  },
);

export interface ParsedIncidentListSearch {
  readonly filters: IncidentListFilters;
  readonly cursor: string | null;
}

export interface IncidentFilterValidation {
  readonly sourceIp: string | null;
  readonly service: string | null;
  readonly time: string | null;
  readonly valid: boolean;
}

function isEnumMember<T extends string>(
  values: readonly T[],
  value: string | null,
): value is T {
  return value !== null && values.includes(value as T);
}

export function isCanonicalIpv4(value: string): boolean {
  const parts = value.split('.');
  return (
    parts.length === 4 &&
    parts.every(
      (part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255,
    )
  );
}

function isUtcMinute(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) {
    return false;
  }
  return Number.isFinite(Date.parse(`${value}:00Z`));
}

export function validateIncidentListFilters(
  filters: IncidentListFilters,
): IncidentFilterValidation {
  const sourceIp =
    filters.sourceIp === '' || isCanonicalIpv4(filters.sourceIp)
      ? null
      : 'Use one canonical IPv4 address without leading zeroes.';
  const service =
    filters.service === '' ||
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(filters.service)
      ? null
      : 'Use a service label containing letters, numbers, dots, dashes, or underscores.';

  let time: string | null = null;
  if (
    (filters.fromUtc !== '' && !isUtcMinute(filters.fromUtc)) ||
    (filters.toUtc !== '' && !isUtcMinute(filters.toUtc))
  ) {
    time = 'Use a valid UTC date and time.';
  } else if (
    filters.fromUtc !== '' &&
    filters.toUtc !== '' &&
    Date.parse(`${filters.fromUtc}:00Z`) > Date.parse(`${filters.toUtc}:00Z`)
  ) {
    time = 'The start time must not be later than the end time.';
  }

  return {
    sourceIp,
    service,
    time,
    valid: sourceIp === null && service === null && time === null,
  };
}

export function parseIncidentListSearch(
  searchParams: URLSearchParams,
): ParsedIncidentListSearch {
  const state = searchParams.get('state');
  const scenario = searchParams.get('scenario');

  return {
    filters: {
      sourceIp: searchParams.get('source')?.trim() ?? '',
      state: isEnumMember(INCIDENT_STATES, state) ? state : 'all',
      scenario: isEnumMember(DETECTION_CLASSIFICATIONS, scenario)
        ? scenario
        : 'all',
      service: searchParams.get('service')?.trim() ?? '',
      fromUtc: searchParams.get('from') ?? '',
      toUtc: searchParams.get('to') ?? '',
    },
    cursor: searchParams.get('cursor'),
  };
}

export function serializeIncidentListSearch(
  filters: IncidentListFilters,
  cursor: string | null = null,
): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.sourceIp !== '') params.set('source', filters.sourceIp);
  if (filters.state !== 'all') params.set('state', filters.state);
  if (filters.scenario !== 'all') params.set('scenario', filters.scenario);
  if (filters.service !== '') params.set('service', filters.service);
  if (filters.fromUtc !== '') params.set('from', filters.fromUtc);
  if (filters.toUtc !== '') params.set('to', filters.toUtc);
  if (cursor !== null) params.set('cursor', cursor);
  return params;
}
