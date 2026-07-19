import type { IncidentListViewItem } from './incidentListModel';
import type {
  IncidentListAdapter,
  IncidentListAdapterResult,
  IncidentListPage,
  IncidentListRequest,
} from './incidentListModel';
import { MOCK_INCIDENT_LIST_RECORDS } from '../mocks/incidentListFixtures';

const CURSOR_PREFIX = 'fixture-cursor-v1:';

function cursorFor(offset: number): string {
  return `${CURSOR_PREFIX}${offset}`;
}

function offsetFrom(cursor: string | null): number {
  if (!cursor?.startsWith(CURSOR_PREFIX)) return 0;
  const parsed = Number(cursor.slice(CURSOR_PREFIX.length));
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
}

function utcMillis(value: string): number | null {
  if (value === '') return null;
  const parsed = Date.parse(`${value}:00Z`);
  return Number.isFinite(parsed) ? parsed : null;
}

function matches(
  item: IncidentListViewItem,
  request: IncidentListRequest,
): boolean {
  const { filters } = request;
  const lastSeen = Date.parse(item.incident.last_seen_at);
  const from = utcMillis(filters.fromUtc);
  const to = utcMillis(filters.toUtc);

  return (
    (filters.sourceIp === '' || item.incident.source_ip === filters.sourceIp) &&
    (filters.state === 'all' || item.incident.state === filters.state) &&
    (filters.scenario === 'all' ||
      item.primarySignal.classification === filters.scenario) &&
    (filters.service === '' ||
      item.incident.service_label.toLowerCase() ===
        filters.service.toLowerCase()) &&
    (from === null || lastSeen >= from) &&
    (to === null || lastSeen <= to)
  );
}

export function buildFixtureIncidentListPage(
  request: IncidentListRequest,
  records: readonly IncidentListViewItem[] = MOCK_INCIDENT_LIST_RECORDS,
): IncidentListPage {
  const sorted = records
    .filter((item) => matches(item, request))
    .sort(
      (left, right) =>
        Date.parse(right.incident.last_seen_at) -
          Date.parse(left.incident.last_seen_at) ||
        left.incident.incident_id.localeCompare(right.incident.incident_id),
    );
  const requestedOffset = offsetFrom(request.cursor);
  const offset = requestedOffset < sorted.length ? requestedOffset : 0;
  const items = sorted.slice(offset, offset + request.pageSize);
  const nextOffset = offset + items.length;
  const previousOffset = Math.max(0, offset - request.pageSize);
  const hasPreviousPage = offset > 0;
  const hasNextPage = nextOffset < sorted.length;

  return Object.freeze({
    items: Object.freeze(items),
    pageInfo: Object.freeze({
      startCursor: items.length > 0 ? cursorFor(offset) : null,
      endCursor: items.length > 0 ? cursorFor(nextOffset) : null,
      previousCursor: hasPreviousPage ? cursorFor(previousOffset) : null,
      nextCursor: hasNextPage ? cursorFor(nextOffset) : null,
      hasPreviousPage,
      hasNextPage,
      firstVisibleIndex: items.length > 0 ? offset + 1 : 0,
      lastVisibleIndex: nextOffset,
      totalItems: sorted.length,
    }),
  });
}

export function createFixtureIncidentListAdapter(
  records: readonly IncidentListViewItem[] = MOCK_INCIDENT_LIST_RECORDS,
): IncidentListAdapter {
  return {
    kind: 'fixture',
    async load(
      request: IncidentListRequest,
      signal?: AbortSignal,
    ): Promise<IncidentListAdapterResult> {
      signal?.throwIfAborted();
      await Promise.resolve();
      signal?.throwIfAborted();
      return {
        kind: 'success',
        page: buildFixtureIncidentListPage(request, records),
      };
    },
  };
}

export const fixtureIncidentListAdapter = createFixtureIncidentListAdapter();
