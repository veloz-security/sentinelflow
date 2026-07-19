import { describe, expect, it } from 'vitest';
import { decodeContract } from '../contracts/registry';
import { MOCK_INCIDENT_LIST_RECORDS } from '../mocks/incidentListFixtures';
import {
  INCIDENT_LIST_PAGE_SIZE,
  type IncidentListFilters,
  type IncidentListRequest,
} from './incidentListModel';
import {
  buildFixtureIncidentListPage,
  createFixtureIncidentListAdapter,
} from './fixtureIncidentListAdapter';
import {
  DEFAULT_INCIDENT_LIST_FILTERS,
  isCanonicalIpv4,
  parseIncidentListSearch,
  serializeIncidentListSearch,
  validateIncidentListFilters,
} from './incidentListSearch';

function request(
  filters: IncidentListFilters = DEFAULT_INCIDENT_LIST_FILTERS,
  cursor: string | null = null,
): IncidentListRequest {
  return { filters, cursor, pageSize: INCIDENT_LIST_PAGE_SIZE };
}

describe('fixture incident list adapter', () => {
  it('applies every typed filter deterministically', async () => {
    const adapter = createFixtureIncidentListAdapter();
    const result = await adapter.load(
      request({
        sourceIp: '203.0.113.20',
        state: 'review_ready',
        scenario: 'brute_force',
        service: 'demo-app',
        fromUtc: '2026-07-18T01:00',
        toUtc: '2026-07-18T01:02',
      }),
    );

    expect(result.kind).toBe('success');
    if (result.kind !== 'success') return;
    expect(result.page.items).toHaveLength(1);
    expect(result.page.items[0]?.incident.source_ip).toBe('203.0.113.20');
    expect(result.page.items[0]?.primarySignal.classification).toBe(
      'brute_force',
    );
  });

  it('uses stable opaque cursors in both directions', () => {
    const first = buildFixtureIncidentListPage(request());
    const repeated = buildFixtureIncidentListPage(request());
    const second = buildFixtureIncidentListPage(
      request(DEFAULT_INCIDENT_LIST_FILTERS, first.pageInfo.nextCursor),
    );

    expect(first.items.map((item) => item.incident.incident_id)).toEqual(
      repeated.items.map((item) => item.incident.incident_id),
    );
    expect(first.pageInfo).toMatchObject({
      firstVisibleIndex: 1,
      lastVisibleIndex: 4,
      totalItems: 8,
      hasNextPage: true,
      hasPreviousPage: false,
    });
    expect(second.pageInfo).toMatchObject({
      firstVisibleIndex: 5,
      lastVisibleIndex: 8,
      hasNextPage: false,
      hasPreviousPage: true,
    });
    const previous = buildFixtureIncidentListPage(
      request(DEFAULT_INCIDENT_LIST_FILTERS, second.pageInfo.previousCursor),
    );
    expect(previous.items.map((item) => item.incident.incident_id)).toEqual(
      first.items.map((item) => item.incident.incident_id),
    );
  });

  it('keeps forbidden request-content fields out of list fixtures', () => {
    const forbidden = new Set([
      'path',
      'query',
      'body',
      'cookie',
      'authorization',
      'headers',
    ]);

    function walk(value: unknown): void {
      if (Array.isArray(value)) {
        value.forEach(walk);
        return;
      }
      if (typeof value !== 'object' || value === null) return;
      for (const [key, child] of Object.entries(value)) {
        expect(forbidden.has(key.toLowerCase())).toBe(false);
        walk(child);
      }
    }

    walk(MOCK_INCIDENT_LIST_RECORDS);
  });

  it('keeps every composed fixture inside the checked registry boundary', () => {
    for (const item of MOCK_INCIDENT_LIST_RECORDS) {
      expect(decodeContract(item.incident)).toMatchObject({ ok: true });
      expect(decodeContract(item.primarySignal)).toMatchObject({ ok: true });
      expect(decodeContract(item.sourceHealth)).toMatchObject({ ok: true });
    }
  });
});

describe('incident list URL state', () => {
  it('round-trips filters in a stable order and preserves an opaque cursor', () => {
    const filters: IncidentListFilters = {
      sourceIp: '198.51.100.10',
      state: 'analyzing',
      scenario: 'request_burst',
      service: 'catalog-api',
      fromUtc: '2026-07-18T00:00',
      toUtc: '2026-07-18T01:00',
    };
    const serialized = serializeIncidentListSearch(
      filters,
      'fixture-cursor-v1:4',
    );

    expect(serialized.toString()).toBe(
      'source=198.51.100.10&state=analyzing&scenario=request_burst&service=catalog-api&from=2026-07-18T00%3A00&to=2026-07-18T01%3A00&cursor=fixture-cursor-v1%3A4',
    );
    expect(parseIncidentListSearch(serialized)).toEqual({
      filters,
      cursor: 'fixture-cursor-v1:4',
    });
  });

  it('validates canonical IPv4 and ordered UTC bounds', () => {
    expect(isCanonicalIpv4('203.0.113.20')).toBe(true);
    expect(isCanonicalIpv4('203.000.113.20')).toBe(false);
    expect(isCanonicalIpv4('256.0.0.1')).toBe(false);
    expect(
      validateIncidentListFilters({
        ...DEFAULT_INCIDENT_LIST_FILTERS,
        fromUtc: '2026-07-18T02:00',
        toUtc: '2026-07-18T01:00',
      }),
    ).toMatchObject({ valid: false, time: expect.any(String) });
  });
});
