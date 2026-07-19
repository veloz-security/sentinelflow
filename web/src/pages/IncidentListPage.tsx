import { Alert, Paper, Stack } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { IncidentFilterBar } from '../components/IncidentFilterBar';
import { IncidentListResults } from '../components/IncidentListResults';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { MOCK_INCIDENT_SUMMARY } from '../mocks/contractFixtures';
import { MOCK_INCIDENT_SERVICES } from '../mocks/incidentListFixtures';
import {
  INCIDENT_LIST_PAGE_SIZE,
  type IncidentListAdapter,
  type IncidentListLoadState,
  type IncidentListRequest,
} from '../incidents/incidentListModel';
import { fixtureIncidentListAdapter } from '../incidents/fixtureIncidentListAdapter';
import {
  DEFAULT_INCIDENT_LIST_FILTERS,
  parseIncidentListSearch,
  serializeIncidentListSearch,
} from '../incidents/incidentListSearch';

function useIncidentListState(
  adapter: IncidentListAdapter,
  request: IncidentListRequest,
  revision: number,
): IncidentListLoadState {
  const stateKey = `${revision}:${JSON.stringify(request)}`;
  const [snapshot, setSnapshot] = useState<{
    readonly key: string;
    readonly state: IncidentListLoadState;
  }>({
    key: stateKey,
    state: { kind: 'loading' },
  });

  useEffect(() => {
    const controller = new AbortController();

    void adapter.load(request, controller.signal).then(
      (result) => {
        if (controller.signal.aborted) return;
        if (result.kind === 'success') {
          setSnapshot({
            key: stateKey,
            state:
              result.page.items.length === 0
                ? { kind: 'empty' }
                : { kind: 'populated', page: result.page },
          });
          return;
        }
        setSnapshot({ key: stateKey, state: result });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        setSnapshot({
          key: stateKey,
          state: {
            kind: 'error',
            error: {
              code: 'internal_error',
              message:
                error instanceof Error
                  ? 'The incident adapter failed before returning a typed result.'
                  : 'The incident adapter returned an unknown failure.',
              trace_id: '019b0000-0000-7000-8000-000000000803',
              details: { resource: 'incident-list', retryable: true },
            },
          },
        });
      },
    );

    return () => controller.abort();
  }, [adapter, request, stateKey]);

  return snapshot.key === stateKey ? snapshot.state : { kind: 'loading' };
}

export interface IncidentListPageProps {
  readonly adapter?: IncidentListAdapter;
}

export function IncidentListPage({
  adapter = fixtureIncidentListAdapter,
}: IncidentListPageProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [revision, setRevision] = useState(0);
  const searchKey = searchParams.toString();
  const parsed = useMemo(
    () => parseIncidentListSearch(new URLSearchParams(searchKey)),
    [searchKey],
  );
  const request = useMemo<IncidentListRequest>(
    () => ({
      filters: parsed.filters,
      cursor: parsed.cursor,
      pageSize: INCIDENT_LIST_PAGE_SIZE,
    }),
    [parsed.cursor, parsed.filters],
  );
  const state = useIncidentListState(adapter, request, revision);

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Incident workspace"
        title="Incidents"
        description="Filter privacy-minimized incident summaries by canonical source, state, deterministic scenario, service, and UTC time. The current page consumes a frozen adapter, not a live API."
        status={<StatusBadge label="Frozen fixture adapter" tone="neutral" />}
      />

      <Alert severity="info">
        M7-001 is not integrated. URL filters and opaque cursors exercise the
        frontend port only; no HTTP request or server pagination is claimed.
      </Alert>

      <Paper
        component="section"
        variant="outlined"
        aria-label="Incident filter controls"
        sx={{ p: { xs: 2.25, md: 3 } }}
      >
        <IncidentFilterBar
          key={searchKey}
          filters={parsed.filters}
          services={MOCK_INCIDENT_SERVICES}
          onApply={(filters) =>
            setSearchParams(serializeIncidentListSearch(filters))
          }
          onReset={() =>
            setSearchParams(
              serializeIncidentListSearch(DEFAULT_INCIDENT_LIST_FILTERS),
            )
          }
        />
      </Paper>

      <IncidentListResults
        state={state}
        detailFixtureId={MOCK_INCIDENT_SUMMARY.incident_id}
        onCursor={(cursor) =>
          setSearchParams(serializeIncidentListSearch(parsed.filters, cursor))
        }
        onReset={() =>
          setSearchParams(
            serializeIncidentListSearch(DEFAULT_INCIDENT_LIST_FILTERS),
          )
        }
        onRetry={() => setRevision((current) => current + 1)}
      />
    </Stack>
  );
}
