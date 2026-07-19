import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { IncidentDetailResults } from '../components/IncidentDetailResults';
import { fixtureIncidentDetailAdapter } from '../incidents/fixtureIncidentDetailAdapter';
import type {
  IncidentDetailAdapter,
  IncidentDetailViewState,
} from '../incidents/incidentDetailModel';

function useIncidentDetailState(
  adapter: IncidentDetailAdapter,
  incidentId: string | undefined,
  revision: number,
): IncidentDetailViewState {
  const stateKey = `${revision}:${incidentId ?? 'unknown'}`;
  const [snapshot, setSnapshot] = useState<{
    readonly key: string;
    readonly state: IncidentDetailViewState;
  }>({
    key: stateKey,
    state: incidentId
      ? { kind: 'loading', requestedId: incidentId }
      : { kind: 'unknown', requestedId: null },
  });

  useEffect(() => {
    if (!incidentId) return;

    const controller = new AbortController();
    void adapter.load(incidentId, controller.signal).then(
      (state) => {
        if (controller.signal.aborted) return;
        setSnapshot({ key: stateKey, state });
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
              trace_id: '019b0000-0000-7000-8000-000000000905',
              details: { resource: 'incident-detail', retryable: true },
            },
          },
        });
      },
    );

    return () => controller.abort();
  }, [adapter, incidentId, stateKey]);

  if (snapshot.key === stateKey) return snapshot.state;
  return incidentId
    ? { kind: 'loading', requestedId: incidentId }
    : { kind: 'unknown', requestedId: null };
}

export interface IncidentsPageProps {
  readonly adapter?: IncidentDetailAdapter;
}

export function IncidentsPage({
  adapter = fixtureIncidentDetailAdapter,
}: IncidentsPageProps) {
  const params = useParams();
  const [revision, setRevision] = useState(0);
  const state = useIncidentDetailState(adapter, params.incidentId, revision);

  return (
    <IncidentDetailResults
      state={state}
      onRetry={() => setRevision((current) => current + 1)}
    />
  );
}
