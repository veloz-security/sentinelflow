import type {
  IncidentDetailAdapter,
  IncidentDetailViewState,
} from './incidentDetailModel';
import {
  MOCK_COMPLETE_INVESTIGATION,
  MOCK_INCIDENT_DETAIL_STATES,
} from '../mocks/incidentDetailFixtures';

export const fixtureIncidentDetailAdapter: IncidentDetailAdapter = {
  kind: 'fixture',
  async load(
    incidentId: string,
    signal?: AbortSignal,
  ): Promise<IncidentDetailViewState> {
    signal?.throwIfAborted();
    await Promise.resolve();
    signal?.throwIfAborted();

    if (
      incidentId !== MOCK_COMPLETE_INVESTIGATION.detail.incident.incident_id
    ) {
      return MOCK_INCIDENT_DETAIL_STATES['not-found'];
    }
    return MOCK_INCIDENT_DETAIL_STATES.complete;
  },
};
