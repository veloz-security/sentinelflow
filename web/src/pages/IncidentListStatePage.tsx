import { Button, Stack } from '@mui/material';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { IncidentListResults } from '../components/IncidentListResults';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { MOCK_INCIDENT_SUMMARY } from '../mocks/contractFixtures';
import {
  INCIDENT_LIST_STATE_NAMES,
  MOCK_INCIDENT_LIST_STATES,
  type IncidentListStateName,
} from '../mocks/incidentListStates';
import { humanizeIdentifier } from '../utils/presentation';

function isStateName(
  value: string | undefined,
): value is IncidentListStateName {
  return (
    value !== undefined &&
    INCIDENT_LIST_STATE_NAMES.includes(value as IncidentListStateName)
  );
}

export function IncidentListStatePage() {
  const params = useParams();
  const stateName = isStateName(params.stateName)
    ? params.stateName
    : 'populated';

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Incident state laboratory"
        title={`Incident list: ${humanizeIdentifier(stateName)}`}
        description="A deterministic fixture isolates this rendering state. It does not simulate authentication, network traffic, or a completed incident API."
        status={<StatusBadge label="State fixture" tone="neutral" />}
      />

      <Stack
        component="nav"
        aria-label="Incident list state fixtures"
        direction="row"
        spacing={1}
        useFlexGap
        flexWrap="wrap"
      >
        {INCIDENT_LIST_STATE_NAMES.map((name) => (
          <Button
            key={name}
            component={RouterLink}
            to={`/states/incidents/${name}`}
            size="small"
            variant={name === stateName ? 'contained' : 'outlined'}
            aria-current={name === stateName ? 'page' : undefined}
          >
            {humanizeIdentifier(name)}
          </Button>
        ))}
      </Stack>

      <IncidentListResults
        state={MOCK_INCIDENT_LIST_STATES[stateName]}
        detailFixtureId={MOCK_INCIDENT_SUMMARY.incident_id}
      />
    </Stack>
  );
}
