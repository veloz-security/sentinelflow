import { Button, Stack } from '@mui/material';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { IncidentDetailResults } from '../components/IncidentDetailResults';
import {
  INCIDENT_DETAIL_STATE_NAMES,
  MOCK_INCIDENT_DETAIL_STATES,
  type IncidentDetailStateName,
} from '../mocks/incidentDetailFixtures';
import { humanizeIdentifier } from '../utils/presentation';

function isStateName(
  value: string | undefined,
): value is IncidentDetailStateName {
  return (
    value !== undefined &&
    INCIDENT_DETAIL_STATE_NAMES.includes(value as IncidentDetailStateName)
  );
}

export function IncidentDetailStatePage() {
  const params = useParams();
  const stateName = isStateName(params.stateName)
    ? params.stateName
    : 'unknown';

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <Stack
        component="nav"
        aria-label="Incident detail state fixtures"
        direction="row"
        spacing={1}
        useFlexGap
        flexWrap="wrap"
      >
        {INCIDENT_DETAIL_STATE_NAMES.map((name) => (
          <Button
            key={name}
            component={RouterLink}
            to={`/states/incident-detail/${name}`}
            size="small"
            variant={name === stateName ? 'contained' : 'outlined'}
            aria-current={name === stateName ? 'page' : undefined}
          >
            {humanizeIdentifier(name)}
          </Button>
        ))}
      </Stack>

      <IncidentDetailResults state={MOCK_INCIDENT_DETAIL_STATES[stateName]} />
    </Stack>
  );
}
