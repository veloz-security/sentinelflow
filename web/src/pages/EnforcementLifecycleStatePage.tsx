import { Button, Stack } from '@mui/material';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { EnforcementLifecycleResults } from '../components/EnforcementLifecycleResults';
import {
  ENFORCEMENT_LIFECYCLE_STATE_NAMES,
  type EnforcementLifecycleStateName,
} from '../enforcement/enforcementLifecycleModel';
import { MOCK_ENFORCEMENT_LIFECYCLE_STATES } from '../mocks/enforcementLifecycleFixtures';
import { humanizeIdentifier } from '../utils/presentation';

function isStateName(
  value: string | undefined,
): value is EnforcementLifecycleStateName {
  return (
    value !== undefined &&
    ENFORCEMENT_LIFECYCLE_STATE_NAMES.includes(
      value as EnforcementLifecycleStateName,
    )
  );
}

export function EnforcementLifecycleStatePage() {
  const params = useParams();
  const stateName = isStateName(params.stateName) ? params.stateName : 'empty';

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <Stack
        component="nav"
        aria-label="Enforcement lifecycle state fixtures"
        direction="row"
        spacing={1}
        useFlexGap
        flexWrap="wrap"
      >
        {ENFORCEMENT_LIFECYCLE_STATE_NAMES.map((name) => (
          <Button
            key={name}
            component={RouterLink}
            to={`/states/enforcement/${name}`}
            size="small"
            variant={name === stateName ? 'contained' : 'outlined'}
            aria-current={name === stateName ? 'page' : undefined}
          >
            {humanizeIdentifier(name).replaceAll('-', ' ')}
          </Button>
        ))}
      </Stack>
      <EnforcementLifecycleResults
        state={MOCK_ENFORCEMENT_LIFECYCLE_STATES[stateName]}
      />
    </Stack>
  );
}
