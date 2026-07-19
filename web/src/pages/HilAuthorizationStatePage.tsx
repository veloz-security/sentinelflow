import { Button, Stack } from '@mui/material';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { HilAuthorizationResults } from '../components/HilAuthorizationResults';
import {
  HIL_AUTHORIZATION_STATE_NAMES,
  type HilAuthorizationStateName,
} from '../hil/hilAuthorizationModel';
import { MOCK_HIL_AUTHORIZATION_STATES } from '../mocks/hilAuthorizationFixtures';
import { humanizeIdentifier } from '../utils/presentation';

function isStateName(
  value: string | undefined,
): value is HilAuthorizationStateName {
  return (
    value !== undefined &&
    HIL_AUTHORIZATION_STATE_NAMES.includes(value as HilAuthorizationStateName)
  );
}

export function HilAuthorizationStatePage() {
  const params = useParams();
  const stateName = isStateName(params.stateName) ? params.stateName : 'ready';

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <Stack
        component="nav"
        aria-label="HIL authorization state fixtures"
        direction="row"
        spacing={1}
        useFlexGap
        flexWrap="wrap"
      >
        {HIL_AUTHORIZATION_STATE_NAMES.map((name) => (
          <Button
            key={name}
            component={RouterLink}
            to={`/states/hil/${name}`}
            size="small"
            variant={name === stateName ? 'contained' : 'outlined'}
            aria-current={name === stateName ? 'page' : undefined}
          >
            {humanizeIdentifier(name).replaceAll('-', ' ')}
          </Button>
        ))}
      </Stack>
      <HilAuthorizationResults
        state={MOCK_HIL_AUTHORIZATION_STATES[stateName]}
      />
    </Stack>
  );
}
