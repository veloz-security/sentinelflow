import { Button, Stack } from '@mui/material';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { ValidationReviewResults } from '../components/ValidationReviewResults';
import {
  MOCK_VALIDATION_REVIEW_STATES,
  VALIDATION_REVIEW_STATE_NAMES,
  type ValidationReviewStateName,
} from '../mocks/validationReviewFixtures';
import { humanizeIdentifier } from '../utils/presentation';

function isStateName(
  value: string | undefined,
): value is ValidationReviewStateName {
  return (
    value !== undefined &&
    VALIDATION_REVIEW_STATE_NAMES.includes(value as ValidationReviewStateName)
  );
}

export function ValidationReviewStatePage() {
  const params = useParams();
  const stateName = isStateName(params.stateName)
    ? params.stateName
    : 'missing';

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <Stack
        component="nav"
        aria-label="Validation review state fixtures"
        direction="row"
        spacing={1}
        useFlexGap
        flexWrap="wrap"
      >
        {VALIDATION_REVIEW_STATE_NAMES.map((name) => (
          <Button
            key={name}
            component={RouterLink}
            to={`/states/validation/${name}`}
            size="small"
            variant={name === stateName ? 'contained' : 'outlined'}
            aria-current={name === stateName ? 'page' : undefined}
          >
            {humanizeIdentifier(name).replaceAll('-', ' ')}
          </Button>
        ))}
      </Stack>
      <ValidationReviewResults
        state={MOCK_VALIDATION_REVIEW_STATES[stateName]}
      />
    </Stack>
  );
}
