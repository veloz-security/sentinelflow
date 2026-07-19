import { Stack, Typography } from '@mui/material';
import { PresentationState } from '../components/PresentationState';
import type { PresentationModel } from '../contracts/resourceState';

const notFoundState: PresentationModel = Object.freeze({
  kind: 'empty' as const,
  title: 'Page not found',
  message: 'This route is not part of the frontend foundation.',
  detail: 'Use the primary navigation to return to a defined mock surface.',
  action: null,
});

export function NotFoundPage() {
  return (
    <Stack spacing={3}>
      <Typography component="h1" variant="h1">
        Unknown route
      </Typography>
      <PresentationState state={notFoundState} />
    </Stack>
  );
}
