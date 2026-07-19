import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Skeleton,
  Stack,
  Typography,
} from '@mui/material';
import type { AlertColor } from '@mui/material';
import type {
  PresentationModel,
  ResourceStateKind,
} from '../contracts/resourceState';
import { StatusBadge, type SemanticTone } from './StatusBadge';

const severityByKind: Readonly<Partial<Record<ResourceStateKind, AlertColor>>> =
  {
    error: 'error',
    'permission-denied': 'warning',
    disabled: 'info',
    success: 'success',
  };

const labelByKind: Readonly<Record<ResourceStateKind, string>> = {
  loading: 'Loading',
  empty: 'Empty',
  error: 'Error',
  'permission-denied': 'Permission denied',
  disabled: 'Disabled',
  success: 'Success',
};

const toneByKind: Readonly<Record<ResourceStateKind, SemanticTone>> = {
  loading: 'neutral',
  empty: 'neutral',
  error: 'critical',
  'permission-denied': 'warning',
  disabled: 'warning',
  success: 'positive',
};

export interface PresentationStateProps {
  readonly state: PresentationModel;
  readonly onAction?: () => void;
}

export function PresentationState({ state, onAction }: PresentationStateProps) {
  const titleId = `presentation-${state.kind}-title`;
  const severity = severityByKind[state.kind];
  const statusRole =
    state.kind === 'error' || state.kind === 'permission-denied'
      ? 'alert'
      : 'status';

  return (
    <Card
      component="section"
      variant="outlined"
      aria-labelledby={titleId}
      sx={{ height: '100%' }}
    >
      <CardContent>
        <Stack spacing={2.25}>
          <Stack
            direction="row"
            spacing={1.5}
            alignItems="center"
            justifyContent="space-between"
          >
            <Typography id={titleId} component="h2" variant="h2">
              {state.title}
            </Typography>
            <StatusBadge
              label={labelByKind[state.kind]}
              tone={toneByKind[state.kind]}
            />
          </Stack>

          {state.kind === 'loading' ? (
            <Stack
              role="status"
              aria-label="Loading typed investigation"
              aria-busy="true"
              aria-live="polite"
              spacing={1.25}
            >
              <Typography>{state.message}</Typography>
              <Skeleton aria-hidden="true" variant="text" width="92%" />
              <Skeleton aria-hidden="true" variant="text" width="68%" />
            </Stack>
          ) : severity ? (
            <Alert severity={severity} role={statusRole}>
              {state.message}
            </Alert>
          ) : (
            <Box role="status" aria-live="polite">
              <Typography>{state.message}</Typography>
            </Box>
          )}

          {state.detail ? (
            <Typography color="text.secondary">{state.detail}</Typography>
          ) : null}

          {state.action ? (
            <Box>
              <Button
                variant="contained"
                disabled={state.action.disabled || !onAction}
                onClick={onAction}
              >
                {state.action.label}
              </Button>
            </Box>
          ) : null}
        </Stack>
      </CardContent>
    </Card>
  );
}
