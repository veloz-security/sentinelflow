import { Alert, Button, Skeleton, Stack, Typography } from '@mui/material';
import type { ApiClientError } from './apiClient';

export function LiveLoading({ label }: { readonly label: string }) {
  return (
    <Stack
      role="status"
      aria-label={label}
      aria-live="polite"
      aria-busy="true"
      spacing={1.25}
    >
      <Typography>{label}</Typography>
      <Skeleton variant="rounded" height={72} />
      <Skeleton variant="rounded" height={72} />
    </Stack>
  );
}

export function LiveError({
  error,
  onRetry,
}: {
  readonly error: ApiClientError;
  readonly onRetry: () => void;
}) {
  const permissionDenied = error.status === 403;
  return (
    <Alert
      severity={permissionDenied ? 'warning' : 'error'}
      role="alert"
      action={
        <Button color="inherit" size="small" onClick={onRetry}>
          Retry
        </Button>
      }
    >
      <Typography component="p" sx={{ fontWeight: 720 }}>
        {permissionDenied ? 'Permission required' : error.envelope.message}
      </Typography>
      <Typography component="p" variant="caption" sx={{ mt: 0.5 }}>
        Code: <code>{error.envelope.code}</code> · Trace:{' '}
        <code>{error.envelope.trace_id}</code>
      </Typography>
    </Alert>
  );
}

export function EmptyState({
  title,
  detail,
}: {
  readonly title: string;
  readonly detail: string;
}) {
  return (
    <Alert severity="info" role="status">
      <Typography component="p" sx={{ fontWeight: 720 }}>
        {title}
      </Typography>
      <Typography component="p" variant="body2">
        {detail}
      </Typography>
    </Alert>
  );
}
