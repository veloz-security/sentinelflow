import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Container,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useState, type FormEvent } from 'react';
import { DetailList } from '../components/DetailList';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { ApiClientError } from './apiClient';
import { LiveError, LiveLoading } from './LiveFeedback';
import { useSession } from './sessionContext';

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value));
}

export function LoginPage() {
  const session = useSession();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiClientError | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await session.login(username, password);
    } catch (caught) {
      if (caught instanceof ApiClientError) {
        setError(caught);
      }
    } finally {
      setPassword('');
      setPending(false);
    }
  };

  return (
    <Container
      component="main"
      maxWidth="sm"
      sx={{ minHeight: '100vh', display: 'grid', placeItems: 'center', py: 4 }}
    >
      <Card variant="outlined" sx={{ width: '100%' }}>
        <CardContent sx={{ p: { xs: 3, sm: 5 } }}>
          <Stack spacing={3}>
            <Box>
              <Typography variant="overline" color="primary.dark">
                SentinelFlow administrator
              </Typography>
              <Typography component="h1" variant="h1" sx={{ mt: 0.75 }}>
                Sign in to review evidence
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 1.25 }}>
                Credentials are sent only to the same-origin management API and
                are never retained by this interface.
              </Typography>
            </Box>
            {error ? (
              <LiveError error={error} onRetry={() => setError(null)} />
            ) : null}
            {session.reauthenticationNotice ? (
              <Alert severity="success" role="status">
                <Typography sx={{ fontWeight: 720 }}>
                  Exact decision was already recorded
                </Typography>
                <Typography variant="body2">
                  Decision{' '}
                  <code>
                    {session.reauthenticationNotice.decision.decision_id}
                  </code>{' '}
                  was returned by an exact idempotent replay. This is not a new
                  authorization. The previous session was expired; sign in again
                  before any further review or mutation.
                </Typography>
                {'revocation_id' in session.reauthenticationNotice ? (
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    Existing revocation:{' '}
                    <code>{session.reauthenticationNotice.revocation_id}</code>
                    {' · '}action{' '}
                    <code>
                      {session.reauthenticationNotice.decision.resource_id}
                    </code>
                  </Typography>
                ) : session.reauthenticationNotice.action_id ? (
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    Existing action:{' '}
                    <code>{session.reauthenticationNotice.action_id}</code>
                  </Typography>
                ) : null}
              </Alert>
            ) : null}
            <Box component="form" onSubmit={(event) => void submit(event)}>
              <Stack spacing={2}>
                <TextField
                  label="Username"
                  name="username"
                  autoComplete="username"
                  required
                  inputProps={{ maxLength: 128 }}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={pending}
                />
                <TextField
                  label="Password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  inputProps={{ maxLength: 1024 }}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={pending}
                />
                <Button
                  type="submit"
                  variant="contained"
                  disabled={
                    pending || username.length === 0 || password.length === 0
                  }
                  startIcon={
                    pending ? (
                      <CircularProgress size={16} color="inherit" />
                    ) : undefined
                  }
                >
                  {pending ? 'Signing in' : 'Sign in'}
                </Button>
              </Stack>
            </Box>
          </Stack>
        </CardContent>
      </Card>
    </Container>
  );
}

export function BootstrapPage() {
  const session = useSession();
  return (
    <Container component="main" maxWidth="md" sx={{ py: 8 }}>
      {session.phase === 'bootstrapping' ? (
        <LiveLoading label="Restoring the administrator session" />
      ) : session.error ? (
        <LiveError error={session.error} onRetry={session.retryBootstrap} />
      ) : null}
    </Container>
  );
}

export function SessionPage() {
  const session = useSession();
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState<'step-up' | 'logout' | null>(null);
  const [error, setError] = useState<ApiClientError | null>(null);
  const [success, setSuccess] = useState(false);

  if (!session.session) {
    return null;
  }

  const stepUp = async (event: FormEvent) => {
    event.preventDefault();
    setPending('step-up');
    setError(null);
    setSuccess(false);
    try {
      await session.stepUp(password);
      setSuccess(true);
    } catch (caught) {
      if (caught instanceof ApiClientError) {
        setError(caught);
      }
    } finally {
      setPassword('');
      setPending(null);
    }
  };

  const logout = async () => {
    setPending('logout');
    setError(null);
    try {
      await session.logout();
    } catch (caught) {
      if (caught instanceof ApiClientError) {
        setError(caught);
      }
      setPending(null);
    }
  };

  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Administrator session"
        title="Session security"
        description="Review the opaque session lifetime and perform password step-up. CSRF capability remains in memory and is never displayed."
        status={
          <StatusBadge
            label={
              session.csrfAvailable
                ? 'Mutation guard ready'
                : 'Read-only fallback'
            }
            tone={session.csrfAvailable ? 'positive' : 'warning'}
          />
        }
      />
      {!session.csrfAvailable ? (
        <Alert severity="warning">
          The restored response did not include a valid CSRF capability. Reads
          remain available, but logout and step-up fail closed. Sign in again to
          restore the mutation guard.
        </Alert>
      ) : null}
      {error ? (
        <LiveError error={error} onRetry={() => setError(null)} />
      ) : null}
      {success ? (
        <Alert severity="success" role="status">
          Password step-up succeeded and the session was rotated.
        </Alert>
      ) : null}
      <Card variant="outlined">
        <CardContent>
          <DetailList
            items={[
              { label: 'Actor', value: session.session.actor_id },
              {
                label: 'Session ID',
                value: <code>{session.session.session_id}</code>,
              },
              {
                label: 'Authenticated',
                value: formatTime(session.session.authenticated_at),
              },
              {
                label: 'Absolute expiry',
                value: formatTime(session.session.expires_at),
              },
            ]}
          />
        </CardContent>
      </Card>
      <Card variant="outlined">
        <CardContent>
          <Stack
            component="form"
            onSubmit={(event) => void stepUp(event)}
            spacing={2}
          >
            <Typography component="h2" variant="h2">
              Password step-up
            </Typography>
            <Typography color="text.secondary">
              Step-up rotates the opaque session. It does not approve an
              enforcement artifact.
            </Typography>
            <TextField
              label="Current password"
              type="password"
              autoComplete="current-password"
              required
              inputProps={{ maxLength: 1024 }}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={pending !== null || !session.csrfAvailable}
            />
            <Box>
              <Button
                type="submit"
                variant="contained"
                disabled={
                  pending !== null ||
                  !session.csrfAvailable ||
                  password.length === 0
                }
              >
                {pending === 'step-up'
                  ? 'Verifying'
                  : 'Verify password and rotate'}
              </Button>
            </Box>
          </Stack>
        </CardContent>
      </Card>
      <Box>
        <Button
          color="error"
          variant="outlined"
          disabled={pending !== null || !session.csrfAvailable}
          onClick={() => void logout()}
        >
          {pending === 'logout' ? 'Signing out' : 'Sign out'}
        </Button>
      </Box>
    </Stack>
  );
}
