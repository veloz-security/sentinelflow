import {
  Alert,
  Box,
  Button,
  Grid,
  Paper,
  Skeleton,
  Stack,
  Typography,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import type { IncidentDetailViewState } from '../incidents/incidentDetailModel';
import { semanticTokens } from '../theme';
import {
  formatUtc,
  humanizeIdentifier,
  shortIdentifier,
} from '../utils/presentation';
import { DetailList } from './DetailList';
import { IncidentEvidenceLayers } from './IncidentEvidenceLayers';
import { PageHeader } from './PageHeader';
import { StatusBadge, type SemanticTone } from './StatusBadge';

export interface IncidentDetailResultsProps {
  readonly state: IncidentDetailViewState;
  readonly onRetry?: () => void;
}

function BackToIncidents() {
  return (
    <Box>
      <Button component={RouterLink} to="/fixtures/incidents" variant="text">
        Back to incidents
      </Button>
    </Box>
  );
}

function LoadingState({
  requestedId,
}: {
  readonly requestedId: string | null;
}) {
  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <BackToIncidents />
      <PageHeader
        eyebrow="Incident investigation"
        title="Loading incident detail"
        description="The frozen adapter is resolving a typed investigation view."
        status={<StatusBadge label="Loading" tone="neutral" />}
      />
      <Paper
        component="section"
        variant="outlined"
        role="status"
        aria-label="Loading incident detail"
        aria-live="polite"
        aria-busy="true"
        sx={{ p: { xs: 2.5, md: 3 } }}
      >
        <Stack spacing={1.5}>
          <Typography color="text.secondary">
            {requestedId
              ? `Resolving ${shortIdentifier(requestedId)}`
              : 'Resolving the requested incident'}
          </Typography>
          <Skeleton aria-hidden="true" variant="text" width="54%" />
          <Skeleton aria-hidden="true" variant="rounded" height={116} />
          <Skeleton aria-hidden="true" variant="rounded" height={220} />
        </Stack>
      </Paper>
    </Stack>
  );
}

interface EmptyStateProps {
  readonly title: string;
  readonly description: string;
  readonly status: string;
  readonly tone: SemanticTone;
  readonly message: string;
  readonly role?: 'status' | 'alert';
  readonly action?: React.ReactNode;
}

function EmptyState({
  title,
  description,
  status,
  tone,
  message,
  role = 'status',
  action,
}: EmptyStateProps) {
  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <BackToIncidents />
      <PageHeader
        eyebrow="Incident investigation"
        title={title}
        description={description}
        status={<StatusBadge label={status} tone={tone} />}
      />
      <Paper
        component="section"
        variant="outlined"
        role={role}
        aria-live={role === 'alert' ? 'assertive' : 'polite'}
        sx={{ p: { xs: 2.5, md: 3 } }}
      >
        <Stack spacing={2}>
          <Typography>{message}</Typography>
          {action ? <Box>{action}</Box> : null}
        </Stack>
      </Paper>
    </Stack>
  );
}

function SourceCoverage({
  state,
}: {
  readonly state: Extract<
    IncidentDetailViewState,
    { kind: 'degraded' | 'analysis-failed' | 'complete' }
  >;
}) {
  const health = state.view.detail.source_health_events[0];
  const isDegraded = state.kind === 'degraded';

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="source-coverage-title"
      sx={{ p: { xs: 2.25, md: 2.5 } }}
    >
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={1.25}
          alignItems="center"
          justifyContent="space-between"
        >
          <Typography id="source-coverage-title" component="h2" variant="h3">
            Source coverage
          </Typography>
          <StatusBadge
            label={health ? humanizeIdentifier(health.state) : 'Unknown'}
            tone={isDegraded ? 'warning' : health ? 'positive' : 'neutral'}
          />
        </Stack>

        {health ? (
          <DetailList
            items={[
              { label: 'Producer', value: health.source_id },
              { label: 'Cause', value: humanizeIdentifier(health.cause) },
              {
                label: 'Affected interval',
                value: health.interval_start
                  ? `${formatUtc(health.interval_start)} — ${
                      health.interval_end
                        ? formatUtc(health.interval_end)
                        : 'still open'
                    }`
                  : 'Not reported',
              },
              {
                label: 'Sequence range',
                value:
                  health.sequence_start !== null && health.sequence_end !== null
                    ? `${health.sequence_start}–${health.sequence_end}`
                    : 'Not reported',
              },
              { label: 'Dropped records', value: health.dropped_count },
              {
                label: 'Detail',
                value: humanizeIdentifier(health.detail_code),
              },
            ]}
          />
        ) : (
          <Typography role="status">Coverage status is unavailable.</Typography>
        )}
      </Stack>
    </Paper>
  );
}

function PrivacyBoundary() {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="privacy-boundary-title"
      sx={{ p: { xs: 2.25, md: 2.5 } }}
    >
      <Stack spacing={1.25}>
        <Typography id="privacy-boundary-title" component="h2" variant="h3">
          Privacy boundary
        </Typography>
        <Typography color="text.secondary">
          Only allowlisted metadata is presented. Sensitive request content and
          unrestricted transport metadata remain outside this view.
        </Typography>
        <Typography variant="body2" sx={{ fontWeight: 700 }}>
          Direct-peer identity · classified route · safe relation IDs
        </Typography>
      </Stack>
    </Paper>
  );
}

function InvestigationState({
  state,
}: {
  readonly state: Extract<
    IncidentDetailViewState,
    { kind: 'degraded' | 'analysis-failed' | 'complete' }
  >;
}) {
  const incident = state.view.detail.incident;
  const statePresentation = {
    complete: { label: 'Review ready', tone: 'warning' },
    degraded: { label: 'Coverage degraded', tone: 'warning' },
    'analysis-failed': { label: 'Analysis failed', tone: 'critical' },
  } as const;

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <BackToIncidents />
      <PageHeader
        eyebrow="Incident investigation"
        title="Failed login activity"
        description="Observed facts, reproducible rule results, and model interpretation remain visibly separate. This route uses a frozen presentation adapter, not a live incident endpoint."
        status={
          <StatusBadge
            label={statePresentation[state.kind].label}
            tone={statePresentation[state.kind].tone}
          />
        }
      />

      {state.kind === 'degraded' ? (
        <Alert severity="warning" role="alert">
          Coverage is incomplete: sequence gap 42–45 reports 4 dropped records.
          This incident cannot support an enforcement decision while the
          interval remains open.
        </Alert>
      ) : null}

      {state.kind === 'analysis-failed' ? (
        <Alert severity="error" role="alert">
          Model analysis failed with reason{' '}
          <strong>
            {humanizeIdentifier(
              incident.analysis_failure_reason ?? 'unspecified',
            )}
          </strong>
          . Observed and deterministic evidence remains reviewable.
        </Alert>
      ) : null}

      <Paper
        component="section"
        variant="outlined"
        aria-labelledby="incident-identity-title"
        sx={{ p: { xs: 2.25, md: 3 } }}
      >
        <Stack spacing={2.25}>
          <Stack
            direction={{ xs: 'column', sm: 'row' }}
            spacing={1.5}
            alignItems={{ xs: 'flex-start', sm: 'center' }}
            justifyContent="space-between"
          >
            <Box>
              <Typography
                id="incident-identity-title"
                component="h2"
                variant="h2"
              >
                Incident identity
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mt: 0.4 }}
              >
                The canonical source is the Gateway direct TCP peer.
              </Typography>
            </Box>
            <Typography
              variant="caption"
              sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}
            >
              {incident.incident_id}
            </Typography>
          </Stack>
          <DetailList
            items={[
              { label: 'Canonical source', value: incident.source_ip },
              { label: 'Service', value: incident.service_label },
              {
                label: 'Incident state',
                value: humanizeIdentifier(incident.state),
              },
              { label: 'Version', value: incident.incident_version },
              { label: 'Signals', value: incident.signal_count },
              {
                label: 'First observed',
                value: formatUtc(incident.first_seen_at),
              },
              {
                label: 'Last observed',
                value: formatUtc(incident.last_seen_at),
              },
              { label: 'Updated', value: formatUtc(incident.updated_at) },
            ]}
          />
        </Stack>
      </Paper>

      <Grid container spacing={3} alignItems="flex-start">
        <Grid size={{ xs: 12, lg: 8.5 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="evidence-composition-title"
            sx={{ overflow: 'hidden' }}
          >
            <Box sx={{ px: { xs: 2.25, md: 3 }, py: 2.5 }}>
              <Typography
                id="evidence-composition-title"
                component="h2"
                variant="h2"
              >
                Evidence composition
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 0.6 }}>
                Later interpretation cannot rewrite earlier evidence.
              </Typography>
            </Box>
            <Box sx={{ borderTop: 1, borderColor: 'divider' }}>
              <IncidentEvidenceLayers view={state.view} />
            </Box>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, lg: 3.5 }}>
          <Stack spacing={3}>
            <SourceCoverage state={state} />
            <PrivacyBoundary />
            <Paper
              component="aside"
              variant="outlined"
              aria-labelledby="authority-boundary-title"
              sx={{
                p: { xs: 2.25, md: 2.5 },
                borderColor: semanticTokens.warning.border,
                bgcolor: semanticTokens.warning.background,
              }}
            >
              <Typography
                id="authority-boundary-title"
                component="h2"
                variant="h3"
              >
                Authority boundary
              </Typography>
              <Typography sx={{ mt: 1 }} color="text.secondary">
                This evidence screen does not approve, dispatch, or execute an
                adaptive action.
              </Typography>
            </Paper>
          </Stack>
        </Grid>
      </Grid>
    </Stack>
  );
}

export function IncidentDetailResults({
  state,
  onRetry,
}: IncidentDetailResultsProps) {
  switch (state.kind) {
    case 'loading':
      return <LoadingState requestedId={state.requestedId} />;
    case 'unknown':
      return (
        <EmptyState
          title="Incident state unknown"
          description="A safe incident identifier is required before the detail adapter can resolve a view."
          status="Unknown"
          tone="neutral"
          message="No investigation was requested. Return to the incident list and choose a typed fixture record."
        />
      );
    case 'not-found':
      return (
        <EmptyState
          title="Incident not found"
          description="The frozen adapter could not match the requested identifier."
          status="Not found"
          tone="neutral"
          message={state.error.message}
        />
      );
    case 'error':
      return (
        <EmptyState
          title="Incident detail unavailable"
          description="The detail adapter returned a typed failure without exposing partial investigation data."
          status="Error"
          tone="critical"
          role="alert"
          message={state.error.message}
          action={
            <Button variant="contained" onClick={onRetry} disabled={!onRetry}>
              Retry incident detail
            </Button>
          }
        />
      );
    case 'permission-denied':
      return (
        <EmptyState
          title="Incident access required"
          description="The adapter denied this investigation request."
          status="Permission denied"
          tone="warning"
          role="alert"
          message={state.error.message}
        />
      );
    case 'degraded':
    case 'analysis-failed':
    case 'complete':
      return <InvestigationState state={state} />;
  }
}
