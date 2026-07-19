import {
  Alert,
  Box,
  Button,
  Divider,
  Paper,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import type { IncidentState } from '../contracts/apiDtos';
import type { SourceHealthState } from '../contracts/rootContracts';
import type {
  IncidentListLoadState,
  IncidentListPage,
  IncidentListViewItem,
} from '../incidents/incidentListModel';
import { semanticTokens } from '../theme';
import { formatUtc, humanizeIdentifier } from '../utils/presentation';
import { StatusBadge, type SemanticTone } from './StatusBadge';

const stateTone: Readonly<Record<IncidentState, SemanticTone>> = {
  open: 'info',
  analyzing: 'neutral',
  review_ready: 'warning',
  closed: 'neutral',
  analysis_failed: 'critical',
};

const healthTone: Readonly<Record<SourceHealthState, SemanticTone>> = {
  recovered: 'positive',
  degraded: 'warning',
  lost: 'critical',
};

export interface IncidentListResultsProps {
  readonly state: IncidentListLoadState;
  readonly detailFixtureId: string;
  readonly onCursor?: (cursor: string | null) => void;
  readonly onReset?: () => void;
  readonly onRetry?: () => void;
}

function IncidentStateBadge({ state }: { readonly state: IncidentState }) {
  return (
    <StatusBadge label={humanizeIdentifier(state)} tone={stateTone[state]} />
  );
}

function HealthBadge({ state }: { readonly state: SourceHealthState }) {
  return (
    <StatusBadge label={humanizeIdentifier(state)} tone={healthTone[state]} />
  );
}

function DetailAction({
  item,
  detailFixtureId,
}: {
  readonly item: IncidentListViewItem;
  readonly detailFixtureId: string;
}) {
  if (item.incident.incident_id !== detailFixtureId) {
    return (
      <Typography variant="caption" color="text.secondary">
        List fixture only
      </Typography>
    );
  }

  return (
    <Button
      component={RouterLink}
      to={`/incidents/${item.incident.incident_id}`}
      size="small"
      variant="text"
      aria-label={`Open fixture detail for ${item.incident.source_ip}`}
    >
      Open detail
    </Button>
  );
}

function IncidentSummaryStrip({ page }: { readonly page: IncidentListPage }) {
  const visible = page.items;
  const reviewReady = visible.filter(
    (item) => item.incident.state === 'review_ready',
  ).length;
  const degraded = visible.filter(
    (item) => item.sourceHealth.state !== 'recovered',
  );
  const dropped = degraded.reduce(
    (total, item) => total + item.sourceHealth.dropped_count,
    0,
  );
  const scenarios = [
    ...new Set(visible.map((item) => item.primarySignal.classification)),
  ];

  return (
    <Box
      component="section"
      aria-labelledby="incident-result-summary-title"
      sx={{ py: 2.25, borderTop: 1, borderBottom: 1, borderColor: 'divider' }}
    >
      <Stack
        direction={{ xs: 'column', lg: 'row' }}
        spacing={2}
        alignItems={{ xs: 'flex-start', lg: 'center' }}
        justifyContent="space-between"
      >
        <Box>
          <Typography
            id="incident-result-summary-title"
            component="h2"
            variant="h3"
          >
            Result summary
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
            Counts describe the visible cursor page unless marked as total.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
          <StatusBadge
            label={`${page.pageInfo.totalItems} total matches`}
            tone="neutral"
          />
          <StatusBadge label={`${reviewReady} review ready`} tone="warning" />
          <StatusBadge
            label={`${scenarios.length} visible scenarios`}
            tone="info"
          />
          <StatusBadge
            label={
              degraded.length === 0
                ? 'Visible coverage complete'
                : `${degraded.length} degraded sources`
            }
            tone={degraded.length === 0 ? 'positive' : 'critical'}
          />
          <StatusBadge
            label={`${dropped} dropped records`}
            tone={dropped > 0 ? 'critical' : 'neutral'}
          />
        </Stack>
      </Stack>
    </Box>
  );
}

function DegradationNotice({ page }: { readonly page: IncidentListPage }) {
  const affected = page.items.filter(
    (item) => item.sourceHealth.state !== 'recovered',
  );
  if (affected.length === 0) return null;

  const lost = affected.filter(
    (item) => item.sourceHealth.state === 'lost',
  ).length;
  return (
    <Alert severity={lost > 0 ? 'error' : 'warning'}>
      <strong>
        Coverage is incomplete for {affected.length} visible source
        {affected.length === 1 ? '' : 's'}.
      </strong>{' '}
      Degraded or lost telemetry remains distinct from incident state and cannot
      be interpreted as complete enforcement evidence.
    </Alert>
  );
}

function DesktopIncidentTable({
  page,
  detailFixtureId,
}: {
  readonly page: IncidentListPage;
  readonly detailFixtureId: string;
}) {
  return (
    <TableContainer sx={{ display: { xs: 'none', md: 'block' } }}>
      <Table size="small" aria-label="Filtered incidents">
        <caption>
          Privacy-minimized fixture incidents ordered by most recent
          observation.
        </caption>
        <TableHead>
          <TableRow>
            <TableCell>Canonical source</TableCell>
            <TableCell>Scenario</TableCell>
            <TableCell>Service</TableCell>
            <TableCell>Incident state</TableCell>
            <TableCell>Source health</TableCell>
            <TableCell>Last observed</TableCell>
            <TableCell align="right">Detail</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {page.items.map((item) => (
            <TableRow key={item.incident.incident_id} hover>
              <TableCell>
                <Typography sx={{ fontFamily: 'monospace', fontWeight: 700 }}>
                  {item.incident.source_ip}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  direct TCP peer
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" sx={{ fontWeight: 700 }}>
                  {humanizeIdentifier(item.primarySignal.classification)}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {item.incident.signal_count} signal
                  {item.incident.signal_count === 1 ? '' : 's'}
                </Typography>
              </TableCell>
              <TableCell>{item.incident.service_label}</TableCell>
              <TableCell>
                <IncidentStateBadge state={item.incident.state} />
                {item.incident.analysis_failure_reason ? (
                  <Typography
                    variant="caption"
                    color="error.main"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {humanizeIdentifier(item.incident.analysis_failure_reason)}
                  </Typography>
                ) : null}
              </TableCell>
              <TableCell>
                <HealthBadge state={item.sourceHealth.state} />
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mt: 0.5 }}
                >
                  {humanizeIdentifier(item.sourceHealth.cause)}
                  {item.sourceHealth.dropped_count > 0
                    ? `, ${item.sourceHealth.dropped_count} dropped`
                    : ''}
                </Typography>
              </TableCell>
              <TableCell>{formatUtc(item.incident.last_seen_at)}</TableCell>
              <TableCell align="right">
                <DetailAction item={item} detailFixtureId={detailFixtureId} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function NarrowIncidentList({
  page,
  detailFixtureId,
}: {
  readonly page: IncidentListPage;
  readonly detailFixtureId: string;
}) {
  return (
    <Box
      component="ul"
      aria-label="Filtered incidents"
      sx={{
        display: { xs: 'block', md: 'none' },
        p: 0,
        m: 0,
        listStyle: 'none',
      }}
    >
      {page.items.map((item, index) => (
        <Box component="li" key={item.incident.incident_id}>
          {index > 0 ? <Divider /> : null}
          <Stack spacing={2} sx={{ p: 2.25 }}>
            <Stack
              direction="row"
              spacing={1.5}
              alignItems="flex-start"
              justifyContent="space-between"
            >
              <Box sx={{ minWidth: 0 }}>
                <Typography sx={{ fontFamily: 'monospace', fontWeight: 740 }}>
                  {item.incident.source_ip}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Canonical direct TCP peer
                </Typography>
              </Box>
              <IncidentStateBadge state={item.incident.state} />
            </Stack>
            <Box
              component="dl"
              sx={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 1.5,
                m: 0,
              }}
            >
              {[
                [
                  'Scenario',
                  humanizeIdentifier(item.primarySignal.classification),
                ],
                ['Service', item.incident.service_label],
                ['Last observed', formatUtc(item.incident.last_seen_at)],
              ].map(([label, value]) => (
                <Box key={label}>
                  <Typography
                    component="dt"
                    variant="caption"
                    color="text.secondary"
                  >
                    {label}
                  </Typography>
                  <Typography
                    component="dd"
                    variant="body2"
                    sx={{ m: 0, mt: 0.25, fontWeight: 650 }}
                  >
                    {value}
                  </Typography>
                </Box>
              ))}
              <Box>
                <Typography
                  component="dt"
                  variant="caption"
                  color="text.secondary"
                >
                  Source health
                </Typography>
                <Box component="dd" sx={{ m: 0, mt: 0.5 }}>
                  <HealthBadge state={item.sourceHealth.state} />
                </Box>
              </Box>
            </Box>
            <Box>
              <DetailAction item={item} detailFixtureId={detailFixtureId} />
            </Box>
          </Stack>
        </Box>
      ))}
    </Box>
  );
}

function PopulatedIncidentList({
  page,
  detailFixtureId,
  onCursor,
}: {
  readonly page: IncidentListPage;
  readonly detailFixtureId: string;
  readonly onCursor?: (cursor: string | null) => void;
}) {
  return (
    <Stack spacing={2.5} data-testid="populated-incident-list">
      <IncidentSummaryStrip page={page} />
      <DegradationNotice page={page} />
      <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
        <DesktopIncidentTable page={page} detailFixtureId={detailFixtureId} />
        <NarrowIncidentList page={page} detailFixtureId={detailFixtureId} />
        <Divider />
        <Stack
          component="nav"
          aria-label="Incident list pages"
          direction="row"
          spacing={1.5}
          alignItems="center"
          justifyContent="space-between"
          sx={{ p: 1.5 }}
        >
          <Button
            size="small"
            variant="outlined"
            disabled={!page.pageInfo.hasPreviousPage || !onCursor}
            onClick={() => onCursor?.(page.pageInfo.previousCursor)}
          >
            Previous
          </Button>
          <Typography
            variant="caption"
            role="status"
            aria-live="polite"
            sx={{ textAlign: 'center' }}
          >
            {page.pageInfo.firstVisibleIndex}–{page.pageInfo.lastVisibleIndex}{' '}
            of {page.pageInfo.totalItems}
          </Typography>
          <Button
            size="small"
            variant="outlined"
            disabled={!page.pageInfo.hasNextPage || !onCursor}
            onClick={() => onCursor?.(page.pageInfo.nextCursor)}
          >
            Next
          </Button>
        </Stack>
      </Paper>
    </Stack>
  );
}

function LoadingIncidentList() {
  return (
    <Paper
      component="section"
      variant="outlined"
      role="status"
      aria-label="Loading incident list"
      aria-busy="true"
      aria-live="polite"
      sx={{ overflow: 'hidden' }}
    >
      <Box sx={{ p: 2.5 }}>
        <Typography component="h2" variant="h3">
          Loading incidents
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Waiting for one complete adapter result. Partial rows are not
          interpreted.
        </Typography>
      </Box>
      <Divider />
      {[82, 68, 76, 59].map((width, index) => (
        <Box
          key={width}
          sx={{
            px: 2.5,
            py: 1.75,
            borderTop: index === 0 ? 0 : 1,
            borderColor: 'divider',
          }}
        >
          <Skeleton aria-hidden="true" variant="text" width={`${width}%`} />
          <Skeleton
            aria-hidden="true"
            variant="text"
            width={`${Math.max(width - 24, 30)}%`}
          />
        </Box>
      ))}
    </Paper>
  );
}

export function IncidentListResults({
  state,
  detailFixtureId,
  onCursor,
  onReset,
  onRetry,
}: IncidentListResultsProps) {
  if (state.kind === 'loading') return <LoadingIncidentList />;

  if (state.kind === 'populated') {
    return (
      <PopulatedIncidentList
        page={state.page}
        detailFixtureId={detailFixtureId}
        onCursor={onCursor}
      />
    );
  }

  if (state.kind === 'empty') {
    return (
      <Paper
        component="section"
        variant="outlined"
        role="status"
        sx={{ p: { xs: 2.5, md: 4 } }}
      >
        <Stack spacing={1.5} alignItems="flex-start">
          <StatusBadge label="Empty result" tone="neutral" />
          <Typography component="h2" variant="h2">
            No incidents match these filters
          </Typography>
          <Typography color="text.secondary">
            The adapter returned a valid empty page. This is distinct from an
            outage or permission denial.
          </Typography>
          {onReset ? (
            <Button variant="outlined" onClick={onReset}>
              Clear filters
            </Button>
          ) : null}
        </Stack>
      </Paper>
    );
  }

  const permissionDenied = state.kind === 'permission-denied';
  const token = permissionDenied
    ? semanticTokens.warning
    : semanticTokens.critical;
  return (
    <Paper
      component="section"
      variant="outlined"
      role="alert"
      sx={{
        p: { xs: 2.5, md: 4 },
        bgcolor: token.background,
        borderColor: token.border,
      }}
    >
      <Stack spacing={1.5} alignItems="flex-start">
        <StatusBadge
          label={permissionDenied ? 'Permission denied' : 'Adapter error'}
          tone={permissionDenied ? 'warning' : 'critical'}
        />
        <Typography component="h2" variant="h2">
          {permissionDenied
            ? 'Incident access required'
            : 'Incident list unavailable'}
        </Typography>
        <Typography>{state.error.message}</Typography>
        <Typography variant="caption" color="text.secondary">
          Typed error: {state.error.code}. The client does not infer additional
          authority or backend state.
        </Typography>
        {!permissionDenied && onRetry ? (
          <Button variant="outlined" onClick={onRetry}>
            Retry fixture adapter
          </Button>
        ) : null}
      </Stack>
    </Paper>
  );
}
