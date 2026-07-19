import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Link,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useCallback, useState, type FormEvent } from 'react';
import { Link as RouterLink, useParams } from 'react-router-dom';
import { DetailList } from '../components/DetailList';
import { PageHeader } from '../components/PageHeader';
import { ProvenanceTag } from '../components/ProvenanceTag';
import { SectionHeading } from '../components/SectionHeading';
import { StatusBadge, type SemanticTone } from '../components/StatusBadge';
import { managementApi, type IncidentListQuery } from './apiClient';
import { AnalysisProviderDetails } from './AnalysisProviderDetails';
import type { AuditPage, IncidentDetail, IncidentEventPage } from './contracts';
import { EmptyState, LiveError, LiveLoading } from './LiveFeedback';
import { useLiveUpdates } from './liveUpdatesContext';
import { useManagementResource } from './useManagementResource';

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value));
}

function stateTone(state: string): SemanticTone {
  if (['review_ready', 'valid', 'active', 'succeeded'].includes(state)) {
    return 'positive';
  }
  if (['analysis_failed', 'invalid', 'failed', 'lost'].includes(state)) {
    return 'critical';
  }
  if (['analyzing', 'validating', 'incomplete'].includes(state)) {
    return 'warning';
  }
  return 'neutral';
}

function LiveFreshness() {
  const updates = useLiveUpdates();
  if (updates.replayGap || updates.state === 'stale') {
    return (
      <Alert severity="warning" role="status">
        The notification replay window was missed. REST snapshots are being
        invalidated and reloaded before newer state is shown.
      </Alert>
    );
  }
  if (updates.state === 'reconnecting' || updates.state === 'error') {
    return (
      <Alert severity="info" role="status">
        Live notifications are reconnecting. The REST snapshot below remains
        readable and will refresh after reconnection.
      </Alert>
    );
  }
  return null;
}

export function LiveIncidentListPage() {
  const updates = useLiveUpdates();
  const [draft, setDraft] = useState<IncidentListQuery>({ limit: 25 });
  const [query, setQuery] = useState<IncidentListQuery>({ limit: 25 });
  const [cursorStack, setCursorStack] = useState<
    readonly (string | undefined)[]
  >([undefined]);
  const cursor = cursorStack[cursorStack.length - 1];
  const load = useCallback(
    (signal: AbortSignal) =>
      managementApi.incidents({ ...query, cursor }, signal),
    [cursor, query],
  );
  const resource = useManagementResource(
    load,
    updates.revision,
    JSON.stringify({ query, cursor }),
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setQuery({ ...draft, limit: 25 });
    setCursorStack([undefined]);
  };

  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Observed investigation index"
        title="Incidents"
        description="Authenticated, keyset-paginated deterministic incident snapshots. Counts describe only the visible page; analysis-provider identity is shown only when the detail response supplies its exact provenance."
        status={<StatusBadge label="Live REST" tone="info" />}
      />
      <LiveFreshness />
      <Card variant="outlined">
        <CardContent>
          <Stack
            component="form"
            onSubmit={submit}
            direction={{ xs: 'column', lg: 'row' }}
            spacing={1.5}
            alignItems={{ lg: 'center' }}
          >
            <FormControl size="small" sx={{ minWidth: 170 }}>
              <InputLabel id="incident-state-label">State</InputLabel>
              <Select
                labelId="incident-state-label"
                label="State"
                value={draft.state ?? ''}
                onChange={(event) =>
                  setDraft({ ...draft, state: event.target.value || undefined })
                }
              >
                <MenuItem value="">Any state</MenuItem>
                {[
                  'open',
                  'analyzing',
                  'review_ready',
                  'analysis_failed',
                  'closed',
                ].map((state) => (
                  <MenuItem key={state} value={state}>
                    {state}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 190 }}>
              <InputLabel id="incident-kind-label">Kind</InputLabel>
              <Select
                labelId="incident-kind-label"
                label="Kind"
                value={draft.kind ?? ''}
                onChange={(event) =>
                  setDraft({ ...draft, kind: event.target.value || undefined })
                }
              >
                <MenuItem value="">Any kind</MenuItem>
                {[
                  'credential_stuffing',
                  'brute_force',
                  'path_scan',
                  'request_burst',
                  'mixed',
                  'unknown',
                ].map((kind) => (
                  <MenuItem key={kind} value={kind}>
                    {kind}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              size="small"
              label="Source IPv4"
              value={draft.source ?? ''}
              inputProps={{ maxLength: 15 }}
              onChange={(event) =>
                setDraft({ ...draft, source: event.target.value || undefined })
              }
            />
            <TextField
              size="small"
              label="Service"
              value={draft.service ?? ''}
              inputProps={{ maxLength: 128 }}
              onChange={(event) =>
                setDraft({ ...draft, service: event.target.value || undefined })
              }
            />
            <Button type="submit" variant="contained">
              Apply filters
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {resource.loading ? (
        <LiveLoading label="Loading incident snapshot" />
      ) : null}
      {resource.error ? (
        <LiveError error={resource.error} onRetry={resource.reload} />
      ) : null}
      {resource.data && resource.data.items.length === 0 ? (
        <EmptyState
          title="No incidents on this page"
          detail="No authenticated incident snapshot matches the current filter and cursor."
        />
      ) : null}
      {resource.data && resource.data.items.length > 0 ? (
        <Card variant="outlined">
          <CardContent sx={{ p: 0 }}>
            <Box
              sx={{ px: 2.5, py: 2, borderBottom: 1, borderColor: 'divider' }}
            >
              <Stack
                direction="row"
                justifyContent="space-between"
                alignItems="center"
              >
                <Typography component="h2" variant="h2">
                  Visible page
                </Typography>
                <StatusBadge
                  label={
                    resource.refreshing
                      ? 'Refreshing'
                      : `${resource.data.items.length} visible`
                  }
                  tone={resource.refreshing ? 'warning' : 'positive'}
                />
              </Stack>
            </Box>
            <TableContainer>
              <Table aria-label="Live incidents">
                <TableHead>
                  <TableRow>
                    <TableCell>Incident</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Kind</TableCell>
                    <TableCell>State</TableCell>
                    <TableCell>Last seen</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {resource.data.items.map((incident) => (
                    <TableRow key={incident.incident_id} hover>
                      <TableCell>
                        <Link
                          component={RouterLink}
                          to={`/incidents/${incident.incident_id}`}
                        >
                          <code>{incident.incident_id}</code>
                        </Link>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          display="block"
                        >
                          {incident.service_label} · v{incident.version}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <code>{incident.source_ip}</code>
                      </TableCell>
                      <TableCell>{incident.kind}</TableCell>
                      <TableCell>
                        <StatusBadge
                          label={incident.state}
                          tone={stateTone(incident.state)}
                        />
                      </TableCell>
                      <TableCell>{formatTime(incident.last_seen)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <Stack direction="row" spacing={1} sx={{ p: 2 }}>
              <Button
                variant="outlined"
                disabled={cursorStack.length === 1 || resource.refreshing}
                onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
              >
                Previous page
              </Button>
              <Button
                variant="outlined"
                disabled={!resource.data.next_cursor || resource.refreshing}
                onClick={() => {
                  if (resource.data?.next_cursor) {
                    setCursorStack((stack) => [
                      ...stack,
                      resource.data?.next_cursor,
                    ]);
                  }
                }}
              >
                Next page
              </Button>
            </Stack>
          </CardContent>
        </Card>
      ) : null}
    </Stack>
  );
}

interface DetailBundle {
  readonly detail: Readonly<IncidentDetail>;
  readonly events: Readonly<IncidentEventPage>;
  readonly audit: Readonly<AuditPage>;
}

export function LiveIncidentDetailPage() {
  const { incidentId = '' } = useParams();
  const updates = useLiveUpdates();
  const load = useCallback(
    async (signal: AbortSignal): Promise<Readonly<DetailBundle>> => {
      const [detail, events, audit] = await Promise.all([
        managementApi.incident(incidentId, signal),
        managementApi.incidentEvents(incidentId, undefined, signal),
        managementApi.audit({ incident_id: incidentId, limit: 100 }, signal),
      ]);
      return Object.freeze({ detail, events, audit });
    },
    [incidentId],
  );
  const resource = useManagementResource(load, updates.revision, incidentId);

  if (resource.loading) {
    return <LiveLoading label="Loading incident evidence layers" />;
  }
  if (resource.error) {
    return <LiveError error={resource.error} onRetry={resource.reload} />;
  }
  if (!resource.data) {
    return null;
  }

  const { detail, events, audit } = resource.data;
  const incident = detail.incident;
  const analysis = detail.latest_analysis;
  const deterministicAnalysis =
    analysis?.provider_kind === 'deterministic_stub';
  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Incident investigation"
        title={`${incident.kind.replaceAll('_', ' ')} from ${incident.source_ip}`}
        description={`Incident ${incident.incident_id} · immutable view of version ${incident.version}`}
        status={
          <StatusBadge
            label={incident.state}
            tone={stateTone(incident.state)}
          />
        }
      />
      <LiveFreshness />
      {resource.refreshing ? (
        <Alert severity="info">
          Refreshing this REST snapshot after a live notification.
        </Alert>
      ) : null}

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="observed-facts-heading"
            title="Observed incident facts"
            description="Incident identity and time bounds persisted by the deterministic pipeline."
            action={<ProvenanceTag kind="observed" />}
          />
          <DetailList
            items={[
              {
                label: 'Incident ID',
                value: <code>{incident.incident_id}</code>,
              },
              {
                label: 'Source IPv4',
                value: <code>{incident.source_ip}</code>,
              },
              { label: 'Service', value: incident.service_label },
              { label: 'First seen', value: formatTime(incident.first_seen) },
              { label: 'Last seen', value: formatTime(incident.last_seen) },
              {
                label: 'Deterministic score',
                value: incident.deterministic_score,
              },
            ]}
          />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Exact paths, query strings, bodies, cookies, authorization values,
            and unrestricted headers are intentionally absent.
          </Typography>
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="observed-events-heading"
            title="Allowlisted observed events"
            description="Minimized gateway, authentication, and source-health records correlated to this incident."
            action={<ProvenanceTag kind="observed" />}
          />
          {events.items.length === 0 ? (
            <EmptyState
              title="No visible events"
              detail="No authorized minimized event is available for this incident."
            />
          ) : (
            <Stack spacing={1.25} sx={{ mt: 2 }}>
              {events.items.map((event) => (
                <Box
                  key={event.incident_event_id}
                  sx={{
                    p: 1.75,
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1.5,
                  }}
                >
                  <Stack
                    direction={{ xs: 'column', sm: 'row' }}
                    justifyContent="space-between"
                    spacing={1}
                  >
                    <Typography sx={{ fontWeight: 720 }}>
                      {event.kind}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {formatTime(event.occurred_at)}
                    </Typography>
                  </Stack>
                  <Typography variant="body2" sx={{ mt: 0.75 }}>
                    Trust: <code>{event.trust_state}</code> (
                    {event.trust_reason}) · Relation: {event.relation_reason}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {event.route_label
                      ? `Route ${event.route_label}`
                      : 'No route label'}
                    {event.status_code ? ` · HTTP ${event.status_code}` : ''}
                    {event.trace_id ? (
                      <>
                        {' '}
                        · Trace <code>{event.trace_id}</code>
                      </>
                    ) : null}
                  </Typography>
                </Box>
              ))}
              {events.next_cursor ? (
                <Alert severity="info">
                  More observed events exist; this bounded view shows the first
                  100.
                </Alert>
              ) : null}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="deterministic-signals-heading"
            title="Deterministic conclusions"
            description="Rule outputs remain separate from provider-identified analysis interpretation."
            action={<ProvenanceTag kind="deterministic" />}
          />
          {detail.signals.length === 0 ? (
            <EmptyState
              title="No visible signals"
              detail="The current incident snapshot contains no authorized deterministic signal summaries."
            />
          ) : (
            <Stack spacing={1.25} sx={{ mt: 2 }}>
              {detail.signals.map((signal) => (
                <Box
                  key={signal.signal_id}
                  sx={{
                    p: 1.75,
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1.5,
                  }}
                >
                  <Typography sx={{ fontWeight: 720 }}>
                    {signal.rule_id} v{signal.rule_version}
                  </Typography>
                  <Typography variant="body2">
                    Observed {signal.observed_count} / threshold{' '}
                    {signal.threshold_count} · source health{' '}
                    {signal.source_health_status}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    <code>{signal.evidence_digest}</code>
                  </Typography>
                </Box>
              ))}
              {detail.signals_truncated ? (
                <Alert severity="warning">
                  Signal summaries were bounded by the API.
                </Alert>
              ) : null}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="analysis-interpretation-heading"
            title={
              deterministicAnalysis
                ? 'Deterministic analysis interpretation'
                : analysis
                  ? 'AI interpretation'
                  : 'Analysis interpretation'
            }
            description={
              deterministicAnalysis
                ? 'Schema-constrained offline stub output is deterministic test interpretation, never direct firewall authority.'
                : 'Schema-constrained provider analysis is untrusted interpretation, never direct firewall authority.'
            }
            action={
              deterministicAnalysis ? (
                <ProvenanceTag kind="deterministic" />
              ) : analysis ? (
                <ProvenanceTag kind="ai" />
              ) : (
                <StatusBadge label="No provider" tone="neutral" />
              )
            }
          />
          {!analysis ? (
            <EmptyState
              title="No analysis summary"
              detail="No provider-identified analysis summary is available for this incident version."
            />
          ) : (
            <Box sx={{ mt: 2 }}>
              <AnalysisProviderDetails analysis={analysis} />
              <DetailList
                items={[
                  {
                    label: 'Result',
                    value: analysis.result_state,
                  },
                  ...(analysis.result_state === 'succeeded'
                    ? [
                        {
                          label: 'Classification',
                          value: analysis.classification,
                        },
                        {
                          label: 'Confidence',
                          value: analysis.confidence,
                        },
                      ]
                    : analysis.result_state === 'failed'
                      ? [
                          {
                            label: 'Failure code',
                            value: analysis.failure_code,
                          },
                        ]
                      : []),
                ]}
              />
              {analysis.result_state === 'succeeded' ? (
                <>
                  <Typography sx={{ mt: 2 }}>{analysis.summary}</Typography>
                  {analysis.uncertainty ? (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      {analysis.uncertainty}
                    </Alert>
                  ) : null}
                </>
              ) : analysis.result_state === 'failed' ? (
                <Alert severity="error" sx={{ mt: 2 }}>
                  Analysis ended without a provider result. Deterministic
                  evidence remains available for investigation.
                </Alert>
              ) : (
                <Alert severity="info" sx={{ mt: 2 }}>
                  Analysis is in progress. No terminal provider result is
                  available yet.
                </Alert>
              )}
            </Box>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="human-policy-heading"
            title="Human review and policy artifacts"
            description="Policy candidates are inert until validation and exact-artifact HIL approval. This interface is currently read-only."
            action={<ProvenanceTag kind="human" />}
          />
          {detail.policies.length === 0 ? (
            <EmptyState
              title="No policy candidate"
              detail="No response policy is associated with this incident snapshot."
            />
          ) : (
            <Stack spacing={1.25} sx={{ mt: 2 }}>
              {detail.policies.map((policy) => (
                <Box
                  key={`${policy.policy_id}:${policy.version}`}
                  sx={{
                    p: 1.75,
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1.5,
                  }}
                >
                  <Stack
                    direction={{ xs: 'column', sm: 'row' }}
                    justifyContent="space-between"
                    spacing={1}
                  >
                    <Link
                      component={RouterLink}
                      to={`/policies/${policy.policy_id}`}
                      sx={{ fontWeight: 720 }}
                    >
                      Policy {policy.policy_id}
                    </Link>
                    <StatusBadge
                      label={policy.state}
                      tone={stateTone(policy.state)}
                    />
                  </Stack>
                  <Typography variant="body2" sx={{ mt: 0.75 }}>
                    Target <code>{policy.target_ipv4}</code> · TTL{' '}
                    {policy.ttl_seconds}s · revision {policy.state_revision}
                  </Typography>
                </Box>
              ))}
              {detail.policies_truncated ? (
                <Alert severity="warning">
                  Policy summaries were bounded by the API.
                </Alert>
              ) : null}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="audit-outcomes-heading"
            title="Audit outcomes"
            description="Traceable human, system, dispatcher, and executor outcomes."
            action={<ProvenanceTag kind="enforcement" />}
          />
          {audit.items.length === 0 ? (
            <EmptyState
              title="No audit records"
              detail="No authorized audit record is visible for this incident."
            />
          ) : (
            <Stack spacing={1.25} sx={{ mt: 2 }}>
              {audit.items.map((event) => (
                <Box
                  key={event.event_id}
                  sx={{
                    display: 'grid',
                    gridTemplateColumns: { xs: '1fr', md: '180px 1fr auto' },
                    gap: 1,
                    py: 1.25,
                    borderBottom: 1,
                    borderColor: 'divider',
                  }}
                >
                  <Typography variant="caption" color="text.secondary">
                    {formatTime(event.occurred_at)}
                  </Typography>
                  <Typography variant="body2">
                    <strong>{event.action}</strong> on {event.object_type} by{' '}
                    {event.actor_type}
                  </Typography>
                  <StatusBadge
                    label={event.outcome}
                    tone={stateTone(event.outcome)}
                  />
                </Box>
              ))}
              {audit.next_cursor ? (
                <Alert severity="info">
                  More audit events exist; this bounded view shows the first
                  100.
                </Alert>
              ) : null}
            </Stack>
          )}
        </CardContent>
      </Card>
    </Stack>
  );
}
