import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Link,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useCallback, useState, type FormEvent } from 'react';
import { Link as RouterLink, useNavigate, useParams } from 'react-router-dom';
import { DetailList } from '../components/DetailList';
import { PageHeader } from '../components/PageHeader';
import { ProvenanceTag } from '../components/ProvenanceTag';
import { SectionHeading } from '../components/SectionHeading';
import { StatusBadge, type SemanticTone } from '../components/StatusBadge';
import { managementApi, type AuditQuery } from './apiClient';
import type { AuditPage, IncidentPage, PolicyDetail } from './contracts';
import { isCanonicalUUID } from './contracts';
import { EmptyState, LiveError, LiveLoading } from './LiveFeedback';
import { useLiveUpdates } from './liveUpdatesContext';
import { PolicyDecisionPanel } from './PolicyDecisionPanel';
import { RevocationDecisionPanel } from './RevocationDecisionPanel';
import { useManagementResource } from './useManagementResource';

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value));
}

function tone(value: string): SemanticTone {
  if (
    ['valid', 'active', 'succeeded', 'approved', 'accepted'].includes(value)
  ) {
    return 'positive';
  }
  if (['invalid', 'failed', 'rejected', 'indeterminate'].includes(value)) {
    return 'critical';
  }
  if (['stale', 'queued', 'validating', 'incomplete'].includes(value)) {
    return 'warning';
  }
  return 'neutral';
}

interface OverviewBundle {
  readonly incidents: Readonly<IncidentPage>;
  readonly audit: Readonly<AuditPage>;
}

export function LiveOverviewPage() {
  const updates = useLiveUpdates();
  const load = useCallback(
    async (signal: AbortSignal): Promise<Readonly<OverviewBundle>> => {
      const [incidents, audit] = await Promise.all([
        managementApi.incidents({ limit: 5 }, signal),
        managementApi.audit({ limit: 5 }, signal),
      ]);
      return Object.freeze({ incidents, audit });
    },
    [],
  );
  const resource = useManagementResource(load, updates.revision, 'overview');

  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Authenticated management plane"
        title="Investigation workspace"
        description="Read-only live snapshots and notification-driven refresh. Deterministic evidence, AI interpretation, human decisions, and enforcement outcomes remain separate."
        status={
          <StatusBadge
            label={
              updates.state === 'connected'
                ? 'Live notifications'
                : updates.state
            }
            tone={updates.state === 'connected' ? 'positive' : 'warning'}
          />
        }
      />
      {updates.replayGap ? (
        <Alert severity="warning">
          A replay gap invalidated cached snapshots. REST resources are being
          fetched again.
        </Alert>
      ) : null}
      {resource.loading ? (
        <LiveLoading label="Loading the investigation workspace" />
      ) : null}
      {resource.error ? (
        <LiveError error={resource.error} onRetry={resource.reload} />
      ) : null}
      {resource.data ? (
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
            gap: 2.5,
          }}
        >
          <Card variant="outlined">
            <CardContent>
              <SectionHeading
                id="recent-incidents-heading"
                title="Recent incidents"
                description="At most five visible rows; no global count is inferred."
                action={<ProvenanceTag kind="observed" />}
              />
              {resource.data.incidents.items.length === 0 ? (
                <EmptyState
                  title="No visible incidents"
                  detail="The authenticated incident snapshot is empty."
                />
              ) : (
                <Stack spacing={1.25} sx={{ mt: 2 }}>
                  {resource.data.incidents.items.map((incident) => (
                    <Box
                      key={incident.incident_id}
                      sx={{
                        p: 1.5,
                        border: 1,
                        borderColor: 'divider',
                        borderRadius: 1.5,
                      }}
                    >
                      <Stack
                        direction="row"
                        justifyContent="space-between"
                        spacing={1}
                      >
                        <Link
                          component={RouterLink}
                          to={`/incidents/${incident.incident_id}`}
                          sx={{ fontWeight: 720 }}
                        >
                          {incident.kind.replaceAll('_', ' ')}
                        </Link>
                        <StatusBadge
                          label={incident.state}
                          tone={tone(incident.state)}
                        />
                      </Stack>
                      <Typography variant="body2">
                        <code>{incident.source_ip}</code> ·{' '}
                        {incident.service_label}
                      </Typography>
                    </Box>
                  ))}
                  <Link component={RouterLink} to="/incidents">
                    Open incident index
                  </Link>
                </Stack>
              )}
            </CardContent>
          </Card>
          <Card variant="outlined">
            <CardContent>
              <SectionHeading
                id="recent-audit-heading"
                title="Recent audit outcomes"
                description="Latest authorized audit records, without free-form reasons or authority bytes."
                action={<ProvenanceTag kind="enforcement" />}
              />
              {resource.data.audit.items.length === 0 ? (
                <EmptyState
                  title="No visible audit records"
                  detail="The authenticated audit snapshot is empty."
                />
              ) : (
                <Stack spacing={1.25} sx={{ mt: 2 }}>
                  {resource.data.audit.items.map((event) => (
                    <Box
                      key={event.event_id}
                      sx={{ py: 1.25, borderBottom: 1, borderColor: 'divider' }}
                    >
                      <Stack
                        direction="row"
                        justifyContent="space-between"
                        spacing={1}
                      >
                        <Typography sx={{ fontWeight: 720 }}>
                          {event.action}
                        </Typography>
                        <StatusBadge
                          label={event.outcome}
                          tone={tone(event.outcome)}
                        />
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        {event.actor_type} · {formatTime(event.occurred_at)}
                      </Typography>
                    </Box>
                  ))}
                  <Link component={RouterLink} to="/audit">
                    Open audit ledger
                  </Link>
                </Stack>
              )}
            </CardContent>
          </Card>
        </Box>
      ) : null}
      <Alert severity="info">
        Policy approval and active-action revocation use separate guarded HIL
        contracts. Audit views remain authenticated read-only projections.
      </Alert>
    </Stack>
  );
}

export function ResourceLookupPage({
  kind,
}: {
  readonly kind: 'policy' | 'action';
}) {
  const navigate = useNavigate();
  const [identifier, setIdentifier] = useState('');
  const [invalid, setInvalid] = useState(false);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!isCanonicalUUID(identifier)) {
      setInvalid(true);
      return;
    }
    navigate(
      kind === 'policy'
        ? `/policies/${identifier}`
        : `/enforcement-actions/${identifier}`,
    );
  };
  const policy = kind === 'policy';
  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow={policy ? 'Validation and HIL review' : 'Enforcement lifecycle'}
        title={policy ? 'Open a policy artifact' : 'Open an enforcement action'}
        description={
          policy
            ? 'The backend exposes exact policy lookup, not a policy queue endpoint. Open an ID from an incident or enter a known canonical UUID.'
            : 'The backend exposes exact action lookup, not an action list endpoint. An active action may expose a separate guarded revocation flow.'
        }
        status={
          <StatusBadge
            label={policy ? 'Exact HIL available' : 'Exact lifecycle lookup'}
            tone="info"
          />
        }
      />
      <Alert severity="info">
        No list response is synthesized in the browser. This preserves the
        currently implemented management API boundary.
      </Alert>
      <Card variant="outlined">
        <CardContent>
          <Stack component="form" onSubmit={submit} spacing={2}>
            <TextField
              label={policy ? 'Policy UUID' : 'Action UUID'}
              value={identifier}
              error={invalid}
              helperText={
                invalid
                  ? 'Enter a lowercase canonical UUID.'
                  : 'Identifiers are validated before a path request is created.'
              }
              inputProps={{ maxLength: 36 }}
              onChange={(event) => {
                setIdentifier(event.target.value);
                setInvalid(false);
              }}
            />
            <Box>
              <Button type="submit" variant="contained">
                Open {policy ? 'exact review' : 'lifecycle detail'}
              </Button>
            </Box>
          </Stack>
        </CardContent>
      </Card>
      {policy ? (
        <Alert severity="info">
          A policy can be decided only after its server-provided exact artifact
          and all deterministic prerequisites pass. The browser cannot create or
          repair validation authority.
        </Alert>
      ) : null}
    </Stack>
  );
}

export function PolicyValidationEvidence({
  policy,
}: {
  readonly policy: Readonly<PolicyDetail>;
}) {
  const attempt = policy.latest_validation_attempt;
  if (policy.latest_validation && (!attempt || attempt.state === 'valid')) {
    return (
      <Stack spacing={1.5} sx={{ mt: 2 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <StatusBadge
            label={policy.latest_validation.state}
            tone={tone(policy.latest_validation.state)}
          />
          <StatusBadge
            label={`Source ${policy.latest_validation.source_health_status}`}
            tone={tone(policy.latest_validation.source_health_status)}
          />
        </Stack>
        {policy.latest_validation.gates.map((gate) => (
          <Box
            key={`${gate.order}:${gate.name}`}
            sx={{
              p: 1.75,
              border: 1,
              borderColor: gate.passed ? 'success.light' : 'error.light',
              borderRadius: 1.5,
            }}
          >
            <Stack direction="row" justifyContent="space-between" spacing={1}>
              <Typography sx={{ fontWeight: 720 }}>
                {gate.order}. {gate.name}
              </Typography>
              <StatusBadge
                label={gate.passed ? 'Passed' : 'Failed'}
                tone={gate.passed ? 'positive' : 'critical'}
              />
            </Stack>
            <Typography variant="body2">
              Result: <code>{gate.result_code}</code> ·{' '}
              {formatTime(gate.checked_at)}
            </Typography>
          </Box>
        ))}
        <Typography variant="caption">
          Valid until {formatTime(policy.latest_validation.valid_until)} ·{' '}
          <code>{policy.latest_validation.snapshot_digest}</code>
        </Typography>
      </Stack>
    );
  }

  if (!attempt) {
    return (
      <EmptyState
        title="No validation snapshot"
        detail="This policy has no latest deterministic validation summary or terminal attempt evidence."
      />
    );
  }

  return (
    <Stack spacing={1.5} sx={{ mt: 2 }}>
      <Alert severity={attempt.state === 'invalid' ? 'error' : 'warning'}>
        <Typography component="h3" variant="subtitle2">
          Fail-closed validation attempt
        </Typography>
        This terminal attempt did not provide a HIL-authorizing validation
        snapshot. Its evidence is read-only and cannot enable approval.
      </Alert>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
        <StatusBadge label={attempt.state} tone={tone(attempt.state)} />
        {attempt.failure_code ? (
          <StatusBadge
            label={`Failure ${attempt.failure_code}`}
            tone="critical"
          />
        ) : null}
      </Stack>
      <DetailList
        items={[
          {
            label: 'Failed gate',
            value: <code>{attempt.failed_gate ?? 'none'}</code>,
          },
          {
            label: 'Completed',
            value: formatTime(attempt.completed_at),
          },
          {
            label: 'Prepared snapshot digest',
            value: <code>{attempt.prepared_snapshot_digest}</code>,
          },
          {
            label: 'Terminal mutation digest',
            value: (
              <code>{attempt.terminal_mutation_digest ?? 'not produced'}</code>
            ),
          },
        ]}
      />
      <Typography component="h3" variant="h3">
        Ordered attempt gates
      </Typography>
      {attempt.gates.map((gate) => (
        <Box
          key={`${gate.order}:${gate.name}`}
          sx={{
            p: 1.75,
            border: 1,
            borderColor:
              gate.state === 'passed' ? 'success.light' : 'error.light',
            borderRadius: 1.5,
          }}
        >
          <Stack direction="row" justifyContent="space-between" spacing={1}>
            <Typography sx={{ fontWeight: 720 }}>
              {gate.order}. {gate.name}
            </Typography>
            <StatusBadge
              label={gate.state === 'passed' ? 'Passed' : 'Failed'}
              tone={gate.state === 'passed' ? 'positive' : 'critical'}
            />
          </Stack>
          <Typography variant="body2">
            Result: <code>{gate.result_code}</code>
          </Typography>
          <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>
            Artifact: <code>{gate.artifact_digest}</code>
          </Typography>
        </Box>
      ))}
      <Typography variant="caption">
        Attempt <code>{attempt.validation_attempt_id}</code>
      </Typography>
    </Stack>
  );
}

export function LivePolicyPage() {
  const { policyId = '' } = useParams();
  const updates = useLiveUpdates();
  const load = useCallback(
    (signal: AbortSignal) => managementApi.policy(policyId, signal),
    [policyId],
  );
  const resource = useManagementResource(load, updates.revision, policyId);

  if (resource.loading)
    return <LiveLoading label="Loading policy and validation snapshot" />;
  if (resource.error)
    return <LiveError error={resource.error} onRetry={resource.reload} />;
  if (!resource.data) return null;
  const policy = resource.data;
  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Evidence-bound response candidate"
        title={`Policy for ${policy.target_ipv4}`}
        description={`Policy ${policy.policy_id} · version ${policy.version} · revision ${policy.state_revision}`}
        status={<StatusBadge label={policy.state} tone={tone(policy.state)} />}
      />
      {resource.refreshing ? (
        <Alert severity="info">Refreshing after a policy notification.</Alert>
      ) : null}
      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="policy-ai-heading"
            title="Analysis-proposed artifact"
            description="Untrusted analysis interpretation and generated candidate bytes. Provider identity is not repeated in this policy response; inspect the linked incident rather than inferring it in the browser."
            action={<StatusBadge label="Untrusted proposal" tone="warning" />}
          />
          <DetailList
            items={[
              {
                label: 'Incident',
                value: (
                  <Link
                    component={RouterLink}
                    to={`/incidents/${policy.incident_id}`}
                  >
                    <code>{policy.incident_id}</code>
                  </Link>
                ),
              },
              { label: 'Analysis', value: <code>{policy.analysis_id}</code> },
              { label: 'Target', value: <code>{policy.target_ipv4}</code> },
              {
                label: 'TTL',
                value: `${policy.ttl_seconds}s (${policy.timeout_token})`,
              },
              { label: 'Parse state', value: policy.parse_state },
              {
                label: 'Evidence snapshot',
                value: <code>{policy.evidence_snapshot_digest}</code>,
              },
            ]}
          />
          <Typography sx={{ mt: 2 }}>{policy.rationale}</Typography>
          <Typography component="h3" variant="h3" sx={{ mt: 2.5 }}>
            Generated command candidate
          </Typography>
          <Box
            component="pre"
            aria-label="Generated command candidate"
            sx={{
              p: 2,
              mt: 1,
              overflowX: 'auto',
              bgcolor: 'oklch(0.955 0.01 285)',
              borderRadius: 1.5,
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
            }}
          >
            {policy.generated_command}
          </Box>
          <Typography variant="caption">
            <code>{policy.generated_artifact_digest}</code>
          </Typography>
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="policy-validation-heading"
            title="Deterministic validation"
            description="The server returns each actual ordered gate; the UI does not combine or invent gates."
            action={<ProvenanceTag kind="deterministic" />}
          />
          <PolicyValidationEvidence policy={policy} />
          <Typography component="h3" variant="h3" sx={{ mt: 3 }}>
            Canonical command
          </Typography>
          <Box
            component="pre"
            aria-label="Canonical command"
            sx={{
              p: 2,
              mt: 1,
              overflowX: 'auto',
              bgcolor: 'oklch(0.955 0.01 285)',
              borderRadius: 1.5,
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
            }}
          >
            {policy.canonical_command}
          </Box>
          <Typography variant="caption">
            <code>{policy.canonical_artifact_digest}</code>
          </Typography>
        </CardContent>
      </Card>

      <PolicyDecisionPanel policy={policy} onCommitted={resource.reload} />
    </Stack>
  );
}

export function LiveEnforcementActionPage() {
  const { actionId = '' } = useParams();
  const updates = useLiveUpdates();
  const load = useCallback(
    (signal: AbortSignal) => managementApi.enforcementAction(actionId, signal),
    [actionId],
  );
  const resource = useManagementResource(load, updates.revision, actionId);
  if (resource.loading)
    return <LiveLoading label="Loading enforcement lifecycle" />;
  if (resource.error)
    return <LiveError error={resource.error} onRetry={resource.reload} />;
  if (!resource.data) return null;
  const action = resource.data;
  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Executor outcome projection"
        title={`Action ${action.action_id}`}
        description="Lifecycle projection with a separate exact-artifact revocation control for active actions. Capabilities, signatures, handles, and executor request bytes are not exposed."
        status={<StatusBadge label={action.state} tone={tone(action.state)} />}
      />
      <Card variant="outlined">
        <CardContent>
          <SectionHeading
            id="action-outcome-heading"
            title="Enforcement outcome"
            description="Executor and dispatcher facts remain separate from approval."
            action={<ProvenanceTag kind="enforcement" />}
          />
          <DetailList
            items={[
              {
                label: 'Policy',
                value: (
                  <Link
                    component={RouterLink}
                    to={`/policies/${action.policy_id}`}
                  >
                    <code>{action.policy_id}</code>
                  </Link>
                ),
              },
              { label: 'Target', value: <code>{action.target_ipv4}</code> },
              { label: 'Approved', value: formatTime(action.approved_at) },
              {
                label: 'Applied',
                value: action.applied_at
                  ? formatTime(action.applied_at)
                  : 'Not applied',
              },
              {
                label: 'Expected expiry',
                value: action.expected_expires_at
                  ? formatTime(action.expected_expires_at)
                  : 'Not established',
              },
              {
                label: 'Artifact digest',
                value: <code>{action.canonical_artifact_digest}</code>,
              },
            ]}
          />
          {action.latest_result ? (
            <Box sx={{ mt: 2.5 }}>
              <Typography component="h3" variant="h3">
                Latest signed result projection
              </Typography>
              <DetailList
                items={[
                  { label: 'Operation', value: action.latest_result.operation },
                  {
                    label: 'Classification',
                    value: action.latest_result.classification,
                  },
                  {
                    label: 'Read-back',
                    value: action.latest_result.readback_state,
                  },
                  {
                    label: 'Remaining TTL',
                    value:
                      action.latest_result.remaining_ttl_seconds === undefined
                        ? 'Not reported'
                        : `${action.latest_result.remaining_ttl_seconds}s`,
                  },
                  {
                    label: 'Error code',
                    value: action.latest_result.error_code || 'none',
                  },
                  {
                    label: 'Result digest',
                    value: <code>{action.latest_result.result_digest}</code>,
                  },
                ]}
              />
            </Box>
          ) : (
            <EmptyState
              title="No terminal result"
              detail="No executor result projection is visible yet."
            />
          )}
        </CardContent>
      </Card>
      <RevocationDecisionPanel action={action} onCommitted={resource.reload} />
    </Stack>
  );
}

export function LiveAuditPage() {
  const updates = useLiveUpdates();
  const [draft, setDraft] = useState<AuditQuery>({ limit: 25 });
  const [query, setQuery] = useState<AuditQuery>({ limit: 25 });
  const [cursors, setCursors] = useState<readonly (string | undefined)[]>([
    undefined,
  ]);
  const cursor = cursors[cursors.length - 1];
  const load = useCallback(
    (signal: AbortSignal) => managementApi.audit({ ...query, cursor }, signal),
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
    setCursors([undefined]);
  };
  return (
    <Stack spacing={3.5}>
      <PageHeader
        eyebrow="Immutable outcome trail"
        title="Audit ledger"
        description="Authenticated, filtered, keyset-paginated audit projections. Secret, free-form reason, and capability material is excluded."
        status={<StatusBadge label="Read-only" tone="info" />}
      />
      <Card variant="outlined">
        <CardContent>
          <Stack
            component="form"
            onSubmit={submit}
            direction={{ xs: 'column', md: 'row' }}
            spacing={1.5}
          >
            <TextField
              size="small"
              label="Incident UUID"
              value={draft.incident_id ?? ''}
              inputProps={{ maxLength: 36 }}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  incident_id: event.target.value || undefined,
                })
              }
            />
            <TextField
              size="small"
              label="Policy UUID"
              value={draft.policy_id ?? ''}
              inputProps={{ maxLength: 36 }}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  policy_id: event.target.value || undefined,
                })
              }
            />
            <TextField
              size="small"
              label="Action UUID"
              value={draft.action_id ?? ''}
              inputProps={{ maxLength: 36 }}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  action_id: event.target.value || undefined,
                })
              }
            />
            <Button type="submit" variant="contained">
              Apply filters
            </Button>
          </Stack>
        </CardContent>
      </Card>
      {resource.loading ? <LiveLoading label="Loading audit snapshot" /> : null}
      {resource.error ? (
        <LiveError error={resource.error} onRetry={resource.reload} />
      ) : null}
      {resource.data?.items.length === 0 ? (
        <EmptyState
          title="No audit records"
          detail="No authorized record matches the current filter and cursor."
        />
      ) : null}
      {resource.data && resource.data.items.length > 0 ? (
        <Card variant="outlined">
          <CardContent sx={{ p: 0 }}>
            <Table aria-label="Live audit ledger">
              <TableHead>
                <TableRow>
                  <TableCell>Recorded</TableCell>
                  <TableCell>Actor</TableCell>
                  <TableCell>Action / object</TableCell>
                  <TableCell>Outcome</TableCell>
                  <TableCell>Trace</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {resource.data.items.map((event) => (
                  <TableRow key={event.event_id}>
                    <TableCell>{formatTime(event.recorded_at)}</TableCell>
                    <TableCell>
                      {event.actor_type}
                      <Typography variant="caption" display="block">
                        {event.actor_id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <strong>{event.action}</strong>
                      <Typography variant="caption" display="block">
                        {event.object_type}
                        {event.object_id ? ` · ${event.object_id}` : ''}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <StatusBadge
                        label={event.outcome}
                        tone={tone(event.outcome)}
                      />
                    </TableCell>
                    <TableCell>
                      {event.trace_id ? <code>{event.trace_id}</code> : '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Stack direction="row" spacing={1} sx={{ p: 2 }}>
              <Button
                variant="outlined"
                disabled={cursors.length === 1 || resource.refreshing}
                onClick={() => setCursors((values) => values.slice(0, -1))}
              >
                Previous page
              </Button>
              <Button
                variant="outlined"
                disabled={!resource.data.next_cursor || resource.refreshing}
                onClick={() => {
                  if (resource.data?.next_cursor)
                    setCursors((values) => [
                      ...values,
                      resource.data?.next_cursor,
                    ]);
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
