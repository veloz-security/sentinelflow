import {
  Alert,
  Box,
  Button,
  Divider,
  Grid,
  Paper,
  Skeleton,
  Stack,
  Typography,
} from '@mui/material';
import type {
  LifecycleState,
  SignatureVerificationState,
} from '../contracts/apiDtos';
import type {
  AuditProvenanceKind,
  EnforcementLifecycleState,
  EnforcementLifecycleView,
  JournalIntegrity,
} from '../enforcement/enforcementLifecycleModel';
import { useServerSampleCountdown } from '../enforcement/useServerSampleCountdown';
import { formatUtc, humanizeIdentifier } from '../utils/presentation';
import { DetailList } from './DetailList';
import { PageHeader } from './PageHeader';
import { SectionHeading } from './SectionHeading';
import { StatusBadge, type SemanticTone } from './StatusBadge';

export interface EnforcementLifecycleResultsProps {
  readonly state: EnforcementLifecycleState;
}

const lifecycleTone: Readonly<Record<LifecycleState, SemanticTone>> = {
  pending: 'neutral',
  applied: 'positive',
  active: 'positive',
  expired: 'neutral',
  revoked: 'neutral',
  failed: 'critical',
  indeterminate: 'critical',
};

const integrityTone: Readonly<Record<JournalIntegrity, SemanticTone>> = {
  complete: 'positive',
  torn: 'critical',
  corrupt: 'critical',
  unknown: 'warning',
};

const provenanceLabels: Readonly<Record<AuditProvenanceKind, string>> = {
  fact: 'Observed fact',
  'deterministic-rule': 'Deterministic rule',
  'ai-generated': 'AI generated',
  canonicalized: 'Canonicalized artifact',
  'human-decision': 'Human decision',
  dispatcher: 'Dispatcher',
  'executor-result': 'Executor result',
  recovery: 'Recovery',
};

const operationLabels = {
  add: 'Shell-free temporary add',
  inspect: 'Read-only inspect',
  revoke: 'Deterministic revoke',
} as const;

const operationDescriptions = {
  add: 'The isolated executor may invoke the exact add artifact at most once.',
  inspect:
    'A separately signed, typed operation may only run the fixed read-back command.',
  revoke:
    'A separate removal artifact cannot add a rule or inherit add authority.',
} as const;

function FullDigest({ value }: { readonly value: string }) {
  return (
    <Box
      component="code"
      sx={{
        display: 'block',
        mt: 0.45,
        fontSize: '0.72rem',
        lineHeight: 1.55,
        overflowWrap: 'anywhere',
      }}
    >
      {value}
    </Box>
  );
}

function formatDuration(seconds: number) {
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}m ${remainder}s`;
}

function LoadingLifecycle() {
  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Action lifecycle"
        title="Loading enforcement lifecycle"
        description="The fixture adapter is resolving typed operation, journal, and audit evidence."
        status={<StatusBadge label="Loading" tone="neutral" />}
      />
      <Paper
        component="section"
        role="status"
        aria-label="Loading enforcement lifecycle"
        aria-live="polite"
        aria-busy="true"
        variant="outlined"
        sx={{ p: { xs: 2.25, md: 3 } }}
      >
        <Stack spacing={1.5}>
          <Skeleton aria-hidden="true" variant="text" width="42%" />
          <Skeleton aria-hidden="true" variant="rounded" height={180} />
          <Skeleton aria-hidden="true" variant="rounded" height={260} />
        </Stack>
      </Paper>
    </Stack>
  );
}

function NonReadyLifecycle({
  kind,
  message,
  traceId,
}: {
  readonly kind: 'empty' | 'error' | 'permission-denied';
  readonly message: string;
  readonly traceId?: string;
}) {
  const copy = {
    empty: {
      title: 'No enforcement lifecycle',
      label: 'Empty',
      tone: 'neutral' as const,
      severity: 'info' as const,
    },
    error: {
      title: 'Enforcement lifecycle unavailable',
      label: 'Error',
      tone: 'critical' as const,
      severity: 'error' as const,
    },
    'permission-denied': {
      title: 'Enforcement access required',
      label: 'Permission denied',
      tone: 'warning' as const,
      severity: 'warning' as const,
    },
  }[kind];

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Action lifecycle"
        title={copy.title}
        description="Lifecycle evidence is read-only and remains unavailable until the server returns an authorized typed response."
        status={<StatusBadge label={copy.label} tone={copy.tone} />}
      />
      <Alert
        severity={copy.severity}
        role={kind === 'empty' ? 'status' : 'alert'}
      >
        {message}
        {traceId ? ` Trace ${traceId}.` : ''}
      </Alert>
    </Stack>
  );
}

function FixtureBoundary() {
  return (
    <Alert severity="info" role="status">
      Fixture-only lifecycle evidence. This browser does not hold signature
      bytes, private keys, capability authority, executor access, or any path to
      mutate nftables. No operation, refresh, re-add, revoke, or TTL extension
      occurs here.
    </Alert>
  );
}

function ServerClockPanel({
  view,
}: {
  readonly view: EnforcementLifecycleView;
}) {
  const remaining = useServerSampleCountdown(
    view.serverClock.remainingTtlSeconds,
  );
  const isAtZero = remaining === 0;

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="server-clock-title"
      sx={{ p: { xs: 2.25, md: 2.5 }, minWidth: 0 }}
    >
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={1}
          alignItems="center"
          justifyContent="space-between"
        >
          <Typography id="server-clock-title" component="h2" variant="h3">
            Server-time TTL
          </Typography>
          <StatusBadge
            label={remaining === null ? 'Not active' : 'Server sampled'}
            tone={remaining === null ? 'neutral' : 'info'}
          />
        </Stack>
        <Typography variant="h2" aria-live="off">
          {remaining === null ? 'Not applicable' : formatDuration(remaining)}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {isAtZero
            ? 'The display reached zero. It awaits server confirmation and does not change lifecycle state.'
            : 'The display interpolates from the last server sample. Only a new server response can confirm state or remaining TTL.'}
        </Typography>
        <DetailList
          items={[
            {
              label: 'Server sampled',
              value: formatUtc(view.serverClock.serverNow),
            },
            {
              label: 'Approved TTL',
              value: `${view.lifecycle.approved_ttl_seconds} seconds`,
            },
          ]}
        />
      </Stack>
    </Paper>
  );
}

function signatureTone(verification: SignatureVerificationState): SemanticTone {
  return verification === 'verified' ? 'positive' : 'critical';
}

function OperationHistory({
  view,
}: {
  readonly view: EnforcementLifecycleView;
}) {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="operation-history-title"
      sx={{ overflow: 'hidden', minWidth: 0 }}
    >
      <Box sx={{ px: { xs: 2.25, md: 3 }, py: 2.5 }}>
        <SectionHeading
          id="operation-history-title"
          eyebrow="Distinct typed operations"
          title="Add, inspect, and revoke history"
          description="Verification status is server-reported display evidence. It is not a browser control and no signature material is exposed."
        />
      </Box>
      <Box
        component="ol"
        aria-label="Enforcement operation history"
        sx={{
          p: 0,
          m: 0,
          listStyle: 'none',
          borderTop: 1,
          borderColor: 'divider',
        }}
      >
        {view.lifecycle.operations.map((entry, index) => {
          const result = entry.result;
          const resultDigest = result
            ? view.resultDigests[result.result_id]
            : null;
          return (
            <Box
              component="li"
              key={entry.operation_id}
              sx={{
                px: { xs: 2.25, md: 3 },
                py: 2.5,
                borderBottom:
                  index < view.lifecycle.operations.length - 1 ? 1 : 0,
                borderColor: 'divider',
              }}
            >
              <Stack spacing={2}>
                <Stack
                  direction={{ xs: 'column', sm: 'row' }}
                  spacing={1.25}
                  alignItems={{ xs: 'flex-start', sm: 'center' }}
                  justifyContent="space-between"
                >
                  <Stack direction="row" spacing={1.25} alignItems="flex-start">
                    <Typography
                      aria-hidden="true"
                      variant="caption"
                      sx={{
                        display: 'grid',
                        flex: '0 0 auto',
                        placeItems: 'center',
                        width: 30,
                        height: 30,
                        borderRadius: '50%',
                        bgcolor: 'action.selected',
                        color: 'primary.dark',
                        fontWeight: 780,
                      }}
                    >
                      {index + 1}
                    </Typography>
                    <Box sx={{ minWidth: 0 }}>
                      <Typography component="h3" variant="h3">
                        {operationLabels[entry.operation]}
                      </Typography>
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{ mt: 0.35 }}
                      >
                        {operationDescriptions[entry.operation]}
                      </Typography>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: 'block', mt: 0.65 }}
                      >
                        Requested {formatUtc(entry.requested_at)}
                      </Typography>
                    </Box>
                  </Stack>
                  <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                    <StatusBadge
                      label={`Signature status: ${humanizeIdentifier(entry.signature_verification)}`}
                      tone={signatureTone(entry.signature_verification)}
                    />
                    <StatusBadge
                      label={
                        result
                          ? humanizeIdentifier(result.classification)
                          : 'Pending result'
                      }
                      tone={
                        !result
                          ? 'neutral'
                          : result.classification === 'failed' ||
                              result.classification === 'indeterminate' ||
                              result.classification === 'inspect_mismatch'
                            ? 'critical'
                            : 'positive'
                      }
                    />
                  </Stack>
                </Stack>

                {result ? (
                  <Grid container spacing={2.25}>
                    <Grid size={{ xs: 12, md: 4 }}>
                      <DetailList
                        items={[
                          {
                            label: 'Read-back',
                            value: humanizeIdentifier(result.readback_state),
                          },
                          {
                            label: 'Executor exit',
                            value: result.nft_exit_class ?? 'No process result',
                          },
                          {
                            label: 'Error code',
                            value: humanizeIdentifier(result.error_code),
                          },
                          {
                            label: 'Journal sequence',
                            value: result.journal_sequence,
                          },
                          {
                            label: 'TTL at result',
                            value:
                              result.remaining_ttl_seconds === null
                                ? 'Not applicable'
                                : `${result.remaining_ttl_seconds} seconds`,
                          },
                        ]}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, md: 8 }}>
                      <Stack spacing={1.35} sx={{ minWidth: 0 }}>
                        <Box>
                          <Typography variant="caption" color="text.secondary">
                            Artifact digest
                          </Typography>
                          <FullDigest value={result.artifact_digest} />
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">
                            Capability digest
                          </Typography>
                          <FullDigest value={result.capability_digest} />
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">
                            Executor result digest
                          </Typography>
                          <FullDigest value={resultDigest ?? 'Unavailable'} />
                        </Box>
                      </Stack>
                    </Grid>
                  </Grid>
                ) : (
                  <Alert severity="info">
                    The request is pending. No executor result or mutation is
                    inferred.
                  </Alert>
                )}
              </Stack>
            </Box>
          );
        })}
      </Box>
    </Paper>
  );
}

function JournalAndRecovery({
  view,
}: {
  readonly view: EnforcementLifecycleView;
}) {
  const critical =
    view.recovery.integrity === 'torn' || view.recovery.integrity === 'corrupt';

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="journal-title"
      sx={{ overflow: 'hidden', minWidth: 0 }}
    >
      <Box sx={{ px: { xs: 2.25, md: 3 }, py: 2.5 }}>
        <SectionHeading
          id="journal-title"
          eyebrow="Crash-safe evidence"
          title="Journal sequence and recovery"
          description="The complete visible sequence is read-only. Torn, corrupt, or uncertain records fail closed without truncation, re-add, or TTL refresh."
          action={
            <StatusBadge
              label={`Integrity: ${humanizeIdentifier(view.recovery.integrity)}`}
              tone={integrityTone[view.recovery.integrity]}
            />
          }
        />
      </Box>
      <Divider />
      <Box sx={{ p: { xs: 2.25, md: 3 } }}>
        <Stack spacing={2.5}>
          <Alert severity={critical ? 'error' : 'info'}>
            {view.recovery.detail}
          </Alert>
          {view.journal.length === 0 ? (
            <Typography role="status" color="text.secondary">
              No journal record has been committed.
            </Typography>
          ) : (
            <Box
              component="ol"
              aria-label="Executor journal sequence"
              sx={{ p: 0, m: 0, listStyle: 'none' }}
            >
              {view.journal.map((record, index) => (
                <Box
                  component="li"
                  key={`${record.sequence}-${record.phase}`}
                  sx={{
                    display: 'grid',
                    gridTemplateColumns: {
                      xs: '32px minmax(0, 1fr)',
                      sm: '32px minmax(0, 1fr) auto',
                    },
                    gap: 1.5,
                    alignItems: 'start',
                    pb: index < view.journal.length - 1 ? 2.25 : 0,
                    mb: index < view.journal.length - 1 ? 2.25 : 0,
                    borderBottom: index < view.journal.length - 1 ? 1 : 0,
                    borderColor: 'divider',
                  }}
                >
                  <Typography
                    aria-hidden="true"
                    variant="caption"
                    sx={{
                      display: 'grid',
                      placeItems: 'center',
                      width: 30,
                      height: 30,
                      borderRadius: 1,
                      bgcolor: 'action.selected',
                      color: 'primary.dark',
                      fontWeight: 780,
                    }}
                  >
                    {record.sequence}
                  </Typography>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography component="h3" variant="h3">
                      {humanizeIdentifier(record.operation)} ·{' '}
                      {humanizeIdentifier(record.phase)}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {formatUtc(record.recordedAt)}
                    </Typography>
                    {record.terminalResultDigest ? (
                      <Box sx={{ mt: 1.1 }}>
                        <Typography variant="caption" color="text.secondary">
                          Terminal result digest
                        </Typography>
                        <FullDigest value={record.terminalResultDigest} />
                      </Box>
                    ) : null}
                  </Box>
                  <Box sx={{ gridColumn: { xs: '2', sm: 'auto' } }}>
                    <StatusBadge
                      label={humanizeIdentifier(record.integrity).replaceAll(
                        '-',
                        ' ',
                      )}
                      tone={
                        record.integrity === 'verified'
                          ? 'positive'
                          : 'critical'
                      }
                    />
                  </Box>
                </Box>
              ))}
            </Box>
          )}
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
            <StatusBadge label="Automatic re-add: disabled" tone="positive" />
            <StatusBadge label="TTL refresh: disabled" tone="positive" />
            <StatusBadge
              label={`Recovery mode: ${humanizeIdentifier(
                view.recovery.mode,
              ).replaceAll('-', ' ')}`}
              tone={view.recovery.mode === 'halted' ? 'critical' : 'info'}
            />
          </Stack>
        </Stack>
      </Box>
    </Paper>
  );
}

function AuditTimeline({ view }: { readonly view: EnforcementLifecycleView }) {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="audit-timeline-title"
      sx={{ overflow: 'hidden', minWidth: 0 }}
    >
      <Box sx={{ px: { xs: 2.25, md: 3 }, py: 2.5 }}>
        <SectionHeading
          id="audit-timeline-title"
          eyebrow="Provenance preserved"
          title="Audit provenance timeline"
          description="Facts, deterministic conclusions, model output, canonicalization, human decisions, dispatcher authority, executor results, and recovery remain distinguishable."
        />
      </Box>
      <Box
        component="ol"
        aria-label="Audit provenance timeline"
        sx={{
          p: 0,
          m: 0,
          listStyle: 'none',
          borderTop: 1,
          borderColor: 'divider',
        }}
      >
        {view.auditTrail.map((entry, index) => (
          <Box
            component="li"
            key={entry.event.audit_id}
            sx={{
              display: 'grid',
              gridTemplateColumns: {
                xs: 'minmax(0, 1fr)',
                sm: '150px minmax(0, 1fr)',
              },
              gap: 2,
              px: { xs: 2.25, md: 3 },
              py: 2.25,
              borderBottom: index < view.auditTrail.length - 1 ? 1 : 0,
              borderColor: 'divider',
            }}
          >
            <Box>
              <StatusBadge
                label={provenanceLabels[entry.provenance]}
                tone="info"
              />
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', mt: 0.75 }}
              >
                {formatUtc(entry.event.occurred_at)}
              </Typography>
            </Box>
            <Box sx={{ minWidth: 0 }}>
              <Typography component="h3" variant="h3">
                {entry.title}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mt: 0.35 }}
              >
                {entry.detail}
              </Typography>
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', mt: 0.8, overflowWrap: 'anywhere' }}
              >
                {entry.event.event_type} · {entry.event.actor_kind}{' '}
                {entry.event.actor_id} · {entry.event.outcome}
              </Typography>
            </Box>
          </Box>
        ))}
      </Box>
    </Paper>
  );
}

function ActionSummary({ view }: { readonly view: EnforcementLifecycleView }) {
  const lifecycle = view.lifecycle;
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="action-summary-title"
      sx={{ p: { xs: 2.25, md: 2.5 }, minWidth: 0 }}
    >
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={1}
          alignItems="center"
          justifyContent="space-between"
        >
          <Typography id="action-summary-title" component="h2" variant="h3">
            Action summary
          </Typography>
          <StatusBadge
            label={humanizeIdentifier(lifecycle.state)}
            tone={lifecycleTone[lifecycle.state]}
          />
        </Stack>
        <DetailList
          items={[
            { label: 'Documentation target', value: lifecycle.target_ipv4 },
            { label: 'Action version', value: lifecycle.action_version },
            {
              label: 'Applied',
              value: lifecycle.applied_at
                ? formatUtc(lifecycle.applied_at)
                : 'Not applied',
            },
            {
              label: 'Expires',
              value: lifecycle.expires_at
                ? formatUtc(lifecycle.expires_at)
                : 'Not scheduled',
            },
          ]}
        />
        <Box>
          <Typography variant="caption" color="text.secondary">
            Original add artifact digest
          </Typography>
          <FullDigest value={lifecycle.original_add_digest} />
        </Box>
        <Button variant="contained" disabled fullWidth>
          Reapply action
        </Button>
        <Typography variant="caption" color="text.secondary">
          Reapplication is never inferred from an approval, a duplicate request,
          a refresh, or a recovery result.
        </Typography>
      </Stack>
    </Paper>
  );
}

function ReadyLifecycle({
  fixtureName,
  view,
}: {
  readonly fixtureName: string;
  readonly view: EnforcementLifecycleView;
}) {
  const statusLabel =
    fixtureName === 'recovered-active'
      ? 'Recovered active'
      : fixtureName === 'torn-journal'
        ? 'Torn journal'
        : fixtureName === 'corrupt-journal'
          ? 'Corrupt journal'
          : humanizeIdentifier(view.lifecycle.state);
  const statusTone =
    fixtureName === 'torn-journal' || fixtureName === 'corrupt-journal'
      ? 'critical'
      : lifecycleTone[view.lifecycle.state];

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Action lifecycle"
        title="Temporary block history"
        description="Review distinct add, signed read-only inspect, and revoke outcomes with server-time TTL, crash-safe journal evidence, and provenance-preserving audit records."
        status={<StatusBadge label={statusLabel} tone={statusTone} />}
      />
      <FixtureBoundary />

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <OperationHistory view={view} />
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Stack spacing={3}>
            <ActionSummary view={view} />
            <ServerClockPanel key={view.serverClock.serverNow} view={view} />
          </Stack>
        </Grid>
      </Grid>

      <JournalAndRecovery view={view} />
      <AuditTimeline view={view} />
    </Stack>
  );
}

export function EnforcementLifecycleResults({
  state,
}: EnforcementLifecycleResultsProps) {
  if (state.kind === 'loading') return <LoadingLifecycle />;
  if (state.kind === 'empty') {
    return (
      <NonReadyLifecycle
        kind="empty"
        message="No temporary enforcement action exists for this fixture."
      />
    );
  }
  if (state.kind === 'error' || state.kind === 'permission-denied') {
    return (
      <NonReadyLifecycle
        kind={state.kind}
        message={state.error.message}
        traceId={state.error.trace_id}
      />
    );
  }
  return <ReadyLifecycle fixtureName={state.fixtureName} view={state.view} />;
}
