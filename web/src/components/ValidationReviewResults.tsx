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
import type {
  ValidationReviewGateOutcome,
  ValidationReviewState,
  ValidationReviewView,
} from '../validation/validationReviewModel';
import { semanticTokens } from '../theme';
import {
  formatUtc,
  humanizeIdentifier,
  shortDigest,
} from '../utils/presentation';
import { DetailList } from './DetailList';
import { PageHeader } from './PageHeader';
import { SectionHeading } from './SectionHeading';
import { StatusBadge, type SemanticTone } from './StatusBadge';

const outcomeTone: Readonly<Record<ValidationReviewGateOutcome, SemanticTone>> =
  {
    pass: 'positive',
    fail: 'critical',
    blocked: 'warning',
  };

function formatDuration(seconds: number) {
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}m ${remainder}s`;
}

function displayValue(value: string) {
  return humanizeIdentifier(value).replaceAll('-', ' ');
}

function LoadingReview() {
  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Safety review"
        title="Loading validation review"
        description="The frozen adapter is resolving policy, artifact, validation, and impact evidence."
        status={<StatusBadge label="Loading" tone="neutral" />}
      />
      <Paper
        component="section"
        variant="outlined"
        role="status"
        aria-label="Loading validation review"
        aria-live="polite"
        aria-busy="true"
        sx={{ p: { xs: 2.5, md: 3 } }}
      >
        <Stack spacing={1.5}>
          <Skeleton aria-hidden="true" variant="text" width="48%" />
          <Skeleton aria-hidden="true" variant="rounded" height={128} />
          <Skeleton aria-hidden="true" variant="rounded" height={260} />
        </Stack>
      </Paper>
    </Stack>
  );
}

function UnavailableReview({
  title,
  description,
  message,
  permission = false,
}: {
  readonly title: string;
  readonly description: string;
  readonly message: string;
  readonly permission?: boolean;
}) {
  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Safety review"
        title={title}
        description={description}
        status={
          <StatusBadge
            label={permission ? 'Permission denied' : 'Missing'}
            tone={permission ? 'warning' : 'neutral'}
          />
        }
      />
      <Paper
        component="section"
        variant="outlined"
        role={permission ? 'alert' : 'status'}
        aria-live={permission ? 'assertive' : 'polite'}
        sx={{ p: { xs: 2.5, md: 3 } }}
      >
        <Typography>{message}</Typography>
      </Paper>
    </Stack>
  );
}

function PolicySummary({ view }: { readonly view: ValidationReviewView }) {
  const command = view.command;
  const equal = command.ttlEquality === 'equal';

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="policy-summary-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="policy-summary-title"
          eyebrow="Structured policy"
          title="Policy and TTL"
          description="TTL equality is server-reported fixture evidence. The browser does not canonicalize or authorize it."
          action={
            <StatusBadge
              label={equal ? 'TTL values equal' : 'TTL mismatch'}
              tone={equal ? 'positive' : 'critical'}
            />
          }
        />
        <DetailList
          items={[
            { label: 'Action', value: displayValue(view.policy.action) },
            { label: 'Documentation target', value: view.policy.target_ipv4 },
            {
              label: 'Policy TTL',
              value: `${command.policyTtlSeconds} seconds`,
            },
            {
              label: 'Generated token',
              value: `${command.generatedTimeoutToken} = ${command.generatedParsedSeconds} seconds`,
            },
            {
              label: 'Canonical token',
              value: `${command.canonicalTimeoutToken} = ${command.canonicalParsedSeconds} seconds`,
            },
            {
              label: 'Evidence snapshot',
              value: shortDigest(view.policy.evidence_snapshot_digest),
            },
          ]}
        />
        <Alert severity={equal ? 'success' : 'error'}>
          {equal
            ? `${command.policyTtlSeconds} seconds = ${command.canonicalTimeoutToken} = ${command.canonicalParsedSeconds} seconds.`
            : `${command.policyTtlSeconds} seconds ≠ ${command.canonicalTimeoutToken} (${command.canonicalParsedSeconds} seconds).`}
        </Alert>
      </Stack>
    </Paper>
  );
}

function InertCommand({
  label,
  provenance,
  command,
  digest,
}: {
  readonly label: string;
  readonly provenance: string;
  readonly command: string;
  readonly digest: string;
}) {
  return (
    <Box component="section" aria-label={label} sx={{ minWidth: 0 }}>
      <Typography component="h3" variant="h3">
        {label}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
        {provenance}
      </Typography>
      <Box
        component="pre"
        sx={{
          m: 0,
          mt: 1.5,
          p: 2,
          minHeight: 106,
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
          bgcolor: 'oklch(0.965 0.006 285)',
          color: 'text.primary',
          whiteSpace: 'pre-wrap',
          overflowWrap: 'anywhere',
          fontSize: '0.78rem',
          lineHeight: 1.6,
        }}
      >
        <code>{command}</code>
      </Box>
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ display: 'block', mt: 1, fontFamily: 'monospace' }}
      >
        {shortDigest(digest)}
      </Typography>
    </Box>
  );
}

function CommandComparison({ view }: { readonly view: ValidationReviewView }) {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="command-comparison-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="command-comparison-title"
          eyebrow="Inert artifact comparison"
          title="Generated and canonical command"
          description="Rendered as selectable text only. Nothing in this panel is sent to a shell, dispatcher, or executor."
        />
        <Grid container spacing={2.5}>
          <Grid size={{ xs: 12, md: 6 }}>
            <InertCommand
              label="Generated candidate"
              provenance="Untrusted structured model output"
              command={view.command.generatedCommand}
              digest={view.command.generatedDigest}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <InertCommand
              label="Canonical artifact"
              provenance="Validator output, still non-authoritative in this browser"
              command={view.command.canonicalCommand}
              digest={view.command.canonicalDigest}
            />
          </Grid>
        </Grid>
      </Stack>
    </Paper>
  );
}

function OrderedValidation({ view }: { readonly view: ValidationReviewView }) {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="ordered-validation-title"
      sx={{ overflow: 'hidden' }}
    >
      <Box sx={{ px: { xs: 2.25, md: 3 }, py: 2.5 }}>
        <SectionHeading
          id="ordered-validation-title"
          eyebrow="Fixed server order"
          title="Five validation results"
          description="Consistency is evaluated before target protection. A failure blocks every later gate."
        />
      </Box>
      <Box
        component="ol"
        aria-label="Five ordered validation results"
        sx={{
          p: 0,
          m: 0,
          listStyle: 'none',
          borderTop: 1,
          borderColor: 'divider',
        }}
      >
        {view.gates.map((gate, index) => (
          <Box
            component="li"
            key={gate.id}
            sx={{
              display: 'grid',
              gridTemplateColumns: {
                xs: '32px minmax(0, 1fr)',
                sm: '32px minmax(0, 1fr) auto',
              },
              gap: { xs: 1.25, sm: 2 },
              alignItems: 'start',
              px: { xs: 2.25, md: 3 },
              py: 2.25,
              borderBottom: index < view.gates.length - 1 ? 1 : 0,
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
                {gate.title}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mt: 0.4 }}
              >
                {gate.detail}
              </Typography>
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', mt: 0.85, overflowWrap: 'anywhere' }}
              >
                Root checks: {gate.sourceCheckIds.map(displayValue).join(' + ')}
              </Typography>
            </Box>
            <Box sx={{ gridColumn: { xs: '2', sm: 'auto' } }}>
              <StatusBadge
                label={displayValue(gate.outcome)}
                tone={outcomeTone[gate.outcome]}
              />
            </Box>
          </Box>
        ))}
      </Box>
    </Paper>
  );
}

function ValidityPanel({ view }: { readonly view: ValidationReviewView }) {
  const validityTone: Readonly<
    Record<ValidationReviewView['validity']['status'], SemanticTone>
  > = {
    fresh: 'positive',
    stale: 'critical',
    expired: 'critical',
    missing: 'warning',
  };

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="validity-title"
      sx={{ p: { xs: 2.25, md: 2.5 } }}
    >
      <Stack spacing={2}>
        <Stack
          direction="row"
          spacing={1}
          alignItems="center"
          justifyContent="space-between"
        >
          <Typography id="validity-title" component="h2" variant="h3">
            Validity
          </Typography>
          <StatusBadge
            label={displayValue(view.validity.status)}
            tone={validityTone[view.validity.status]}
          />
        </Stack>
        <Typography variant="h3">
          {formatDuration(view.validity.remainingSeconds)} remaining
        </Typography>
        <Typography variant="body2" color="text.secondary">
          of the fixed {formatDuration(view.validity.windowSeconds)} validation
          window
        </Typography>
        <DetailList
          items={[
            {
              label: 'Created',
              value: view.validity.createdAt
                ? formatUtc(view.validity.createdAt)
                : 'No snapshot',
            },
            {
              label: 'Valid until',
              value: view.validity.validUntil
                ? formatUtc(view.validity.validUntil)
                : 'No snapshot',
            },
            {
              label: 'Server evaluated',
              value: formatUtc(view.validity.serverEvaluatedAt),
            },
          ]}
        />
        <Typography variant="body2" color="text.secondary">
          {view.validity.reason}
        </Typography>
      </Stack>
    </Paper>
  );
}

function CoverageAndHistory({ view }: { readonly view: ValidationReviewView }) {
  const historyVerified = view.demoHistory.signatureVerification === 'verified';
  const coverageComplete =
    view.sourceHealth.gateway === 'complete' &&
    view.sourceHealth.authentication === 'complete';

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="coverage-history-title"
      sx={{ p: { xs: 2.25, md: 2.5 } }}
    >
      <Stack spacing={2.25}>
        <Typography id="coverage-history-title" component="h2" variant="h3">
          Coverage and signed history
        </Typography>
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
          <StatusBadge
            label={`Gateway ${displayValue(view.sourceHealth.gateway)}`}
            tone={coverageComplete ? 'positive' : 'critical'}
          />
          <StatusBadge
            label={`Auth ${displayValue(view.sourceHealth.authentication)}`}
            tone={coverageComplete ? 'positive' : 'critical'}
          />
          <StatusBadge
            label={`History ${displayValue(view.demoHistory.signatureVerification)}`}
            tone={historyVerified ? 'positive' : 'critical'}
          />
        </Stack>
        {view.sourceHealth.unresolvedSequenceRange ? (
          <Alert severity="error">
            Unresolved sequence range{' '}
            {view.sourceHealth.unresolvedSequenceRange}
          </Alert>
        ) : null}
        <DetailList
          items={[
            {
              label: 'Source-health digest',
              value: view.sourceHealth.digest
                ? shortDigest(view.sourceHealth.digest)
                : 'Unavailable',
            },
            {
              label: 'Manifest digest',
              value: view.demoHistory.manifestDigest
                ? shortDigest(view.demoHistory.manifestDigest)
                : 'Unavailable',
            },
            {
              label: 'Dataset records',
              value: view.demoHistory.datasetRecordCount,
            },
            {
              label: 'Fixture scope',
              value: view.demoHistory.fixtureOnly
                ? 'Isolated demo only'
                : 'Not asserted',
            },
          ]}
        />
        <Typography variant="caption" color="text.secondary">
          Verification state is server-reported presentation data. Signature
          bytes and key material are not shown and do not grant browser
          authority.
        </Typography>
      </Stack>
    </Paper>
  );
}

function AuthorityBoundary() {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="validation-authority-title"
      sx={{
        p: { xs: 2.25, md: 2.5 },
        borderColor: semanticTokens.warning.border,
        bgcolor: semanticTokens.warning.background,
      }}
    >
      <Stack spacing={1.75}>
        <Typography id="validation-authority-title" component="h2" variant="h3">
          Authorization is a separate surface
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Server-side exact-artifact authorization exists. Approval controls
          live on the separate Authorization/HIL surface and are intentionally
          not duplicated in this validation result view. This browser cannot
          mint, repair, or bypass authorization.
        </Typography>
        <Button variant="contained" disabled fullWidth>
          No authorization control in this view
        </Button>
      </Stack>
    </Paper>
  );
}

function IntegrityProof({ view }: { readonly view: ValidationReviewView }) {
  const validation = view.validation;

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="integrity-proof-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="integrity-proof-title"
          eyebrow="Snapshot binding"
          title="Protected target and owned-schema proof"
          description="Static and effective protection remain distinct from raw contract bytes and the canonical live structure."
          action={
            <StatusBadge
              label={validation ? 'Snapshot present' : 'Snapshot unavailable'}
              tone={validation ? 'info' : 'warning'}
            />
          }
        />
        {validation ? (
          <DetailList
            items={[
              {
                label: 'Protected IPv4 static',
                value: shortDigest(validation.protected_ipv4_static_digest),
              },
              {
                label: 'Protected IPv4 effective',
                value: shortDigest(
                  validation.protected_ipv4_effective_config_digest,
                ),
              },
              {
                label: 'Owned base-chain raw',
                value: shortDigest(validation.base_chain_contract_raw_digest),
              },
              {
                label: 'Owned live structure',
                value: shortDigest(validation.live_owned_schema_digest),
              },
              {
                label: 'Policy digest',
                value: shortDigest(validation.policy_digest),
              },
              {
                label: 'Historical impact',
                value: shortDigest(validation.historical_impact_digest),
              },
            ]}
          />
        ) : (
          <Alert severity="warning">
            No immutable validation snapshot was produced for this state.
          </Alert>
        )}
      </Stack>
    </Paper>
  );
}

function ImpactReport({ view }: { readonly view: ValidationReviewView }) {
  const successful = view.impact.successfulAuthenticationSeen;

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="impact-report-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="impact-report-title"
          eyebrow="24-hour retained evidence"
          title="Historical impact report"
          description="Complete source coverage and verified demo-history binding are required before this result can pass."
          action={
            <StatusBadge
              label={displayValue(view.impact.result)}
              tone={
                view.impact.result === 'no-verified-success'
                  ? 'positive'
                  : 'critical'
              }
            />
          }
        />
        <DetailList
          items={[
            {
              label: 'Lookback start',
              value: formatUtc(view.impact.lookbackStart),
            },
            {
              label: 'Lookback end',
              value: formatUtc(view.impact.lookbackEnd),
            },
            { label: 'Coverage', value: displayValue(view.impact.coverage) },
            {
              label: 'Verified successful authentication seen',
              value:
                successful === null ? 'Unknown' : successful ? 'Yes' : 'No',
            },
            {
              label: 'Dataset digest',
              value: shortDigest(view.demoHistory.datasetDigest),
            },
            {
              label: 'Impact digest',
              value: view.impact.impactDigest
                ? shortDigest(view.impact.impactDigest)
                : 'Unavailable',
            },
          ]}
        />
      </Stack>
    </Paper>
  );
}

const statePresentation = {
  gapped: {
    label: 'Coverage gapped',
    tone: 'critical',
    severity: 'error',
    message:
      'Source coverage is incomplete. Historical impact cannot pass and no validation snapshot exists.',
  },
  unsigned: {
    label: 'History unsigned',
    tone: 'critical',
    severity: 'error',
    message:
      'Demo-history signature verification is absent. The fixture cannot support impact validation.',
  },
  failed: {
    label: 'Validation failed',
    tone: 'critical',
    severity: 'error',
    message:
      'An ordered hard gate failed. Later results are blocked and no snapshot was produced.',
  },
  mismatch: {
    label: 'Artifact mismatch',
    tone: 'critical',
    severity: 'error',
    message:
      'Policy seconds and canonical timeout differ. Consistency failed before protected-target evaluation.',
  },
  stale: {
    label: 'Validation stale',
    tone: 'warning',
    severity: 'warning',
    message:
      'A dependent evidence version changed. The prior result remains visible but cannot support approval.',
  },
  expired: {
    label: 'Validation expired',
    tone: 'critical',
    severity: 'error',
    message:
      'The fixed five-minute validation window elapsed. Revalidation is required.',
  },
  ready: {
    label: 'Validation complete',
    tone: 'positive',
    severity: 'success',
    message:
      'All five presentation gates passed with a fresh immutable snapshot. Human approval is still unavailable.',
  },
} as const;

function ReviewContent({
  state,
}: {
  readonly state: Extract<
    ValidationReviewState,
    {
      kind:
        | 'gapped'
        | 'unsigned'
        | 'failed'
        | 'mismatch'
        | 'stale'
        | 'expired'
        | 'ready';
    }
  >;
}) {
  const presentation = statePresentation[state.kind];

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Safety review"
        title="Validation review"
        description="Policy, inert command text, ordered gate results, coverage, impact, and immutable digests come from a frozen presentation adapter, not a live API."
        status={
          <StatusBadge label={presentation.label} tone={presentation.tone} />
        }
      />
      <Alert
        severity={presentation.severity}
        role={state.kind === 'ready' ? 'status' : 'alert'}
      >
        {presentation.message}
      </Alert>

      <Grid container spacing={3} alignItems="flex-start">
        <Grid size={{ xs: 12, lg: 8.5 }}>
          <Stack spacing={3}>
            <PolicySummary view={state.view} />
            <CommandComparison view={state.view} />
            <OrderedValidation view={state.view} />
          </Stack>
        </Grid>
        <Grid size={{ xs: 12, lg: 3.5 }}>
          <Stack spacing={3}>
            <ValidityPanel view={state.view} />
            <CoverageAndHistory view={state.view} />
            <AuthorityBoundary />
          </Stack>
        </Grid>
      </Grid>

      <Grid container spacing={3} alignItems="stretch">
        <Grid size={{ xs: 12, lg: 6 }}>
          <IntegrityProof view={state.view} />
        </Grid>
        <Grid size={{ xs: 12, lg: 6 }}>
          <ImpactReport view={state.view} />
        </Grid>
      </Grid>
    </Stack>
  );
}

export function ValidationReviewResults({
  state,
}: {
  readonly state: ValidationReviewState;
}) {
  switch (state.kind) {
    case 'loading':
      return <LoadingReview />;
    case 'missing':
      return (
        <UnavailableReview
          title="Validation review missing"
          description="No policy and validation review fixture was supplied."
          message="A missing policy, command, history proof, or validation snapshot cannot be presented as complete."
        />
      );
    case 'permission-denied':
      return (
        <UnavailableReview
          title="Validation access required"
          description="The adapter denied access to this validation review."
          message={state.error.message}
          permission
        />
      );
    case 'gapped':
    case 'unsigned':
    case 'failed':
    case 'mismatch':
    case 'stale':
    case 'expired':
    case 'ready':
      return <ReviewContent state={state} />;
  }
}
