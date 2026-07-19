import {
  Alert,
  Box,
  Button,
  Checkbox,
  FormControl,
  FormControlLabel,
  FormHelperText,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Radio,
  RadioGroup,
  Select,
  Skeleton,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useState, type FormEvent } from 'react';
import {
  HIL_REASON_CODES,
  type HilReasonCode,
} from '../contracts/rootContracts';
import {
  challengeMatchesExactView,
  normalizeHilReason,
  type HilAuthorizationErrorStateName,
  type HilAuthorizationState,
  type HilAuthorizationView,
  type HilDecisionOperation,
  type HilDecisionPreviewInput,
} from '../hil/hilAuthorizationModel';
import { semanticTokens } from '../theme';
import {
  formatUtc,
  humanizeIdentifier,
  shortIdentifier,
} from '../utils/presentation';
import { DetailList } from './DetailList';
import { PageHeader } from './PageHeader';
import { SectionHeading } from './SectionHeading';
import { StatusBadge, type SemanticTone } from './StatusBadge';

export interface HilAuthorizationResultsProps {
  readonly state: HilAuthorizationState;
  readonly busy?: boolean;
  readonly onPreviewChallenge?: (operation: HilDecisionOperation) => void;
  readonly onPreviewStepUp?: (operation: HilDecisionOperation) => void;
  readonly onPreviewDecision?: (input: HilDecisionPreviewInput) => void;
}

function duration(seconds: number) {
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}m ${remainder}s`;
}

function FullDigest({ value }: { readonly value: string }) {
  return (
    <Box
      component="code"
      sx={{
        display: 'block',
        mt: 0.4,
        fontSize: '0.72rem',
        lineHeight: 1.5,
        overflowWrap: 'anywhere',
      }}
    >
      {value}
    </Box>
  );
}

function LoadingAuthorization() {
  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Human authorization"
        title="Loading HIL authorization review"
        description="The fixture adapter is resolving a fresh validation snapshot and exact-artifact presentation state."
        status={<StatusBadge label="Loading" tone="neutral" />}
      />
      <Paper
        component="section"
        role="status"
        aria-label="Loading HIL authorization review"
        aria-live="polite"
        aria-busy="true"
        variant="outlined"
        sx={{ p: { xs: 2.25, md: 3 } }}
      >
        <Stack spacing={1.5}>
          <Skeleton aria-hidden="true" variant="text" width="45%" />
          <Skeleton aria-hidden="true" variant="rounded" height={180} />
          <Skeleton aria-hidden="true" variant="rounded" height={220} />
        </Stack>
      </Paper>
    </Stack>
  );
}

function FixtureBoundary() {
  return (
    <Alert severity="info" role="status">
      Fixture-only preview. No live session, password verification, challenge
      nonce consumption, decision persistence, capability, firewall change, or
      executor integration occurs in this browser.
    </Alert>
  );
}

function ExactArtifactBinding({
  view,
}: {
  readonly view: HilAuthorizationView;
}) {
  const policy = view.validationReview.policy;
  const validation = view.validationReview.validation;
  const challenge = view.challenge;
  const exactMatch = challenge ? challengeMatchesExactView(view) : null;

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="exact-artifact-title"
      sx={{ p: { xs: 2.25, md: 3 }, minWidth: 0 }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="exact-artifact-title"
          eyebrow="Immutable decision scope"
          title="Exact policy and artifact binding"
          description="The operation, version, target, validation, evidence, and artifact digests must remain byte-identical. The browser cannot override a mismatch."
          action={
            <StatusBadge
              label={
                exactMatch === null
                  ? 'Challenge not issued'
                  : exactMatch
                    ? 'Exact binding matches'
                    : 'Binding mismatch'
              }
              tone={
                exactMatch === null
                  ? 'neutral'
                  : exactMatch
                    ? 'positive'
                    : 'critical'
              }
            />
          }
        />

        <Grid container spacing={2.5}>
          <Grid size={{ xs: 12, md: 4 }}>
            <DetailList
              items={[
                { label: 'Operation', value: view.operation },
                { label: 'Policy version', value: policy.policy_version },
                { label: 'Target IPv4', value: policy.target_ipv4 },
                { label: 'TTL', value: `${policy.ttl_seconds} seconds` },
              ]}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 8 }}>
            <Stack spacing={1.5}>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Policy digest
                </Typography>
                <FullDigest
                  value={validation?.policy_digest ?? 'Unavailable'}
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Generated artifact digest
                </Typography>
                <FullDigest
                  value={
                    validation?.generated_candidate_digest ?? 'Unavailable'
                  }
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Canonical artifact digest
                </Typography>
                <FullDigest
                  value={validation?.canonical_artifact_digest ?? 'Unavailable'}
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Evidence snapshot digest
                </Typography>
                <FullDigest
                  value={validation?.evidence_snapshot_digest ?? 'Unavailable'}
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Validation snapshot digest
                </Typography>
                <FullDigest
                  value={
                    challenge?.validation_snapshot_digest ??
                    'Bound only when a fixture challenge opens'
                  }
                />
              </Box>
            </Stack>
          </Grid>
        </Grid>

        <Box>
          <Typography component="h3" variant="h3">
            Canonical artifact, inert text
          </Typography>
          <Box
            component="pre"
            sx={{
              m: 0,
              mt: 1.25,
              p: 2,
              border: 1,
              borderColor: 'divider',
              borderRadius: 1,
              bgcolor: 'oklch(0.965 0.006 285)',
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: '0.78rem',
            }}
          >
            <code>{view.validationReview.command.canonicalCommand}</code>
          </Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: 'block', mt: 0.75 }}
          >
            Selectable evidence only; never executable from this surface.
          </Typography>
        </Box>
      </Stack>
    </Paper>
  );
}

function OperationChoice({
  view,
  busy,
  onPreviewChallenge,
}: {
  readonly view: HilAuthorizationView;
  readonly busy: boolean;
  readonly onPreviewChallenge?: (operation: HilDecisionOperation) => void;
}) {
  const [operation, setOperation] = useState<HilDecisionOperation>(
    view.operation,
  );

  const isApprove = operation === 'approve';
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="decision-intent-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="decision-intent-title"
          eyebrow="Administrator intent"
          title="Choose approval or rejection"
          description="Each operation requires its own exact-artifact, single-use challenge. Changing this choice invalidates any prior challenge."
        />
        <FormControl>
          <RadioGroup
            aria-label="HIL decision operation"
            value={operation}
            onChange={(event) =>
              setOperation(event.target.value as HilDecisionOperation)
            }
          >
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Paper
                  variant="outlined"
                  sx={{
                    p: 1.5,
                    height: '100%',
                    borderColor:
                      operation === 'approve'
                        ? semanticTokens.critical.border
                        : 'divider',
                    bgcolor:
                      operation === 'approve'
                        ? semanticTokens.critical.background
                        : 'background.paper',
                  }}
                >
                  <FormControlLabel
                    value="approve"
                    control={<Radio />}
                    label={
                      <Box>
                        <Typography sx={{ fontWeight: 720 }}>
                          Approve temporary block
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Authorizes only this exact policy artifact for a
                          later, separately gated dispatcher step.
                        </Typography>
                      </Box>
                    }
                    sx={{ m: 0, alignItems: 'flex-start' }}
                  />
                </Paper>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <Paper
                  variant="outlined"
                  sx={{
                    p: 1.5,
                    height: '100%',
                    borderColor:
                      operation === 'reject'
                        ? semanticTokens.info.border
                        : 'divider',
                    bgcolor:
                      operation === 'reject'
                        ? semanticTokens.info.background
                        : 'background.paper',
                  }}
                >
                  <FormControlLabel
                    value="reject"
                    control={<Radio />}
                    label={
                      <Box>
                        <Typography sx={{ fontWeight: 720 }}>
                          Reject this artifact
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Records a human rejection and creates no enforcement
                          authority.
                        </Typography>
                      </Box>
                    }
                    sx={{ m: 0, alignItems: 'flex-start' }}
                  />
                </Paper>
              </Grid>
            </Grid>
          </RadioGroup>
        </FormControl>
        <Alert severity={isApprove ? 'warning' : 'info'}>
          {isApprove
            ? 'Approval is the consequential path. Validation may still fail closed after this review.'
            : 'Rejection cannot add, extend, or execute a firewall rule.'}
        </Alert>
        <Button
          type="button"
          variant={isApprove ? 'contained' : 'outlined'}
          color={isApprove ? 'error' : 'secondary'}
          disabled={busy || !onPreviewChallenge}
          onClick={() => onPreviewChallenge?.(operation)}
          sx={{ alignSelf: { sm: 'flex-start' } }}
        >
          Open {operation} challenge fixture
        </Button>
      </Stack>
    </Paper>
  );
}

function StepUpPanel({
  view,
  busy,
  onPreviewStepUp,
}: {
  readonly view: HilAuthorizationView;
  readonly busy: boolean;
  readonly onPreviewStepUp?: (operation: HilDecisionOperation) => void;
}) {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    form.reset();
    onPreviewStepUp?.(view.operation);
  }

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="step-up-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="step-up-title"
          eyebrow="15-minute authentication boundary"
          title="Password step-up required"
          description="The server-reported authenticated age exceeds the fixed threshold. A challenge cannot be issued until step-up succeeds and the session rotates."
          action={<StatusBadge label="Step-up required" tone="warning" />}
        />
        <DetailList
          items={[
            {
              label: 'Authenticated at',
              value: formatUtc(view.session.authenticatedAt),
            },
            {
              label: 'Authenticated age',
              value: duration(view.session.authenticatedAgeSeconds),
            },
            {
              label: 'Step-up threshold',
              value: duration(view.session.reauthRequiredAfterSeconds),
            },
            { label: 'Session rotation', value: 'Required after step-up' },
          ]}
        />
        <Box component="form" onSubmit={handleSubmit} autoComplete="off">
          <Stack spacing={1.5}>
            <TextField
              id="step-up-password"
              required
              fullWidth
              type="password"
              name="step-up-password"
              label="Administrator password"
              autoComplete="current-password"
              inputProps={{
                'aria-describedby': 'step-up-password-privacy',
              }}
            />
            <Typography
              id="step-up-password-privacy"
              variant="caption"
              color="text.secondary"
            >
              Uncontrolled one-use input. It is cleared from the DOM before the
              fixture callback runs and is never placed in React state,
              fixtures, logs, storage, or screenshots.
            </Typography>
            <Button
              type="submit"
              variant="contained"
              disabled={busy || !onPreviewStepUp}
              sx={{ alignSelf: { sm: 'flex-start' } }}
            >
              Preview step-up and session rotation
            </Button>
          </Stack>
        </Box>
      </Stack>
    </Paper>
  );
}

function ChallengeFacts({ view }: { readonly view: HilAuthorizationView }) {
  const challenge = view.challenge;
  if (!challenge) return null;
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="challenge-facts-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2.25}>
        <SectionHeading
          id="challenge-facts-title"
          eyebrow="Single-use authorization"
          title="Challenge and session binding"
          description="Only the digest is displayed. The raw nonce is never represented in this fixture model."
          action={
            <StatusBadge
              label={humanizeIdentifier(view.challengeUse)}
              tone={view.challengeUse === 'available' ? 'positive' : 'critical'}
            />
          }
        />
        <DetailList
          items={[
            {
              label: 'Challenge ID',
              value: shortIdentifier(challenge.challenge_id),
            },
            { label: 'Operation', value: challenge.operation },
            { label: 'Issued', value: formatUtc(challenge.issued_at) },
            { label: 'Expires', value: formatUtc(challenge.expires_at) },
            {
              label: 'Maximum window',
              value: duration(view.challengeWindowSeconds),
            },
            {
              label: 'Session rotation',
              value: humanizeIdentifier(view.session.sessionRotation),
            },
            {
              label: 'Idempotency key',
              value: shortIdentifier(view.idempotencyKey),
            },
            {
              label: 'Idempotency digest',
              value: <FullDigest value={view.idempotencyKeyDigest} />,
            },
          ]}
        />
        <Typography variant="caption" color="text.secondary">
          One challenge can produce at most one byte-identical decision. A
          replay, mutation, stale version, or conflicting idempotency key fails
          closed.
        </Typography>
      </Stack>
    </Paper>
  );
}

function DecisionForm({
  view,
  busy,
  onPreviewDecision,
}: {
  readonly view: HilAuthorizationView;
  readonly busy: boolean;
  readonly onPreviewDecision?: (input: HilDecisionPreviewInput) => void;
}) {
  const defaultCode: HilReasonCode =
    view.operation === 'approve' ? 'threat_confirmed' : 'false_positive';
  const [reasonCode, setReasonCode] = useState<HilReasonCode>(defaultCode);
  const [reasonText, setReasonText] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const reason = normalizeHilReason(reasonCode, reasonText);
  const challenge = view.challenge;
  const bindingMatches = challengeMatchesExactView(view);
  const canSubmit = Boolean(
    challenge &&
    bindingMatches &&
    view.challengeUse === 'available' &&
    confirmed &&
    reason &&
    onPreviewDecision &&
    !busy,
  );

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAttempted(true);
    if (!challenge || !confirmed || !reason || !bindingMatches) return;
    onPreviewDecision?.({
      operation: view.operation,
      challengeId: challenge.challenge_id,
      idempotencyKey: view.idempotencyKey,
      confirmedExactArtifact: true,
      reason,
    });
  }

  const approve = view.operation === 'approve';
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="decision-form-title"
      sx={{
        p: { xs: 2.25, md: 3 },
        borderColor: approve
          ? semanticTokens.critical.border
          : semanticTokens.info.border,
      }}
    >
      <Stack spacing={2.5}>
        <SectionHeading
          id="decision-form-title"
          eyebrow="Human decision"
          title={approve ? 'Approve exact artifact' : 'Reject exact artifact'}
          description={
            approve
              ? 'Approval is bound only to the displayed version and digests. It does not run nftables from the browser.'
              : 'Rejection records no enforcement authority and cannot be reused as an approval.'
          }
          action={
            <StatusBadge
              label={approve ? 'Consequential path' : 'No authority created'}
              tone={approve ? 'critical' : 'info'}
            />
          }
        />
        <Box component="form" onSubmit={handleSubmit} noValidate>
          <Stack spacing={2}>
            <FormControl fullWidth>
              <InputLabel id="hil-reason-code-label">Reason code</InputLabel>
              <Select
                labelId="hil-reason-code-label"
                label="Reason code"
                value={reasonCode}
                onChange={(event) =>
                  setReasonCode(event.target.value as HilReasonCode)
                }
              >
                {HIL_REASON_CODES.map((code) => (
                  <MenuItem key={code} value={code}>
                    {humanizeIdentifier(code)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              required
              fullWidth
              multiline
              minRows={3}
              label="Decision reason"
              value={reasonText}
              onChange={(event) => setReasonText(event.target.value)}
              error={attempted && reason === null}
              helperText={
                attempted && reason === null
                  ? 'Enter 1–500 valid characters after NFC normalization.'
                  : 'Normalized to NFC and trimmed before the checked hil-reason-v1 shape is previewed.'
              }
              inputProps={{ maxLength: 500 }}
            />
            <FormControl error={attempted && !confirmed}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={confirmed}
                    onChange={(event) => setConfirmed(event.target.checked)}
                  />
                }
                label={`I confirm the exact ${view.operation} operation, policy version ${view.validationReview.policy.policy_version}, target ${view.validationReview.policy.target_ipv4}, and every displayed digest.`}
              />
              {attempted && !confirmed ? (
                <FormHelperText>
                  Exact-artifact confirmation is required.
                </FormHelperText>
              ) : null}
            </FormControl>
            <Button
              type="submit"
              variant={approve ? 'contained' : 'outlined'}
              color={approve ? 'error' : 'secondary'}
              disabled={!canSubmit}
              sx={{ alignSelf: { sm: 'flex-start' } }}
            >
              Preview {approve ? 'approval' : 'rejection'} decision
            </Button>
          </Stack>
        </Box>
      </Stack>
    </Paper>
  );
}

const errorPresentation: Readonly<
  Record<
    HilAuthorizationErrorStateName,
    {
      readonly label: string;
      readonly title: string;
      readonly tone: SemanticTone;
    }
  >
> = {
  expired: {
    label: 'Challenge expired',
    title: 'Challenge window expired',
    tone: 'critical',
  },
  replayed: {
    label: 'Replay rejected',
    title: 'Single-use challenge already consumed',
    tone: 'critical',
  },
  stale: {
    label: 'Version stale',
    title: 'Policy version changed',
    tone: 'critical',
  },
  mutation: {
    label: 'Digest mismatch',
    title: 'Exact artifact changed',
    tone: 'critical',
  },
  conflict: {
    label: 'Idempotency conflict',
    title: 'Conflicting decision bytes rejected',
    tone: 'critical',
  },
  'permission-denied': {
    label: 'Permission denied',
    title: 'Decision permission required',
    tone: 'warning',
  },
  unauthorized: {
    label: 'Authentication required',
    title: 'Administrator session required',
    tone: 'warning',
  },
  'rate-limited': {
    label: 'Rate limited',
    title: 'Decision rate limit reached',
    tone: 'warning',
  },
  'step-up-failed': {
    label: 'Step-up failed',
    title: 'Authentication was not refreshed',
    tone: 'critical',
  },
};

function ErrorOutcome({
  state,
}: {
  readonly state: Extract<HilAuthorizationState, { error: unknown }>;
}) {
  const presentation = errorPresentation[state.kind];
  return (
    <Paper
      component="section"
      variant="outlined"
      role="alert"
      aria-labelledby="authorization-error-title"
      sx={{ p: { xs: 2.25, md: 3 } }}
    >
      <Stack spacing={2}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={1.5}
          alignItems={{ xs: 'flex-start', sm: 'center' }}
          justifyContent="space-between"
        >
          <Typography
            id="authorization-error-title"
            component="h2"
            variant="h3"
          >
            {presentation.title}
          </Typography>
          <StatusBadge label={presentation.label} tone={presentation.tone} />
        </Stack>
        <Typography>{state.error.message}</Typography>
        {state.kind === 'rate-limited' ? (
          <Alert severity="warning">
            Retry-After: {state.retryAfterSeconds} seconds
          </Alert>
        ) : null}
        <DetailList
          items={[
            { label: 'Safe error code', value: state.error.code },
            { label: 'Trace ID', value: shortIdentifier(state.error.trace_id) },
            { label: 'Decision authority', value: 'None' },
            { label: 'Next requirement', value: 'New valid server state' },
          ]}
        />
        <Button disabled variant="contained">
          Decision unavailable
        </Button>
      </Stack>
    </Paper>
  );
}

function DecisionOutcome({
  view,
  outcome,
}: {
  readonly view: HilAuthorizationView;
  readonly outcome: 'approved' | 'rejected';
}) {
  const decision = view.decision;
  const approved = outcome === 'approved';
  return (
    <Paper
      component="section"
      variant="outlined"
      role="status"
      aria-labelledby="decision-outcome-title"
      sx={{
        p: { xs: 2.25, md: 3 },
        borderColor: approved
          ? semanticTokens.warning.border
          : semanticTokens.info.border,
        bgcolor: approved
          ? semanticTokens.warning.background
          : semanticTokens.info.background,
      }}
    >
      <Stack spacing={2.25}>
        <SectionHeading
          id="decision-outcome-title"
          eyebrow="Fixture terminal state"
          title={
            approved
              ? 'Fixture approval recorded'
              : 'Fixture rejection recorded'
          }
          description={
            approved
              ? 'The checked decision shape is displayed as consumed. This browser created no authorized job, capability, or enforcement action.'
              : 'The checked rejection shape is displayed as consumed. It creates no firewall authority.'
          }
          action={
            <StatusBadge
              label={approved ? 'Approval preview only' : 'Rejected'}
              tone={approved ? 'warning' : 'info'}
            />
          }
        />
        {decision && view.reason ? (
          <DetailList
            items={[
              { label: 'Decision', value: decision.decision },
              { label: 'Operation', value: decision.operation },
              { label: 'Actor', value: decision.actor_id },
              { label: 'Reason code', value: view.reason.reason_code },
              { label: 'Reason', value: view.reason.reason_text },
              { label: 'Decided', value: formatUtc(decision.decided_at) },
              {
                label: 'Decision valid until',
                value: formatUtc(decision.decision_valid_until),
              },
              { label: 'Challenge state', value: 'consumed' },
            ]}
          />
        ) : null}
        <Alert severity={approved ? 'warning' : 'info'}>
          {approved
            ? 'Any later mutation, expiry, or failed dispatcher recheck still fails closed. No automatic execution follows this fixture.'
            : 'A rejected artifact must be revalidated and receive a new challenge before any future decision.'}
        </Alert>
      </Stack>
    </Paper>
  );
}

function stateHeader(
  state: Exclude<HilAuthorizationState, { kind: 'loading' }>,
) {
  if ('error' in state) {
    const presentation = errorPresentation[state.kind];
    return { label: presentation.label, tone: presentation.tone } as const;
  }
  switch (state.kind) {
    case 'ready':
      return { label: 'Ready to choose', tone: 'info' } as const;
    case 'step-up-required':
      return { label: 'Step-up required', tone: 'warning' } as const;
    case 'step-up-complete':
      return { label: 'Session rotated', tone: 'positive' } as const;
    case 'challenge-issued':
      return { label: 'Approve challenge ready', tone: 'warning' } as const;
    case 'reject-challenge-issued':
      return { label: 'Reject challenge ready', tone: 'info' } as const;
    case 'approved':
      return { label: 'Approval fixture complete', tone: 'warning' } as const;
    case 'rejected':
      return { label: 'Rejection fixture complete', tone: 'info' } as const;
  }
}

export function HilAuthorizationResults({
  state,
  busy = false,
  onPreviewChallenge,
  onPreviewStepUp,
  onPreviewDecision,
}: HilAuthorizationResultsProps) {
  if (state.kind === 'loading') return <LoadingAuthorization />;
  const header = stateHeader(state);
  const challenged =
    state.kind === 'step-up-complete' ||
    state.kind === 'challenge-issued' ||
    state.kind === 'reject-challenge-issued';

  return (
    <Stack spacing={{ xs: 3.5, md: 4.5 }}>
      <PageHeader
        eyebrow="Human authorization"
        title="HIL authorization review"
        description="A single administrator reviews an exact validated policy, chooses approval or rejection, and confirms the operation-bound artifact. Every transition shown here is frozen fixture presentation only."
        status={<StatusBadge label={header.label} tone={header.tone} />}
      />
      <FixtureBoundary />

      <Grid container spacing={3} alignItems="flex-start">
        <Grid size={{ xs: 12, lg: 8 }}>
          <Stack spacing={3}>
            <ExactArtifactBinding view={state.view} />
            {state.kind === 'ready' ? (
              <OperationChoice
                key={state.view.operation}
                view={state.view}
                busy={busy}
                onPreviewChallenge={onPreviewChallenge}
              />
            ) : null}
            {state.kind === 'step-up-required' ? (
              <StepUpPanel
                view={state.view}
                busy={busy}
                onPreviewStepUp={onPreviewStepUp}
              />
            ) : null}
            {challenged ? (
              <DecisionForm
                key={state.view.challenge?.challenge_id}
                view={state.view}
                busy={busy}
                onPreviewDecision={onPreviewDecision}
              />
            ) : null}
            {'error' in state ? <ErrorOutcome state={state} /> : null}
            {state.kind === 'approved' || state.kind === 'rejected' ? (
              <DecisionOutcome view={state.view} outcome={state.kind} />
            ) : null}
          </Stack>
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Stack spacing={3}>
            <ChallengeFacts view={state.view} />
            <Paper
              component="section"
              variant="outlined"
              aria-labelledby="hil-boundary-title"
              sx={{ p: { xs: 2.25, md: 2.5 } }}
            >
              <Stack spacing={1.5}>
                <Typography id="hil-boundary-title" component="h2" variant="h3">
                  Authority boundary
                </Typography>
                <StatusBadge
                  label="Browser has no executor authority"
                  tone="neutral"
                />
                <Typography variant="body2" color="text.secondary">
                  The future server remains responsible for session, CSRF,
                  Argon2id step-up, rate limits, exact-byte checks, nonce
                  consumption, audit, and idempotency. The dispatcher and
                  executor remain outside this UI.
                </Typography>
              </Stack>
            </Paper>
          </Stack>
        </Grid>
      </Grid>
    </Stack>
  );
}
