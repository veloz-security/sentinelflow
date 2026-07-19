import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  CircularProgress,
  FormControl,
  FormControlLabel,
  FormLabel,
  Link,
  MenuItem,
  Radio,
  RadioGroup,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { DetailList } from '../components/DetailList';
import { ProvenanceTag } from '../components/ProvenanceTag';
import { SectionHeading } from '../components/SectionHeading';
import { StatusBadge } from '../components/StatusBadge';
import { ApiClientError } from './apiClient';
import type {
  HILChallengeEnvelope,
  HILDecisionEnvelope,
  HILOperation,
  HILReasonCode,
  PolicyArtifactBinding,
  PolicyDetail,
} from './contracts';
import { LiveError } from './LiveFeedback';
import {
  createHILIdempotencyKey,
  policyArtifactBinding,
  policyBindingFingerprint,
  policyDecisionReadiness,
  reasonForDecision,
  validateDecisionReason,
  verifyPolicyCommandIntegrity,
  type PolicyCommandIntegrityResult,
} from './policyHil';
import { useSession } from './sessionContext';

interface PendingChallenge {
  readonly envelope: Readonly<HILChallengeEnvelope>;
  readonly binding: Readonly<PolicyArtifactBinding>;
  readonly idempotencyKey: string;
  readonly intentFingerprint: string;
}

interface PolicyCommandIntegrityState extends PolicyCommandIntegrityResult {
  readonly fingerprint: string;
}

function pendingCommandIntegrity(
  fingerprint: string,
): Readonly<PolicyCommandIntegrityState> {
  return Object.freeze({
    fingerprint,
    status: 'pending',
    verified: false,
    blockers: Object.freeze([
      'Browser SHA-256 verification of both exact command artifacts is pending.',
    ]),
  });
}

export interface PolicyDecisionPanelProps {
  readonly policy: Readonly<PolicyDetail>;
  readonly onCommitted?: () => void;
  readonly now?: () => number;
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value));
}

function intentFingerprint(
  operation: HILOperation,
  reasonCode: HILReasonCode,
  reasonText: string,
): string {
  return JSON.stringify([operation, reasonCode, reasonText.normalize('NFC')]);
}

function reasonOptions(operation: HILOperation) {
  return operation === 'approve'
    ? ([
        ['threat_confirmed', 'Threat confirmed'],
        ['operator_request', 'Operator request'],
        ['other', 'Other'],
      ] as const)
    : ([
        ['false_positive', 'False positive'],
        ['business_exception', 'Business exception'],
        ['other', 'Other'],
      ] as const);
}

export function PolicyDecisionPanel(props: PolicyDecisionPanelProps) {
  return (
    <PolicyDecisionPanelContent
      key={policyBindingFingerprint(props.policy)}
      {...props}
    />
  );
}

function PolicyDecisionPanelContent({
  policy,
  onCommitted,
  now = Date.now,
}: PolicyDecisionPanelProps) {
  const session = useSession();
  const [operation, setOperation] = useState<HILOperation>('approve');
  const [reasonCode, setReasonCode] =
    useState<HILReasonCode>('threat_confirmed');
  const [reasonText, setReasonText] = useState('');
  const [challenge, setChallenge] = useState<PendingChallenge | null>(null);
  const [retryKey, setRetryKey] = useState<string | null>(null);
  const [stepUpRequired, setStepUpRequired] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [pending, setPending] = useState<
    'challenge' | 'step-up' | 'decision' | null
  >(null);
  const [error, setError] = useState<ApiClientError | null>(null);
  const [result, setResult] = useState<Readonly<HILDecisionEnvelope> | null>(
    null,
  );

  const integrityFingerprint = policyBindingFingerprint(policy);
  const [integrityState, setIntegrityState] = useState<
    Readonly<PolicyCommandIntegrityState>
  >(() => pendingCommandIntegrity(integrityFingerprint));
  const commandIntegrity =
    integrityState.fingerprint === integrityFingerprint
      ? integrityState
      : pendingCommandIntegrity(integrityFingerprint);

  const generatedCommand = policy.generated_command;
  const generatedArtifactDigest = policy.generated_artifact_digest;
  const canonicalCommand = policy.canonical_command;
  const canonicalArtifactDigest = policy.canonical_artifact_digest;
  useEffect(() => {
    let cancelled = false;
    void verifyPolicyCommandIntegrity({
      generated_command: generatedCommand,
      generated_artifact_digest: generatedArtifactDigest,
      canonical_command: canonicalCommand,
      canonical_artifact_digest: canonicalArtifactDigest,
    }).then((verification) => {
      if (cancelled) {
        return;
      }
      setIntegrityState(
        Object.freeze({
          fingerprint: integrityFingerprint,
          ...verification,
        }),
      );
    });
    return () => {
      cancelled = true;
    };
  }, [
    canonicalArtifactDigest,
    canonicalCommand,
    generatedArtifactDigest,
    generatedCommand,
    integrityFingerprint,
  ]);

  const serverReadiness = policyDecisionReadiness(
    policy,
    session.csrfAvailable,
    now(),
  );
  const readiness = Object.freeze({
    ready: serverReadiness.ready && commandIntegrity.verified,
    blockers: Object.freeze([
      ...serverReadiness.blockers,
      ...commandIntegrity.blockers,
    ]),
  });
  const reason = useMemo(
    () => reasonForDecision(reasonCode, reasonText),
    [reasonCode, reasonText],
  );
  const reasonError = validateDecisionReason(reason);
  const currentIntent = intentFingerprint(operation, reasonCode, reasonText);

  const resetIssuedAuthority = () => {
    setChallenge(null);
    setRetryKey(null);
    setStepUpRequired(false);
    setPassword('');
    setConfirmed(false);
    setError(null);
    setResult(null);
  };

  const changeOperation = (value: HILOperation) => {
    resetIssuedAuthority();
    setOperation(value);
    setReasonCode(value === 'approve' ? 'threat_confirmed' : 'false_positive');
  };

  const acquireChallenge = async (idempotencyKey?: string) => {
    const binding = policyArtifactBinding(policy, operation);
    if (!readiness.ready || !binding || reasonError) {
      return;
    }
    const key = idempotencyKey ?? createHILIdempotencyKey();
    setPending('challenge');
    setError(null);
    setStepUpRequired(false);
    setConfirmed(false);
    try {
      const envelope = await session.issuePolicyChallenge(
        policy.policy_id,
        binding,
        key,
      );
      if (Date.parse(envelope.challenge.expires_at) <= now()) {
        throw new ApiClientError(
          409,
          Object.freeze({
            code: 'challenge_expired',
            message: 'The issued challenge is already expired.',
            trace_id: '00000000-0000-4000-8000-000000000000',
            details: Object.freeze({}),
          }),
          null,
        );
      }
      setChallenge({
        envelope,
        binding,
        idempotencyKey: key,
        intentFingerprint: currentIntent,
      });
      setRetryKey(null);
    } catch (caught) {
      if (
        caught instanceof ApiClientError &&
        caught.envelope.code === 'step_up_required'
      ) {
        setRetryKey(key);
        setStepUpRequired(true);
      } else if (caught instanceof ApiClientError) {
        setError(caught);
      }
    } finally {
      setPending(null);
    }
  };

  const performStepUp = async (event: FormEvent) => {
    event.preventDefault();
    if (!retryKey || password.length === 0) {
      return;
    }
    const key = retryKey;
    setPending('step-up');
    setError(null);
    try {
      await session.stepUp(password);
      setPassword('');
      setStepUpRequired(false);
      setPending(null);
      await acquireChallenge(key);
    } catch (caught) {
      if (caught instanceof ApiClientError) {
        setError(caught);
      }
      setPending(null);
      setPassword('');
    }
  };

  const commitDecision = async () => {
    if (
      !challenge ||
      !confirmed ||
      challenge.intentFingerprint !== currentIntent
    ) {
      setChallenge(null);
      setConfirmed(false);
      return;
    }
    if (Date.parse(challenge.envelope.challenge.expires_at) <= now()) {
      setChallenge(null);
      setConfirmed(false);
      setError(
        new ApiClientError(
          409,
          Object.freeze({
            code: 'challenge_expired',
            message:
              'The exact challenge expired before the decision was submitted.',
            trace_id: '00000000-0000-4000-8000-000000000000',
            details: Object.freeze({}),
          }),
          null,
        ),
      );
      return;
    }
    setPending('decision');
    setError(null);
    try {
      const committed = await session.decidePolicy(
        policy.policy_id,
        challenge.binding,
        challenge.envelope,
        reason,
        challenge.idempotencyKey,
      );
      setResult(committed);
      setChallenge(null);
      setConfirmed(false);
      onCommitted?.();
    } catch (caught) {
      if (caught instanceof ApiClientError) {
        setError(caught);
        if (
          caught.status === 409 ||
          caught.envelope.code === 'challenge_expired' ||
          caught.envelope.code === 'validation_failed'
        ) {
          setChallenge(null);
          setConfirmed(false);
        }
      }
    } finally {
      setPending(null);
    }
  };

  const options = reasonOptions(operation);
  return (
    <Card variant="outlined">
      <CardContent>
        <SectionHeading
          id="policy-human-heading"
          title="Human decision"
          description="The server issues one session-, operation-, and exact-artifact-bound challenge. This interface cannot repair a failed prerequisite or create authority locally."
          action={<ProvenanceTag kind="human" />}
        />

        {policy.decision ? (
          <DetailList
            items={[
              { label: 'Decision', value: policy.decision.decision },
              { label: 'Administrator', value: policy.decision.actor_id },
              {
                label: 'Decided',
                value: formatTime(policy.decision.decided_at),
              },
              {
                label: 'Reason digest',
                value: <code>{policy.decision.reason_digest}</code>,
              },
            ]}
          />
        ) : null}

        {!readiness.ready ? (
          <Alert severity="warning" sx={{ mt: 2 }}>
            <Typography sx={{ fontWeight: 720 }}>
              HIL decision is disabled
            </Typography>
            <Box component="ul" sx={{ mb: 0, pl: 2.5 }}>
              {readiness.blockers.map((blocker) => (
                <li key={blocker}>{blocker}</li>
              ))}
            </Box>
          </Alert>
        ) : null}

        {error ? (
          <Box sx={{ mt: 2 }}>
            <LiveError error={error} onRetry={() => setError(null)} />
            {error.retryAfterSeconds ? (
              <Typography variant="caption">
                Retry after {error.retryAfterSeconds} seconds.
              </Typography>
            ) : null}
          </Box>
        ) : null}

        {result ? (
          <Alert severity="success" role="status" sx={{ mt: 2 }}>
            <Typography sx={{ fontWeight: 720 }}>
              Exact artifact {result.decision.decision}
            </Typography>
            <Typography variant="body2">
              Decision <code>{result.decision.decision_id}</code> was recorded;
              {'replayed' in result
                ? ' the server confirmed an exact prior result, expired the old session, and requires sign-in. No new authorization was created.'
                : ' the administrator session and CSRF guard were rotated.'}
            </Typography>
            {result.action_id ? (
              <Link
                component={RouterLink}
                to={`/enforcement-actions/${result.action_id}`}
              >
                Open queued enforcement action
              </Link>
            ) : null}
          </Alert>
        ) : null}

        {!policy.decision && !result ? (
          <Stack spacing={2.25} sx={{ mt: 2.5 }}>
            <FormControl disabled={!readiness.ready || pending !== null}>
              <FormLabel id="hil-operation-label">Decision</FormLabel>
              <RadioGroup
                row
                aria-labelledby="hil-operation-label"
                value={operation}
                onChange={(event) =>
                  changeOperation(event.target.value as HILOperation)
                }
              >
                <FormControlLabel
                  value="approve"
                  control={<Radio />}
                  label="Approve temporary block"
                />
                <FormControlLabel
                  value="reject"
                  control={<Radio />}
                  label="Reject artifact"
                />
              </RadioGroup>
            </FormControl>
            <TextField
              select
              label="Reason category"
              value={reasonCode}
              disabled={!readiness.ready || pending !== null}
              onChange={(event) => {
                resetIssuedAuthority();
                setReasonCode(event.target.value as HILReasonCode);
              }}
            >
              {options.map(([value, label]) => (
                <MenuItem key={value} value={value}>
                  {label}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="Administrator reason"
              value={reasonText}
              required
              error={reasonText.length > 0 && Boolean(reasonError)}
              helperText={
                reasonError ??
                'The normalized reason is bound into the final decision digest.'
              }
              inputProps={{ maxLength: 500 }}
              disabled={!readiness.ready || pending !== null}
              onChange={(event) => {
                resetIssuedAuthority();
                setReasonText(event.target.value);
              }}
            />

            <Box>
              <Button
                variant="outlined"
                disabled={
                  !readiness.ready ||
                  Boolean(reasonError) ||
                  pending !== null ||
                  challenge !== null
                }
                startIcon={
                  pending === 'challenge' ? (
                    <CircularProgress size={16} color="inherit" />
                  ) : undefined
                }
                onClick={() => void acquireChallenge()}
              >
                {pending === 'challenge'
                  ? 'Requesting challenge'
                  : 'Request exact challenge'}
              </Button>
            </Box>

            {stepUpRequired ? (
              <Alert severity="warning">
                <Stack
                  component="form"
                  spacing={1.5}
                  onSubmit={(event) => void performStepUp(event)}
                >
                  <Typography sx={{ fontWeight: 720 }}>
                    Password step-up required
                  </Typography>
                  <Typography variant="body2">
                    Re-authentication rotates the session, then requests a new
                    exact challenge. It does not approve the artifact.
                  </Typography>
                  <TextField
                    label="Current password"
                    type="password"
                    autoComplete="current-password"
                    required
                    inputProps={{ maxLength: 1024 }}
                    value={password}
                    disabled={pending !== null}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                  <Box>
                    <Button
                      type="submit"
                      variant="contained"
                      disabled={pending !== null || password.length === 0}
                    >
                      {pending === 'step-up'
                        ? 'Verifying password'
                        : 'Step up and retry challenge'}
                    </Button>
                  </Box>
                </Stack>
              </Alert>
            ) : null}

            {challenge ? (
              <Box
                sx={{
                  p: 2,
                  border: 1,
                  borderColor: 'warning.light',
                  borderRadius: 1.5,
                  bgcolor: 'background.paper',
                }}
              >
                <Stack spacing={2}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <StatusBadge label="Single-use challenge" tone="warning" />
                    <Typography variant="caption">
                      Expires{' '}
                      {formatTime(challenge.envelope.challenge.expires_at)}
                    </Typography>
                  </Stack>
                  <DetailList
                    items={[
                      {
                        label: 'Challenge ID',
                        value: (
                          <code>
                            {challenge.envelope.challenge.challenge_id}
                          </code>
                        ),
                      },
                      {
                        label: 'Policy digest',
                        value: <code>{policy.policy_digest}</code>,
                      },
                      {
                        label: 'Evidence snapshot',
                        value: <code>{policy.evidence_snapshot_digest}</code>,
                      },
                      {
                        label: 'Validation snapshot',
                        value: (
                          <code>
                            {policy.latest_validation?.snapshot_digest}
                          </code>
                        ),
                      },
                      {
                        label: 'Generated digest',
                        value: <code>{policy.generated_artifact_digest}</code>,
                      },
                      {
                        label: 'Canonical digest',
                        value: <code>{policy.canonical_artifact_digest}</code>,
                      },
                    ]}
                  />
                  <Typography component="h3" variant="h3">
                    Exact canonical command to authorize
                  </Typography>
                  <Box
                    component="pre"
                    aria-label="Exact command awaiting HIL decision"
                    sx={{
                      p: 2,
                      m: 0,
                      overflowX: 'auto',
                      bgcolor: 'oklch(0.955 0.01 285)',
                      borderRadius: 1.5,
                      whiteSpace: 'pre-wrap',
                      overflowWrap: 'anywhere',
                    }}
                  >
                    {policy.canonical_command}
                  </Box>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={confirmed}
                        onChange={(event) => setConfirmed(event.target.checked)}
                      />
                    }
                    label="I reviewed the exact target, TTL, command, evidence, validation, and digests above."
                  />
                  <Box>
                    <Button
                      variant={
                        operation === 'approve' ? 'contained' : 'outlined'
                      }
                      color={operation === 'approve' ? 'primary' : 'error'}
                      disabled={!confirmed || pending !== null}
                      onClick={() => void commitDecision()}
                    >
                      {pending === 'decision'
                        ? 'Recording decision'
                        : operation === 'approve'
                          ? 'Approve exact artifact'
                          : 'Reject exact artifact'}
                    </Button>
                  </Box>
                </Stack>
              </Box>
            ) : null}
          </Stack>
        ) : null}
      </CardContent>
    </Card>
  );
}
