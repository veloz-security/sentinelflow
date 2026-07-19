import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  CircularProgress,
  FormControlLabel,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { DetailList } from '../components/DetailList';
import { ProvenanceTag } from '../components/ProvenanceTag';
import { SectionHeading } from '../components/SectionHeading';
import { StatusBadge } from '../components/StatusBadge';
import { ApiClientError } from './apiClient';
import type {
  EnforcementActionDetail,
  RevocationArtifactBinding,
  RevocationChallengeEnvelope,
  RevocationDecisionEnvelope,
  RevocationReasonCode,
} from './contracts';
import { LiveError } from './LiveFeedback';
import { createHILIdempotencyKey } from './policyHil';
import {
  reasonForRevocation,
  revocationArtifactBinding,
  revocationBindingFingerprint,
  revocationReadiness,
  validateRevocationReason,
} from './revocationHil';
import { useSession } from './sessionContext';

interface PendingRevocationChallenge {
  readonly envelope: Readonly<RevocationChallengeEnvelope>;
  readonly binding: Readonly<RevocationArtifactBinding>;
  readonly idempotencyKey: string;
  readonly intentFingerprint: string;
  readonly confirmationFingerprint: string;
}

interface RetryAuthority {
  readonly idempotencyKey: string;
  readonly intentFingerprint: string;
}

export interface RevocationDecisionPanelProps {
  readonly action: Readonly<EnforcementActionDetail>;
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
  actionFingerprint: string,
  reasonCode: RevocationReasonCode,
  reasonText: string,
): string {
  return JSON.stringify([
    actionFingerprint,
    reasonCode,
    reasonText.normalize('NFC'),
  ]);
}

function confirmationFingerprint(
  intent: string,
  envelope: Readonly<RevocationChallengeEnvelope>,
): string {
  return JSON.stringify([
    intent,
    envelope.challenge.challenge_id,
    envelope.challenge.canonical_artifact_digest,
    envelope.canonical_revoke_artifact,
  ]);
}

function invalidatesAuthority(error: ApiClientError): boolean {
  return (
    error.status === 401 ||
    error.status === 403 ||
    error.status === 409 ||
    error.envelope.code === 'challenge_expired' ||
    error.envelope.code === 'challenge_consumed' ||
    error.envelope.code === 'validation_failed' ||
    error.envelope.code === 'schema_invalid' ||
    error.envelope.code === 'digest_mismatch' ||
    error.envelope.code === 'stale_version'
  );
}

export function RevocationDecisionPanel(props: RevocationDecisionPanelProps) {
  return (
    <RevocationDecisionPanelContent
      key={revocationBindingFingerprint(props.action)}
      {...props}
    />
  );
}

function RevocationDecisionPanelContent({
  action,
  onCommitted,
  now = Date.now,
}: RevocationDecisionPanelProps) {
  const session = useSession();
  const [reasonCode, setReasonCode] =
    useState<RevocationReasonCode>('operator_request');
  const [reasonText, setReasonText] = useState('');
  const [challenge, setChallenge] = useState<PendingRevocationChallenge | null>(
    null,
  );
  const [retryAuthority, setRetryAuthority] = useState<RetryAuthority | null>(
    null,
  );
  const [stepUpRequired, setStepUpRequired] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmedFingerprint, setConfirmedFingerprint] = useState<
    string | null
  >(null);
  const [pending, setPending] = useState<
    'challenge' | 'step-up' | 'decision' | null
  >(null);
  const [error, setError] = useState<ApiClientError | null>(null);
  const [result, setResult] =
    useState<Readonly<RevocationDecisionEnvelope> | null>(null);
  const mounted = useRef(true);
  const authorityGeneration = useRef(0);

  useEffect(
    () => () => {
      mounted.current = false;
      authorityGeneration.current += 1;
    },
    [],
  );

  const bindingFingerprint = revocationBindingFingerprint(action);
  const currentIntent = intentFingerprint(
    bindingFingerprint,
    reasonCode,
    reasonText,
  );
  const currentIntentRef = useRef(currentIntent);
  useEffect(() => {
    currentIntentRef.current = currentIntent;
  }, [currentIntent]);
  const readiness = revocationReadiness(action, session.csrfAvailable);
  const reason = useMemo(
    () => reasonForRevocation(reasonCode, reasonText),
    [reasonCode, reasonText],
  );
  const reasonError = validateRevocationReason(reason);
  const confirmed =
    challenge !== null &&
    confirmedFingerprint === challenge.confirmationFingerprint;

  const resetIssuedAuthority = () => {
    authorityGeneration.current += 1;
    setChallenge(null);
    setRetryAuthority(null);
    setStepUpRequired(false);
    setPassword('');
    setConfirmedFingerprint(null);
    setError(null);
    setResult(null);
  };

  const acquireChallenge = async (idempotencyKey?: string) => {
    if (!readiness.ready || reasonError) return;
    const requestIntent = currentIntent;
    const requestGeneration = authorityGeneration.current + 1;
    authorityGeneration.current = requestGeneration;
    const key = idempotencyKey ?? createHILIdempotencyKey();
    const binding = revocationArtifactBinding(action);
    setPending('challenge');
    setError(null);
    setStepUpRequired(false);
    setConfirmedFingerprint(null);
    try {
      const envelope = await session.issueRevocationChallenge(
        action.action_id,
        binding,
        key,
      );
      if (
        !mounted.current ||
        authorityGeneration.current !== requestGeneration ||
        currentIntentRef.current !== requestIntent
      ) {
        return;
      }
      if (Date.parse(envelope.challenge.expires_at) <= now()) {
        throw new ApiClientError(
          409,
          Object.freeze({
            code: 'challenge_expired',
            message: 'The issued revocation challenge is already expired.',
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
        intentFingerprint: requestIntent,
        confirmationFingerprint: confirmationFingerprint(
          requestIntent,
          envelope,
        ),
      });
      setRetryAuthority(null);
    } catch (caught) {
      if (
        !mounted.current ||
        authorityGeneration.current !== requestGeneration ||
        currentIntentRef.current !== requestIntent
      ) {
        return;
      }
      if (
        caught instanceof ApiClientError &&
        caught.envelope.code === 'step_up_required'
      ) {
        setRetryAuthority({
          idempotencyKey: key,
          intentFingerprint: requestIntent,
        });
        setStepUpRequired(true);
      } else if (caught instanceof ApiClientError) {
        setError(caught);
      }
    } finally {
      if (
        mounted.current &&
        authorityGeneration.current === requestGeneration &&
        currentIntentRef.current === requestIntent
      ) {
        setPending(null);
      }
    }
  };

  const performStepUp = async (event: FormEvent) => {
    event.preventDefault();
    if (
      !retryAuthority ||
      retryAuthority.intentFingerprint !== currentIntent ||
      password.length === 0
    ) {
      resetIssuedAuthority();
      return;
    }
    const authority = retryAuthority;
    const requestGeneration = authorityGeneration.current;
    setPending('step-up');
    setError(null);
    try {
      await session.stepUp(password);
      if (
        !mounted.current ||
        authorityGeneration.current !== requestGeneration ||
        currentIntentRef.current !== authority.intentFingerprint
      ) {
        return;
      }
      setPassword('');
      setStepUpRequired(false);
      setPending(null);
      await acquireChallenge(authority.idempotencyKey);
    } catch (caught) {
      if (
        mounted.current &&
        authorityGeneration.current === requestGeneration &&
        currentIntentRef.current === authority.intentFingerprint &&
        caught instanceof ApiClientError
      ) {
        if (caught.status === 401 || caught.status === 403) {
          resetIssuedAuthority();
          setError(caught);
        } else {
          setError(caught);
          setPending(null);
          setPassword('');
        }
      }
    }
  };

  const commitRevocation = async () => {
    if (
      !challenge ||
      challenge.intentFingerprint !== currentIntent ||
      confirmedFingerprint !== challenge.confirmationFingerprint
    ) {
      resetIssuedAuthority();
      return;
    }
    if (Date.parse(challenge.envelope.challenge.expires_at) <= now()) {
      resetIssuedAuthority();
      setError(
        new ApiClientError(
          409,
          Object.freeze({
            code: 'challenge_expired',
            message:
              'The exact revocation challenge expired before submission.',
            trace_id: '00000000-0000-4000-8000-000000000000',
            details: Object.freeze({}),
          }),
          null,
        ),
      );
      return;
    }
    const submitted = challenge;
    const requestGeneration = authorityGeneration.current;
    setPending('decision');
    setError(null);
    try {
      const committed = await session.decideRevocation(
        action.action_id,
        submitted.binding,
        submitted.envelope,
        reason,
        submitted.idempotencyKey,
      );
      if (
        !mounted.current ||
        authorityGeneration.current !== requestGeneration ||
        currentIntentRef.current !== submitted.intentFingerprint
      ) {
        return;
      }
      setResult(committed);
      setChallenge(null);
      setConfirmedFingerprint(null);
      onCommitted?.();
    } catch (caught) {
      if (
        mounted.current &&
        authorityGeneration.current === requestGeneration &&
        currentIntentRef.current === submitted.intentFingerprint &&
        caught instanceof ApiClientError
      ) {
        setError(caught);
        if (invalidatesAuthority(caught)) {
          authorityGeneration.current += 1;
          setChallenge(null);
          setConfirmedFingerprint(null);
        }
      }
    } finally {
      if (
        mounted.current &&
        authorityGeneration.current === requestGeneration &&
        currentIntentRef.current === submitted.intentFingerprint
      ) {
        setPending(null);
      }
    }
  };

  return (
    <Card variant="outlined">
      <CardContent>
        <SectionHeading
          id="action-revocation-heading"
          title="Manual revocation"
          description="A separate server-derived delete artifact requires its own session-bound challenge, administrator reason, exact confirmation, and audit trail. The original add approval grants no removal authority."
          action={<ProvenanceTag kind="human" />}
        />

        <DetailList
          items={[
            { label: 'Action version', value: action.version },
            { label: 'Target', value: <code>{action.target_ipv4}</code> },
            {
              label: 'Original add digest',
              value: <code>{action.canonical_artifact_digest}</code>,
            },
          ]}
        />

        {!readiness.ready ? (
          <Alert
            severity={action.state === 'active' ? 'warning' : 'info'}
            sx={{ mt: 2 }}
          >
            <Typography sx={{ fontWeight: 720 }}>
              Manual revocation is unavailable
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
              Exact revocation recorded
            </Typography>
            <Typography variant="body2">
              Revocation <code>{result.revocation_id}</code> is bound to
              decision <code>{result.decision.decision_id}</code>.
              {'replayed' in result
                ? ' The server confirmed the exact historical result, expired the previous session, and requires a fresh sign-in. No new authority was created.'
                : ' The administrator session and CSRF guard were rotated.'}
            </Typography>
          </Alert>
        ) : null}

        {readiness.ready && !result ? (
          <Stack spacing={2.25} sx={{ mt: 2.5 }}>
            <TextField
              select
              label="Revocation reason category"
              value={reasonCode}
              disabled={pending !== null}
              onChange={(event) => {
                resetIssuedAuthority();
                setReasonCode(event.target.value as RevocationReasonCode);
              }}
            >
              <MenuItem value="emergency_revoke">Emergency removal</MenuItem>
              <MenuItem value="operator_request">Operator request</MenuItem>
              <MenuItem value="other">Other</MenuItem>
            </TextField>
            <TextField
              label="Administrator revocation reason"
              value={reasonText}
              required
              error={reasonText.length > 0 && Boolean(reasonError)}
              helperText={
                reasonError ??
                'The NFC-normalized reason is bound into the revocation authorization digest.'
              }
              inputProps={{ maxLength: 500 }}
              disabled={pending !== null}
              onChange={(event) => {
                resetIssuedAuthority();
                setReasonText(event.target.value);
              }}
            />
            <Box>
              <Button
                variant="outlined"
                disabled={
                  Boolean(reasonError) || pending !== null || challenge !== null
                }
                startIcon={
                  pending === 'challenge' ? (
                    <CircularProgress size={16} color="inherit" />
                  ) : undefined
                }
                onClick={() => void acquireChallenge()}
              >
                {pending === 'challenge'
                  ? 'Verifying exact revoke artifact'
                  : 'Request exact revoke challenge'}
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
                    Step-up rotates the session, then retries the same
                    revocation intent and idempotency key. It does not remove
                    the rule.
                  </Typography>
                  <TextField
                    label="Current password for revocation"
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
                        : 'Step up and retry revocation challenge'}
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
                    <StatusBadge label="Browser checks passed" tone="warning" />
                    <Typography variant="caption">
                      Server digest revalidation required · Expires{' '}
                      {formatTime(challenge.envelope.challenge.expires_at)}
                    </Typography>
                  </Stack>
                  <Alert severity="info">
                    <Typography sx={{ fontWeight: 720 }}>
                      Browser assurance boundary
                    </Typography>
                    <Typography variant="body2">
                      The browser recalculated the exact delete artifact and
                      nonce digests, then compared the action, policy identity,
                      evidence, and session timing with loaded projections.
                      Policy, validation, and session digests are displayed
                      server-bound values, not independent browser proof. The
                      API must revalidate them before recording revocation.
                    </Typography>
                  </Alert>
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
                        label: 'Server-derived policy',
                        value: (
                          <span>
                            <code>{challenge.envelope.policy_id}</code> ·
                            version {challenge.envelope.policy_version}
                          </span>
                        ),
                      },
                      {
                        label: 'Policy digest (server-bound)',
                        value: (
                          <code>
                            {challenge.envelope.challenge.policy_digest}
                          </code>
                        ),
                      },
                      {
                        label: 'Evidence snapshot (browser-compared)',
                        value: (
                          <code>
                            {
                              challenge.envelope.challenge
                                .evidence_snapshot_digest
                            }
                          </code>
                        ),
                      },
                      {
                        label: 'Validation digest (server-bound)',
                        value: (
                          <code>
                            {
                              challenge.envelope.challenge
                                .validation_snapshot_digest
                            }
                          </code>
                        ),
                      },
                      {
                        label: 'Session digest (server-bound)',
                        value: (
                          <code>
                            {challenge.envelope.challenge.session_digest}
                          </code>
                        ),
                      },
                      {
                        label: 'Delete artifact digest (browser-recalculated)',
                        value: (
                          <code>
                            {
                              challenge.envelope.challenge
                                .canonical_artifact_digest
                            }
                          </code>
                        ),
                      },
                    ]}
                  />
                  <Typography component="h3" variant="h3">
                    Exact delete artifact to authorize
                  </Typography>
                  <Box
                    component="pre"
                    aria-label="Exact revoke artifact awaiting confirmation"
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
                    {challenge.envelope.canonical_revoke_artifact}
                  </Box>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={confirmed}
                        onChange={(event) =>
                          setConfirmedFingerprint(
                            event.target.checked
                              ? challenge.confirmationFingerprint
                              : null,
                          )
                        }
                      />
                    }
                    label="I reviewed the exact delete artifact and displayed bindings. I understand policy, validation, and session digests are server-bound and must be revalidated by the API."
                  />
                  <Box>
                    <Button
                      variant="contained"
                      color="error"
                      disabled={!confirmed || pending !== null}
                      onClick={() => void commitRevocation()}
                    >
                      {pending === 'decision'
                        ? 'Recording exact revocation'
                        : 'Revoke exact active action'}
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
