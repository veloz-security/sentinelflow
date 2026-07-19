import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PropsWithChildren,
} from 'react';
import {
  ApiClientError,
  ManagementApiClient,
  managementApi,
} from './apiClient';
import type { SessionProjection } from './contracts';
import type {
  HILChallengeEnvelope,
  HILDecisionEnvelope,
  HILReason,
  PolicyArtifactBinding,
  ReauthenticationNotice,
  RevocationArtifactBinding,
  RevocationChallengeEnvelope,
  RevocationDecisionEnvelope,
  RevocationReason,
} from './contracts';
import {
  challengeMatchesExactBinding,
  decisionMatchesExactBinding,
} from './policyHil';
import {
  checkRevocationChallengeInBrowser,
  revocationDecisionMatchesExactBinding,
} from './revocationHil';
import {
  SessionContext,
  type SessionContextValue,
  type SessionPhase,
} from './sessionContext';

function localSessionError(
  message: string,
  code: 'internal_error' | 'csrf_invalid' = 'internal_error',
  status = 502,
): ApiClientError {
  return new ApiClientError(
    status,
    Object.freeze({
      code,
      message,
      trace_id: '00000000-0000-4000-8000-000000000000',
      details: Object.freeze({}),
    }),
    null,
  );
}

export interface SessionProviderProps extends PropsWithChildren {
  readonly client?: ManagementApiClient;
}

export function SessionProvider({
  children,
  client = managementApi,
}: SessionProviderProps) {
  const [phase, setPhase] = useState<SessionPhase>('bootstrapping');
  const [session, setSession] = useState<Readonly<SessionProjection> | null>(
    null,
  );
  const [error, setError] = useState<ApiClientError | null>(null);
  const [csrfAvailable, setCSRFAvailable] = useState(false);
  const [reauthenticationNotice, setReauthenticationNotice] =
    useState<Readonly<ReauthenticationNotice> | null>(null);
  const [bootstrapRevision, setBootstrapRevision] = useState(0);
  const csrfToken = useRef<string | null>(null);
  const currentSession = useRef<Readonly<SessionProjection> | null>(null);

  const acceptEnvelope = useCallback(
    (envelope: Awaited<ReturnType<ManagementApiClient['session']>>) => {
      csrfToken.current = envelope.csrf_token ?? null;
      currentSession.current = envelope.session;
      setCSRFAvailable(Boolean(envelope.csrf_token));
      setSession(envelope.session);
      setError(null);
      setReauthenticationNotice(null);
      setPhase('authenticated');
    },
    [],
  );

  const clearSession = useCallback(() => {
    csrfToken.current = null;
    currentSession.current = null;
    setCSRFAvailable(false);
    setSession(null);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void client
      .session(controller.signal)
      .then(acceptEnvelope)
      .catch((caught: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        clearSession();
        if (caught instanceof ApiClientError && caught.status === 401) {
          setPhase('anonymous');
          return;
        }
        setError(
          caught instanceof ApiClientError
            ? caught
            : localSessionError(
                'The administrator session could not be restored.',
              ),
        );
        setPhase('error');
      });
    return () => controller.abort();
  }, [acceptEnvelope, bootstrapRevision, clearSession, client]);

  const login = useCallback(
    async (username: string, password: string) => {
      try {
        acceptEnvelope(await client.login(username, password));
      } catch (caught) {
        if (caught instanceof ApiClientError) {
          throw caught;
        }
        throw localSessionError('Sign in could not be completed.');
      }
    },
    [acceptEnvelope, client],
  );

  const invalidate = useCallback(() => {
    clearSession();
    setError(null);
    setReauthenticationNotice(null);
    setPhase('anonymous');
  }, [clearSession]);

  const logout = useCallback(async () => {
    const token = csrfToken.current;
    if (!token) {
      throw localSessionError(
        'This restored session has no CSRF capability. Sign in again before a state-changing request.',
        'csrf_invalid',
        409,
      );
    }
    try {
      await client.logout(token);
    } catch (caught) {
      if (caught instanceof ApiClientError && caught.status === 401) {
        invalidate();
      } else if (
        caught instanceof ApiClientError &&
        caught.envelope.code === 'csrf_invalid'
      ) {
        csrfToken.current = null;
        setCSRFAvailable(false);
      }
      throw caught;
    }
    clearSession();
    setError(null);
    setPhase('anonymous');
  }, [clearSession, client, invalidate]);

  const stepUp = useCallback(
    async (password: string) => {
      const token = csrfToken.current;
      if (!token) {
        throw localSessionError(
          'This restored session has no CSRF capability. Sign in again before step-up.',
          'csrf_invalid',
          409,
        );
      }
      try {
        acceptEnvelope(await client.stepUp(password, token));
      } catch (caught) {
        if (caught instanceof ApiClientError && caught.status === 401) {
          invalidate();
        } else if (
          caught instanceof ApiClientError &&
          caught.envelope.code === 'csrf_invalid'
        ) {
          csrfToken.current = null;
          setCSRFAvailable(false);
        }
        throw caught;
      }
    },
    [acceptEnvelope, client, invalidate],
  );

  const requireCSRF = useCallback((action: string): string => {
    const token = csrfToken.current;
    if (!token) {
      throw localSessionError(
        `This restored session has no CSRF capability. Sign in again before ${action}.`,
        'csrf_invalid',
        409,
      );
    }
    return token;
  }, []);

  const handleMutationFailure = useCallback(
    (caught: unknown, preserveStepUp: boolean) => {
      if (!(caught instanceof ApiClientError)) {
        return;
      }
      if (
        caught.status === 401 &&
        !(preserveStepUp && caught.envelope.code === 'step_up_required')
      ) {
        invalidate();
      } else if (caught.envelope.code === 'csrf_invalid') {
        csrfToken.current = null;
        setCSRFAvailable(false);
      }
    },
    [invalidate],
  );

  const issuePolicyChallenge = useCallback(
    async (
      policyID: string,
      binding: Readonly<PolicyArtifactBinding>,
      idempotencyKey: string,
    ): Promise<Readonly<HILChallengeEnvelope>> => {
      try {
        const challenge = await client.policyDecisionChallenge(
          policyID,
          binding,
          idempotencyKey,
          requireCSRF('requesting an exact-artifact challenge'),
        );
        const acceptedSession = currentSession.current;
        if (
          !acceptedSession ||
          !(await challengeMatchesExactBinding(
            challenge,
            policyID,
            binding,
            acceptedSession,
          ))
        ) {
          throw localSessionError(
            'The challenge did not match the exact reviewed artifact.',
          );
        }
        return challenge;
      } catch (caught) {
        handleMutationFailure(caught, true);
        if (caught instanceof ApiClientError) {
          throw caught;
        }
        throw localSessionError(
          'The exact-artifact challenge could not be issued.',
        );
      }
    },
    [client, handleMutationFailure, requireCSRF],
  );

  const decidePolicy = useCallback(
    async (
      policyID: string,
      binding: Readonly<PolicyArtifactBinding>,
      challenge: Readonly<HILChallengeEnvelope>,
      reason: Readonly<HILReason>,
      idempotencyKey: string,
    ): Promise<Readonly<HILDecisionEnvelope>> => {
      try {
        const result = await client.policyDecision(
          policyID,
          binding,
          challenge,
          reason,
          idempotencyKey,
          requireCSRF('recording an exact-artifact decision'),
        );
        if (
          !(await decisionMatchesExactBinding(
            result,
            challenge,
            binding,
            reason,
            idempotencyKey,
            currentSession.current?.actor_id ?? '',
          ))
        ) {
          invalidate();
          throw localSessionError(
            'The decision result did not match the consumed exact artifact.',
          );
        }
        if (result.replayed === true) {
          clearSession();
          setError(null);
          setReauthenticationNotice(result);
          setPhase('anonymous');
          return result;
        }
        acceptEnvelope(result);
        return result;
      } catch (caught) {
        handleMutationFailure(caught, false);
        if (caught instanceof ApiClientError) {
          throw caught;
        }
        throw localSessionError(
          'The exact-artifact decision could not be recorded.',
        );
      }
    },
    [
      acceptEnvelope,
      clearSession,
      client,
      handleMutationFailure,
      invalidate,
      requireCSRF,
    ],
  );

  const issueRevocationChallenge = useCallback(
    async (
      actionID: string,
      binding: Readonly<RevocationArtifactBinding>,
      idempotencyKey: string,
    ): Promise<Readonly<RevocationChallengeEnvelope>> => {
      try {
        const challenge = await client.revocationChallenge(
          actionID,
          binding,
          idempotencyKey,
          requireCSRF('requesting an exact revocation challenge'),
        );
        const acceptedSession = currentSession.current;
        if (!acceptedSession) {
          throw localSessionError(
            'The administrator session changed while the revocation challenge was issued.',
          );
        }
        const browserCheck = await checkRevocationChallengeInBrowser(
          challenge,
          actionID,
          binding,
          acceptedSession,
        );
        if (!browserCheck.passed) {
          throw localSessionError(
            browserCheck.blockers[0] ??
              'The revocation challenge failed the independent browser checks for the exact active action.',
          );
        }
        return challenge;
      } catch (caught) {
        handleMutationFailure(caught, true);
        if (caught instanceof ApiClientError) throw caught;
        throw localSessionError(
          'The exact revocation challenge could not be issued.',
        );
      }
    },
    [client, handleMutationFailure, requireCSRF],
  );

  const decideRevocation = useCallback(
    async (
      actionID: string,
      binding: Readonly<RevocationArtifactBinding>,
      challenge: Readonly<RevocationChallengeEnvelope>,
      reason: Readonly<RevocationReason>,
      idempotencyKey: string,
    ): Promise<Readonly<RevocationDecisionEnvelope>> => {
      const acceptedSession = currentSession.current;
      if (!acceptedSession) {
        throw localSessionError(
          'The administrator session is unavailable for revocation.',
          'csrf_invalid',
          409,
        );
      }
      try {
        const result = await client.revokeEnforcementAction(
          actionID,
          binding,
          challenge,
          reason,
          idempotencyKey,
          requireCSRF('recording an exact revocation decision'),
        );
        if (
          !(await revocationDecisionMatchesExactBinding(
            result,
            challenge,
            binding,
            reason,
            idempotencyKey,
            acceptedSession,
          ))
        ) {
          invalidate();
          throw localSessionError(
            'The revocation result did not match the consumed exact delete artifact.',
          );
        }
        if (result.replayed === true) {
          clearSession();
          setError(null);
          setReauthenticationNotice(result);
          setPhase('anonymous');
          return result;
        }
        acceptEnvelope(result);
        return result;
      } catch (caught) {
        handleMutationFailure(caught, false);
        if (caught instanceof ApiClientError) throw caught;
        throw localSessionError(
          'The exact revocation decision could not be recorded.',
        );
      }
    },
    [
      acceptEnvelope,
      clearSession,
      client,
      handleMutationFailure,
      invalidate,
      requireCSRF,
    ],
  );

  const retryBootstrap = useCallback(() => {
    setPhase('bootstrapping');
    setError(null);
    setBootstrapRevision((revision) => revision + 1);
  }, []);

  const value = useMemo<SessionContextValue>(
    () => ({
      phase,
      session,
      csrfAvailable,
      reauthenticationNotice,
      error,
      login,
      logout,
      stepUp,
      issuePolicyChallenge,
      decidePolicy,
      issueRevocationChallenge,
      decideRevocation,
      retryBootstrap,
      invalidate,
    }),
    [
      csrfAvailable,
      error,
      invalidate,
      login,
      logout,
      issuePolicyChallenge,
      decidePolicy,
      issueRevocationChallenge,
      decideRevocation,
      phase,
      reauthenticationNotice,
      retryBootstrap,
      session,
      stepUp,
    ],
  );

  return (
    <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
  );
}
