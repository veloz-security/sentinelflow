import { createContext, useContext } from 'react';
import type { ApiClientError } from './apiClient';
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
  SessionProjection,
} from './contracts';

export type SessionPhase =
  'bootstrapping' | 'anonymous' | 'authenticated' | 'error';

export interface SessionContextValue {
  readonly phase: SessionPhase;
  readonly session: Readonly<SessionProjection> | null;
  readonly csrfAvailable: boolean;
  readonly reauthenticationNotice: Readonly<ReauthenticationNotice> | null;
  readonly error: ApiClientError | null;
  readonly login: (username: string, password: string) => Promise<void>;
  readonly logout: () => Promise<void>;
  readonly stepUp: (password: string) => Promise<void>;
  readonly issuePolicyChallenge: (
    policyID: string,
    binding: Readonly<PolicyArtifactBinding>,
    idempotencyKey: string,
  ) => Promise<Readonly<HILChallengeEnvelope>>;
  readonly decidePolicy: (
    policyID: string,
    binding: Readonly<PolicyArtifactBinding>,
    challenge: Readonly<HILChallengeEnvelope>,
    reason: Readonly<HILReason>,
    idempotencyKey: string,
  ) => Promise<Readonly<HILDecisionEnvelope>>;
  readonly issueRevocationChallenge: (
    actionID: string,
    binding: Readonly<RevocationArtifactBinding>,
    idempotencyKey: string,
  ) => Promise<Readonly<RevocationChallengeEnvelope>>;
  readonly decideRevocation: (
    actionID: string,
    binding: Readonly<RevocationArtifactBinding>,
    challenge: Readonly<RevocationChallengeEnvelope>,
    reason: Readonly<RevocationReason>,
    idempotencyKey: string,
  ) => Promise<Readonly<RevocationDecisionEnvelope>>;
  readonly retryBootstrap: () => void;
  readonly invalidate: () => void;
}

export const SessionContext = createContext<SessionContextValue | null>(null);

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('SessionProvider is required');
  }
  return context;
}
