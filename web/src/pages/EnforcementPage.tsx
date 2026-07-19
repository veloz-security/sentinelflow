import { useEffect, useState } from 'react';
import { EnforcementLifecycleResults } from '../components/EnforcementLifecycleResults';
import { fixtureEnforcementLifecycleAdapter } from '../enforcement/fixtureEnforcementLifecycleAdapter';
import type {
  EnforcementLifecycleAdapter,
  EnforcementLifecycleState,
} from '../enforcement/enforcementLifecycleModel';
import { MOCK_ENFORCEMENT_LIFECYCLE_STATES } from '../mocks/enforcementLifecycleFixtures';

export interface EnforcementPageProps {
  readonly adapter?: EnforcementLifecycleAdapter;
}

export function EnforcementPage({
  adapter = fixtureEnforcementLifecycleAdapter,
}: EnforcementPageProps) {
  const [state, setState] = useState<EnforcementLifecycleState>({
    kind: 'loading',
  });

  useEffect(() => {
    const controller = new AbortController();
    void adapter.load(controller.signal).then(
      (result) => {
        if (!controller.signal.aborted) setState(result);
      },
      () => {
        if (!controller.signal.aborted) {
          setState(MOCK_ENFORCEMENT_LIFECYCLE_STATES.error);
        }
      },
    );
    return () => controller.abort();
  }, [adapter]);

  return <EnforcementLifecycleResults state={state} />;
}
