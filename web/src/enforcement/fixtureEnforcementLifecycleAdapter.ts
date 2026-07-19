import { MOCK_ENFORCEMENT_LIFECYCLE_STATES } from '../mocks/enforcementLifecycleFixtures';
import type {
  EnforcementLifecycleAdapter,
  EnforcementLifecycleState,
} from './enforcementLifecycleModel';

async function resolveFixture(
  state: EnforcementLifecycleState,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  await Promise.resolve();
  signal?.throwIfAborted();
  return state;
}

export const fixtureEnforcementLifecycleAdapter: EnforcementLifecycleAdapter = {
  kind: 'fixture',
  load(signal) {
    return resolveFixture(MOCK_ENFORCEMENT_LIFECYCLE_STATES.active, signal);
  },
};
