import { describe, expect, it } from 'vitest';
import { fixtureEnforcementLifecycleAdapter } from './fixtureEnforcementLifecycleAdapter';

describe('fixtureEnforcementLifecycleAdapter', () => {
  it('loads the frozen active lifecycle fixture', async () => {
    await expect(
      fixtureEnforcementLifecycleAdapter.load(),
    ).resolves.toMatchObject({
      kind: 'ready',
      fixtureName: 'active',
      view: { lifecycle: { state: 'active' } },
    });
  });

  it('honors an aborted request boundary', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      fixtureEnforcementLifecycleAdapter.load(controller.signal),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });
});
