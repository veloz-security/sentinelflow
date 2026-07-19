import { createHash } from 'node:crypto';
import { expect, test as base } from '@playwright/test';

export const TEST_NAMESPACE_HEADER = 'X-SentinelFlow-Test-Namespace';

export const test = base.extend<{ testNamespace: string }>({
  testNamespace: [
    async ({ context }, use, testInfo) => {
      const digest = createHash('sha256')
        .update(
          [
            testInfo.project.name,
            testInfo.testId,
            testInfo.repeatEachIndex,
            testInfo.retry,
          ].join('\0'),
        )
        .digest('hex');
      const testNamespace = `pw-${digest.slice(0, 32)}`;
      await context.setExtraHTTPHeaders({
        [TEST_NAMESPACE_HEADER]: testNamespace,
      });
      await use(testNamespace);
    },
    { auto: true },
  ],
});

export { expect };
