import { expect, test } from '@playwright/test';
import { readDeploymentCsp } from '../scripts/deploymentCsp';
import { scanProductionJavaScriptChunks } from '../scripts/productionCsp';

interface CapturedCspViolation {
  readonly effectiveDirective: string;
  readonly blockedUri: string;
}

test('renders the production bundle under the deployment CSP without dynamic code generation', async ({
  page,
}) => {
  const bundleScan = scanProductionJavaScriptChunks();
  expect(bundleScan.chunks.length).toBeGreaterThan(1);
  expect(bundleScan.chunks).toEqual([...bundleScan.chunks].sort());

  const browserErrors: string[] = [];

  page.on('console', (message) => {
    if (message.type() === 'error') {
      browserErrors.push(`console: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) => {
    browserErrors.push(`pageerror: ${error.message}`);
  });
  await page.addInitScript(() => {
    const captured = globalThis as typeof globalThis & {
      __sentinelflowCspViolations?: CapturedCspViolation[];
    };
    captured.__sentinelflowCspViolations = [];
    globalThis.addEventListener('securitypolicyviolation', (event) => {
      captured.__sentinelflowCspViolations?.push({
        effectiveDirective: event.effectiveDirective,
        blockedUri: event.blockedURI,
      });
    });
  });

  const response = await page.goto('/fixtures', {
    waitUntil: 'domcontentloaded',
  });
  expect(response).not.toBeNull();

  const deploymentCsp = readDeploymentCsp();
  expect(response?.headers()['content-security-policy']).toBe(deploymentCsp);
  expect(deploymentCsp).toContain("default-src 'self'");
  expect(deploymentCsp).not.toContain("'unsafe-eval'");

  await expect(
    page.getByRole('heading', { level: 1, name: 'Review queue' }),
  ).toBeVisible();
  await expect(page.locator('#root')).not.toBeEmpty();
  await page.waitForLoadState('networkidle');

  const cspViolations = await page.evaluate(() => {
    const captured = globalThis as typeof globalThis & {
      __sentinelflowCspViolations?: CapturedCspViolation[];
    };
    return captured.__sentinelflowCspViolations ?? [];
  });
  expect(cspViolations).toEqual([]);
  expect(browserErrors).toEqual([]);
});
