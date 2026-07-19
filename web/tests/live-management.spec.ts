import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './test-fixture';

test('loads authenticated REST and SSE through the Vite management proxy', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const diagnostics: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );

  await page.goto('/');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Investigation workspace' }),
  ).toBeVisible();
  await expect(page.getByText('Live notifications')).toBeVisible();
  await expect(page.getByText('brute force')).toBeVisible();
  await expect(page.getByText('incident_opened')).toBeVisible();

  await page.getByRole('link', { name: 'brute force' }).click();
  await expect(
    page.getByRole('heading', {
      level: 1,
      name: 'brute force from 203.0.113.20',
    }),
  ).toBeVisible();
  for (const heading of [
    'Observed incident facts',
    'Allowlisted observed events',
    'Deterministic conclusions',
    'AI interpretation',
    'Human review and policy artifacts',
    'Audit outcomes',
  ]) {
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
  }
  await expect(page.getByText(/Exact paths, query strings/)).toBeVisible();
  const provider = page.getByRole('region', {
    name: 'Analysis provider provenance',
  });
  await expect(
    provider.getByText('OpenAI Responses API').first(),
  ).toBeVisible();
  await expect(provider.getByText('gpt-5.6-sol')).toBeVisible();
  await expect(provider.getByText('medium')).toBeVisible();
  await expect(provider.getByText('openai-demo-2026-07-18')).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
  expect(diagnostics).toEqual([]);
});

test('reviews and approves the exact HIL artifact with session rotation', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const diagnostics: string[] = [];
  const failedResponses: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );
  page.on('response', (response) => {
    if (response.status() >= 400) {
      failedResponses.push(`${response.status()} ${response.url()}`);
    }
  });

  await page.goto('/policies/019b0000-0000-7000-8000-000000000301');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Policy for 203.0.113.20' }),
  ).toBeVisible();
  await expect(page.getByText('Deterministic validation')).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Analysis-proposed artifact' }),
  ).toBeVisible();
  await expect(
    page.getByText(/Provider identity is not repeated in this policy response/),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'AI-proposed artifact' }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('heading', { name: 'Human decision' }),
  ).toBeVisible();
  await page
    .getByLabel('Administrator reason')
    .fill('Confirmed synthetic browser attack');
  await page.getByRole('button', { name: 'Request exact challenge' }).click();

  await expect(page.getByText('Single-use challenge')).toBeVisible();
  await expect(
    page.getByLabel('Exact command awaiting HIL decision'),
  ).toContainText(
    'add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }',
  );
  await expect(
    page
      .locator('code')
      .filter({ hasText: /^sha256:[0-9a-f]{64}$/ })
      .last(),
  ).toBeVisible();
  expect(await page.locator('body').innerText()).not.toMatch(
    /\b[A-Za-z0-9_-]{43}\b/,
  );
  await page.getByLabel(/I reviewed the exact target, TTL, command/).check();
  await page.getByRole('button', { name: 'Approve exact artifact' }).click();

  await expect(page.getByText('Exact artifact approved')).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Open queued enforcement action' }),
  ).toHaveAttribute(
    'href',
    /^\/enforcement-actions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  );
  await page.getByRole('link', { name: /Session/ }).click();
  await expect(
    page.getByText('019b0000-0000-7000-8000-000000000309'),
  ).toBeVisible();
  await expect(page.getByText('Mutation guard ready')).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
  expect(failedResponses).toEqual([]);
  expect(diagnostics).toEqual([]);
});

test('recovers response loss through exact replay and requires login', async ({
  page,
}, testInfo) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const diagnostics: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );
  let discardFreshResponse = true;
  let recordedDecisionID = '';
  await page.route('**/api/v1/policies/*/decisions', async (route) => {
    if (!discardFreshResponse) {
      await route.continue();
      return;
    }
    discardFreshResponse = false;
    const response = await route.fetch();
    const envelope = (await response.json()) as {
      decision: { decision_id: string };
    };
    recordedDecisionID = envelope.decision.decision_id;
    await route.abort('failed');
  });

  await page.goto('/policies/019b0000-0000-7000-8000-000000000301');
  await page
    .getByLabel('Administrator reason')
    .fill('Confirm response-loss replay recovery for synthetic browser test');
  await page.getByRole('button', { name: 'Request exact challenge' }).click();
  await expect(page.getByText('Single-use challenge')).toBeVisible();
  await page.getByLabel(/I reviewed the exact target, TTL, command/).check();
  await page.getByRole('button', { name: 'Approve exact artifact' }).click();

  await expect(
    page.getByText('The exact-artifact decision could not be recorded.'),
  ).toBeVisible();
  await expect(page.getByText('Single-use challenge')).toBeVisible();
  await page.getByRole('button', { name: 'Approve exact artifact' }).click();

  await expect(
    page.getByRole('heading', { level: 1, name: 'Sign in to review evidence' }),
  ).toBeVisible();
  await expect(
    page.getByText('Exact decision was already recorded'),
  ).toBeVisible();
  await expect(page.getByText(/This is not a new authorization/)).toBeVisible();
  await expect(page.getByText(/previous session was expired/)).toBeVisible();
  expect(recordedDecisionID).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  );
  await expect(page.getByText(recordedDecisionID)).toBeVisible();
  expect(await page.locator('body').innerText()).not.toMatch(
    /\b[A-Za-z0-9_-]{43}\b/,
  );

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
  expect(diagnostics).toEqual(
    testInfo.project.name.includes('chromium')
      ? ['error: Failed to load resource: net::ERR_FAILED']
      : [],
  );
});
