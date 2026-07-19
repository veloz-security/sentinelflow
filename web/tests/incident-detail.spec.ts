import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './test-fixture';

const fixtureId = '019b0000-0000-7000-8000-000000000601';

const detailStates = {
  loading: 'Loading incident detail',
  unknown: 'Incident state unknown',
  'not-found': 'Incident not found',
  error: 'Incident detail unavailable',
  'permission-denied': 'Incident access required',
  degraded: 'Failed login activity',
  'analysis-failed': 'Failed login activity',
  complete: 'Failed login activity',
} as const;

test('presents a keyboard-reachable evidence investigation without overflow', async ({
  page,
}) => {
  const diagnostics: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );

  await page.goto(`/fixtures/incidents/${fixtureId}`);
  await expect(
    page.getByRole('heading', { level: 1, name: 'Failed login activity' }),
  ).toBeVisible();
  await expect(
    page.getByRole('list', { name: 'Evidence provenance layers' }),
  ).toBeVisible();

  for (const heading of [
    'Observed facts',
    'Deterministic signals',
    'AI interpretation',
    'Analysis provenance',
  ]) {
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
  }
  await expect(page.getByText('Direct-peer provenance')).toBeVisible();
  await expect(page.getByText('Binding verified')).toBeVisible();
  await expect(page.getByText('gpt-5.6-sol')).toBeVisible();
  await expect(page.getByText('sentinelflow_system_prompt_v1')).toBeVisible();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1,
  );
  expect(hasHorizontalOverflow).toBe(false);

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
  expect(diagnostics).toEqual([]);

  const backLink = page.getByRole('link', { name: 'Back to incidents' });
  await backLink.focus();
  await expect(backLink).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Incidents' }),
  ).toBeVisible();
});

test('renders all detail state fixtures with semantics and clean diagnostics', async ({
  page,
}) => {
  const diagnostics: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );

  for (const [state, heading] of Object.entries(detailStates)) {
    await page.goto(`/states/incident-detail/${state}`);
    await expect(
      page.getByRole('heading', { level: 1, name: heading }),
    ).toBeVisible();

    const hasHorizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    expect(hasHorizontalOverflow, `${state} horizontal overflow`).toBe(false);

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, `${state} accessibility violations`).toEqual([]);
  }

  await page.goto('/states/incident-detail/degraded');
  await expect(page.getByRole('alert')).toContainText('sequence gap 42–45');
  await page.goto('/states/incident-detail/analysis-failed');
  await expect(page.getByRole('alert')).toContainText('timeout');
  await page.goto('/states/incident-detail/error');
  await expect(page.getByRole('alert')).toBeVisible();
  await page.goto('/states/incident-detail/permission-denied');
  await expect(page.getByRole('alert')).toBeVisible();

  expect(diagnostics).toEqual([]);
});
