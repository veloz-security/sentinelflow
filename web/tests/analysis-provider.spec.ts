import AxeBuilder from '@axe-core/playwright';
import { createBrowserJSONFixture } from './browser-json-fixture';
import { expect, test } from './test-fixture';

const openAIIncidentID = '019b0000-0000-7000-8000-000000000101';
const stubIncidentID = '019b0000-0000-7000-8000-000000000107';
const traceID = '019b0000-0000-4000-8000-000000000201';

test('renders exact OpenAI and deterministic-stub provenance without spoofed model or cost', async ({
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

  await page.goto(`/incidents/${openAIIncidentID}`);
  await expect(
    page.getByRole('heading', { name: 'AI interpretation' }),
  ).toBeVisible();
  const openAIRegion = page.getByRole('region', {
    name: 'Analysis provider provenance',
  });
  await expect(
    openAIRegion.getByText('OpenAI Responses API').first(),
  ).toBeVisible();
  await expect(openAIRegion.getByText('openai-responses-v1')).toBeVisible();
  await expect(openAIRegion.getByText('gpt-5.6-sol')).toBeVisible();
  await expect(openAIRegion.getByText('medium')).toBeVisible();
  await expect(openAIRegion.getByText('openai-demo-2026-07-18')).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  await page.goto('/incidents');
  await expect(page.getByText('gpt-5.6-sol', { exact: true })).toHaveCount(0);
  await expect(
    page.getByText('Deterministic offline stub', { exact: true }),
  ).toHaveCount(0);
  const stubLink = page.getByRole('link', { name: stubIncidentID });
  await stubLink.focus();
  await expect(stubLink).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(
    page.getByRole('heading', {
      name: 'Deterministic analysis interpretation',
    }),
  ).toBeVisible();
  const stubRegion = page.getByRole('region', {
    name: 'Analysis provider provenance',
  });
  await expect(
    stubRegion.getByText('Deterministic offline stub').first(),
  ).toBeVisible();
  await expect(
    stubRegion.getByText('sentinelflow-deterministic-ai-stub-v1'),
  ).toBeVisible();
  await expect(
    stubRegion.getByText('Offline deterministic adapter'),
  ).toBeVisible();
  for (const forbidden of [
    'gpt-5.6-sol',
    'medium',
    'openai-demo-2026-07-18',
    'Model',
    'Rate card',
    'Token cost',
  ]) {
    await expect(stubRegion.getByText(forbidden, { exact: true })).toHaveCount(
      0,
    );
  }
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  expect(diagnostics).toEqual([]);
});

test('announces loading, empty, error, permission, and success list states', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  let mode: 'loading' | 'error' | 'permission' | 'success' = 'loading';
  let releaseLoading: (() => void) | undefined;
  const loading = new Promise<void>((resolve) => {
    releaseLoading = resolve;
  });
  const fixture = await createBrowserJSONFixture(page, async () => {
    if (mode === 'loading') {
      await loading;
      return { status: 200, value: { items: [] } };
    }
    const permission = mode === 'permission';
    return {
      status: permission ? 403 : 503,
      value: {
        code: permission ? 'permission_denied' : 'service_unavailable',
        message: permission
          ? 'this administrator cannot read incidents'
          : 'the management service is unavailable',
        trace_id: traceID,
        details: {},
      },
    };
  });
  await page.route('**/api/v1/incidents?*', async (route) => {
    if (mode === 'success') {
      await route.continue();
      return;
    }
    await fixture.forward(route);
  });

  await page.goto('/incidents');
  await expect(
    page.getByRole('status', { name: 'Loading incident snapshot' }),
  ).toBeVisible();
  releaseLoading?.();
  await expect(page.getByRole('status')).toContainText(
    'No incidents on this page',
  );

  mode = 'error';
  await page.reload();
  await expect(page.getByRole('alert')).toContainText(
    'the management service is unavailable',
  );
  await expect(page.getByRole('alert')).toContainText(traceID);

  mode = 'permission';
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('Permission required');
  await expect(page.getByRole('alert')).toContainText('permission_denied');

  mode = 'success';
  await page.getByRole('button', { name: 'Retry' }).focus();
  await expect(page.getByRole('button', { name: 'Retry' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(
    page.getByRole('table', { name: 'Live incidents' }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: openAIIncidentID }),
  ).toBeVisible();
  await expect(page.getByRole('link', { name: stubIncidentID })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
