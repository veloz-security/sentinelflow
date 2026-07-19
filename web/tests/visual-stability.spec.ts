import type { Locator, Page } from '@playwright/test';
import { expect, test } from './test-fixture';

async function stabilize(page: Page, path: string, heading: string) {
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
  await page.goto(path);
  await expect(
    page.getByRole('heading', { level: 1, name: heading }),
  ).toBeVisible();
  await page.evaluate(async () => document.fonts.ready);
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation: none !important;
        caret-color: transparent !important;
        transition: none !important;
      }
      header {
        position: static !important;
      }
      a[href='#main-content'] {
        display: none !important;
      }
    `,
  });
}

async function expectStableScreenshot(locator: Locator, name: string) {
  await expect(locator).toHaveScreenshot(name, {
    animations: 'disabled',
    caret: 'hide',
    maxDiffPixelRatio: 0.0005,
    scale: 'css',
    threshold: 0.15,
  });
}

test('keeps the six resource-state treatments visually distinct', async ({
  page,
}) => {
  await stabilize(page, '/states', 'Presentation state library');
  const grid = page.getByTestId('resource-state-visual-grid');
  for (const heading of [
    'Loading investigation data',
    'No incidents to review',
    'Investigation data unavailable',
    'Permission required',
    'Action disabled',
    'Typed contract loaded',
  ]) {
    await expect(grid.getByRole('heading', { name: heading })).toBeVisible();
  }
  await expectStableScreenshot(grid, 'resource-states.png');
});

test('keeps the populated incident result stable across layouts', async ({
  page,
}) => {
  await stabilize(
    page,
    '/states/incidents/populated',
    'Incident list: populated',
  );
  const results = page.getByTestId('populated-incident-list');
  await expect(
    results.getByRole('heading', { name: 'Result summary' }),
  ).toBeVisible();
  await expectStableScreenshot(results, 'populated-incident-list.png');
});
