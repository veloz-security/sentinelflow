import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './test-fixture';

const routes = [
  '/fixtures',
  '/fixtures/incidents',
  '/fixtures/incidents/019b0000-0000-7000-8000-000000000601',
  '/fixtures/validation',
  '/fixtures/authorization',
  '/fixtures/enforcement',
  '/states',
  '/states/incident-detail/complete',
  '/states/validation/ready',
  '/states/hil/ready',
  '/states/enforcement/active',
] as const;

test('renders the fixture shell and every overview surface', async ({
  page,
}, testInfo) => {
  await page.goto('/fixtures');

  await expect(
    page.getByRole('heading', { level: 1, name: 'Review queue' }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Approve exact artifact' }),
  ).toBeDisabled();

  const isNarrow = testInfo.project.name === 'narrow-chromium';
  const primaryNavigation = page.getByTestId(
    isNarrow ? 'narrow-navigation' : 'desktop-sidebar',
  );
  await expect(primaryNavigation).toBeVisible();
  await expect(
    page.getByTestId(isNarrow ? 'desktop-sidebar' : 'narrow-navigation'),
  ).toBeHidden();

  await primaryNavigation.getByRole('link', { name: 'Incidents' }).click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Incidents' }),
  ).toBeVisible();
  await expect(
    page.getByRole(isNarrow ? 'list' : 'table', {
      name: 'Filtered incidents',
    }),
  ).toBeVisible();

  await primaryNavigation.getByRole('link', { name: 'Validation' }).click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Validation review' }),
  ).toBeVisible();
  await expect(
    page.getByRole('list', { name: 'Five ordered validation results' }),
  ).toBeVisible();

  await primaryNavigation.getByRole('link', { name: /Authoriz/ }).click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'HIL authorization review' }),
  ).toBeVisible();
  await expect(
    page.getByRole('radio', { name: /Approve temporary block/ }),
  ).toBeChecked();

  await primaryNavigation.getByRole('link', { name: 'Enforcement' }).click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Temporary block history' }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Reapply action' }),
  ).toBeDisabled();

  await primaryNavigation
    .getByRole('link', { name: isNarrow ? 'States' : 'State library' })
    .click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Presentation state library' }),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', {
      level: 2,
      name: 'Enforcement lifecycle states',
    }),
  ).toBeVisible();

  for (const stateHeading of [
    'Loading investigation data',
    'No incidents to review',
    'Investigation data unavailable',
    'Permission required',
    'Action disabled',
    'Typed contract loaded',
  ]) {
    await expect(
      page.getByRole('heading', { level: 2, name: stateHeading }),
    ).toBeVisible();
  }
  await expect(
    page.getByRole('status', { name: 'Loading typed investigation' }),
  ).toHaveAttribute('aria-busy', 'true');
  await expect(
    page.getByRole('button', { name: 'Approve action' }),
  ).toBeDisabled();
});

test('supports keyboard entry and avoids narrow horizontal overflow', async ({
  page,
}) => {
  await page.goto('/fixtures');
  await page.keyboard.press('Tab');
  const skipLink = page.getByRole('link', { name: 'Skip to content' });
  if (
    !(await skipLink.evaluate((element) => element === document.activeElement))
  ) {
    await page.reload();
    await page.keyboard.press('Alt+Tab');
  }
  await expect(skipLink).toBeFocused();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1,
  );
  expect(hasHorizontalOverflow).toBe(false);
});

test('has no automated accessibility violations across routes', async ({
  page,
}) => {
  for (const path of routes) {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, `${path} accessibility violations`).toEqual([]);
  }
});

test('emits no browser warnings or uncaught errors across routes', async ({
  page,
}) => {
  const diagnostics: string[] = [];

  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) => {
    diagnostics.push(`pageerror: ${error.message}`);
  });

  for (const path of routes) {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  }

  expect(diagnostics).toEqual([]);
});
