import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './test-fixture';

test('filters and paginates the frozen incident adapter', async ({
  page,
}, testInfo) => {
  await page.goto('/fixtures/incidents');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Incidents' }),
  ).toBeVisible();

  const isNarrow = testInfo.project.name === 'narrow-chromium';
  await expect(
    page.getByRole(isNarrow ? 'list' : 'table', {
      name: 'Filtered incidents',
    }),
  ).toBeVisible();
  await expect(page.getByText('1–4 of 8')).toBeVisible();
  await expect(page.getByText(/Coverage is incomplete/)).toBeVisible();

  const source = page.getByRole('textbox', {
    name: 'Canonical source IPv4',
  });
  await source.focus();
  await page.keyboard.type('203.0.113.20');
  await page.keyboard.press('Enter');

  await expect(page).toHaveURL(/\?source=203\.0\.113\.20$/);
  await expect(page.getByText('1–1 of 1')).toBeVisible();
  await expect(page.getByText('Visible coverage complete')).toBeVisible();

  await page.getByRole('button', { name: 'Reset' }).click();
  await expect(page).toHaveURL(/\/fixtures\/incidents$/);
  await expect(page.getByText('1–4 of 8')).toBeVisible();

  await page.getByRole('button', { name: 'Next' }).click();
  await expect(page).toHaveURL(/cursor=fixture-cursor-v1%3A4/);
  await expect(page.getByText('5–8 of 8')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Previous' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();
});

test('renders every incident list state without accessibility or overflow failures', async ({
  page,
}) => {
  const states = [
    ['loading', 'Loading incidents'],
    ['empty', 'No incidents match these filters'],
    ['error', 'Incident list unavailable'],
    ['permission-denied', 'Incident access required'],
    ['populated', 'Result summary'],
  ] as const;

  for (const [state, heading] of states) {
    await page.goto(`/states/incidents/${state}`);
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();

    const hasHorizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    expect(hasHorizontalOverflow, `${state} horizontal overflow`).toBe(false);

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, `${state} accessibility violations`).toEqual([]);
  }
});
