import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './test-fixture';

const validationStates = {
  loading: 'Loading validation review',
  missing: 'Validation review missing',
  gapped: 'Validation review',
  unsigned: 'Validation review',
  failed: 'Validation review',
  mismatch: 'Validation review',
  stale: 'Validation review',
  expired: 'Validation review',
  'permission-denied': 'Validation access required',
  ready: 'Validation review',
} as const;

test('presents an inert five-gate validation review with no active HIL control', async ({
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

  await page.goto('/fixtures/validation');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Validation review' }),
  ).toBeVisible();

  const gates = page.getByRole('list', {
    name: 'Five ordered validation results',
  });
  await expect(gates.getByRole('listitem')).toHaveCount(5);
  await expect(gates.getByRole('listitem').nth(1)).toContainText(
    'Policy, evidence, and command consistency',
  );
  await expect(gates.getByRole('listitem').nth(2)).toContainText(
    'Protected target',
  );

  await expect(
    page.getByText('1800 seconds = 30m = 1800 seconds.'),
  ).toBeVisible();
  await expect(page.getByText('Gateway complete')).toBeVisible();
  await expect(page.getByText('History verified')).toBeVisible();
  await expect(page.getByText('4m 0s remaining')).toBeVisible();
  await expect(page.getByText('Protected IPv4 static')).toBeVisible();
  await expect(page.getByText('Owned live structure')).toBeVisible();
  await expect(
    page.getByRole('button', {
      name: 'No authorization control in this view',
    }),
  ).toBeDisabled();
  await expect(
    page.getByRole('heading', {
      name: 'Authorization is a separate surface',
    }),
  ).toBeVisible();
  await expect(
    page.getByText(/Server-side exact-artifact authorization exists/),
  ).toBeVisible();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1,
  );
  expect(hasHorizontalOverflow).toBe(false);

  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations).toEqual([]);
  expect(diagnostics).toEqual([]);
});

test('renders every validation state with keyboard navigation and clean diagnostics', async ({
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

  await page.goto('/states/validation/ready');
  const mismatchLink = page.getByRole('link', { name: 'mismatch' });
  await mismatchLink.focus();
  await expect(mismatchLink).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByText('Artifact mismatch')).toBeVisible();

  for (const [state, heading] of Object.entries(validationStates)) {
    await page.goto(`/states/validation/${state}`);
    await expect(
      page.getByRole('heading', { level: 1, name: heading }),
    ).toBeVisible();

    const hasHorizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    expect(hasHorizontalOverflow, `${state} horizontal overflow`).toBe(false);

    const axe = await new AxeBuilder({ page }).analyze();
    expect(axe.violations, `${state} accessibility violations`).toEqual([]);
  }

  await page.goto('/states/validation/gapped');
  await expect(page.getByText('Unresolved sequence range 42–45')).toBeVisible();
  await page.goto('/states/validation/unsigned');
  await expect(page.getByText('History unsigned').first()).toBeVisible();
  await page.goto('/states/validation/stale');
  await expect(page.getByText('Validation stale')).toBeVisible();
  await page.goto('/states/validation/expired');
  await expect(page.getByText('Validation expired')).toBeVisible();
  await page.goto('/states/validation/permission-denied');
  await expect(page.getByRole('alert')).toBeVisible();

  expect(diagnostics).toEqual([]);
});
