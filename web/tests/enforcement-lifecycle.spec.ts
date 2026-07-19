import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './test-fixture';

const lifecycleStates = {
  loading: 'Loading enforcement lifecycle',
  empty: 'No enforcement lifecycle',
  error: 'Enforcement lifecycle unavailable',
  'permission-denied': 'Enforcement access required',
  pending: 'Temporary block history',
  applied: 'Temporary block history',
  active: 'Temporary block history',
  expired: 'Temporary block history',
  revoked: 'Temporary block history',
  failed: 'Temporary block history',
  indeterminate: 'Temporary block history',
  'recovered-active': 'Temporary block history',
  'torn-journal': 'Temporary block history',
  'corrupt-journal': 'Temporary block history',
} as const;

test('presents inert lifecycle, digest, journal, and audit evidence', async ({
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

  await page.goto('/fixtures/enforcement');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Temporary block history' }),
  ).toBeVisible();
  await expect(page.getByText(/Fixture-only lifecycle evidence/)).toBeVisible();

  const operations = page.getByRole('list', {
    name: 'Enforcement operation history',
  });
  await expect(operations.getByRole('listitem')).toHaveCount(2);
  await expect(operations.getByText('Shell-free temporary add')).toBeVisible();
  await expect(operations.getByText('Read-only inspect')).toBeVisible();
  await expect(operations.getByText('Artifact digest').first()).toBeVisible();
  await expect(operations.getByText('Capability digest').first()).toBeVisible();
  await expect(
    operations.getByText('Executor result digest').first(),
  ).toBeVisible();
  await expect(
    operations.getByText('Signature status: verified').first(),
  ).toBeVisible();

  await expect(
    page
      .getByRole('list', { name: 'Executor journal sequence' })
      .getByRole('listitem'),
  ).toHaveCount(3);
  await expect(page.getByText('Automatic re-add: disabled')).toBeVisible();
  await expect(page.getByText('TTL refresh: disabled')).toBeVisible();
  await expect(
    page.getByText('Recovery mode: read only inspect'),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { level: 2, name: 'Server-time TTL' }),
  ).toBeVisible();

  const audit = page.getByRole('list', { name: 'Audit provenance timeline' });
  for (const provenance of [
    'Observed fact',
    'Deterministic rule',
    'AI generated',
    'Canonicalized artifact',
    'Human decision',
    'Dispatcher',
    'Executor result',
    'Recovery',
  ]) {
    await expect(audit.getByText(provenance).first()).toBeVisible();
  }

  await expect(
    page.getByRole('button', { name: 'Reapply action' }),
  ).toBeDisabled();
  const bodyText = (await page.locator('body').textContent()) ?? '';
  expect(bodyText).not.toContain('signature_b64url');
  expect(bodyText).not.toContain('private_key');
  expect(bodyText).not.toContain('capability_jcs_b64url');

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1,
  );
  expect(hasHorizontalOverflow).toBe(false);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  expect(diagnostics).toEqual([]);
});

test('renders every lifecycle and recovery state with keyboard access', async ({
  page,
}) => {
  test.slow();
  const diagnostics: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );

  await page.goto('/states/enforcement/active');
  const tornLink = page.getByRole('link', { name: 'torn journal' });
  await tornLink.focus();
  await expect(tornLink).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByText('Torn journal').first()).toBeVisible();
  await expect(page.getByText('Recovery mode: halted')).toBeVisible();

  for (const [state, heading] of Object.entries(lifecycleStates)) {
    await page.goto(`/states/enforcement/${state}`);
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

  await page.goto('/states/enforcement/revoked');
  await expect(
    page
      .getByRole('list', { name: 'Enforcement operation history' })
      .getByRole('listitem'),
  ).toHaveCount(3);
  await expect(page.getByText('Human revoke decision bound')).toBeVisible();
  await page.goto('/states/enforcement/expired');
  await expect(page.getByText('inspect absent')).toBeVisible();
  await page.goto('/states/enforcement/indeterminate');
  await expect(page.getByText('Recovery mode: halted')).toBeVisible();
  await page.goto('/states/enforcement/corrupt-journal');
  await expect(page.getByText('checksum failed')).toBeVisible();
  await page.goto('/states/enforcement/permission-denied');
  await expect(page.getByRole('alert')).toBeVisible();

  expect(diagnostics).toEqual([]);
});
