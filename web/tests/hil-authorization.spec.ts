import AxeBuilder from '@axe-core/playwright';
import type { Page } from '@playwright/test';
import { expect, test } from './test-fixture';

const hilStates = [
  'loading',
  'ready',
  'step-up-required',
  'step-up-complete',
  'challenge-issued',
  'reject-challenge-issued',
  'expired',
  'replayed',
  'stale',
  'mutation',
  'conflict',
  'permission-denied',
  'unauthorized',
  'rate-limited',
  'step-up-failed',
  'rejected',
  'approved',
] as const;

function collectDiagnostics(page: Page) {
  const diagnostics: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      diagnostics.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) =>
    diagnostics.push(`pageerror: ${error.message}`),
  );
  return diagnostics;
}

test('completes keyboard-only approve and reject fixture previews', async ({
  page,
}) => {
  const diagnostics = collectDiagnostics(page);
  await page.goto('/fixtures/authorization');
  await expect(
    page.getByRole('heading', { level: 1, name: 'HIL authorization review' }),
  ).toBeVisible();

  const reject = page.getByRole('radio', { name: /Reject this artifact/ });
  await reject.focus();
  await page.keyboard.press('Space');
  await expect(reject).toBeChecked();
  const openReject = page.getByRole('button', {
    name: 'Open reject challenge fixture',
  });
  await openReject.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('Reject challenge ready')).toBeVisible();

  const rejectReason = page.getByRole('textbox', { name: 'Decision reason' });
  await rejectReason.focus();
  await page.keyboard.type('Synthetic false positive review.');
  const rejectConfirmation = page.getByRole('checkbox', {
    name: /I confirm the exact reject operation/,
  });
  await rejectConfirmation.focus();
  await page.keyboard.press('Space');
  const rejectDecision = page.getByRole('button', {
    name: 'Preview rejection decision',
  });
  await expect(rejectDecision).toBeEnabled();
  await rejectDecision.focus();
  await page.keyboard.press('Enter');
  await expect(
    page.getByRole('heading', { name: 'Fixture rejection recorded' }),
  ).toBeVisible();
  await expect(
    page.getByText(/creates no firewall authority/).first(),
  ).toBeVisible();

  await page.goto('/fixtures/authorization');
  await page
    .getByRole('button', { name: 'Open approve challenge fixture' })
    .click();
  await page
    .getByRole('textbox', { name: 'Decision reason' })
    .fill('Synthetic validated evidence review.');
  await page
    .getByRole('checkbox', {
      name: /I confirm the exact approve operation/,
    })
    .check();
  await page.getByRole('button', { name: 'Preview approval decision' }).click();
  await expect(
    page.getByRole('heading', { name: 'Fixture approval recorded' }),
  ).toBeVisible();
  await expect(page.getByText(/created no authorized job/)).toBeVisible();
  await expect(
    page.getByRole('button', { name: /Preview approval decision/ }),
  ).toHaveCount(0);

  expect(diagnostics).toEqual([]);
});

test('keeps every HIL fixture state accessible, bounded, and fail-closed', async ({
  page,
}) => {
  test.slow();
  const diagnostics = collectDiagnostics(page);

  for (const state of hilStates) {
    await page.goto(`/states/hil/${state}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    const hasHorizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    expect(hasHorizontalOverflow, `${state} horizontal overflow`).toBe(false);

    const axe = await new AxeBuilder({ page }).analyze();
    expect(axe.violations, `${state} accessibility violations`).toEqual([]);
  }

  for (const state of [
    'expired',
    'replayed',
    'stale',
    'mutation',
    'conflict',
    'permission-denied',
    'unauthorized',
    'rate-limited',
    'step-up-failed',
  ] as const) {
    await page.goto(`/states/hil/${state}`);
    await expect(
      page.getByRole('button', { name: 'Decision unavailable' }),
    ).toBeDisabled();
    await expect(
      page.getByRole('button', { name: /Preview .* decision/ }),
    ).toHaveCount(0);
  }

  await page.goto('/states/hil/rate-limited');
  await expect(page.getByText('Retry-After: 42 seconds')).toBeVisible();
  await page.goto('/states/hil/step-up-required');
  const password = page.locator('input[name="step-up-password"]');
  await expect(password).toHaveValue('');
  await expect(password).not.toHaveAttribute('value');
  await page.goto('/states/hil/step-up-complete');
  await expect(page.getByText('Session rotated')).toBeVisible();
  await expect(page.getByText('completed')).toBeVisible();

  expect(diagnostics).toEqual([]);
});
