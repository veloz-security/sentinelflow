import AxeBuilder from '@axe-core/playwright';
import type { Page, Route } from '@playwright/test';
import {
  ACTION_ID,
  ACTIVE_ENFORCEMENT_ACTION,
  HIL_IDEMPOTENCY_KEY,
  REVOCATION_CHALLENGE_ENVELOPE,
  REVOCATION_DECISION_ENVELOPE,
  REVOCATION_REPLAY_DECISION_ENVELOPE,
  REVOCATION_REASON,
  SESSION_ENVELOPE,
} from '../src/live/liveTestFixtures';
import { createBrowserJSONFixture } from './browser-json-fixture';
import { expect, test } from './test-fixture';

const frozenNow = Date.parse('2026-07-18T01:03:30Z');
const uuid = HIL_IDEMPOTENCY_KEY.slice('hil-'.length);

interface CapturedRequest {
  readonly body: Readonly<Record<string, unknown>>;
  readonly csrfToken: string | undefined;
  readonly idempotencyKey: string | undefined;
}

interface RevocationRoutes {
  readonly challengeRequests: CapturedRequest[];
  readonly decisionRequests: CapturedRequest[];
  setActionState(state: 'active' | 'expired'): void;
}

function capture(route: Route): CapturedRequest {
  const request = route.request();
  return {
    body: request.postDataJSON() as Readonly<Record<string, unknown>>,
    csrfToken: request.headers()['x-csrf-token'],
    idempotencyKey: request.headers()['idempotency-key'],
  };
}

async function installRevocationRoutes(
  page: Page,
  decisionMode: 'fresh' | 'response-loss-replay' | 'permission-denied',
): Promise<RevocationRoutes> {
  const challengeRequests: CapturedRequest[] = [];
  const decisionRequests: CapturedRequest[] = [];
  let actionState: 'active' | 'expired' = 'active';
  let decisionAttempt = 0;

  await page.addInitScript(
    ({ now, fixedUUID }) => {
      Date.now = () => now;
      Object.defineProperty(globalThis.crypto, 'randomUUID', {
        configurable: true,
        value: () => fixedUUID,
      });
    },
    { now: frozenNow, fixedUUID: uuid },
  );

  const fixture = await createBrowserJSONFixture(page, ({ method, url }) => {
    if (method === 'GET' && url.pathname === '/api/v1/session') {
      return { status: 200, value: SESSION_ENVELOPE };
    }
    if (
      method === 'GET' &&
      url.pathname === `/api/v1/enforcement-actions/${ACTION_ID}`
    ) {
      const action =
        actionState === 'active'
          ? ACTIVE_ENFORCEMENT_ACTION
          : {
              ...ACTIVE_ENFORCEMENT_ACTION,
              state: 'expired',
              version: ACTIVE_ENFORCEMENT_ACTION.version + 1,
              finished_at: '2026-07-18T01:34:02Z',
              updated_at: '2026-07-18T01:34:02Z',
            };
      return { status: 200, value: action };
    }
    if (
      method === 'POST' &&
      url.pathname ===
        `/api/v1/enforcement-actions/${ACTION_ID}/revocation-challenges`
    ) {
      if (decisionMode === 'permission-denied') {
        return {
          status: 403,
          value: {
            code: 'permission_denied',
            message: 'revocation permission is required',
            trace_id: '019b0000-0000-4000-8000-000000000499',
            details: {},
          },
        };
      }
      return { status: 201, value: REVOCATION_CHALLENGE_ENVELOPE };
    }
    if (
      method === 'POST' &&
      url.pathname === `/api/v1/enforcement-actions/${ACTION_ID}/revocations`
    ) {
      return {
        status: 200,
        value:
          decisionMode === 'response-loss-replay'
            ? REVOCATION_REPLAY_DECISION_ENVELOPE
            : REVOCATION_DECISION_ENVELOPE,
      };
    }
    return {
      status: 404,
      value: {
        code: 'not_found',
        message: 'the browser fixture route was not found',
        trace_id: '019b0000-0000-4000-8000-000000000497',
        details: {},
      },
    };
  });
  await page.route('**/api/v1/session', (route) => fixture.forward(route));
  const forwardEnforcementRequest = async (route: Route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname.endsWith('/revocation-challenges')) {
      challengeRequests.push(capture(route));
    }
    if (pathname.endsWith('/revocations')) {
      decisionRequests.push(capture(route));
      decisionAttempt += 1;
    }
    if (
      pathname.endsWith('/revocations') &&
      decisionMode === 'response-loss-replay' &&
      decisionAttempt === 1
    ) {
      await route.abort('failed');
      return;
    }
    await fixture.forward(route);
  };
  await page.route(
    `**/api/v1/enforcement-actions/${ACTION_ID}`,
    forwardEnforcementRequest,
  );
  await page.route(
    `**/api/v1/enforcement-actions/${ACTION_ID}/**`,
    forwardEnforcementRequest,
  );

  return {
    challengeRequests,
    decisionRequests,
    setActionState(state) {
      actionState = state;
    },
  };
}

async function openExactRevocation(page: Page) {
  await page.goto(`/enforcement-actions/${ACTION_ID}`);
  await expect(
    page.getByRole('heading', { level: 1, name: `Action ${ACTION_ID}` }),
  ).toBeVisible();
  await page
    .getByLabel('Administrator revocation reason')
    .fill(REVOCATION_REASON.reason_text);
  await page
    .getByRole('button', { name: 'Request exact revoke challenge' })
    .click();
  await expect(page.getByText('Browser checks passed')).toBeVisible();
}

test('revokes the exact active action and rotates the session', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const routes = await installRevocationRoutes(page, 'fresh');

  await openExactRevocation(page);
  await expect(page.getByText('Browser assurance boundary')).toBeVisible();
  await expect(
    page.getByText(
      /Policy, validation, and session digests are displayed server-bound values, not independent browser proof/,
    ),
  ).toBeVisible();
  for (const label of [
    'Policy digest (server-bound)',
    'Validation digest (server-bound)',
    'Session digest (server-bound)',
  ]) {
    await expect(page.getByText(label)).toBeVisible();
  }
  await expect(
    page.getByLabel('Exact revoke artifact awaiting confirmation'),
  ).toContainText(
    'delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }',
  );
  expect(await page.locator('body').innerText()).not.toContain(
    REVOCATION_CHALLENGE_ENVELOPE.challenge_nonce,
  );
  await page.getByLabel(/I reviewed the exact delete artifact/).check();
  await page
    .getByRole('button', { name: 'Revoke exact active action' })
    .click();

  await expect(page.getByText('Exact revocation recorded')).toBeVisible();
  await expect(
    page.getByText(REVOCATION_DECISION_ENVELOPE.revocation_id),
  ).toBeVisible();
  await page.getByRole('link', { name: /Session/ }).click();
  await expect(
    page.getByText(REVOCATION_DECISION_ENVELOPE.session.session_id),
  ).toBeVisible();
  await expect(page.getByText('Mutation guard ready')).toBeVisible();

  expect(routes.challengeRequests).toHaveLength(1);
  expect(routes.challengeRequests[0]).toEqual({
    body: {
      action_version: ACTIVE_ENFORCEMENT_ACTION.version,
      original_add_digest: ACTIVE_ENFORCEMENT_ACTION.canonical_artifact_digest,
      target_ipv4: ACTIVE_ENFORCEMENT_ACTION.target_ipv4,
    },
    csrfToken: SESSION_ENVELOPE.csrf_token,
    idempotencyKey: HIL_IDEMPOTENCY_KEY,
  });
  expect(routes.decisionRequests).toHaveLength(1);
  expect(routes.decisionRequests[0].idempotencyKey).toBe(HIL_IDEMPOTENCY_KEY);
  expect(routes.decisionRequests[0].body).toMatchObject({
    challenge: REVOCATION_CHALLENGE_ENVELOPE.challenge,
    challenge_nonce: REVOCATION_CHALLENGE_ENVELOPE.challenge_nonce,
    canonical_revoke_artifact:
      REVOCATION_CHALLENGE_ENVELOPE.canonical_revoke_artifact,
    reason: REVOCATION_REASON,
  });

  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations).toEqual([]);
});

test('recovers exact response loss as historical revocation and requires login', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const routes = await installRevocationRoutes(page, 'response-loss-replay');

  await openExactRevocation(page);
  await page.getByLabel(/I reviewed the exact delete artifact/).check();
  await page
    .getByRole('button', { name: 'Revoke exact active action' })
    .click();
  await expect(
    page.getByText('The exact revocation decision could not be recorded.'),
  ).toBeVisible();
  await expect(page.getByText('Browser checks passed')).toBeVisible();

  await page
    .getByRole('button', { name: 'Revoke exact active action' })
    .click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Sign in to review evidence' }),
  ).toBeVisible();
  await expect(
    page.getByText('Exact decision was already recorded'),
  ).toBeVisible();
  await expect(
    page.getByText(REVOCATION_REPLAY_DECISION_ENVELOPE.revocation_id),
  ).toBeVisible();
  expect(routes.decisionRequests).toHaveLength(2);
  expect(routes.decisionRequests[1]).toEqual(routes.decisionRequests[0]);
  expect(await page.locator('body').innerText()).not.toContain(
    REVOCATION_CHALLENGE_ENVELOPE.challenge_nonce,
  );

  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations).toEqual([]);
});

test('keeps permission denial and a later inactive action fail-closed', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const routes = await installRevocationRoutes(page, 'permission-denied');

  await page.goto(`/enforcement-actions/${ACTION_ID}`);
  await page
    .getByLabel('Administrator revocation reason')
    .fill(REVOCATION_REASON.reason_text);
  await page
    .getByRole('button', { name: 'Request exact revoke challenge' })
    .click();
  await expect(page.getByText('Permission required')).toBeVisible();
  await expect(page.getByText('Browser checks passed')).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Revoke exact active action' }),
  ).toHaveCount(0);

  routes.setActionState('expired');
  await page.reload();
  await expect(
    page.getByText('Manual revocation is unavailable'),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Request exact revoke challenge' }),
  ).toHaveCount(0);
  expect(routes.challengeRequests).toHaveLength(1);
  expect(routes.decisionRequests).toHaveLength(0);

  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations).toEqual([]);
});
