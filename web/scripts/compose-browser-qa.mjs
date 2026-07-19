#!/usr/bin/env node

import AxeBuilder from '@axe-core/playwright';
import { chromium } from '@playwright/test';
import { lstat, mkdir, open, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { validateBrowserQALocator } from '../../scripts/lib/demo-e2e.mjs';

const LOCATOR_SCHEMA = 'sentinelflow-browser-qa-locator-v2';
const CREDENTIAL_KEYS = Object.freeze(['generated_at', 'password', 'username']);
const STOP_MARKER = 'sentinelflow-browser-qa-stop-v1\n';
const MAX_LOCATOR_REMAINING_MS = 15 * 60 * 1_000;
const MANAGEMENT_NAVIGATION_OPTIONS = Object.freeze({
  // The authenticated application deliberately keeps one SSE connection open.
  // `networkidle` therefore cannot be a completion condition for the real
  // Compose UI; route-specific visible state below is the bounded readiness
  // proof instead.
  waitUntil: 'domcontentloaded',
  // The E2E hold may be as short as 60 seconds. Keep one retry bounded so a
  // transient deep-link failure cannot consume the entire revoked-phase gate.
  timeout: 15_000,
});
const MANAGEMENT_NAVIGATION_ATTEMPTS = 2;
const FAILURE_STAGES = new Set([
  'locator',
  'credentials',
  'browser-launch',
  'sign-in-navigation',
  'sign-in-heading',
  'sign-in-submit',
  'sign-in-ready',
  'action-navigation',
  'action-heading',
  'action-state',
  'authority-boundary',
  'accessibility',
  'screenshot',
  'stop-marker',
]);
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function exactRecord(value, label, keys) {
  invariant(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} is invalid`,
  );
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  invariant(
    actual.length === expected.length &&
      actual.every((key, index) => key === expected[index]),
    `${label} shape is invalid`,
  );
  return value;
}

function parseStrictJSON(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function privateRegularMode(stat, mode, label) {
  invariant(
    stat.isFile() && !stat.isSymbolicLink(),
    `${label} must be a regular non-symlink file`,
  );
  invariant(
    (stat.mode & 0o777) === mode,
    `${label} must have mode ${mode.toString(8)}`,
  );
}

async function readPrivateJSON(filename, mode, label) {
  privateRegularMode(await lstat(filename), mode, label);
  return parseStrictJSON(await readFile(filename, 'utf8'), label);
}

function localWebURL(value) {
  invariant(
    typeof value === 'string' && value.length <= 256,
    'browser QA web URL is invalid',
  );
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('browser QA web URL is invalid');
  }
  invariant(
    parsed.protocol === 'http:' &&
      parsed.hostname === 'localhost' &&
      parsed.pathname === '/' &&
      parsed.search === '' &&
      parsed.hash === '' &&
      parsed.username === '' &&
      parsed.password === '' &&
      /^[1-9][0-9]{0,4}$/.test(parsed.port) &&
      Number(parsed.port) <= 65_535,
    'browser QA web URL is invalid',
  );
  return parsed;
}

function deadlineMilliseconds(value, now = Date.now()) {
  invariant(typeof value === 'string', 'browser QA deadline is invalid');
  const parsed = Date.parse(value);
  invariant(
    Number.isFinite(parsed) &&
      parsed > now &&
      parsed - now <= MAX_LOCATOR_REMAINING_MS,
    'browser QA locator is stale or has an invalid deadline',
  );
  return parsed;
}

function locatorExpectation(locator, root, webURL) {
  invariant(
    locator.schema_version === LOCATOR_SCHEMA,
    'browser QA locator schema is invalid',
  );
  invariant(
    locator.phase === 'active' || locator.phase === 'revoked',
    'browser QA locator phase is invalid',
  );
  invariant(
    locator.expected_action_state === locator.phase,
    'browser QA locator state binding is invalid',
  );
  invariant(
    typeof locator.project === 'string' && locator.project.length > 0,
    'browser QA project is invalid',
  );
  invariant(
    typeof locator.credentials_file === 'string' &&
      typeof locator.stop_file === 'string',
    'browser QA locator paths are invalid',
  );
  invariant(
    typeof locator.action_id === 'string' && UUID.test(locator.action_id),
    'browser QA action ID is invalid',
  );
  return {
    root,
    project: locator.project,
    phase: locator.phase,
    web_port: Number(webURL.port),
    credentials_file: locator.credentials_file,
    action_id: locator.action_id,
    expected_action_state: locator.expected_action_state,
    deadline: locator.deadline,
    stop_file: locator.stop_file,
  };
}

export async function readComposeBrowserQALocator(
  locatorFile,
  now = Date.now(),
) {
  invariant(
    typeof locatorFile === 'string' && path.isAbsolute(locatorFile),
    'browser QA locator path is invalid',
  );
  const normalized = path.normalize(locatorFile);
  invariant(
    normalized === locatorFile && !locatorFile.includes('\0'),
    'browser QA locator path is invalid',
  );
  const root = path.dirname(locatorFile);
  const raw = await readPrivateJSON(locatorFile, 0o600, 'browser QA locator');
  const webURL = localWebURL(raw.web_url);
  const locator = validateBrowserQALocator(
    raw,
    locatorExpectation(raw, root, webURL),
  );
  invariant(
    path.basename(locatorFile) === `browser-qa-${locator.phase}-locator.json`,
    'browser QA locator filename is invalid',
  );
  deadlineMilliseconds(locator.deadline, now);
  return Object.freeze({ ...locator, webURL: webURL.toString() });
}

export async function readComposeBrowserQACredentials(credentialsFile) {
  const credentials = exactRecord(
    await readPrivateJSON(credentialsFile, 0o600, 'browser QA credential file'),
    'browser QA credential file',
    CREDENTIAL_KEYS,
  );
  invariant(
    typeof credentials.username === 'string' &&
      credentials.username.length >= 1 &&
      credentials.username.length <= 128,
    'browser QA credential username is invalid',
  );
  invariant(
    typeof credentials.password === 'string' &&
      credentials.password.length >= 16 &&
      credentials.password.length <= 128,
    'browser QA credential password is invalid',
  );
  invariant(
    typeof credentials.generated_at === 'string' &&
      Number.isFinite(Date.parse(credentials.generated_at)),
    'browser QA credential timestamp is invalid',
  );
  return { username: credentials.username, password: credentials.password };
}

export async function writeComposeBrowserQAStopMarker(stopFile) {
  const handle = await open(stopFile, 'wx', 0o600);
  try {
    await handle.writeFile(STOP_MARKER, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  privateRegularMode(await lstat(stopFile), 0o600, 'browser QA stop marker');
}

function screenshotPath(locator) {
  const filename = `${locator.project}-${locator.phase}.png`;
  invariant(
    /^[a-z0-9-]{1,128}-(?:active|revoked)\.png$/.test(filename),
    'browser QA screenshot filename is invalid',
  );
  return path.resolve('web', 'output', 'compose-browser-qa', filename);
}

export function composeBrowserQAFailureClass(error, stage = '') {
  const message = error instanceof Error ? error.message : '';
  if (/browser QA (?:locator|credential)|schema is invalid/.test(message)) {
    return 'private-input';
  }
  if (/critical accessibility/.test(message)) return 'accessibility';
  if (
    /direct revocation authority|unexpected enforcement mutation/.test(message)
  ) {
    return 'authority-boundary';
  }
  if (/credential value/.test(message)) return 'secret-rendering';
  if (
    /sign-in did not establish an authenticated management session/.test(
      message,
    )
  ) {
    return 'authentication';
  }
  if (/browser QA observed page errors/.test(message))
    return 'browser-page-error';
  if (/browser QA observed console errors/.test(message)) {
    return 'browser-console-error';
  }
  // A timeout while waiting for a rendered route state is not evidence that
  // the network navigation failed.  Keep the public failure class narrow and
  // pair it with the fixed, non-sensitive stage below so a later E2E run can
  // distinguish a route load from an action-detail contract/readiness issue
  // without logging an URL, response body, credentials, or browser error.
  if (/timeout|navigation|net::ERR/i.test(message)) {
    return stage.endsWith('-navigation') ? 'navigation' : 'ui-readiness';
  }
  return 'unexpected';
}

export function composeBrowserQAFailureStage(error) {
  const stage =
    error instanceof Error ? error.composeBrowserQAStage : undefined;
  return typeof stage === 'string' && FAILURE_STAGES.has(stage)
    ? stage
    : 'unknown';
}

function transientNavigationError(error) {
  const message = error instanceof Error ? error.message : '';
  return /timeout|navigation|net::ERR/i.test(message);
}

export async function navigateComposeBrowserQAPage(page, url) {
  for (
    let attempt = 1;
    attempt <= MANAGEMENT_NAVIGATION_ATTEMPTS;
    attempt += 1
  ) {
    try {
      await page.goto(url, MANAGEMENT_NAVIGATION_OPTIONS);
      return;
    } catch (error) {
      if (
        attempt === MANAGEMENT_NAVIGATION_ATTEMPTS ||
        !transientNavigationError(error)
      ) {
        throw error;
      }
    }
  }
}

// Login does not navigate away from the root route.  Wait for the explicit
// authenticated shell landmark instead of assuming that a completed click
// changed application state.  A rendered login error is a terminal result for
// this one-attempt QA flow: retrying credentials here could consume the
// server-side pre-hash login budget and would hide a real authentication
// failure.  The error text itself is intentionally not propagated to output.
export async function waitForAuthenticatedManagement(page) {
  const authenticated = page
    .getByRole('navigation', { name: 'Primary' })
    .first()
    .waitFor({ state: 'visible' })
    .then(() => 'authenticated');
  const rejected = page
    .getByRole('alert')
    .first()
    .waitFor({ state: 'visible' })
    .then(() => 'rejected');
  const outcome = await Promise.race([authenticated, rejected]);
  invariant(
    outcome === 'authenticated',
    'browser QA sign-in did not establish an authenticated management session',
  );
}

export function observeComposeBrowserQAPage(
  page,
  diagnostics,
  mutationRequests,
  observeConsole,
) {
  page.on('pageerror', () => diagnostics.push('pageerror'));
  if (observeConsole) {
    page.on('console', (message) => {
      if (message.type() === 'error') diagnostics.push('console-error');
    });
  }
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (
      request.method() !== 'GET' &&
      url.pathname.includes('/enforcement-actions/')
    ) {
      mutationRequests.push(true);
    }
  });
}

async function assertNoDirectBrowserAuthority(page, locator, mutationRequests) {
  const body = page.locator('body');
  await body
    .getByText(
      'Capabilities, signatures, handles, and executor request bytes are not exposed.',
    )
    .waitFor();
  const commit = page.getByRole('button', {
    name: 'Revoke exact active action',
  });
  invariant(
    (await commit.count()) === 0,
    'browser exposed direct revocation authority without an exact challenge',
  );

  if (locator.expected_action_state === 'active') {
    const requestChallenge = page.getByRole('button', {
      name: 'Request exact revoke challenge',
    });
    await requestChallenge.waitFor();
    invariant(
      await requestChallenge.isDisabled(),
      'browser enabled a revoke challenge without a bound administrator reason',
    );
  } else {
    await page.getByText('Manual revocation is unavailable').waitFor();
    await page
      .getByText('Only an active enforcement action can be revoked.')
      .waitFor();
    invariant(
      (await page
        .getByRole('button', { name: 'Request exact revoke challenge' })
        .count()) === 0,
      'browser exposed a revocation challenge for a non-active action',
    );
  }

  invariant(
    mutationRequests.length === 0,
    'browser QA observed an unexpected enforcement mutation request',
  );
}

export async function runComposeBrowserQA(locatorFile) {
  let stage = 'locator';
  let phase = '';
  let browser;
  let credentials;
  let browserPassword = '';
  const mutationRequests = [];
  const diagnostics = [];
  try {
    const locator = await readComposeBrowserQALocator(locatorFile);
    phase = locator.phase;
    stage = 'credentials';
    credentials = await readComposeBrowserQACredentials(
      locator.credentials_file,
    );
    const screenshot = screenshotPath(locator);
    browserPassword = credentials.password;
    stage = 'browser-launch';
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const signInPage = await context.newPage();
    // The unauthenticated session bootstrap intentionally receives a strict
    // `authentication_required` response. Chromium may surface that expected
    // HTTP 401 as a console error, even though the application converts it to
    // the sign-in state. Preserve page-error and mutation checks here, but
    // begin console-error observation only on the authenticated action page.
    observeComposeBrowserQAPage(
      signInPage,
      diagnostics,
      mutationRequests,
      false,
    );

    stage = 'sign-in-navigation';
    await navigateComposeBrowserQAPage(signInPage, locator.webURL);
    stage = 'sign-in-heading';
    await signInPage
      .getByRole('heading', { level: 1, name: 'Sign in to review evidence' })
      .waitFor();
    stage = 'sign-in-submit';
    await signInPage
      .locator('input[name="username"]')
      .fill(credentials.username);
    await signInPage.locator('input[name="password"]').fill(browserPassword);
    credentials.password = '';
    await signInPage.getByRole('button', { name: 'Sign in' }).click();
    stage = 'sign-in-ready';
    await waitForAuthenticatedManagement(signInPage);

    const actionURL = new URL(
      `/enforcement-actions/${locator.action_id}`,
      locator.webURL,
    ).toString();
    stage = 'action-navigation';
    // A full navigation from the signed-in page cancels its live SSE request
    // and Chromium reports that intentional cancellation as a console error.
    // A second same-context page preserves the authenticated cookie, exercises
    // the production deep-link route, and leaves every observed diagnostic
    // meaningful rather than suppressing a broad class of errors.
    const page = await context.newPage();
    observeComposeBrowserQAPage(page, diagnostics, mutationRequests, true);
    await navigateComposeBrowserQAPage(page, actionURL);
    stage = 'action-heading';
    await page
      .getByRole('heading', { level: 1, name: `Action ${locator.action_id}` })
      .waitFor();
    stage = 'action-state';
    await page
      .getByText(locator.expected_action_state, { exact: true })
      .first()
      .waitFor();
    invariant(
      !(await page.locator('body').innerText()).includes(browserPassword),
      'browser rendered a credential value',
    );
    browserPassword = '';
    stage = 'authority-boundary';
    await assertNoDirectBrowserAuthority(page, locator, mutationRequests);
    stage = 'accessibility';
    const accessibility = await new AxeBuilder({ page }).analyze();
    invariant(
      accessibility.violations.every(
        (violation) => violation.impact !== 'critical',
      ),
      'browser QA found a critical accessibility violation',
    );
    invariant(
      !diagnostics.includes('pageerror'),
      'browser QA observed page errors',
    );
    invariant(
      !diagnostics.includes('console-error'),
      'browser QA observed console errors',
    );
    stage = 'screenshot';
    await mkdir(path.dirname(screenshot), { recursive: true, mode: 0o700 });
    await page.screenshot({ path: screenshot, fullPage: true });
    await context.close();
    stage = 'stop-marker';
    await writeComposeBrowserQAStopMarker(locator.stop_file);
  } catch (error) {
    const failure =
      error instanceof Error ? error : new Error('browser QA failed');
    Object.defineProperty(failure, 'composeBrowserQAStage', {
      configurable: true,
      value: stage,
    });
    throw failure;
  } finally {
    if (credentials) credentials.password = '';
    browserPassword = '';
    await browser?.close();
  }
  return Object.freeze({ phase, stage });
}

function parseArguments(args) {
  invariant(
    args.length === 2 && args[0] === '--locator' && path.isAbsolute(args[1]),
    'usage: node web/scripts/compose-browser-qa.mjs --locator /absolute/browser-qa-locator.json',
  );
  return args[1];
}

async function main() {
  try {
    const locatorFile = parseArguments(process.argv.slice(2));
    const result = await runComposeBrowserQA(locatorFile);
    invariant(
      result.stage === 'stop-marker' &&
        (result.phase === 'active' || result.phase === 'revoked'),
      'browser QA did not reach stop marker',
    );
    const { phase } = result;
    process.stdout.write(`PASS: Compose browser QA ${phase} verified.\n`);
  } catch (error) {
    const stage = composeBrowserQAFailureStage(error);
    process.stderr.write(
      `ERROR: Compose browser QA failed class=${composeBrowserQAFailureClass(error, stage)} stage=${stage || 'unknown'} without writing a stop marker.\n`,
    );
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
