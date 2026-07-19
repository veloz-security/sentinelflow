import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import {
  composeBrowserQAFailureClass,
  composeBrowserQAFailureStage,
  navigateComposeBrowserQAPage,
  observeComposeBrowserQAPage,
  readComposeBrowserQACredentials,
  readComposeBrowserQALocator,
  waitForAuthenticatedManagement,
  writeComposeBrowserQAStopMarker,
} from './compose-browser-qa.mjs';

const roots = [];
const actionID = '019b0000-0000-7000-8000-000000000200';
const syntheticPassword = ['correct', 'horse', 'battery', 'staple'].join('-');

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture(overrides = {}) {
  const root = await mkdtemp(
    path.join(tmpdir(), 'sentinelflow-compose-browser-qa-'),
  );
  roots.push(root);
  await chmod(root, 0o700);
  const secrets = path.join(root, 'secrets');
  await mkdir(secrets, { mode: 0o700 });
  const credentialsFile = path.join(secrets, 'admin-credentials.json');
  await writeFile(
    credentialsFile,
    JSON.stringify({
      username: 'admin',
      password: syntheticPassword,
      generated_at: '2026-07-19T00:00:00.000Z',
    }),
    { mode: 0o600 },
  );
  const phase = overrides.phase ?? 'active';
  const locatorFile = path.join(root, `browser-qa-${phase}-locator.json`);
  const locator = {
    schema_version: 'sentinelflow-browser-qa-locator-v2',
    project: 'sf-demo-e2e-browserqa-1234',
    phase,
    web_url: 'http://localhost:4173/',
    credentials_file: credentialsFile,
    action_id: actionID,
    expected_action_state: phase,
    deadline: new Date(Date.now() + 60_000).toISOString(),
    stop_file: path.join(root, `browser-qa-${phase}.stop`),
    ...overrides,
  };
  await writeFile(locatorFile, JSON.stringify(locator), { mode: 0o600 });
  return { root, locator, locatorFile, credentialsFile };
}

describe('Compose browser QA locator boundary', () => {
  it('uses DOM readiness because authenticated management keeps SSE open', async () => {
    const calls = [];
    const page = {
      goto: async (...args) => {
        calls.push(args);
      },
    };
    await navigateComposeBrowserQAPage(page, 'http://localhost:4173/');
    expect(calls).toEqual([
      [
        'http://localhost:4173/',
        { waitUntil: 'domcontentloaded', timeout: 15_000 },
      ],
    ]);
  });

  it('retries one transient fixed-route navigation without changing the URL', async () => {
    const calls = [];
    const page = {
      goto: async (...args) => {
        calls.push(args);
        if (calls.length === 1) {
          throw new Error('page.goto: net::ERR_CONNECTION_RESET');
        }
      },
    };
    await navigateComposeBrowserQAPage(
      page,
      'http://localhost:4173/enforcement-actions/019b0000-0000-7000-8000-000000000200',
    );
    expect(calls).toEqual([
      [
        'http://localhost:4173/enforcement-actions/019b0000-0000-7000-8000-000000000200',
        { waitUntil: 'domcontentloaded', timeout: 15_000 },
      ],
      [
        'http://localhost:4173/enforcement-actions/019b0000-0000-7000-8000-000000000200',
        { waitUntil: 'domcontentloaded', timeout: 15_000 },
      ],
    ]);
  });

  it('does not retry a non-navigation failure or conceal a second navigation failure', async () => {
    const schemaFailure = {
      goto: async () => {
        throw new Error('unsafe route binding');
      },
    };
    await expect(
      navigateComposeBrowserQAPage(schemaFailure, 'http://localhost:4173/'),
    ).rejects.toThrow('unsafe route binding');

    let attempts = 0;
    const repeatedFailure = {
      goto: async () => {
        attempts += 1;
        throw new Error('page.goto: Timeout 30000ms exceeded');
      },
    };
    await expect(
      navigateComposeBrowserQAPage(
        repeatedFailure,
        'http://localhost:4173/enforcement-actions/019b0000-0000-7000-8000-000000000200',
      ),
    ).rejects.toThrow('Timeout');
    expect(attempts).toBe(2);
  });

  it('requires the authenticated shell and fails immediately for a rendered sign-in error', async () => {
    const waits = [];
    const page = {
      getByRole: (role, options = {}) => ({
        first: () => ({
          waitFor: async (waitOptions) => {
            waits.push([role, options, waitOptions]);
            if (role === 'navigation') return;
            await new Promise(() => {});
          },
        }),
      }),
    };
    await expect(waitForAuthenticatedManagement(page)).resolves.toBeUndefined();
    expect(waits).toContainEqual([
      'navigation',
      { name: 'Primary' },
      { state: 'visible' },
    ]);

    const rejectedPage = {
      getByRole: (role) => ({
        first: () => ({
          waitFor: async () => {
            if (role === 'alert') return;
            await new Promise(() => {});
          },
        }),
      }),
    };
    await expect(waitForAuthenticatedManagement(rejectedPage)).rejects.toThrow(
      'browser QA sign-in did not establish an authenticated management session',
    );
  });

  it('classifies failures by a fixed stage without returning error contents', () => {
    expect(
      composeBrowserQAFailureClass(
        new Error('page.goto: Timeout 30000ms exceeded while navigating'),
        'action-navigation',
      ),
    ).toBe('navigation');
    expect(
      composeBrowserQAFailureClass(
        new Error('locator.waitFor: Timeout 30000ms exceeded'),
        'action-heading',
      ),
    ).toBe('ui-readiness');
    expect(
      composeBrowserQAFailureClass(
        new Error('browser rendered a credential value'),
      ),
    ).toBe('secret-rendering');
    expect(
      composeBrowserQAFailureClass(
        new Error(
          'browser QA sign-in did not establish an authenticated management session',
        ),
      ),
    ).toBe('authentication');
    expect(
      composeBrowserQAFailureClass(
        new Error('browser QA observed console errors'),
      ),
    ).toBe('browser-console-error');
    expect(
      composeBrowserQAFailureClass(
        new Error('browser QA observed page errors'),
      ),
    ).toBe('browser-page-error');
    expect(
      composeBrowserQAFailureClass(new Error('untrusted example detail')),
    ).toBe('unexpected');

    const expectedStage = new Error('ignored');
    Object.defineProperty(expectedStage, 'composeBrowserQAStage', {
      value: 'action-heading',
    });
    expect(composeBrowserQAFailureStage(expectedStage)).toBe('action-heading');

    const untrustedStage = new Error('ignored');
    Object.defineProperty(untrustedStage, 'composeBrowserQAStage', {
      value: 'untrusted-error-detail',
    });
    expect(composeBrowserQAFailureStage(untrustedStage)).toBe('unknown');
  });

  it('observes console errors only on the authenticated action page', () => {
    const listeners = new Map();
    const page = {
      on(event, callback) {
        listeners.set(event, callback);
      },
    };
    const diagnostics = [];
    const mutations = [];
    observeComposeBrowserQAPage(page, diagnostics, mutations, false);
    expect([...listeners.keys()].sort()).toEqual(['pageerror', 'request']);

    const actionListeners = new Map();
    observeComposeBrowserQAPage(
      { on: (event, callback) => actionListeners.set(event, callback) },
      diagnostics,
      mutations,
      true,
    );
    expect([...actionListeners.keys()].sort()).toEqual([
      'console',
      'pageerror',
      'request',
    ]);
    actionListeners.get('console')({ type: () => 'error' });
    expect(diagnostics).toEqual(['console-error']);
  });

  it('accepts only a private exact locator and private credentials', async () => {
    const value = await fixture();
    await expect(
      readComposeBrowserQALocator(value.locatorFile),
    ).resolves.toMatchObject({
      action_id: actionID,
      expected_action_state: 'active',
      webURL: 'http://localhost:4173/',
    });
    await expect(
      readComposeBrowserQACredentials(value.credentialsFile),
    ).resolves.toEqual({
      username: 'admin',
      password: syntheticPassword,
    });
  });

  it.each([
    ['a non-localhost URL', { web_url: 'http://127.0.0.1:4173/' }],
    ['an expired deadline', { deadline: '2020-01-01T00:00:00.000Z' }],
    ['a mismatched state', { expected_action_state: 'revoked' }],
    ['an additional untrusted key', { extra: 'not-allowed' }],
  ])('fails closed for %s', async (_label, overrides) => {
    const value = await fixture(overrides);
    await expect(
      readComposeBrowserQALocator(value.locatorFile),
    ).rejects.toThrow();
  });

  it('rejects non-private credential files and writes a marker only once', async () => {
    const value = await fixture();
    await chmod(value.credentialsFile, 0o644);
    await expect(
      readComposeBrowserQACredentials(value.credentialsFile),
    ).rejects.toThrow(/mode 600/);
    await chmod(value.credentialsFile, 0o600);
    await writeComposeBrowserQAStopMarker(value.locator.stop_file);
    await expect(readFile(value.locator.stop_file, 'utf8')).resolves.toBe(
      'sentinelflow-browser-qa-stop-v1\n',
    );
    await expect(
      writeComposeBrowserQAStopMarker(value.locator.stop_file),
    ).rejects.toThrow();
  });
});
