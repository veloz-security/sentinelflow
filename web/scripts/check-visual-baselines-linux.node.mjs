import assert from 'node:assert/strict';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  VISUAL_CONTRACT_INPUTS,
  VISUAL_DEPLOYMENT_INPUTS,
  VISUAL_WEB_INPUTS,
  assertVisualDockerIsolation,
  createSanitizedVisualInput,
  createVisualDockerArguments,
  removeSanitizedVisualInput,
} from './check-visual-baselines-linux.mjs';

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function writeFixture(root, relativePath, value = relativePath) {
  const path = join(root, ...relativePath.split('/'));
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, value);
}

test('container input is allowlisted, secret-free, narrowly mounted, and cleaned', async (t) => {
  const fixtureParent = await mkdtemp(
    join(tmpdir(), 'sentinelflow-visual-fixture-'),
  );
  t.after(() => rm(fixtureParent, { force: true, recursive: true }));

  const repositoryRoot = join(fixtureParent, 'repository');
  await mkdir(repositoryRoot, { recursive: true });
  for (const input of VISUAL_WEB_INPUTS) {
    if (input === 'src' || input.endsWith('-snapshots')) {
      await writeFixture(join(repositoryRoot, 'web'), `${input}/fixture.txt`);
    } else {
      await writeFixture(join(repositoryRoot, 'web'), input);
    }
  }
  for (const input of VISUAL_CONTRACT_INPUTS) {
    await writeFixture(join(repositoryRoot, 'contracts'), input);
  }
  for (const input of VISUAL_DEPLOYMENT_INPUTS) {
    await writeFixture(join(repositoryRoot, 'deployments'), input);
  }

  await writeFixture(repositoryRoot, '.env.local', 'OPENAI_API_KEY=never-copy');
  await writeFixture(repositoryRoot, 'secrets/demo/key', 'never-copy');
  await writeFixture(join(repositoryRoot, 'web'), '.env', 'never-copy');
  await writeFixture(
    join(repositoryRoot, 'web'),
    'src/.env.local',
    'never-copy',
  );
  await writeFixture(
    join(repositoryRoot, 'web'),
    'src/secrets/demo/key',
    'never-copy',
  );
  for (const excluded of [
    'node_modules/dependency.js',
    'dist/bundle.js',
    'playwright-report/index.html',
    'test-results/result.json',
    'output/playwright/screenshot.png',
    'reports/report.json',
    'results/result.json',
  ]) {
    await writeFixture(join(repositoryRoot, 'web'), excluded, 'never-copy');
  }

  const sanitized = await createSanitizedVisualInput({
    repositoryRoot,
    temporaryParent: fixtureParent,
  });
  t.after(() => removeSanitizedVisualInput(sanitized.temporaryRoot));

  assert.equal(
    await readFile(join(sanitized.sourceRoot, 'web/index.html'), 'utf8'),
    'index.html',
  );
  assert.equal(
    await readFile(
      join(
        sanitized.sourceRoot,
        'contracts/ai/sentinelflow_analysis_v1.schema.json',
      ),
      'utf8',
    ),
    'ai/sentinelflow_analysis_v1.schema.json',
  );
  assert.equal(
    await readFile(
      join(sanitized.sourceRoot, 'web/scripts/deploymentCsp.ts'),
      'utf8',
    ),
    'scripts/deploymentCsp.ts',
  );
  assert.equal(
    await readFile(
      join(sanitized.sourceRoot, 'web/scripts/productionCsp.ts'),
      'utf8',
    ),
    'scripts/productionCsp.ts',
  );
  assert.equal(
    await readFile(
      join(sanitized.sourceRoot, 'deployments/nginx.conf'),
      'utf8',
    ),
    'nginx.conf',
  );
  for (const forbidden of [
    'web/.env',
    'web/src/.env.local',
    'web/src/secrets',
    'web/node_modules',
    'web/dist',
    'web/playwright-report',
    'web/test-results',
    'web/output',
    'web/reports',
    'web/results',
  ]) {
    assert.equal(
      await exists(join(sanitized.sourceRoot, ...forbidden.split('/'))),
      false,
      `${forbidden} must not be reachable in the container source`,
    );
  }

  const dockerArguments = createVisualDockerArguments(sanitized.sourceRoot);
  assertVisualDockerIsolation({
    dockerArguments,
    repositoryRoot,
    sourceRoot: sanitized.sourceRoot,
  });
  const serializedArguments = dockerArguments.join('\n');
  assert.equal(serializedArguments.includes(repositoryRoot), false);
  assert.equal(serializedArguments.includes('.env.local'), false);
  assert.equal(serializedArguments.includes('secrets/demo'), false);
  assert.equal(
    dockerArguments.filter((argument) => argument.startsWith('type=bind,'))
      .length,
    1,
  );

  await removeSanitizedVisualInput(sanitized.temporaryRoot);
  assert.equal(await exists(sanitized.temporaryRoot), false);
});
