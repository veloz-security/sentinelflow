import { spawnSync } from 'node:child_process';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const VISUAL_BASELINE_IMAGE =
  'mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48';

export const VISUAL_WEB_INPUTS = Object.freeze([
  'index.html',
  'package-lock.json',
  'package.json',
  'playwright.config.ts',
  'src',
  'scripts/deploymentCsp.ts',
  'scripts/productionCsp.ts',
  'tests/mock-management-hil.mjs',
  'tests/mock-management-server.mjs',
  'tests/test-fixture.ts',
  'tests/visual-stability.spec.ts',
  'tests/visual-stability.spec.ts-snapshots',
  'tsconfig.app.json',
  'tsconfig.json',
  'tsconfig.node.json',
  'vite.config.ts',
]);

export const VISUAL_CONTRACT_INPUTS = Object.freeze([
  'ai/sentinelflow_analysis_input_v1.schema.json',
  'ai/sentinelflow_analysis_v1.schema.json',
  'enforcement/demo_history_manifest_v1.schema.json',
  'enforcement/execution_result_v1.schema.json',
  'enforcement/hil_challenge_v1.schema.json',
  'enforcement/hil_decision_v1.schema.json',
  'enforcement/hil_reason_v1.schema.json',
  'enforcement/response_policy_v1.schema.json',
  'enforcement/validation_snapshot_v1.schema.json',
  'events/auth_event_v1.schema.json',
  'events/gateway_http_v1.schema.json',
  'events/source_health_v1.schema.json',
  'fixtures/demo_history_manifest_v1.json',
  'fixtures/demo_history_signed_manifest_v1.schema.json',
]);

// `vite.config.ts` loads the pinned CSP from this deployment input during the
// production build. Keep this explicit rather than mounting the repository's
// whole deployment directory into the Linux verification container.
export const VISUAL_DEPLOYMENT_INPUTS = Object.freeze(['nginx.conf']);

const forbiddenNames = new Set([
  'dist',
  'node_modules',
  'output',
  'playwright-report',
  'reports',
  'results',
  'secrets',
  'test-results',
]);

export const VISUAL_BASELINE_COMMAND = String.raw`set -euo pipefail
node --version
mkdir -p /work/web /work/contracts
cp -R /source/web/. /work/web/
cp -R /source/contracts/. /work/contracts/
cp -R /source/deployments /work/deployments
cd /work/web
npm ci --ignore-scripts --no-audit --no-fund
npx playwright --version
npm run build
CI=1 npx playwright test tests/visual-stability.spec.ts --reporter=list`;

function isForbiddenName(name) {
  const normalizedName = name.toLowerCase();
  return (
    normalizedName === '.env' ||
    normalizedName.startsWith('.env.') ||
    forbiddenNames.has(normalizedName)
  );
}

function assertRelativeInput(input) {
  if (
    input.length === 0 ||
    input.startsWith('/') ||
    input
      .split('/')
      .some((segment) => segment === '..' || isForbiddenName(segment))
  ) {
    throw new Error(`unsafe visual baseline input: ${input}`);
  }
}

async function copyAllowlistedEntry(source, destination) {
  const sourceStat = await lstat(source);
  if (sourceStat.isSymbolicLink()) {
    throw new Error(`visual baseline input cannot be a symlink: ${source}`);
  }
  if (sourceStat.isDirectory()) {
    await mkdir(destination, { mode: 0o700, recursive: true });
    const entries = await readdir(source, { withFileTypes: true });
    for (const entry of entries.sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      if (isForbiddenName(entry.name)) continue;
      await copyAllowlistedEntry(
        join(source, entry.name),
        join(destination, entry.name),
      );
    }
    return;
  }
  if (!sourceStat.isFile()) {
    throw new Error(
      `visual baseline input must be a file or directory: ${source}`,
    );
  }
  await mkdir(dirname(destination), { mode: 0o700, recursive: true });
  await copyFile(source, destination);
  await chmod(destination, 0o600);
}

async function copyInputs(sourceRoot, destinationRoot, inputs) {
  for (const input of inputs) {
    assertRelativeInput(input);
    await copyAllowlistedEntry(
      join(sourceRoot, ...input.split('/')),
      join(destinationRoot, ...input.split('/')),
    );
  }
}

async function assertSanitizedTree(root) {
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (isForbiddenName(entry.name)) {
      throw new Error(`forbidden visual baseline path copied: ${entry.name}`);
    }
    const path = join(root, entry.name);
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) {
      throw new Error(`visual baseline copy contains a symlink: ${path}`);
    }
    if (stat.isDirectory()) await assertSanitizedTree(path);
  }
}

export async function createSanitizedVisualInput({
  repositoryRoot,
  temporaryParent = tmpdir(),
  webInputs = VISUAL_WEB_INPUTS,
  contractInputs = VISUAL_CONTRACT_INPUTS,
  deploymentInputs = VISUAL_DEPLOYMENT_INPUTS,
}) {
  const resolvedRepositoryRoot = resolve(repositoryRoot);
  const temporaryRoot = await mkdtemp(
    join(resolve(temporaryParent), 'sentinelflow-visual-'),
  );
  await chmod(temporaryRoot, 0o700);
  const sourceRoot = join(temporaryRoot, 'source');
  try {
    await mkdir(join(sourceRoot, 'web'), { mode: 0o700, recursive: true });
    await mkdir(join(sourceRoot, 'contracts'), {
      mode: 0o700,
      recursive: true,
    });
    await mkdir(join(sourceRoot, 'deployments'), {
      mode: 0o700,
      recursive: true,
    });
    await copyInputs(
      join(resolvedRepositoryRoot, 'web'),
      join(sourceRoot, 'web'),
      webInputs,
    );
    await copyInputs(
      join(resolvedRepositoryRoot, 'contracts'),
      join(sourceRoot, 'contracts'),
      contractInputs,
    );
    await copyInputs(
      join(resolvedRepositoryRoot, 'deployments'),
      join(sourceRoot, 'deployments'),
      deploymentInputs,
    );
    await assertSanitizedTree(sourceRoot);
    return Object.freeze({ temporaryRoot, sourceRoot });
  } catch (error) {
    await rm(temporaryRoot, { force: true, recursive: true });
    throw error;
  }
}

export async function removeSanitizedVisualInput(temporaryRoot) {
  await rm(temporaryRoot, { force: true, recursive: true });
}

export function createVisualDockerArguments(sourceRoot) {
  return [
    'run',
    '--rm',
    '--init',
    '--ipc=host',
    '--mount',
    `type=bind,source=${resolve(sourceRoot)},target=/source,readonly`,
    VISUAL_BASELINE_IMAGE,
    'bash',
    '-lc',
    VISUAL_BASELINE_COMMAND,
  ];
}

export function assertVisualDockerIsolation({
  dockerArguments,
  repositoryRoot,
  sourceRoot,
}) {
  const serialized = dockerArguments.join('\n');
  const resolvedRepositoryRoot = resolve(repositoryRoot);
  const resolvedSourceRoot = resolve(sourceRoot);
  const relativeSource = relative(resolvedRepositoryRoot, resolvedSourceRoot);
  if (
    relativeSource === '' ||
    (!relativeSource.startsWith(`..${sep}`) && relativeSource !== '..')
  ) {
    throw new Error('sanitized visual input must be outside the repository');
  }
  if (serialized.includes(resolvedRepositoryRoot)) {
    throw new Error('visual baseline container must not mount the repository');
  }
  const mounts = dockerArguments.filter((argument) =>
    argument.startsWith('type=bind,'),
  );
  if (
    mounts.length !== 1 ||
    !mounts[0].includes(`source=${resolvedSourceRoot},`) ||
    !mounts[0].endsWith(',readonly')
  ) {
    throw new Error(
      'visual baseline container requires one sanitized read-only bind',
    );
  }
}

export async function runVisualBaselines({
  repositoryRoot,
  spawn = spawnSync,
} = {}) {
  const scriptWebRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const resolvedRepositoryRoot = resolve(
    repositoryRoot ?? resolve(scriptWebRoot, '..'),
  );
  const sanitized = await createSanitizedVisualInput({
    repositoryRoot: resolvedRepositoryRoot,
  });
  try {
    const dockerArguments = createVisualDockerArguments(sanitized.sourceRoot);
    assertVisualDockerIsolation({
      dockerArguments,
      repositoryRoot: resolvedRepositoryRoot,
      sourceRoot: sanitized.sourceRoot,
    });
    const result = spawn('docker', dockerArguments, { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.signal) {
      throw new Error(
        `visual baseline container terminated by ${result.signal}`,
      );
    }
    return result.status ?? 1;
  } finally {
    await removeSanitizedVisualInput(sanitized.temporaryRoot);
  }
}

const invokedPath = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : '';
if (import.meta.url === invokedPath) {
  process.exitCode = await runVisualBaselines();
}
