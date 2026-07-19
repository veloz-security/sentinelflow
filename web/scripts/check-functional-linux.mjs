import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  VISUAL_WEB_INPUTS,
  assertVisualDockerIsolation,
  createSanitizedVisualInput,
  removeSanitizedVisualInput,
} from './check-visual-baselines-linux.mjs';

const image =
  'node:24.13.0-bookworm@sha256:1de022d8459f896fff2e7b865823699dc7a8d5567507e8b87b14a7442e07f206';
const command = String.raw`set -euo pipefail
node --version
mkdir -p /work/web /work/contracts
cp -R /source/web/. /work/web/
cp -R /source/contracts/. /work/contracts/
cp -R /source/deployments /work/deployments
cd /work/web
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install --with-deps chromium firefox webkit
npx playwright --version
npm run build
CI=1 npx playwright test \
  tests/analysis-provider.spec.ts \
  tests/enforcement-lifecycle.spec.ts \
  tests/hil-authorization.spec.ts \
  tests/incident-detail.spec.ts \
  tests/incidents.spec.ts \
  tests/live-management.spec.ts \
  tests/revocation-management.spec.ts \
  tests/smoke.spec.ts \
  tests/validation-review.spec.ts \
  --reporter=list`;

const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const repositoryRoot = resolve(webRoot, '..');
const webInputs = [
  ...VISUAL_WEB_INPUTS.filter((input) => !input.startsWith('tests/')),
  'tests',
];
const sanitized = await createSanitizedVisualInput({
  repositoryRoot,
  webInputs,
});
try {
  const dockerArguments = [
    'run',
    '--rm',
    '--init',
    '--ipc=host',
    '--mount',
    `type=bind,source=${sanitized.sourceRoot},target=/source,readonly`,
    image,
    'bash',
    '-lc',
    command,
  ];
  assertVisualDockerIsolation({
    dockerArguments,
    repositoryRoot,
    sourceRoot: sanitized.sourceRoot,
  });
  const result = spawnSync('docker', dockerArguments, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.signal) {
    throw new Error(`functional test container terminated by ${result.signal}`);
  }
  process.exitCode = result.status ?? 1;
} finally {
  await removeSanitizedVisualInput(sanitized.temporaryRoot);
}
