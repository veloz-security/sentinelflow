import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { materializeCleanInput } from './lib/clean-input-snapshot.mjs';

const execFile = promisify(execFileCallback);
const script = new URL('./check-clean-input.mjs', import.meta.url);

async function exec(command, args, cwd) {
  return execFile(command, args, { cwd, encoding: 'utf8' });
}

test('snapshot includes modified tracked and unignored files but excludes ignored local input', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sentinelflow-clean-input-source-'));
  const output = await mkdtemp(join(tmpdir(), 'sentinelflow-clean-input-output-'));
  await rm(output, { recursive: true, force: true });
  t.after(() => Promise.all([
    rm(root, { recursive: true, force: true }),
    rm(output, { recursive: true, force: true }),
  ]));

  await exec('git', ['init', '--quiet'], root);
  await writeFile(join(root, '.gitignore'), 'ignored.txt\n', 'utf8');
  await writeFile(join(root, 'tracked.txt'), 'initial\n', 'utf8');
  await exec('git', ['add', '.gitignore', 'tracked.txt'], root);
  await writeFile(join(root, 'tracked.txt'), 'working tree version\n', 'utf8');
  await writeFile(join(root, 'untracked.txt'), 'include me\n', 'utf8');
  await writeFile(join(root, 'ignored.txt'), 'do not copy\n', 'utf8');

  const { stdout } = await exec(process.execPath, [script.pathname, '--snapshot-only', '--output', output], root);
  assert.match(stdout, /CLEAN_INPUT_SCOPE=pre-commit source snapshot/);
  assert.equal(await readFile(join(output, 'tracked.txt'), 'utf8'), 'working tree version\n');
  assert.equal(await readFile(join(output, 'untracked.txt'), 'utf8'), 'include me\n');
  await assert.rejects(readFile(join(output, 'ignored.txt'), 'utf8'), { code: 'ENOENT' });
  await exec('git', ['diff', '--check'], output);
});

test('snapshot destination inside the source repository fails closed', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sentinelflow-clean-input-source-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await exec('git', ['init', '--quiet'], root);
  await writeFile(join(root, 'tracked.txt'), 'initial\n', 'utf8');
  await exec('git', ['add', 'tracked.txt'], root);

  await assert.rejects(
    materializeCleanInput({ repoRoot: root, destinationRoot: join(root, 'nested-output') }),
    /destination must be outside the source repository/,
  );
});

test('runs an explicit command from the isolated snapshot', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sentinelflow-clean-input-source-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await exec('git', ['init', '--quiet'], root);
  await writeFile(join(root, 'tracked.txt'), 'snapshot command input\n', 'utf8');
  await exec('git', ['add', 'tracked.txt'], root);

  const { stdout } = await exec(
    process.execPath,
    [
      script.pathname,
      '--',
      process.execPath,
      '-e',
      "process.stdout.write(require('node:fs').readFileSync('tracked.txt', 'utf8'))",
    ],
    root,
  );
  assert.match(stdout, /snapshot command input/);
});
