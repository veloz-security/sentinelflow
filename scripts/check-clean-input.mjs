#!/usr/bin/env node

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { execFile as execFileCallback } from 'node:child_process';

import { initializeSnapshotGit, materializeCleanInput } from './lib/clean-input-snapshot.mjs';

const execFile = promisify(execFileCallback);

function usage() {
  return `Usage: scripts/check-clean-input.mjs [--snapshot-only] [--output DIR] [-- command [args...]]

Materialize the current tracked and non-ignored working-tree source into a new
temporary Git-initialized snapshot, then run the given command there. With no
command, the default is: make check

This is pre-commit source-snapshot evidence only. It cannot prove a committed
checkout, a GitHub Actions run, or Linux release qualification.
`;
}

function parseArgs(argv) {
  let snapshotOnly = false;
  let output;
  let command;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') {
      return { help: true };
    }
    if (arg === '--snapshot-only') {
      snapshotOnly = true;
      continue;
    }
    if (arg === '--output') {
      output = argv[index + 1];
      if (!output) {
        throw new Error('--output requires a directory');
      }
      index += 1;
      continue;
    }
    if (arg === '--') {
      command = argv.slice(index + 1);
      break;
    }
    throw new Error(`unknown option: ${arg}`);
  }

  if (snapshotOnly && command?.length) {
    throw new Error('--snapshot-only cannot be combined with a command');
  }
  return { snapshotOnly, output, command };
}

async function repoRoot() {
  const { stdout } = await execFile('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'utf8',
  });
  return stdout.trim();
}

function run(command, cwd) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command[0], command.slice(1), { cwd, stdio: 'inherit' });
    child.on('error', reject);
    child.on('exit', (code, signal) => {
      if (code === 0) {
        resolvePromise();
        return;
      }
      reject(new Error(`snapshot command failed (${signal ?? `exit ${code}`}): ${command.join(' ')}`));
    });
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }

  const sourceRoot = await repoRoot();
  const persistentOutput = options.output ? resolve(options.output) : undefined;
  const temporaryParent = persistentOutput ? undefined : await mkdtemp(resolve(tmpdir(), 'sentinelflow-clean-input-'));
  const snapshotRoot = persistentOutput ?? resolve(temporaryParent, 'source');
  const cleanup = !persistentOutput;

  try {
    const snapshot = await materializeCleanInput({
      repoRoot: sourceRoot,
      destinationRoot: snapshotRoot,
    });
    await initializeSnapshotGit(snapshotRoot);

    process.stdout.write(`CLEAN_INPUT_SNAPSHOT=${snapshotRoot}\n`);
    process.stdout.write(`CLEAN_INPUT_FILE_COUNT=${snapshot.fileCount}\n`);
    process.stdout.write(`CLEAN_INPUT_MANIFEST_SHA256=${snapshot.manifestSha256}\n`);
    process.stdout.write('CLEAN_INPUT_SCOPE=pre-commit source snapshot; not committed-checkout or CI evidence\n');

    if (!options.snapshotOnly) {
      await run(options.command?.length ? options.command : ['make', 'check'], snapshotRoot);
    }
  } finally {
    if (cleanup) {
      await rm(temporaryParent, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  process.stderr.write(`check-clean-input: ${error.message}\n`);
  process.exitCode = 1;
});
