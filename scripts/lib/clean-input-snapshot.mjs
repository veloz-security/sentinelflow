import { createHash } from 'node:crypto';
import { copyFile, chmod, lstat, mkdir, readFile, readlink, rm, symlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';
import { execFile as execFileCallback } from 'node:child_process';

const execFile = promisify(execFileCallback);

function splitNul(value) {
  return value.split('\0').filter(Boolean);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validateRelativePath(path) {
  if (!path || isAbsolute(path) || path.split(/[\\/]/).includes('..')) {
    throw new Error(`unsafe repository path in clean-input manifest: ${JSON.stringify(path)}`);
  }
  return path;
}

async function git(repoRoot, args) {
  const { stdout } = await execFile('git', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  return stdout;
}

export async function listSourceFiles(repoRoot) {
  const output = await git(repoRoot, [
    'ls-files',
    '-z',
    '--cached',
    '--others',
    '--exclude-standard',
  ]);
  return [...new Set(splitNul(output).map(validateRelativePath))].sort();
}

function assertDestinationOutsideSource(repoRoot, destinationRoot) {
  const rel = relative(repoRoot, destinationRoot);
  if (rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))) {
    throw new Error('clean-input destination must be outside the source repository');
  }
}

async function copyOne(sourceRoot, destinationRoot, path) {
  const source = resolve(sourceRoot, path);
  const destination = resolve(destinationRoot, path);
  const stat = await lstat(source);

  if (stat.isDirectory()) {
    throw new Error(`git file manifest unexpectedly contains a directory: ${path}`);
  }
  if (!stat.isFile() && !stat.isSymbolicLink()) {
    throw new Error(`unsupported file type in clean-input snapshot: ${path}`);
  }

  await mkdir(dirname(destination), { recursive: true });
  if (stat.isSymbolicLink()) {
    const target = await readlink(source);
    const targetRelativeToSnapshot = relative(destinationRoot, resolve(dirname(destination), target));
    if (
      isAbsolute(target)
      || targetRelativeToSnapshot === '..'
      || targetRelativeToSnapshot.startsWith(`..${sep}`)
      || isAbsolute(targetRelativeToSnapshot)
    ) {
      throw new Error(`symlink escapes clean-input snapshot: ${path}`);
    }
    await symlink(target, destination);
    return { path, type: 'symlink', sha256: sha256(`symlink\0${target}`) };
  }

  await copyFile(source, destination);
  await chmod(destination, stat.mode & 0o777);
  return { path, type: 'file', sha256: sha256(await readFile(source)) };
}

export async function materializeCleanInput({ repoRoot, destinationRoot }) {
  const source = resolve(repoRoot);
  const destination = resolve(destinationRoot);
  assertDestinationOutsideSource(source, destination);
  await mkdir(destination, { recursive: false });

  try {
    const files = await listSourceFiles(source);
    const manifest = [];
    for (const path of files) {
      manifest.push(await copyOne(source, destination, path));
    }
    const manifestText = `${JSON.stringify({ version: 1, files: manifest }, null, 2)}\n`;
    await writeFile(resolve(destination, '.sentinelflow-clean-input-manifest.json'), manifestText, 'utf8');

    return {
      destination,
      fileCount: manifest.length,
      manifestSha256: sha256(manifestText),
    };
  } catch (error) {
    await rm(destination, { recursive: true, force: true });
    throw error;
  }
}

export async function initializeSnapshotGit(snapshotRoot) {
  await git(snapshotRoot, ['init', '--quiet']);
  await git(snapshotRoot, ['add', '--all']);
  await git(snapshotRoot, ['diff', '--check']);
}
