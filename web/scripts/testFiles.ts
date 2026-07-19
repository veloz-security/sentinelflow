import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function makeTemporaryDirectory(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function removeTemporaryDirectory(directory: string): void {
  rmSync(directory, { force: true, recursive: true });
}
