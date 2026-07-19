import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { makeTemporaryDirectory, removeTemporaryDirectory } from './testFiles';
import { scanProductionJavaScriptChunks } from './productionCsp';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    removeTemporaryDirectory(directory);
  }
});

function fixture(files: Readonly<Record<string, string>>): string {
  const directory = makeTemporaryDirectory('sentinelflow-csp-');
  temporaryDirectories.push(directory);
  for (const [path, source] of Object.entries(files)) {
    const file = join(directory, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, source, 'utf8');
  }
  return directory;
}

describe('production CSP JavaScript scan', () => {
  it('deterministically scans every nested production JavaScript chunk', () => {
    const directory = fixture({
      'assets/z-lazy.js': 'export const z = 1;',
      'assets/nested/a-live-route.js': 'export const a = 1;',
      'ignored.css': 'eval(',
    });

    expect(scanProductionJavaScriptChunks(directory).chunks).toEqual([
      'assets/nested/a-live-route.js',
      'assets/z-lazy.js',
    ]);
  });

  it.each([
    ['eval', 'globalThis.eval("1")'],
    ['new Function', 'const factory = new Function("return 1")'],
    ['Function call', 'const factory = Function("return 1")'],
    ['bare string-form timeout', 'setTimeout("run()", 10)'],
    ['global string-form interval', "globalThis.setInterval('run()', 10)"],
    ['window template-form timeout', 'window.setTimeout(`run()`, 10)'],
    ['self bracket-form interval', 'self["setInterval"]("run()", 10)'],
    ['WebAssembly compile', 'WebAssembly.compile(bytes)'],
    [
      'WebAssembly streaming instantiate',
      'WebAssembly.instantiateStreaming(response)',
    ],
    ['WebAssembly module construction', 'new WebAssembly.Module(bytes)'],
    ['WebAssembly bracket call', 'WebAssembly["compileStreaming"](response)'],
  ])(
    'rejects dynamic code generation through %s in any chunk',
    (_label, source) => {
      const directory = fixture({
        'assets/entry.js': 'export const entry = 1;',
        'assets/live-route.js': source,
      });

      expect(() => scanProductionJavaScriptChunks(directory)).toThrow(
        /live-route\.js/,
      );
    },
  );

  it('fails closed when the production output has no JavaScript chunks', () => {
    const directory = fixture({ 'index.html': '<div id="root"></div>' });
    expect(() => scanProductionJavaScriptChunks(directory)).toThrow(
      /found no JavaScript chunks/,
    );
  });

  it('allows callback timers, unrelated object methods, and non-generating WebAssembly APIs', () => {
    const directory = fixture({
      'assets/entry.js': [
        'setTimeout(() => run(), 10);',
        'globalThis.setInterval(tick, 10);',
        'scheduler.setTimeout("opaque scheduler value", 10);',
        'const memory = new WebAssembly.Memory({ initial: 1 });',
      ].join('\n'),
    });

    expect(scanProductionJavaScriptChunks(directory).chunks).toEqual([
      'assets/entry.js',
    ]);
  });
});
