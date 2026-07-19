import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EXPECTED_ROUTE_KEYS,
  buildRouteFileSets,
  validateRouteManifest,
} from './bundle-budget-contract.mjs';

function validManifest() {
  const manifest = {
    'index.html': {
      file: 'assets/index.js',
      isEntry: true,
      imports: ['_runtime.js'],
      dynamicImports: [...EXPECTED_ROUTE_KEYS],
    },
    '_runtime.js': { file: 'assets/runtime.js' },
  };
  EXPECTED_ROUTE_KEYS.forEach((key, index) => {
    manifest[key] = {
      file: `assets/route-${index}.js`,
      isDynamicEntry: true,
      imports: ['_runtime.js'],
    };
  });
  return manifest;
}

test('accepts only the frozen fourteen-route lazy manifest contract', () => {
  const result = validateRouteManifest(validManifest());
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.dynamicKeys, [...EXPECTED_ROUTE_KEYS].sort());
});

test('rejects the internally consistent one-route manifest bypass', () => {
  const onlyRoute = EXPECTED_ROUTE_KEYS[0];
  const manifest = {
    'index.html': {
      file: 'assets/index.js',
      isEntry: true,
      dynamicImports: [onlyRoute],
    },
    [onlyRoute]: {
      file: 'assets/only-route.js',
      isDynamicEntry: true,
    },
  };
  const errors = validateRouteManifest(manifest).errors.join('\n');
  assert.match(errors, /dynamicImports is missing expected keys/);
  assert.match(errors, /dynamic route entries is missing expected keys/);
});

test('rejects duplicate, eager, substituted, and unreferenced route graphs', () => {
  const manifest = validManifest();
  const removed = EXPECTED_ROUTE_KEYS[1];
  const substituted = 'src/pages/SubstitutedPage.tsx';
  delete manifest[removed];
  manifest[substituted] = {
    file: 'assets/substituted.js',
    isDynamicEntry: true,
  };
  manifest['index.html'].dynamicImports = [
    EXPECTED_ROUTE_KEYS[0],
    EXPECTED_ROUTE_KEYS[0],
    ...EXPECTED_ROUTE_KEYS.slice(2),
  ];
  manifest['index.html'].imports.push(EXPECTED_ROUTE_KEYS[2]);
  manifest[EXPECTED_ROUTE_KEYS[3]].file = manifest[EXPECTED_ROUTE_KEYS[2]].file;

  const errors = validateRouteManifest(manifest).errors.join('\n');
  assert.match(errors, /contains duplicate keys/);
  assert.match(errors, /missing expected keys/);
  assert.match(errors, /contains unexpected keys/);
  assert.match(errors, /imported eagerly/);
  assert.match(errors, /share duplicate output graph/);
});

test('builds route and increment unions without double-counting initial files', () => {
  const manifest = validManifest();
  const routeKey = EXPECTED_ROUTE_KEYS[0];
  manifest[routeKey].imports = ['_runtime.js', '_route-shared.js'];
  manifest['_route-shared.js'] = { file: 'assets/route-shared.js' };

  const files = buildRouteFileSets(manifest, 'index.html', routeKey);
  assert.deepEqual(files.initial, ['assets/index.js', 'assets/runtime.js']);
  assert.deepEqual(files.route, [
    'assets/index.js',
    'assets/route-0.js',
    'assets/route-shared.js',
    'assets/runtime.js',
  ]);
  assert.deepEqual(files.increment, [
    'assets/route-0.js',
    'assets/route-shared.js',
  ]);
});
