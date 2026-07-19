import { readFile, readdir } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EXPECTED_ROUTE_KEYS,
  buildRouteFileSets,
  validateRouteManifest,
} from './bundle-budget-contract.mjs';

const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const distRoot = join(webRoot, 'dist');
const manifestPath = join(distRoot, '.vite', 'manifest.json');

const budgets = Object.freeze({
  chunk: Object.freeze({ raw: 500_000, gzip: 150_000 }),
  initial: Object.freeze({ raw: 775_000, gzip: 230_000 }),
  route: Object.freeze({ raw: 825_000, gzip: 245_000 }),
  routeIncrement: Object.freeze({ raw: 75_000, gzip: 25_000 }),
});

function formatBytes(value) {
  return `${(value / 1000).toFixed(2)} kB`;
}

function assertWithin(errors, subject, actual, limit) {
  for (const encoding of ['raw', 'gzip']) {
    if (actual[encoding] > limit[encoding]) {
      errors.push(
        `${subject} ${encoding} is ${formatBytes(actual[encoding])}; budget is ${formatBytes(limit[encoding])}`,
      );
    }
  }
}

async function measure(file) {
  const path = join(distRoot, file);
  const bytes = await readFile(path);
  return Object.freeze({
    file,
    raw: bytes.byteLength,
    gzip: gzipSync(bytes, { level: 9 }).byteLength,
  });
}

async function measureFiles(key, files) {
  const measured = await Promise.all(files.map(measure));
  return Object.freeze({
    key,
    files,
    raw: measured.reduce((total, item) => total + item.raw, 0),
    gzip: measured.reduce((total, item) => total + item.gzip, 0),
  });
}

let manifest;
try {
  manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
} catch (error) {
  throw new Error(
    `A production build with ${manifestPath} is required before checking the bundle budget`,
    { cause: error },
  );
}

const errors = [];
const routeContract = validateRouteManifest(manifest);
errors.push(...routeContract.errors);
if (!routeContract.entryKey || routeContract.errors.length > 0) {
  for (const error of errors) console.error(`ERROR: ${error}`);
  process.exit(1);
}
const assetNames = (await readdir(join(distRoot, 'assets'))).filter((name) =>
  /\.(?:css|js)$/.test(name),
);
const chunks = await Promise.all(
  assetNames.map((name) => measure(join('assets', name))),
);
chunks.sort(
  (left, right) => right.raw - left.raw || left.file.localeCompare(right.file),
);
for (const chunk of chunks) {
  assertWithin(errors, `chunk ${chunk.file}`, chunk, budgets.chunk);
}

const initialFiles = buildRouteFileSets(
  manifest,
  routeContract.entryKey,
  EXPECTED_ROUTE_KEYS[0],
).initial;
const initial = await measureFiles(routeContract.entryKey, initialFiles);
assertWithin(errors, 'initial static graph', initial, budgets.initial);

const routes = await Promise.all(
  EXPECTED_ROUTE_KEYS.map(async (key) => {
    const fileSets = buildRouteFileSets(manifest, routeContract.entryKey, key);
    const route = await measureFiles(key, fileSets.route);
    const increment = await measureFiles(key, fileSets.increment);
    return Object.freeze({
      ...route,
      incrementalRaw: increment.raw,
      incrementalGzip: increment.gzip,
    });
  }),
);
routes.sort(
  (left, right) => right.raw - left.raw || left.key.localeCompare(right.key),
);
for (const route of routes) {
  assertWithin(errors, `route ${route.key}`, route, budgets.route);
  assertWithin(
    errors,
    `route increment ${route.key}`,
    { raw: route.incrementalRaw, gzip: route.incrementalGzip },
    budgets.routeIncrement,
  );
}

const largestChunk = chunks[0];
const largestRoute = routes[0];
console.log(
  `bundle budget: initial=${formatBytes(initial.raw)} raw/${formatBytes(initial.gzip)} gzip (${initial.files.length} files)`,
);
console.log(
  `bundle budget: largest chunk=${largestChunk.file} ${formatBytes(largestChunk.raw)} raw/${formatBytes(largestChunk.gzip)} gzip`,
);
if (largestRoute) {
  console.log(
    `bundle budget: largest route=${largestRoute.key} ${formatBytes(largestRoute.raw)} raw/${formatBytes(largestRoute.gzip)} gzip; increment=${formatBytes(largestRoute.incrementalRaw)} raw/${formatBytes(largestRoute.incrementalGzip)} gzip`,
  );
}

if (errors.length > 0) {
  for (const error of errors) console.error(`ERROR: ${error}`);
  process.exitCode = 1;
} else {
  console.log(
    `PASS: ${chunks.length} chunks and ${routes.length} dynamic route graphs are within budget`,
  );
}
