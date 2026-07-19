export const EXPECTED_ROUTE_KEYS = Object.freeze([
  'src/pages/OverviewPage.tsx',
  'src/pages/StateMatrixPage.tsx',
  'src/pages/IncidentListPage.tsx',
  'src/pages/IncidentListStatePage.tsx',
  'src/pages/IncidentsPage.tsx',
  'src/pages/IncidentDetailStatePage.tsx',
  'src/pages/ValidationPage.tsx',
  'src/pages/ValidationReviewStatePage.tsx',
  'src/pages/HilAuthorizationPage.tsx',
  'src/pages/HilAuthorizationStatePage.tsx',
  'src/pages/EnforcementPage.tsx',
  'src/pages/EnforcementLifecycleStatePage.tsx',
  'src/live/IncidentPages.tsx',
  'src/live/ReviewPages.tsx',
]);

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function exactSetErrors(label, actual, expected) {
  const errors = [];
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  const repeated = duplicates(actual);
  if (repeated.length > 0) {
    errors.push(`${label} contains duplicate keys: ${repeated.join(', ')}`);
  }
  const missing = expected.filter((key) => !actualSet.has(key));
  if (missing.length > 0) {
    errors.push(`${label} is missing expected keys: ${missing.join(', ')}`);
  }
  const unexpected = [...actualSet]
    .filter((key) => !expectedSet.has(key))
    .sort();
  if (unexpected.length > 0) {
    errors.push(`${label} contains unexpected keys: ${unexpected.join(', ')}`);
  }
  return errors;
}

export function validateRouteManifest(manifest) {
  const errors = [];
  const entryKeys = Object.entries(manifest)
    .filter(([, value]) => value.isEntry)
    .map(([key]) => key);
  if (entryKeys.length !== 1) {
    errors.push(
      `Expected exactly one browser entry in the Vite manifest; found ${entryKeys.length}`,
    );
    return Object.freeze({ errors: Object.freeze(errors), entryKey: null });
  }

  const entryKey = entryKeys[0];
  const entry = manifest[entryKey];
  const dynamicImports = Array.isArray(entry.dynamicImports)
    ? entry.dynamicImports
    : [];
  if (!Array.isArray(entry.dynamicImports)) {
    errors.push('Browser entry is missing its dynamicImports array');
  }
  errors.push(
    ...exactSetErrors(
      'Browser entry dynamicImports',
      dynamicImports,
      EXPECTED_ROUTE_KEYS,
    ),
  );

  const dynamicKeys = Object.entries(manifest)
    .filter(([, value]) => value.isDynamicEntry)
    .map(([key]) => key)
    .sort();
  errors.push(
    ...exactSetErrors(
      'Manifest dynamic route entries',
      dynamicKeys,
      EXPECTED_ROUTE_KEYS,
    ),
  );

  const eagerRoutes = (entry.imports ?? [])
    .filter((key) => EXPECTED_ROUTE_KEYS.includes(key))
    .sort();
  if (eagerRoutes.length > 0) {
    errors.push(
      `Expected lazy routes are imported eagerly by the browser entry: ${eagerRoutes.join(', ')}`,
    );
  }

  const outputOwners = new Map();
  for (const key of dynamicKeys) {
    const file = manifest[key]?.file;
    if (typeof file !== 'string') continue;
    const owner = outputOwners.get(file);
    if (owner) {
      errors.push(
        `Dynamic route entries ${owner} and ${key} share duplicate output graph ${file}`,
      );
    } else {
      outputOwners.set(file, key);
    }
  }

  return Object.freeze({
    errors: Object.freeze(errors),
    entryKey,
    dynamicKeys: Object.freeze(dynamicKeys),
  });
}

export function collectStaticFiles(
  manifest,
  key,
  seen = new Set(),
  files = new Set(),
) {
  if (seen.has(key)) return files;
  seen.add(key);
  const entry = manifest[key];
  if (!entry) {
    throw new Error(`Manifest import ${JSON.stringify(key)} is missing`);
  }

  if (/\.(?:css|js)$/.test(entry.file)) files.add(entry.file);
  for (const css of entry.css ?? []) files.add(css);
  for (const imported of entry.imports ?? []) {
    collectStaticFiles(manifest, imported, seen, files);
  }
  return files;
}

export function buildRouteFileSets(manifest, entryKey, routeKey) {
  const initial = new Set(collectStaticFiles(manifest, entryKey));
  const routeStatic = new Set(collectStaticFiles(manifest, routeKey));
  const route = new Set([...initial, ...routeStatic]);
  const increment = new Set(
    [...routeStatic].filter((file) => !initial.has(file)),
  );
  return Object.freeze({
    initial: Object.freeze([...initial].sort()),
    route: Object.freeze([...route].sort()),
    increment: Object.freeze([...increment].sort()),
  });
}
