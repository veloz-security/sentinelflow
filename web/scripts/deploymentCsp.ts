import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const deploymentNginxConfig = resolve(
  process.cwd(),
  '../deployments/nginx.conf',
);

const contentSecurityPolicyHeader =
  /^\s*add_header\s+Content-Security-Policy\s+"([^"\r\n]+)"\s+always;\s*$/gm;

const requiredDeploymentCsp = new Map<string, readonly string[]>([
  ['default-src', ["'self'"]],
  ['connect-src', ["'self'"]],
  ['img-src', ["'self'", 'data:']],
  ['style-src', ["'self'", "'unsafe-inline'"]],
  ['font-src', ["'self'"]],
  ['object-src', ["'none'"]],
  ['base-uri', ["'none'"]],
  ['frame-ancestors', ["'none'"]],
  ['form-action', ["'self'"]],
]);

function parseDirectives(policy: string): Map<string, readonly string[]> {
  const directives = new Map<string, readonly string[]>();

  for (const segment of policy.split(';')) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) {
      continue;
    }

    const [name, ...sources] = tokens;
    if (!name || directives.has(name)) {
      throw new Error(`deployment CSP contains duplicate directive: ${name}`);
    }
    directives.set(name, sources);
  }

  return directives;
}

function sorted(values: readonly string[]): readonly string[] {
  return [...values].sort();
}

export function assertDeploymentCsp(policy: string): void {
  const directives = parseDirectives(policy);

  for (const [name, requiredSources] of requiredDeploymentCsp) {
    const actualSources = directives.get(name);
    if (
      !actualSources ||
      JSON.stringify(sorted(actualSources)) !==
        JSON.stringify(sorted(requiredSources))
    ) {
      throw new Error(
        `deployment CSP directive ${name} must contain exactly: ${requiredSources.join(' ')}`,
      );
    }
  }

  const unexpected = [...directives.keys()].filter(
    (name) => !requiredDeploymentCsp.has(name),
  );
  if (unexpected.length > 0) {
    throw new Error(
      `deployment CSP contains unpinned directive: ${unexpected.join(', ')}`,
    );
  }
}

export function parseDeploymentCsp(config: string): string {
  const policies = Array.from(
    config.matchAll(contentSecurityPolicyHeader),
    (match) => match[1],
  );

  if (policies.length !== 1 || !policies[0]) {
    throw new Error(
      'deployments/nginx.conf must define exactly one single-line Content-Security-Policy header',
    );
  }

  return policies[0];
}

export function readDeploymentCsp(): string {
  const policy = parseDeploymentCsp(
    readFileSync(deploymentNginxConfig, 'utf8'),
  );
  assertDeploymentCsp(policy);
  return policy;
}
