import { describe, expect, it } from 'vitest';
import {
  assertDeploymentCsp,
  parseDeploymentCsp,
  readDeploymentCsp,
} from './deploymentCsp';

const deploymentCsp =
  "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

describe('deployment CSP contract', () => {
  it('extracts the one nginx CSP header without weakening it', () => {
    expect(
      parseDeploymentCsp(`server {
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
}`),
    ).toBe("default-src 'self'; script-src 'self'");
  });

  it.each([
    ['a missing header', 'server { listen 8080; }'],
    [
      'duplicate headers',
      `add_header Content-Security-Policy "default-src 'self'" always;
add_header Content-Security-Policy "default-src 'none'" always;`,
    ],
    [
      'a multiline header',
      `add_header Content-Security-Policy "default-src 'self';
script-src 'self'" always;`,
    ],
  ])('rejects %s', (_label, config) => {
    expect(() => parseDeploymentCsp(config)).toThrow(
      /exactly one single-line Content-Security-Policy header/,
    );
  });

  it('accepts only the pinned deployment directive and source allowlists', () => {
    expect(() => assertDeploymentCsp(deploymentCsp)).not.toThrow();
    expect(readDeploymentCsp()).toBe(deploymentCsp);
  });

  it.each([
    [
      'unsafe inline scripts',
      `${deploymentCsp}; script-src 'self' 'unsafe-inline'`,
    ],
    [
      'unsafe eval scripts',
      `${deploymentCsp}; script-src 'self' 'unsafe-eval'`,
    ],
    [
      'a removed object restriction',
      deploymentCsp.replace("; object-src 'none'", ''),
    ],
    [
      'a weakened object restriction',
      deploymentCsp.replace("object-src 'none'", "object-src 'self'"),
    ],
    [
      'a broadened connection allowlist',
      deploymentCsp.replace("connect-src 'self'", "connect-src 'self' https:"),
    ],
    ['a duplicate directive', `${deploymentCsp}; default-src 'self'`],
  ])('rejects %s', (_label, policy) => {
    expect(() => assertDeploymentCsp(policy)).toThrow(/deployment CSP/);
  });
});
