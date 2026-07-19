import { createServer } from 'node:http';
import type { IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Page, Route } from '@playwright/test';

export interface BrowserJSONFixtureRequest {
  readonly headers: IncomingHttpHeaders;
  readonly method: string;
  readonly url: URL;
}

export interface BrowserJSONFixtureResponse {
  readonly headers?: Readonly<Record<string, string>>;
  readonly status: number;
  readonly value: unknown;
}

export interface BrowserJSONFixture {
  forward(route: Route): Promise<void>;
}

export async function createBrowserJSONFixture(
  page: Page,
  handler: (
    request: BrowserJSONFixtureRequest,
  ) => Promise<BrowserJSONFixtureResponse> | BrowserJSONFixtureResponse,
): Promise<BrowserJSONFixture> {
  const server = createServer(async (request, response) => {
    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers':
          'Content-Type, Idempotency-Key, X-CSRF-Token, X-SentinelFlow-Test-Namespace',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Origin': 'http://127.0.0.1:4173',
        'Cache-Control': 'no-store',
      });
      response.end();
      return;
    }
    try {
      const address = server.address() as AddressInfo;
      const result = await handler({
        headers: request.headers,
        method: request.method ?? 'GET',
        url: new URL(request.url ?? '/', `http://127.0.0.1:${address.port}`),
      });
      const body = JSON.stringify(result.value);
      response.writeHead(result.status, {
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Origin': 'http://127.0.0.1:4173',
        'Cache-Control': 'no-store',
        'Content-Length': Buffer.byteLength(body),
        'Content-Type': 'application/json; charset=utf-8',
        ...result.headers,
      });
      response.end(body);
    } catch {
      const body = JSON.stringify({
        code: 'internal_error',
        details: {},
        message: 'the browser fixture server failed',
        trace_id: '019b0000-0000-4000-8000-000000000498',
      });
      response.writeHead(500, {
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Origin': 'http://127.0.0.1:4173',
        'Cache-Control': 'no-store',
        'Content-Length': Buffer.byteLength(body),
        'Content-Type': 'application/json; charset=utf-8',
      });
      response.end(body);
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  server.unref();
  const address = server.address() as AddressInfo;
  const fixtureOrigin = `http://127.0.0.1:${address.port}`;
  page.once('close', () => server.close());

  return {
    async forward(route) {
      const original = new URL(route.request().url());
      const target = new URL(
        `${original.pathname}${original.search}`,
        fixtureOrigin,
      );
      await route.continue({ url: target.toString() });
    },
  };
}
