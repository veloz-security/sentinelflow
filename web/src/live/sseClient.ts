import { decodeApiError } from '../contracts/apiErrorDecoder';
import { JSON_CONTENT_TYPE, readBoundedResponse } from './apiClient';
import {
  decodeStreamEvent,
  type StreamEvent,
  type StreamEventType,
} from './contracts';

const EVENT_STREAM_CONTENT_TYPE = 'text/event-stream; charset=utf-8';
const MAX_ERROR_BYTES = 64 * 1024;
const MAX_LINE_BYTES = 8 * 1024;
const MAX_PENDING_BYTES = 64 * 1024;
const HANDSHAKE_TIMEOUT_MS = 10_000;

export type LiveStreamState =
  'connecting' | 'connected' | 'reconnecting' | 'stale' | 'error';

export interface LiveStreamCallbacks {
  readonly onState: (state: LiveStreamState) => void;
  readonly onEvent: (event: Readonly<StreamEvent>) => void;
  readonly onReplayGap: () => void;
  readonly onAuthenticationRequired: () => void;
}

export interface StreamParseCallbacks {
  readonly onComment: (comment: string) => void;
  readonly onEvent: (event: Readonly<StreamEvent>) => void;
}

export class StreamContractError extends Error {
  constructor(message = 'event stream violated its frozen contract') {
    super(message);
    this.name = 'StreamContractError';
  }
}

export class ReplayGapError extends Error {
  constructor() {
    super('event stream replay gap');
    this.name = 'ReplayGapError';
  }
}

function cursorValue(cursor: string): bigint {
  if (!/^s1\.[0-9a-f]{16}$/.test(cursor)) {
    throw new StreamContractError();
  }
  const value = BigInt(`0x${cursor.slice(3)}`);
  if (value > 0x7fffffffffffffffn) {
    throw new StreamContractError();
  }
  return value;
}

interface PendingEvent {
  id?: string;
  type?: StreamEventType;
  data?: string;
}

function consumeLine(
  line: string,
  pending: PendingEvent,
  callbacks: StreamParseCallbacks,
): PendingEvent {
  if (line.length > MAX_LINE_BYTES) {
    throw new StreamContractError();
  }
  if (line === '') {
    const keys = Object.keys(pending);
    if (keys.length === 0) {
      return {};
    }
    if (
      keys.length !== 3 ||
      !pending.id ||
      !pending.type ||
      pending.data === undefined
    ) {
      throw new StreamContractError();
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(pending.data) as unknown;
    } catch {
      throw new StreamContractError();
    }
    callbacks.onEvent(decodeStreamEvent(pending.id, pending.type, parsed));
    return {};
  }
  if (line.startsWith(':')) {
    if (Object.keys(pending).length !== 0) {
      throw new StreamContractError();
    }
    const comment = line.slice(1).trimStart();
    if (
      !['connected', 'heartbeat', 'reconnect', 'replay-gap'].includes(comment)
    ) {
      throw new StreamContractError();
    }
    callbacks.onComment(comment);
    return pending;
  }
  const separator = line.indexOf(':');
  if (separator <= 0) {
    throw new StreamContractError();
  }
  const field = line.slice(0, separator);
  const raw = line.slice(separator + 1);
  const value = raw.startsWith(' ') ? raw.slice(1) : raw;
  if (field === 'id' && pending.id === undefined) {
    cursorValue(value);
    return { ...pending, id: value };
  }
  if (field === 'event' && pending.type === undefined) {
    return { ...pending, type: value as StreamEventType };
  }
  if (field === 'data' && pending.data === undefined && value.length <= 4096) {
    return { ...pending, data: value };
  }
  throw new StreamContractError();
}

export async function parseEventStream(
  body: ReadableStream<Uint8Array>,
  callbacks: StreamParseCallbacks,
  signal?: AbortSignal,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let pendingText = '';
  let pendingEvent: PendingEvent = {};
  try {
    while (true) {
      if (signal?.aborted) {
        return;
      }
      const result = await reader.read();
      if (result.done) {
        pendingText += decoder.decode();
        break;
      }
      pendingText += decoder.decode(result.value, { stream: true });
      if (pendingText.length > MAX_PENDING_BYTES) {
        throw new StreamContractError();
      }
      let lineEnd = pendingText.indexOf('\n');
      while (lineEnd >= 0) {
        let line = pendingText.slice(0, lineEnd);
        if (line.endsWith('\r')) {
          line = line.slice(0, -1);
        }
        pendingText = pendingText.slice(lineEnd + 1);
        pendingEvent = consumeLine(line, pendingEvent, callbacks);
        lineEnd = pendingText.indexOf('\n');
      }
    }
    if (pendingText.length !== 0 || Object.keys(pendingEvent).length !== 0) {
      throw new StreamContractError();
    }
  } finally {
    reader.releaseLock();
  }
}

function waitForReconnect(
  milliseconds: number,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = window.setTimeout(resolve, milliseconds);
    signal.addEventListener(
      'abort',
      () => {
        window.clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

async function validAPIError(
  response: Response,
  code: string,
): Promise<boolean> {
  try {
    if (response.headers.get('Content-Type') !== JSON_CONTENT_TYPE) {
      return false;
    }
    const raw = await readBoundedResponse(response, MAX_ERROR_BYTES);
    const decoded = decodeApiError(JSON.parse(raw) as unknown);
    return decoded.ok && decoded.value.code === code;
  } catch {
    return false;
  }
}

export class ManagementEventStream {
  constructor(private readonly fetchImplementation: typeof fetch = fetch) {}

  start(callbacks: LiveStreamCallbacks): () => void {
    const controller = new AbortController();
    void this.run(callbacks, controller.signal);
    return () => controller.abort();
  }

  private async run(
    callbacks: LiveStreamCallbacks,
    signal: AbortSignal,
  ): Promise<void> {
    let cursor: string | null = null;
    let attempt = 0;
    const versions = new Map<string, number>();
    callbacks.onState('connecting');

    while (!signal.aborted) {
      const handshake = new AbortController();
      const abortHandshake = () => handshake.abort(signal.reason);
      signal.addEventListener('abort', abortHandshake, { once: true });
      const timeout = window.setTimeout(
        () =>
          handshake.abort(
            new DOMException('event stream handshake timeout', 'TimeoutError'),
          ),
        HANDSHAKE_TIMEOUT_MS,
      );
      try {
        const path = cursor
          ? `/api/v1/events/stream?cursor=${encodeURIComponent(cursor)}`
          : '/api/v1/events/stream';
        const fetchImplementation = this.fetchImplementation;
        const response = await fetchImplementation(path, {
          method: 'GET',
          headers: { Accept: 'text/event-stream' },
          credentials: 'same-origin',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          signal: handshake.signal,
        });
        window.clearTimeout(timeout);

        if (response.status === 401) {
          if (await validAPIError(response, 'authentication_required')) {
            signal.removeEventListener('abort', abortHandshake);
            callbacks.onAuthenticationRequired();
            return;
          }
          throw new StreamContractError();
        }
        if (response.status === 409) {
          if (!(await validAPIError(response, 'stale_version'))) {
            throw new StreamContractError();
          }
          signal.removeEventListener('abort', abortHandshake);
          callbacks.onState('stale');
          callbacks.onReplayGap();
          cursor = null;
          versions.clear();
          attempt = 0;
          await waitForReconnect(250, signal);
          callbacks.onState('reconnecting');
          continue;
        }
        if (
          response.status !== 200 ||
          response.headers.get('Content-Type') !== EVENT_STREAM_CONTENT_TYPE ||
          !response.body
        ) {
          throw new StreamContractError();
        }

        attempt = 0;
        callbacks.onState('connected');
        await parseEventStream(
          response.body,
          {
            onComment: (comment) => {
              if (comment === 'replay-gap') {
                throw new ReplayGapError();
              }
            },
            onEvent: (event) => {
              if (cursor && cursorValue(event.id) <= cursorValue(cursor)) {
                throw new StreamContractError();
              }
              cursor = event.id;
              const key = `${event.type}:${event.resource_id}`;
              const priorVersion = versions.get(key) ?? 0;
              if (event.resource_version > priorVersion) {
                versions.set(key, event.resource_version);
                callbacks.onEvent(event);
              }
            },
          },
          signal,
        );
        signal.removeEventListener('abort', abortHandshake);
      } catch (caught) {
        window.clearTimeout(timeout);
        signal.removeEventListener('abort', abortHandshake);
        if (signal.aborted) {
          return;
        }
        if (caught instanceof ReplayGapError) {
          callbacks.onState('stale');
          callbacks.onReplayGap();
          cursor = null;
          versions.clear();
          attempt = 0;
        } else if (caught instanceof StreamContractError) {
          callbacks.onState('error');
        }
      }
      if (signal.aborted) {
        return;
      }
      callbacks.onState('reconnecting');
      const delay = Math.min(2000, 250 * 2 ** Math.min(attempt, 3));
      attempt += 1;
      await waitForReconnect(delay, signal);
    }
  }
}

export const managementEventStream = new ManagementEventStream();
