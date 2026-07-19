import { describe, expect, it, vi } from 'vitest';
import { STREAM_PAYLOAD } from './liveTestFixtures';
import {
  ManagementEventStream,
  parseEventStream,
  StreamContractError,
} from './sseClient';

function stream(source: string): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(source));
      controller.close();
    },
  });
}

describe('event stream parser', () => {
  it('parses canonical typed events and recognized comments', async () => {
    const onComment = vi.fn();
    const onEvent = vi.fn();
    await parseEventStream(
      stream(
        `: connected\n\nid: s1.0000000000000002\nevent: incident.updated\ndata: ${JSON.stringify(STREAM_PAYLOAD)}\n\n: heartbeat\n\n`,
      ),
      { onComment, onEvent },
    );

    expect(onComment.mock.calls.map(([value]) => value)).toEqual([
      'connected',
      'heartbeat',
    ]);
    expect(onEvent).toHaveBeenCalledOnce();
    expect(Object.isFrozen(onEvent.mock.calls[0][0])).toBe(true);
  });

  it('rejects duplicate fields, noncanonical IDs, and partial events', async () => {
    const callbacks = { onComment: vi.fn(), onEvent: vi.fn() };
    await expect(
      parseEventStream(
        stream('id: s1.0000000000000001\nid: s1.0000000000000002\n\n'),
        callbacks,
      ),
    ).rejects.toBeInstanceOf(StreamContractError);
    await expect(
      parseEventStream(
        stream('id: s1.1\nevent: incident.updated\ndata: {}\n\n'),
        callbacks,
      ),
    ).rejects.toBeInstanceOf(StreamContractError);
  });

  it('reconnects with the last canonical cursor and invalidates on a typed replay gap', async () => {
    const first = new Response(
      stream(
        `: connected\n\nid: s1.0000000000000002\nevent: incident.updated\ndata: ${JSON.stringify(STREAM_PAYLOAD)}\n\n`,
      ),
      { headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } },
    );
    const gap = new Response(
      JSON.stringify({
        code: 'stale_version',
        message: 'requested replay is no longer available',
        trace_id: '019b0000-0000-4000-8000-000000000203',
        details: {},
      }),
      {
        status: 409,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      },
    );
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(gap);
    const client = new ManagementEventStream(fetchMock);
    let stop: () => void = () => undefined;
    const replayGap = new Promise<void>((resolve) => {
      stop = client.start({
        onState: vi.fn(),
        onEvent: vi.fn(),
        onReplayGap: resolve,
        onAuthenticationRequired: vi.fn(),
      });
    });

    await replayGap;
    stop();
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/events/stream');
    expect(fetchMock.mock.calls[1][0]).toBe(
      '/api/v1/events/stream?cursor=s1.0000000000000002',
    );
  });
});
