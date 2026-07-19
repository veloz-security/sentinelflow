import { useEffect, useMemo, useState, type PropsWithChildren } from 'react';
import type { StreamEvent } from './contracts';
import {
  LiveUpdatesContext,
  type LiveUpdatesContextValue,
} from './liveUpdatesContext';
import { useSession } from './sessionContext';
import {
  ManagementEventStream,
  managementEventStream,
  type LiveStreamState,
} from './sseClient';

export interface LiveUpdatesProviderProps extends PropsWithChildren {
  readonly stream?: ManagementEventStream;
}

export function LiveUpdatesProvider({
  children,
  stream = managementEventStream,
}: LiveUpdatesProviderProps) {
  const session = useSession();
  const [state, setState] = useState<LiveStreamState>('connecting');
  const [revision, setRevision] = useState(0);
  const [replayGap, setReplayGap] = useState(false);
  const [lastEvent, setLastEvent] = useState<Readonly<StreamEvent> | null>(
    null,
  );

  useEffect(
    () =>
      stream.start({
        onState: (next) => {
          setState(next);
          if (next === 'connected') {
            setReplayGap(false);
          }
        },
        onEvent: (event) => {
          setLastEvent(event);
          setRevision((value) => value + 1);
        },
        onReplayGap: () => {
          setReplayGap(true);
          setRevision((value) => value + 1);
        },
        onAuthenticationRequired: session.invalidate,
      }),
    [session.invalidate, stream],
  );

  const value = useMemo<LiveUpdatesContextValue>(
    () => ({ state, revision, replayGap, lastEvent }),
    [lastEvent, replayGap, revision, state],
  );

  return (
    <LiveUpdatesContext.Provider value={value}>
      {children}
    </LiveUpdatesContext.Provider>
  );
}
