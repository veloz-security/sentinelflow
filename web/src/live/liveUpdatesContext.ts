import { createContext, useContext } from 'react';
import type { StreamEvent } from './contracts';
import type { LiveStreamState } from './sseClient';

export interface LiveUpdatesContextValue {
  readonly state: LiveStreamState;
  readonly revision: number;
  readonly replayGap: boolean;
  readonly lastEvent: Readonly<StreamEvent> | null;
}

export const LiveUpdatesContext = createContext<LiveUpdatesContextValue>({
  state: 'connecting',
  revision: 0,
  replayGap: false,
  lastEvent: null,
});

export function useLiveUpdates(): LiveUpdatesContextValue {
  return useContext(LiveUpdatesContext);
}
