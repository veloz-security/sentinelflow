import { useCallback, useEffect, useState } from 'react';
import { ApiClientError } from './apiClient';
import { useSession } from './sessionContext';

export interface ManagementResource<T> {
  readonly data: Readonly<T> | null;
  readonly error: ApiClientError | null;
  readonly loading: boolean;
  readonly refreshing: boolean;
  readonly reload: () => void;
}

export function useManagementResource<T>(
  load: (signal: AbortSignal) => Promise<Readonly<T>>,
  liveRevision = 0,
  identity = 'resource',
): ManagementResource<T> {
  const session = useSession();
  const [reloadRevision, setReloadRevision] = useState(0);
  const requestKey = `${identity}:${liveRevision}:${reloadRevision}`;
  const [result, setResult] = useState<{
    readonly data: Readonly<T> | null;
    readonly error: ApiClientError | null;
    readonly completedKey: string | null;
  }>({ data: null, error: null, completedKey: null });
  const invalidateSession = session.invalidate;

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) {
          setResult({ data: value, error: null, completedKey: requestKey });
        }
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        if (caught instanceof ApiClientError && caught.status === 401) {
          invalidateSession();
          return;
        }
        const error =
          caught instanceof ApiClientError
            ? caught
            : new ApiClientError(
                502,
                Object.freeze({
                  code: 'internal_error',
                  message: 'The management request could not be completed.',
                  trace_id: '00000000-0000-4000-8000-000000000000',
                  details: Object.freeze({}),
                }),
                null,
              );
        setResult((prior) => ({
          data: prior.data,
          error,
          completedKey: requestKey,
        }));
      });
    return () => controller.abort();
  }, [invalidateSession, load, requestKey]);

  const reload = useCallback(
    () => setReloadRevision((revision) => revision + 1),
    [],
  );

  const pending = result.completedKey !== requestKey;
  return {
    data: result.data,
    error: pending ? null : result.error,
    loading: pending && result.data === null,
    refreshing: pending && result.data !== null,
    reload,
  };
}
