import { useCallback, useEffect, useRef, useState } from 'react';
import { HilAuthorizationResults } from '../components/HilAuthorizationResults';
import { fixtureHilAuthorizationAdapter } from '../hil/fixtureHilAuthorizationAdapter';
import type {
  HilAuthorizationAdapter,
  HilAuthorizationState,
  HilDecisionOperation,
  HilDecisionPreviewInput,
} from '../hil/hilAuthorizationModel';
import { MOCK_HIL_AUTHORIZATION_STATES } from '../mocks/hilAuthorizationFixtures';

export interface HilAuthorizationPageProps {
  readonly adapter?: HilAuthorizationAdapter;
}

export function HilAuthorizationPage({
  adapter = fixtureHilAuthorizationAdapter,
}: HilAuthorizationPageProps) {
  const [state, setState] = useState<HilAuthorizationState>({
    kind: 'loading',
  });
  const [busy, setBusy] = useState(false);
  const activePreview = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void adapter.load(controller.signal).then(
      (next) => {
        if (!controller.signal.aborted) setState(next);
      },
      () => {
        if (!controller.signal.aborted) {
          setState(MOCK_HIL_AUTHORIZATION_STATES.mutation);
        }
      },
    );
    return () => controller.abort();
  }, [adapter]);

  useEffect(
    () => () => {
      activePreview.current?.abort();
    },
    [],
  );

  const runPreview = useCallback(
    (preview: (signal: AbortSignal) => Promise<HilAuthorizationState>) => {
      activePreview.current?.abort();
      const controller = new AbortController();
      activePreview.current = controller;
      setBusy(true);
      void preview(controller.signal)
        .then(
          (next) => {
            if (!controller.signal.aborted) setState(next);
          },
          () => {
            if (!controller.signal.aborted) {
              setState(MOCK_HIL_AUTHORIZATION_STATES.mutation);
            }
          },
        )
        .finally(() => {
          if (!controller.signal.aborted) setBusy(false);
        });
    },
    [],
  );

  const previewChallenge = useCallback(
    (operation: HilDecisionOperation) => {
      runPreview((signal) => adapter.previewChallenge(operation, signal));
    },
    [adapter, runPreview],
  );

  const previewStepUp = useCallback(
    (operation: HilDecisionOperation) => {
      runPreview((signal) => adapter.previewStepUp(operation, signal));
    },
    [adapter, runPreview],
  );

  const previewDecision = useCallback(
    (input: HilDecisionPreviewInput) => {
      runPreview((signal) => adapter.previewDecision(input, signal));
    },
    [adapter, runPreview],
  );

  return (
    <HilAuthorizationResults
      state={state}
      busy={busy}
      onPreviewChallenge={previewChallenge}
      onPreviewStepUp={previewStepUp}
      onPreviewDecision={previewDecision}
    />
  );
}
