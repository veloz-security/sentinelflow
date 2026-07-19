import { useEffect, useState } from 'react';
import { ValidationReviewResults } from '../components/ValidationReviewResults';
import { MOCK_VALIDATION_REVIEW_STATES } from '../mocks/validationReviewFixtures';
import { fixtureValidationReviewAdapter } from '../validation/fixtureValidationReviewAdapter';
import type {
  ValidationReviewAdapter,
  ValidationReviewState,
} from '../validation/validationReviewModel';

function useValidationReviewState(
  adapter: ValidationReviewAdapter,
): ValidationReviewState {
  const [state, setState] = useState<ValidationReviewState>({
    kind: 'loading',
  });

  useEffect(() => {
    const controller = new AbortController();
    void adapter.load(controller.signal).then(
      (result) => {
        if (!controller.signal.aborted) setState(result);
      },
      () => {
        if (!controller.signal.aborted) {
          setState(MOCK_VALIDATION_REVIEW_STATES.failed);
        }
      },
    );
    return () => controller.abort();
  }, [adapter]);

  return state;
}

export interface ValidationPageProps {
  readonly adapter?: ValidationReviewAdapter;
}

export function ValidationPage({
  adapter = fixtureValidationReviewAdapter,
}: ValidationPageProps) {
  const state = useValidationReviewState(adapter);
  return <ValidationReviewResults state={state} />;
}
