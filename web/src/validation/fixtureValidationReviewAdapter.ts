import { MOCK_VALIDATION_REVIEW_STATES } from '../mocks/validationReviewFixtures';
import type { ValidationReviewAdapter } from './validationReviewModel';

export const fixtureValidationReviewAdapter: ValidationReviewAdapter = {
  kind: 'fixture',
  async load(signal) {
    signal?.throwIfAborted();
    await Promise.resolve();
    signal?.throwIfAborted();
    return MOCK_VALIDATION_REVIEW_STATES.ready;
  },
};
