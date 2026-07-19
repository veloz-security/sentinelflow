import type { ApiErrorV1 } from './apiDtos';

export const RESOURCE_STATE_KINDS = [
  'loading',
  'empty',
  'error',
  'permission-denied',
  'disabled',
  'success',
] as const;
export type ResourceStateKind = (typeof RESOURCE_STATE_KINDS)[number];

interface ResourceStateBase {
  readonly resource: 'incident-detail';
}

export type ResourceState<T> =
  | (ResourceStateBase & {
      readonly kind: 'loading';
      readonly value: null;
      readonly error: null;
      readonly disabledReason: null;
    })
  | (ResourceStateBase & {
      readonly kind: 'empty';
      readonly value: null;
      readonly error: null;
      readonly disabledReason: null;
    })
  | (ResourceStateBase & {
      readonly kind: 'error' | 'permission-denied';
      readonly value: null;
      readonly error: ApiErrorV1;
      readonly disabledReason: null;
    })
  | (ResourceStateBase & {
      readonly kind: 'disabled';
      readonly value: T | null;
      readonly error: null;
      readonly disabledReason: string;
    })
  | (ResourceStateBase & {
      readonly kind: 'success';
      readonly value: T;
      readonly error: null;
      readonly disabledReason: null;
    });

export interface PresentationActionModel {
  readonly label: string;
  readonly disabled: boolean;
}

export interface PresentationModel {
  readonly kind: ResourceStateKind;
  readonly title: string;
  readonly message: string;
  readonly detail: string | null;
  readonly action: PresentationActionModel | null;
}

export function toPresentationModel<T>(
  state: ResourceState<T>,
): PresentationModel {
  switch (state.kind) {
    case 'loading':
      return {
        kind: state.kind,
        title: 'Loading investigation data',
        message: 'The typed adapter is waiting for a contract-valid response.',
        detail: 'No partial payload is interpreted while loading.',
        action: null,
      };
    case 'empty':
      return {
        kind: state.kind,
        title: 'No incidents to review',
        message: 'The selected scope contains no incident records.',
        detail: 'Empty remains distinct from unavailable or unauthorized.',
        action: null,
      };
    case 'error':
      return {
        kind: state.kind,
        title: 'Investigation data unavailable',
        message: state.error.message,
        detail: `Typed error: ${state.error.code}`,
        action: null,
      };
    case 'permission-denied':
      return {
        kind: state.kind,
        title: 'Permission required',
        message: state.error.message,
        detail: 'The client does not infer or expand administrator authority.',
        action: null,
      };
    case 'disabled':
      return {
        kind: state.kind,
        title: 'Action disabled',
        message: state.disabledReason,
        detail:
          'This presentation does not calculate or override server safety.',
        action: { label: 'Approve action', disabled: true },
      };
    case 'success':
      return {
        kind: state.kind,
        title: 'Typed contract loaded',
        message:
          'The frozen incident fixture passed the registered runtime guard.',
        detail:
          'This confirms presentation data only, not live backend behavior.',
        action: null,
      };
  }
}
