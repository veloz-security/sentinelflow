import {
  RESOURCE_STATE_KINDS,
  toPresentationModel,
  type PresentationModel,
  type ResourceStateKind,
} from '../contracts/resourceState';
import { MOCK_RESOURCE_STATES } from './contractFixtures';

export const PRESENTATION_STATE_ORDER: readonly ResourceStateKind[] =
  RESOURCE_STATE_KINDS;

export const MOCK_PRESENTATION_STATES: Readonly<
  Record<ResourceStateKind, PresentationModel>
> = Object.freeze(
  Object.fromEntries(
    PRESENTATION_STATE_ORDER.map((kind) => [
      kind,
      Object.freeze(toPresentationModel(MOCK_RESOURCE_STATES[kind])),
    ]),
  ) as Record<ResourceStateKind, PresentationModel>,
);
