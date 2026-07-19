import type {
  ApiErrorV1,
  IncidentState,
  IncidentSummaryV1,
} from '../contracts/apiDtos';
import type {
  DetectionClassification,
  DeterministicSignalV1,
  SourceHealthV1,
} from '../contracts/rootContracts';

export const INCIDENT_LIST_PAGE_SIZE = 4;

export interface IncidentListFilters {
  readonly sourceIp: string;
  readonly state: IncidentState | 'all';
  readonly scenario: DetectionClassification | 'all';
  readonly service: string;
  readonly fromUtc: string;
  readonly toUtc: string;
}

export interface IncidentListRequest {
  readonly filters: IncidentListFilters;
  readonly cursor: string | null;
  readonly pageSize: number;
}

/**
 * Presentation-only composition of already typed contracts. It is not an API
 * DTO and deliberately adds no raw request fields.
 */
export interface IncidentListViewItem {
  readonly incident: IncidentSummaryV1;
  readonly primarySignal: DeterministicSignalV1;
  readonly sourceHealth: SourceHealthV1;
}

export interface IncidentListPageInfo {
  readonly startCursor: string | null;
  readonly endCursor: string | null;
  readonly previousCursor: string | null;
  readonly nextCursor: string | null;
  readonly hasPreviousPage: boolean;
  readonly hasNextPage: boolean;
  readonly firstVisibleIndex: number;
  readonly lastVisibleIndex: number;
  readonly totalItems: number;
}

export interface IncidentListPage {
  readonly items: readonly IncidentListViewItem[];
  readonly pageInfo: IncidentListPageInfo;
}

export type IncidentListAdapterResult =
  | { readonly kind: 'success'; readonly page: IncidentListPage }
  | { readonly kind: 'error'; readonly error: ApiErrorV1 }
  | { readonly kind: 'permission-denied'; readonly error: ApiErrorV1 };

export interface IncidentListAdapter {
  readonly kind: 'fixture' | 'http';
  load(
    request: IncidentListRequest,
    signal?: AbortSignal,
  ): Promise<IncidentListAdapterResult>;
}

/**
 * Marker interface for the M7-001 HTTP implementation. There is intentionally
 * no fetch implementation or response envelope here until that contract is
 * frozen and registered.
 */
export interface FutureHttpIncidentListAdapter extends IncidentListAdapter {
  readonly kind: 'http';
}

export type IncidentListLoadState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'empty' }
  | { readonly kind: 'error'; readonly error: ApiErrorV1 }
  | { readonly kind: 'permission-denied'; readonly error: ApiErrorV1 }
  | { readonly kind: 'populated'; readonly page: IncidentListPage };
