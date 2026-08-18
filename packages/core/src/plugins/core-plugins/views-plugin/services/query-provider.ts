/**
 * query-provider.ts — the Views data-access adapter seam.
 *
 * `ViewService.execute` resolves the collection/schema/columns and merges filters/sort
 * (substrate-agnostic), then hands a fully-resolved request to a `ViewQueryProvider` that
 * OWNS the substrate-specific "build SQL + run it → rows + total" step. On this codebase
 * the only substrate is the document model, so the only impl is `DocumentQueryProvider`
 * (document-query-provider.ts). The seam is retained — it is what made this plugin portable
 * across substrates in the first place, and a future engine swaps in with no change to
 * `ViewService` or its callers.
 */

import type { EnrichedColumn, FilterRule, FilterGroup, SortRule, ColumnConfig, PaginationConfig } from './types'
import type { CursorPosition } from './cursor'

/** One resolved keyset sort key (field + direction), SERVER-derived from the view sort. */
export interface CursorKey {
  readonly field: string
  readonly dir: 'asc' | 'desc'
}
/** A resolved keyset-cursor request. `keys` are the ordered non-id sort keys (server-derived, never
 *  from the token); the `id` tiebreaker follows the LAST key's dir. `position` is the decoded
 *  last-row boundary (absent on the first page). */
export interface CursorRequest {
  readonly keys: CursorKey[]
  readonly position?: CursorPosition
}

/** A fully-resolved view query — everything the provider needs to fetch rows + a total count. */
export interface ViewQueryRequest {
  /** Substrate table identifier — `'documents'` here (the doc provider keys on `collectionId`). */
  readonly tableName: string
  /** The view's resolved collection id — resolves to the `document_types` id. */
  readonly collectionId: string
  readonly columns: EnrichedColumn[]
  /** Top-level rules — ALWAYS AND-ed (with each other, the groups, and the forced status). */
  readonly filters: FilterRule[]
  /** OR/AND groups (OR-logic). Carried SEPARATELY from the flat top-level list; each is AND-ed in. */
  readonly groups?: FilterGroup[]
  readonly sort: SortRule[]
  readonly columnConfig: ColumnConfig
  readonly pagination: PaginationConfig
  readonly page: number
  readonly limit: number
  /** Keyset-cursor mode (opt-in). When set, the provider ignores `page`/offset, skips the COUNT,
   *  and returns `nextCursor` instead of `total`. */
  readonly cursor?: CursorRequest
  /** Set by the anonymous public surfaces (public API + embed). Drives two safeguards the
   *  authed admin path skips: (1) internal auth user-id columns (`created_by`/`updated_by`) are
   *  dropped from the projection, and (2) per-document `deny` ACL overrides are honored
   *  (the collection-grant gate covers the type level; this adds the row level — "deny wins"). */
  readonly anonymousPublic?: boolean
}

export interface ViewQueryResult {
  readonly rows: Record<string, unknown>[]
  /** Offset mode: the full count. Cursor mode: 0 (unused — the cursor path skips COUNT). */
  readonly total: number
  /** Cursor mode only: the token for the next page, or `null` when this is the last page. */
  readonly nextCursor?: string | null
}

/** The substrate seam: resolve a view query to rows + total. One impl per substrate.
 *  `kind` discriminates cursor-key admission: the `document` engine keysets on structural
 *  columns only (a `collection`-kind engine could admit arbitrary NOT-NULL columns). */
export interface ViewQueryProvider {
  readonly kind: 'collection' | 'document'
  query(req: ViewQueryRequest): Promise<ViewQueryResult>
}
