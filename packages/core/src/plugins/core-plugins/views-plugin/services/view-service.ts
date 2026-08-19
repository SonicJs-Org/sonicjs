// views-plugin/services/view-service.ts

import type { D1Database } from '@cloudflare/workers-types'
import {
  CollectionNotReadyError,
  CollectionResolutionError,
  type ViewCollectionResolver,
  type ResolvedViewCollection,
} from './view-collection-resolver'
import type { ViewQueryProvider, CursorRequest } from './query-provider'
import { parseQueryParams } from './query-parser'
import { formatJsonResponse, formatCsvResponse, formatCursorResponse } from './response-formatter'
import { decodeCursor, type CursorPosition } from './cursor'
import type {
  FilterRule, FilterConfig, FilterGroup, FilterOperator, SortConfig, ColumnConfig,
  PaginationConfig, ParsedQueryParams, SortRule,
} from './types'
import type { JsonEnvelope, CursorJsonEnvelope } from './response-formatter'

/** Cursor pagination (PR-3) supports a single sort key on these NOT-NULL STRUCTURAL columns.
 *  Anything else (nullable/user columns, multi-key, mixed direction) → CursorUnsupportedError. */
const CURSOR_SORT_FIELDS = new Set<string>(['updated_at', 'created_at', 'id'])

/** Raised when a view/query asks for cursor pagination on a sort the keyset engine can't serve. */
export class CursorUnsupportedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CursorUnsupportedError'
  }
}

/** The single choke point (both providers can't drift): resolve the view sort to an ORDERED set of
 *  cursor keys (1..N, EXCLUDING `id` — it is the implicit tiebreaker), or throw loud. No sort (or
 *  only `[id]`) → the deterministic default `updated_at DESC` (newest first). Multi-key + mixed
 *  direction over the NOT-NULL structural columns (PR-3b) PLUS any user/promoted column proven
 *  NOT NULL via `notNullFields` (from `EnrichedColumn.notNull`). Nullable columns stay rejected —
 *  NULL-policy A: a nullable key would leave NULL rows in an undefined ordering gap the keyset
 *  predicate can't seek past. `notNullFields` omitted ⇒ structural-only (the conservative default). */
export function resolveCursorKeys(
  sort: SortRule[],
  notNullFields?: ReadonlySet<string>,
): Array<{ field: string; dir: 'asc' | 'desc' }> {
  const effective = sort.length === 0 ? [{ field: 'updated_at', direction: 'desc' as const }] : sort
  const keys: Array<{ field: string; dir: 'asc' | 'desc' }> = []
  for (const s of effective) {
    if (s.field === 'id') continue // implicit tiebreaker — strip an explicit user `id` key (must-fix #4)
    const keysetSafe = CURSOR_SORT_FIELDS.has(s.field) || (notNullFields?.has(s.field) ?? false)
    if (!keysetSafe) {
      throw new CursorUnsupportedError(
        `cursor pagination supports sorting only by ${[...CURSOR_SORT_FIELDS].join(', ')} or a NOT-NULL column (got "${s.field}")`,
      )
    }
    keys.push({ field: s.field, dir: s.direction === 'asc' ? 'asc' : 'desc' })
  }
  if (keys.length === 0) keys.push({ field: 'updated_at', dir: 'desc' }) // sort was only [id] → default
  return keys
}

// ─────────────────────────────────────────────────────────────────────────
// View row — shape from views table
// ─────────────────────────────────────────────────────────────────────────

interface ViewRow {
  id: string
  name: string
  display_name: string | null
  description: string | null
  collection_id: string | null
  filter_config: string | null
  sort_config: string | null
  columns_config: string | null
  page_size: number
  is_public: number
  status: string
}

/**
 * An UNSAVED view config to execute for live preview (Views MVP PR-3). The builder posts the
 * in-progress collection + filter/sort/column JSON; `previewDraft` runs it through the exact
 * same pipeline as a saved view — without an `views` row.
 */
export interface ViewPreviewDraft {
  collection_id: string | null
  filter_config?: string | null
  sort_config?: string | null
  columns_config?: string | null
  page_size?: number
}

// ─────────────────────────────────────────────────────────────────────────
// ViewService errors
// ─────────────────────────────────────────────────────────────────────────

export class ViewServiceError extends Error {
  constructor(
    message: string,
    public readonly code: 'NOT_FOUND' | 'NO_COLLECTION' | 'COLLECTION_ERROR' | 'QUERY_ERROR',
    public readonly statusCode: number = 400
  ) {
    super(message)
    this.name = 'ViewServiceError'
  }
}

// ─────────────────────────────────────────────────────────────────────────
// ViewService — orchestrates view execution
// ─────────────────────────────────────────────────────────────────────────

export class ViewService {
  constructor(
    private readonly db: D1Database,
    // The substrate provider (row fetch) — the doc-model engine on this codebase.
    private readonly queryProvider: ViewQueryProvider,
    // The resolution seam (collection + schema + columns) — document_types-backed.
    private readonly collectionResolver: ViewCollectionResolver,
    private readonly tenantId: string = 'default',
  ) {}

  // NOTE: execute() is the cursor-capable JSON entry — its `json` is JsonEnvelope (offset) OR
  // CursorJsonEnvelope (cursor mode). Offset consumers narrow via `'page' in meta`.
  async execute(
    viewName: string,
    queryParams: Record<string, string>,
    opts?: { forcePublished?: boolean; anonymousPublic?: boolean }
  ): Promise<{ json: JsonEnvelope | CursorJsonEnvelope } | { csv: string; filename: string }> {
    // 1. Load view row, then run the shared pipeline.
    const view = await this.loadView(viewName)
    // Anonymous public API (GET /api/views/:name): the view must be explicitly public AND
    // its collection must grant public read. Both failures 404 (don't reveal a private view's
    // existence). Authed/admin callers use the builder preview, which never sets this flag.
    if (opts?.anonymousPublic) {
      await this.assertAnonymousPublicAllowed(view, viewName)
    }
    return this.runResolvedView(view, queryParams, opts)
  }

  /** Gate for the anonymous public surfaces. Throws NOT_FOUND (mapped to 404 upstream) if the
   *  view is private (`is_public != 1`) or its backing collection does not grant public read.
   *  `requireViewPublic=false` for the embed (which has its own display-level publish opt-in;
   *  only the collection-grant backstop applies there). */
  private async assertAnonymousPublicAllowed(
    view: ViewRow,
    label: string,
    requireViewPublic = true,
  ): Promise<void> {
    if (requireViewPublic && view.is_public !== 1) {
      throw new ViewServiceError(`View "${label}" not found`, 'NOT_FOUND', 404)
    }
    const publicOk =
      !!view.collection_id && (await this.collectionResolver.isCollectionPublic(view.collection_id))
    if (!publicOk) {
      throw new ViewServiceError(`View "${label}" not found`, 'NOT_FOUND', 404)
    }
  }

  /**
   * Execute a PUBLISHED, whitelisted view for the public embed surface (PR-C2).
   * Locked down vs `execute`: only a clamped `page` is honored — no runtime
   * filter/sort/limit/format/shorthand reaches `parseQueryParams`, so there is
   * nothing to override the forced `status='published'`; the column whitelist is
   * forced into the SQL SELECT (system columns never reach the row objects); and
   * stored shorthands are dropped. Always JSON.
   */
  async executePublic(
    viewId: string,
    whitelist: string[],
    pageSize: number,
    page: number
  ): Promise<{ json: JsonEnvelope }> {
    const view = await this.loadViewById(viewId)
    // Collection-grant backstop: even a published display cannot expose a non-public collection.
    await this.assertAnonymousPublicAllowed(view, viewId, false)
    const synthetic: ViewRow = {
      ...view,
      filter_config: this.stripShorthands(view.filter_config),
      columns_config: JSON.stringify({ fields: whitelist }),
      page_size: pageSize,
    }
    const result = await this.runResolvedView(synthetic, { page: String(page) }, { forcePublished: true, anonymousPublic: true })
    return result as { json: JsonEnvelope }
  }

  /**
   * Cursor (keyset) variant of executePublic for a display in `paginate:'cursor'` mode (PR-4).
   * Forces published; passes the opaque cursor token (or none for the first page). Returns the
   * cursor envelope. Throws `CursorUnsupportedError` if the view sort isn't keyset-serviceable —
   * the caller catches it and falls back to `executePublic` (offset), so the live embed never 500s.
   */
  async executePublicCursor(
    viewId: string,
    whitelist: string[],
    pageSize: number,
    cursorToken?: string
  ): Promise<{ json: CursorJsonEnvelope }> {
    const view = await this.loadViewById(viewId)
    await this.assertAnonymousPublicAllowed(view, viewId, false)
    const synthetic: ViewRow = {
      ...view,
      filter_config: this.stripShorthands(view.filter_config),
      columns_config: JSON.stringify({ fields: whitelist }),
      page_size: pageSize,
    }
    const query: Record<string, string> = { paginate: 'cursor' }
    if (cursorToken !== undefined) query['cursor'] = cursorToken
    const result = await this.runResolvedView(synthetic, query, { forcePublished: true, anonymousPublic: true })
    return result as { json: CursorJsonEnvelope }
  }

  /**
   * Execute an UNSAVED draft config for live preview (PR-3, the C1 correction — the editor's
   * "live preview" was save-first because no endpoint ran an unsaved config). Builds a synthetic
   * view row and runs the IDENTICAL pipeline as `execute`, so the preview matches the saved view
   * exactly. Always JSON (no CSV download for a preview).
   */
  async previewDraft(
    draft: ViewPreviewDraft,
    queryParams: Record<string, string>
  ): Promise<{ json: JsonEnvelope }> {
    const view: ViewRow = {
      id: 'preview',
      name: 'preview',
      display_name: null,
      description: null,
      collection_id: draft.collection_id,
      filter_config: draft.filter_config ?? null,
      sort_config: draft.sort_config ?? null,
      columns_config: draft.columns_config ?? null,
      page_size: draft.page_size ?? 25,
      is_public: 0, // preview is authed-only; never reaches an anonymous-public gate
      status: 'active',
    }
    const result = await this.runResolvedView(view, { ...queryParams, format: 'json' })
    // runResolvedView only returns CSV when format=csv, which we forced off above — narrow it.
    return result as { json: JsonEnvelope }
  }

  /**
   * The shared execution pipeline (steps 2-13): resolve collection/schema/columns, merge
   * stored+runtime filters/sort, page, run via the substrate provider (PR-2 seam), and format.
   * Used by both `execute` (saved view) and `previewDraft` (unsaved draft). `view.name` drives
   * the response meta / CSV filename / error messages.
   */
  private async runResolvedView(
    view: ViewRow,
    queryParams: Record<string, string>,
    opts?: { forcePublished?: boolean; anonymousPublic?: boolean }
  ): Promise<{ json: JsonEnvelope | CursorJsonEnvelope } | { csv: string; filename: string }> {
    const viewName = view.name

    // 2. Guard null collection_id
    if (!view.collection_id) {
      throw new ViewServiceError(
        `View "${viewName}" has no collection assigned`,
        'NO_COLLECTION', 400
      )
    }

    // 3+4+5. Resolve collection + schema + columns via the resolution seam (C5). The resolver
    // carries substrate facts; the user-facing error text (and codes) stay here, unchanged.
    let collectionName: string
    let tableName: string
    let enrichedColumns: ResolvedViewCollection['enrichedColumns']
    try {
      ;({ collectionName, tableName, enrichedColumns } =
        await this.collectionResolver.resolve(view.collection_id))
    } catch (err) {
      if (err instanceof CollectionNotReadyError) {
        throw new ViewServiceError(
          `Collection for view "${viewName}" is not ready`,
          'COLLECTION_ERROR', 409
        )
      }
      if (err instanceof CollectionResolutionError) {
        throw new ViewServiceError(
          `Collection error for view "${viewName}": ${err.message}`,
          'COLLECTION_ERROR', err.httpStatus
        )
      }
      throw err
    }

    // 6. Parse stored config
    const storedFilters = this.parseJsonConfig<FilterConfig>(view.filter_config, { rules: [], shorthands: [] })
    const storedSort = this.parseJsonConfig<SortConfig>(view.sort_config, [])
    const storedColumns = this.parseJsonConfig<ColumnConfig>(view.columns_config, { fields: [] })

    // 7. Parse query string
    const parsed: ParsedQueryParams = parseQueryParams(queryParams, storedFilters.shorthands)

    // 8. Merge stored + runtime filters (runtime overrides on same field+op). Groups
    // (OR-logic) are carried SEPARATELY — runtime params are always flat rules
    // (parseQueryParams has no group syntax), so a runtime param can never inject or
    // mutate a group.
    let mergedFilters = this.mergeFilters(storedFilters.rules, parsed.filters)
    let groups: FilterGroup[] = storedFilters.groups ?? []

    // 8b. Public surfaces force published-only NON-OVERRIDABLY. This MUST happen
    // after the merge: injecting status='published' as a stored rule is overridable
    // by a runtime ?filter[status][_eq]=draft (mergeFilters lets runtime win on the
    // same field). Stripping every status rule then appending exactly one makes the
    // top-level WHERE deterministically status='published' — and because that forced
    // rule is a TOP-LEVEL AND-conjunct wrapping the whole tree (every group is AND-ed
    // in), no OR group can re-admit a non-published row (SQL AND is monotonic).
    // Also strip status from groups + drop any emptied group (defense-in-depth +
    // avoids a status-only group rendering the public view always-empty).
    if (opts?.forcePublished) {
      mergedFilters = mergedFilters.filter((f) => f.field !== 'status')
      mergedFilters.push({ field: 'status', operator: '_eq' as FilterOperator, value: 'published' })
      groups = groups
        .map((g) => ({ ...g, rules: g.rules.filter((r) => r.field !== 'status') }))
        .filter((g) => g.rules.length > 0)
    }

    // 9. Merge sort (runtime overrides stored if provided)
    const mergedSort = parsed.sort.length > 0 ? parsed.sort : storedSort

    // 9b. Cursor pagination (opt-in, JSON API only). The SINGLE choke point: validate the sort into
    // a keyset here (both providers can't drift), decode the token, build the cursor request.
    let cursorReq: CursorRequest | undefined
    if (parsed.cursor !== undefined || parsed.paginate === 'cursor') {
      if (parsed.format === 'csv') {
        throw new CursorUnsupportedError('cursor pagination is not available for CSV output')
      }
      // Only the collection (c_*) engine can keyset on an arbitrary NOT-NULL user column; the doc
      // engine keysets on structural columns only. In collection mode, admit any NOT-NULL column.
      const notNullFields =
        this.queryProvider.kind === 'collection'
          ? new Set(enrichedColumns.filter((col) => col.notNull).map((col) => col.name))
          : undefined
      const keys = resolveCursorKeys(mergedSort, notNullFields)
      let position: CursorPosition | undefined
      if (parsed.cursor !== undefined) {
        const decoded = decodeCursor(parsed.cursor)
        if (!decoded) throw new ViewServiceError('Invalid cursor token', 'QUERY_ERROR', 400)
        // Drift check (must-fix #5): a stale v1 token, or a token from a since-changed sort, has the
        // wrong value count. Throw CursorUnsupportedError (NOT ViewServiceError) so BOTH surfaces
        // degrade correctly — the embed offset-falls-back on it (#1132), the JSON API 400s (must-fix #2).
        if (decoded.values.length !== keys.length) {
          throw new CursorUnsupportedError('cursor token does not match the current sort keys')
        }
        // Field-level drift (polish item 4): a sort-FIELD/dir change that keeps the same key
        // count (title asc → slug asc) passed the count check and mispositioned the page. New
        // tokens carry a "field:dir" fingerprint; tokens minted before it fall back to the
        // count-only check above (back-compat — one stale page at worst, values still bound).
        if (decoded.keys && decoded.keys.join('|') !== keys.map((k) => `${k.field}:${k.dir}`).join('|')) {
          throw new CursorUnsupportedError('cursor token does not match the current sort keys')
        }
        position = decoded
      }
      cursorReq = { keys, position }
    }

    // 10. Build pagination config. defaultLimit is capped at maxLimit here so a stored
    // page_size can never exceed the serveable ceiling — the repo hard-caps rows at 200,
    // so an uncapped page_size (201–1000) previously truncated silently with a wrong
    // meta (total/pages/hasNext computed off the uncapped limit). Cap once, use everywhere.
    const maxLimit = 100
    const paginationConfig: PaginationConfig = {
      defaultLimit: Math.min(view.page_size || 25, maxLimit),
      maxLimit,
    }

    // 11-12. Build + execute the query via the substrate provider (PR-2 seam). Cursor mode skips
    // the COUNT and returns nextCursor; offset mode is byte-identical to before.
    const { rows, total, nextCursor } = await this.queryProvider.query({
      tableName,
      collectionId: view.collection_id,
      columns: enrichedColumns,
      filters: mergedFilters,
      groups,
      sort: mergedSort,
      columnConfig: storedColumns,
      pagination: paginationConfig,
      page: parsed.page,
      limit: parsed.limit,
      cursor: cursorReq,
      // Anonymous surfaces (public API + embed): redact internal auth user ids AND honor
      // per-document deny overrides (the provider owns both when this is set).
      anonymousPublic: !!opts?.anonymousPublic,
    })

    const effectiveLimit = parsed.limit > 0
      ? Math.min(parsed.limit, paginationConfig.maxLimit)
      : paginationConfig.defaultLimit

    // 13. Format response
    if (cursorReq) {
      return {
        json: formatCursorResponse(rows, nextCursor ?? null, effectiveLimit, viewName, collectionName),
      }
    }

    if (parsed.format === 'csv') {
      return {
        csv: formatCsvResponse(rows),
        filename: `${viewName}.csv`,
      }
    }

    return {
      json: formatJsonResponse(rows, total, parsed.page, effectiveLimit, viewName, collectionName),
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  // Private helpers
  // ─────────────────────────────────────────────────────────────────────

  private async loadView(viewName: string): Promise<ViewRow> {
    const view = await this.db
      .prepare(`SELECT * FROM views WHERE name = ? AND tenant_id = ? AND status = 'active'`)
      .bind(viewName, this.tenantId)
      .first<ViewRow>()

    if (!view) {
      throw new ViewServiceError(`View "${viewName}" not found`, 'NOT_FOUND', 404)
    }
    return view
  }

  /** Load by id (the public embed resolves a display → view id, not a name). */
  private async loadViewById(viewId: string): Promise<ViewRow> {
    const view = await this.db
      .prepare(`SELECT * FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'`)
      .bind(viewId, this.tenantId)
      .first<ViewRow>()
    if (!view) {
      throw new ViewServiceError(`View "${viewId}" not found`, 'NOT_FOUND', 404)
    }
    return view
  }

  /**
   * Drop stored shorthands so no public query param can be mapped onto a filter
   * field — but PRESERVE `rules` AND `groups` (the OR-logic groups), so the embed
   * surface renders the same filter the admin built. (Dropping groups here would
   * silently disable OR on `/v/:path` and make a group-based filter a no-op.)
   */
  private stripShorthands(filterConfig: string | null): string | null {
    if (!filterConfig) return filterConfig
    try {
      const parsed = JSON.parse(filterConfig) as FilterConfig
      return JSON.stringify({ rules: parsed.rules ?? [], groups: parsed.groups, shorthands: [] })
    } catch {
      return null
    }
  }

  private mergeFilters(stored: FilterRule[], runtime: FilterRule[]): FilterRule[] {
    // Runtime overrides stored on same field+operator
    const merged = [...stored]
    for (const rf of runtime) {
      const idx = merged.findIndex(f => f.field === rf.field && f.operator === rf.operator)
      if (idx >= 0) {
        merged[idx] = rf
      } else {
        merged.push(rf)
      }
    }
    return merged
  }

  private parseJsonConfig<T>(raw: string | null, fallback: T): T {
    if (!raw) return fallback
    try {
      const parsed = JSON.parse(raw)
      // Normalize legacy format: {op: 'eq'} → {operator: '_eq'}
      if (parsed && typeof parsed === 'object' && Array.isArray(parsed.rules)) {
        parsed.rules = parsed.rules.map((rule: Record<string, unknown>) => {
          if (!rule.operator && rule.op) {
            return {
              field: rule.field,
              operator: ('_' + rule.op) as FilterOperator,
              value: rule.value,
            }
          }
          return rule
        })
      }
      // Strip filter rules missing required fields to prevent runtime crashes
      if (parsed && typeof parsed === 'object' && Array.isArray(parsed.rules)) {
        parsed.rules = parsed.rules.filter((rule: Record<string, unknown>) =>
          rule.field && typeof rule.field === 'string' &&
          rule.operator && typeof rule.operator === 'string'
        )
      }
      // Defense-in-depth (OR-logic): keep only well-formed groups with a non-empty
      // valid rule set, so a hand-edited/legacy row can never reach the builder with
      // an empty group (which would emit invalid `()` SQL).
      if (parsed && typeof parsed === 'object' && Array.isArray(parsed.groups)) {
        parsed.groups = parsed.groups
          .filter((g: Record<string, unknown>) => g && (g.match === 'and' || g.match === 'or') && Array.isArray(g.rules))
          .map((g: { match: string; rules: Array<Record<string, unknown>> }) => ({
            match: g.match,
            rules: g.rules.filter((r) => typeof r.field === 'string' && typeof r.operator === 'string'),
          }))
          .filter((g: { rules: unknown[] }) => g.rules.length > 0)
      }
      return parsed as T
    } catch {
      return fallback
    }
  }
}
