import { Hono } from 'hono'
import { requireAuth, requireRole } from '../../../../middleware'
import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import type { Bindings, Variables } from '../../../../app'
import { renderViewsListPage, type ViewListItem } from '../templates/admin-views-list.template'
import { renderViewEditorPage, type CollectionOption } from '../templates/admin-views-editor.template'
import { FilterError, OPS_BY_FAMILY, getSupportedOperators } from '../services/filter-handlers'
import { resolveHandlerFamily } from '../services/column-resolver'
import { buildColumnMeta } from '../services/column-meta'
import { DocumentCollectionResolver } from '../services/view-collection-resolver'
import type { FilterOperator, HandlerFamily } from '../services/types'
import { ViewService, ViewServiceError, CursorUnsupportedError, resolveCursorKeys, type ViewPreviewDraft } from '../services/view-service'
import { DocModelUnsupportedError } from '../services/document-query-provider'
import { createViewService } from './api-views'
import type { SortRule } from '../services/types'
import { ViewDisplayRepository } from '../services/view-display-repository'
import {
  deriveDefaultTableConfig,
  displayVisibleColumns,
  parseDisplayConfig,
  assertColumnsInProjection,
  DisplayConfigError,
  type ViewDisplayConfig,
} from '../services/display-config'
import { ViewCacheService } from '../services/view-cache'
import { renderViewDisplayPage } from '../templates/admin-view-display.template'
import { getRequestTenant } from '../../../../services/document-request-context'
import type { ContentfulStatusCode } from 'hono/utils/http-status'

const adminViewsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Admin-gated end to end (the menu-plugin convention: requireAuth + requireRole('admin')).
adminViewsRoutes.use('*', requireAuth())
adminViewsRoutes.use('*', requireRole(['admin']))

// ─────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────

/** URL-safe name: lowercase alphanumeric, hyphens, underscores. 1-100 chars. */
const VIEW_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,99}$/

function validateName(name: unknown): string | null {
  if (typeof name !== 'string' || !VIEW_NAME_RE.test(name)) {
    return 'name must be 1-100 chars, lowercase alphanumeric with hyphens/underscores, starting with alphanumeric'
  }
  return null
}

function validatePageSize(pageSize: unknown): number {
  const n = typeof pageSize === 'number' ? pageSize : parseInt(String(pageSize || '25'), 10)
  if (isNaN(n) || n < 1) return 25
  // Cap at 100 — the serveable ceiling (PaginationConfig.maxLimit + the display-config
  // 1..100 clamp). A larger stored page_size would be silently truncated by the repo's
  // row cap, so reject it at the source.
  return Math.min(Math.floor(n), 100)
}

function isValidJson(value: unknown): boolean {
  if (value === null || value === undefined) return true
  if (typeof value === 'object') return true
  return false
}

/** Must match FilterOperator in ../services/types.ts */
const VALID_FILTER_OPS = new Set([
  '_eq', '_neq', '_gt', '_gte', '_lt', '_lte',
  '_between', '_in', '_contains', '_starts', '_null',
])

/** Validate a single filter rule; returns an error string or null. `where` labels the location. */
function validateFilterRule(rule: Record<string, unknown>, where: string): string | null {
  if (!rule.field || typeof rule.field !== 'string') {
    return `${where}: missing or invalid 'field'`
  }
  if (!rule.operator || !VALID_FILTER_OPS.has(rule.operator as string)) {
    return `${where}: missing or invalid 'operator' (got '${rule.operator}'). Valid: ${[...VALID_FILTER_OPS].join(', ')}`
  }
  if (rule.operator !== '_null' && rule.value === undefined) {
    return `${where}: missing 'value' for operator '${rule.operator}'`
  }
  return null
}

function validateFilterConfig(config: unknown): string | null {
  if (!config || typeof config !== 'object') return null // empty is ok
  const fc = config as Record<string, unknown>

  if (fc.rules !== undefined) {
    if (!Array.isArray(fc.rules)) return 'filter_config.rules must be an array'
    for (let i = 0; i < fc.rules.length; i++) {
      const err = validateFilterRule(fc.rules[i] as Record<string, unknown>, `filter_config.rules[${i}]`)
      if (err) return err
    }
  }

  // OR-logic groups. Top-level composition is ALWAYS AND (there is no top-level
  // `match`) — OR only inside a group. Each group needs a valid `match` and a
  // NON-empty rule set (an empty group would emit invalid `()` SQL on the public path).
  if (fc.groups !== undefined) {
    if (!Array.isArray(fc.groups)) return 'filter_config.groups must be an array'
    for (let i = 0; i < fc.groups.length; i++) {
      const group = fc.groups[i] as Record<string, unknown>
      if (group?.match !== 'and' && group?.match !== 'or') {
        return `filter_config.groups[${i}]: 'match' must be 'and' or 'or'`
      }
      if (!Array.isArray(group.rules) || group.rules.length === 0) {
        return `filter_config.groups[${i}]: 'rules' must be a non-empty array`
      }
      for (let j = 0; j < group.rules.length; j++) {
        const err = validateFilterRule(group.rules[j] as Record<string, unknown>, `filter_config.groups[${i}].rules[${j}]`)
        if (err) return err
      }
    }
  }

  return null
}

// ─────────────────────────────────────────────────────────────────────────
// Save-time serveability validation (collection/family-aware)
//
// `validateFilterConfig` above only checks SHAPE + operator-NAME membership. It cannot tell
// that `_contains` on a numeric field, or `_between` on text, is unserveable — those save fine
// and then fail at READ time. On this substrate there is NO c_* fallback, so a read-time failure
// is a 500 on the public embed. So we reject unserveable views at SAVE, loud (400), naming the
// offending rule. Two rejection classes:
//   (a) family-invalid  — op ∉ OPS_BY_FAMILY[family]; c_* rejects it too (e.g. `_gt` on text).
//   (b) doc-unserveable — family-valid on c_*, but the document model can't express it here:
//       JSON `_in` (c_*'s json_each EXISTS membership) and JSON `_contains` (c_*'s LIKE over RAW
//       stored text vs json_extract's normalized text). Corpus count for both = 0 → reject.
// The status family (F/G) is NOT rejected here: on THIS substrate `status` is a native column, so
// `status _neq/_in` and status-inside-a-group are trivially served (unlike the projection substrate).
// ─────────────────────────────────────────────────────────────────────────

/** Resolve field→handler-family for a collection, or null if it has no provisioned type
 *  (H — provisioning, not a filter op; the serveability check is skipped and the runtime
 *  provisioning guard surfaces it). */
async function resolveFilterFamilies(
  db: D1Database,
  collectionId: string,
): Promise<Map<string, HandlerFamily> | null> {
  try {
    const { enrichedColumns } = await new DocumentCollectionResolver(db).resolve(collectionId)
    return new Map(enrichedColumns.map((col) => [col.name, resolveHandlerFamily(col)]))
  } catch {
    return null
  }
}

/** One rule → error string or null, given the resolved family map. */
function checkRuleServeable(
  rule: Record<string, unknown>,
  familyByName: Map<string, HandlerFamily>,
  where: string,
): string | null {
  const field = typeof rule.field === 'string' ? rule.field : undefined
  const op = typeof rule.operator === 'string' ? (rule.operator as FilterOperator) : undefined
  // Structural shape errors are already returned by validateFilterConfig; skip them here.
  if (!field || !op) return null
  if (op === '_null') return null // universal — every family serves IS [NOT] NULL
  const family = familyByName.get(field)
  if (!family) return null // unknown/unresolvable field — not this check's responsibility
  // (a) family-invalid — parity with c_*'s OPS_BY_FAMILY (fails on BOTH engines otherwise)
  if (!OPS_BY_FAMILY[family].has(op)) {
    return `${where}: operator '${op}' is not supported for field '${field}' (${family}). Supported: ${getSupportedOperators(family).join(', ')}`
  }
  // (b) doc-unserveable — family-valid on c_* but inexpressible on the document model here
  if (family === 'json' && (op === '_in' || op === '_contains')) {
    return `${where}: '${op}' on the JSON/array field '${field}' cannot be served by the document model (no c_* fallback exists) — narrow the view or change the field type`
  }
  return null
}

/** Collection/family-aware serveability pass over a filter config. Returns an error string or
 *  null. Structure is assumed already validated by `validateFilterConfig`. Exported for direct
 *  unit-testing (the save-reject break-it proof). */
export function validateFilterServeability(
  config: unknown,
  familyByName: Map<string, HandlerFamily>,
): string | null {
  if (!config || typeof config !== 'object') return null
  const fc = config as Record<string, unknown>

  const rules = Array.isArray(fc.rules) ? fc.rules : []
  for (let i = 0; i < rules.length; i++) {
    const err = checkRuleServeable(rules[i] as Record<string, unknown>, familyByName, `filter_config.rules[${i}]`)
    if (err) return err
  }

  const groups = Array.isArray(fc.groups) ? fc.groups : []
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i] as Record<string, unknown>
    const grules = Array.isArray(group?.rules) ? group.rules : []
    for (let j = 0; j < grules.length; j++) {
      const err = checkRuleServeable(
        grules[j] as Record<string, unknown>,
        familyByName,
        `filter_config.groups[${i}].rules[${j}]`,
      )
      if (err) return err
    }
  }
  return null
}

// Collection/column resolution routes through the resolution seam (view-collection-resolver.ts)
// so the builder shares one substrate source with ViewService.

async function collectionExists(db: D1Database, collectionId: string): Promise<boolean> {
  return new DocumentCollectionResolver(db).collectionExists(collectionId)
}

async function getActiveCollections(db: D1Database): Promise<CollectionOption[]> {
  return new DocumentCollectionResolver(db).listCollections()
}

/** URL-safe public slug for a published display. Same shape as a view name. */
const DISPLAY_PATH_RE = /^[a-z0-9][a-z0-9_-]{0,99}$/

/** Map a display config to the render spec the templates consume (table or cards). */
type DisplaySpec =
  | { kind: 'table'; columns: string[] }
  | { kind: 'cards'; titleField: string; fields: string[] }
function toDisplaySpec(config: ViewDisplayConfig): DisplaySpec {
  if (config.type === 'table') return { kind: 'table', columns: displayVisibleColumns(config) }
  return { kind: 'cards', titleField: config.titleField, fields: config.fields }
}

/**
 * Best-effort invalidation of a view's public read caches after an admin mutation
 * (view edit/delete, publish/unpublish). The content-change hook covers content
 * writes; these cover config changes the hook can't see. Never throws into the
 * request — a cache fault leaves a stale entry to expire via TTL.
 */
async function invalidateViewCaches(
  kv: KVNamespace | undefined,
  tenantId: string,
  opts: { name?: string | null; path?: string | null }
): Promise<void> {
  if (!kv) return
  try {
    const cache = new ViewCacheService(kv)
    const tasks: Promise<void>[] = []
    if (opts.name) tasks.push(cache.invalidateView(tenantId, opts.name))
    if (opts.path) tasks.push(cache.invalidateEmbed(tenantId, opts.path))
    await Promise.all(tasks)
  } catch (err) {
    console.warn('[ViewCache] admin invalidation failed:', err)
  }
}

/**
 * The column names of a view's collection backing store — used to validate a publish
 * whitelist (`⊆` the store) and that a `status` column exists for the forced published
 * filter. Returns null if the collection has no backing store (not ready).
 */
async function resolveCollectionColumns(db: D1Database, collectionId: string): Promise<string[] | null> {
  return new DocumentCollectionResolver(db).collectionColumns(collectionId)
}

// ─────────────────────────────────────────────────────────────────────────
// PAGE ROUTES — serve HTML
// ─────────────────────────────────────────────────────────────────────────

// GET /admin/views — list page
adminViewsRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const tenantId = getRequestTenant(c)

  const { results } = await db
    .prepare(`
      SELECT v.id, v.name, v.display_name, v.page_size, v.created_at,
             v.filter_config, dt.name as collection_name
      FROM views v
      LEFT JOIN document_types dt ON v.collection_id = dt.id
      WHERE v.status = 'active' AND v.tenant_id = ?
      ORDER BY v.created_at DESC
    `)
    .bind(tenantId)
    .all<{ id: string; name: string; display_name: string; page_size: number; created_at: number; filter_config: string | null; collection_name: string | null }>()
  const views: ViewListItem[] = (results || []).map((r) => {
    let filterCount = 0
    try {
      const fc = r.filter_config ? JSON.parse(r.filter_config) : null
      filterCount = fc?.rules?.length || 0
    } catch { /* ignore */ }

    return {
      id: r.id,
      name: r.name,
      display_name: r.display_name,
      collection_name: r.collection_name,
      filter_count: filterCount,
      page_size: r.page_size || 25,
      created_at: r.created_at,
    }
  })

  // Resolve build-ready collections at render time so the cold-start empty
  // state can branch on what actually exists right now (the runtime
  // collection-resolution mechanism behind the "first ready collection").
  const readyCollections = await getActiveCollections(db)

  return c.html(renderViewsListPage({
    views,
    readyCollections,
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion') as string | undefined,
  }))
})

// GET /admin/views/new — create page
adminViewsRoutes.get('/new', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const collections = await getActiveCollections(db)

  return c.html(renderViewEditorPage({
    isEdit: false,
    collections,
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion') as string | undefined,
  }))
})

// GET /admin/views/:id/display — render the saved view as a paginated table.
// Distinct two-segment pattern; does not collide with `/:id` (one segment) or
// the static `/api/*` routes.
adminViewsRoutes.get('/:id/display', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const user = c.get('user')
  const tenantId = getRequestTenant(c)

  interface DisplayViewRow {
    id: string
    name: string
    display_name: string | null
    collection_id: string | null
    columns_config: string | null
    page_size: number | null
  }
  const view = await db
    .prepare(`SELECT id, name, display_name, collection_id, columns_config, page_size FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'`)
    .bind(id, tenantId)
    .first<DisplayViewRow>()
  if (!view) return c.notFound()

  const userCtx = user
    ? { name: user.email, email: user.email, role: user.role }
    : undefined
  const version = c.get('appVersion') as string | undefined

  // Effective display config: the stored default, else one derived from the view
  // itself (no backfill). A corrupt stored row falls back to the derived default.
  let fields: string[] | undefined
  if (view.columns_config) {
    try {
      fields = (JSON.parse(view.columns_config) as { fields?: string[] })?.fields
    } catch {
      fields = undefined
    }
  }
  const displays = new ViewDisplayRepository(db, tenantId)
  const stored = await displays.getDefault(view.id).catch(() => null)
  const config =
    stored?.config ?? deriveDefaultTableConfig({ columnsFields: fields, pageSize: view.page_size })
  const displaySpec = toDisplaySpec(config)

  // The Display-settings picker (#1b) offers the view's PROJECTION (the same set
  // the config endpoint validates ⊆), so it can never offer a column the save
  // would reject: columns_config.fields when set, else all collection columns.
  const allCols = view.collection_id
    ? (await resolveCollectionColumns(db, view.collection_id)) ?? []
    : []
  const availableColumns = fields && fields.length > 0 ? fields : allCols
  const settings = { availableColumns, pageSize: config.pageSize, paginate: config.paginate }
  const share = stored ? { isPublic: stored.isPublic, shareToken: stored.shareToken, path: stored.path } : undefined

  // Run the same engine path the public API uses; the display config's pageSize
  // is authoritative for this surface.
  const svc = createViewService(db, tenantId)
  let result: Awaited<ReturnType<ViewService['execute']>>
  const runOffset = (): ReturnType<ViewService['execute']> => {
    const q: Record<string, string> = { ...c.req.query() }
    delete q['cursor']
    delete q['paginate']
    return svc.execute(view.name, { ...q, limit: String(config.pageSize) })
  }
  try {
    if (config.paginate === 'cursor') {
      // The display opts into cursor mode: pass ?cursor= through. If the view sort drifted
      // non-structural, the engine throws CursorUnsupportedError → fall back to the offset pager
      // (never a 500), mirroring the embed (#1132).
      try {
        result = await svc.execute(view.name, { ...c.req.query(), limit: String(config.pageSize) })
      } catch (err) {
        if (err instanceof CursorUnsupportedError) result = await runOffset()
        else throw err
      }
    } else {
      result = await runOffset()
    }
  } catch (err) {
    if (err instanceof ViewServiceError) {
      // Surface the engine's state (e.g. 409 collection-not-ready) as a banner,
      // never a 500.
      return c.html(
        renderViewDisplayPage({
          view,
          display: displaySpec,
          settings,
          share,
          rows: [],
          meta: { total: 0, page: 1, pages: 1, hasNext: false, hasPrev: false },
          error: err.message,
          user: userCtx,
          version,
        }),
        err.statusCode as ContentfulStatusCode
      )
    }
    throw err
  }

  if (!('json' in result)) {
    return c.text('This display renders as HTML; use the API endpoint for CSV.', 400)
  }
  const { data: rows, meta } = result.json
  // meta is offset (ViewMeta) or cursor (ViewCursorMeta) — the pager template branches on `'page' in meta`.
  return c.html(
    renderViewDisplayPage({ view, display: displaySpec, settings, share, rows, meta, user: userCtx, version })
  )
})

// POST /admin/views/:id/display/publish — open a display to the public at a slug.
// Authed (router-level requireAuth). No public surface is served here — that is
// PR-C2's /v/:path route; this only sets the gate.
adminViewsRoutes.post('/:id/display/publish', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const tenantId = getRequestTenant(c)
  const body = await parseJsonBody(c)
  if (!body) return c.json({ error: 'Request body must be valid JSON' }, 400)

  interface PublishViewRow {
    id: string
    collection_id: string | null
    columns_config: string | null
    page_size: number | null
  }
  const view = await db
    .prepare(`SELECT id, collection_id, columns_config, page_size FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'`)
    .bind(id, tenantId)
    .first<PublishViewRow>()
  if (!view) return c.json({ error: 'View not found' }, 404)
  if (!view.collection_id) return c.json({ error: 'View has no collection assigned' }, 400)

  // Validate the public slug.
  const path = body.path
  if (typeof path !== 'string' || !DISPLAY_PATH_RE.test(path)) {
    return c.json({ error: 'path must be 1-100 chars, lowercase alphanumeric with hyphens/underscores, starting alphanumeric' }, 400)
  }

  // Resolve the projection + require a `status` column (the forced published filter
  // operates on it) — the type-agnostic safety bar.
  const tableColumns = await resolveCollectionColumns(db, view.collection_id)
  if (!tableColumns) return c.json({ error: 'Collection is not ready' }, 400)
  if (!tableColumns.includes('status')) {
    return c.json({ error: 'Collection has no status column; cannot publish a published-only display' }, 400)
  }
  let projectedFields: string[] = []
  if (view.columns_config) {
    try {
      projectedFields = (JSON.parse(view.columns_config) as { fields?: string[] })?.fields ?? []
    } catch { /* treat as all */ }
  }
  const projection = projectedFields.length > 0 ? projectedFields : tableColumns

  // Determine the config to publish. Default: publish the STORED display config
  // (table or cards). Back-compat bridge: when `columns` is supplied AND the stored
  // display is a table (or none yet), set a table whitelist — preserves the original
  // `{ path, columns }` publish API. The bridge NEVER applies to a cards display
  // (it would clobber the cards config); the cards visible set is set via PUT config.
  const repo = new ViewDisplayRepository(db, tenantId)
  const stored = await repo.getDefault(id).catch(() => null)
  const bodyColumns = body.columns
  let config: ViewDisplayConfig
  if (bodyColumns !== undefined && (!stored || stored.config.type === 'table')) {
    if (!Array.isArray(bodyColumns) || bodyColumns.length === 0 || !bodyColumns.every((col: unknown) => typeof col === 'string')) {
      return c.json({ error: 'columns must be a non-empty array of column names' }, 400)
    }
    const base = deriveDefaultTableConfig({ columnsFields: projectedFields, pageSize: view.page_size })
    config = { ...base, columns: bodyColumns as string[], pageSize: stored?.config.pageSize ?? base.pageSize }
  } else if (stored) {
    config = stored.config
  } else {
    return c.json({ error: 'No display configured to publish; set the display config first' }, 400)
  }

  // The visible set must be non-empty ⊆ projection (type-agnostic) — no empty=all,
  // no system-column leak, for table OR cards.
  if (displayVisibleColumns(config).length === 0) {
    return c.json({ error: 'The display has no visible columns to publish' }, 400)
  }
  try {
    assertColumnsInProjection(config, projection)
  } catch (err) {
    if (err instanceof DisplayConfigError) return c.json({ error: err.message }, 400)
    throw err
  }

  // Slug uniqueness: another view already owns this path → 409 (the partial unique
  // index is the real guard; this gives a friendly error first).
  const owner = await repo.findPathOwner(path)
  if (owner && owner !== id) {
    return c.json({ error: `path "${path}" is already in use` }, 409)
  }

  const now = Date.now()
  let shareToken: string
  try {
    ;({ shareToken } = await repo.setPublished(id, config, path, now))
  } catch (err) {
    const msg = err instanceof Error ? err.message : ''
    if (msg.includes('UNIQUE') || msg.includes('unique')) {
      // `share_token` is pre-checked unique in the repo, so a UNIQUE failure here is
      // the `path` partial index — another view owns this slug.
      return c.json({ error: `path "${path}" is already in use` }, 409)
    }
    throw err
  }

  // A republish to a different whitelist changes the embed's config fingerprint
  // (so old keys are unreachable), but invalidate to free KV and cover a re-path.
  await invalidateViewCaches(c.env.CACHE_KV, tenantId, { path })

  // `share_token` is additive — the public share link is /v/<share_token>.
  return c.json({ message: 'Display published', path, share_token: shareToken })
})

// PUT /admin/views/:id/display/config — set the display TYPE + config (the picker
// backend). Authed (router-level requireAuth). Keeps is_public/path; the new visible
// set goes live on the public surface immediately if already published, so it gets
// the FULL publish safety bar (non-empty visible set ⊆ projection + a status column).
adminViewsRoutes.put('/:id/display/config', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const tenantId = getRequestTenant(c)
  const body = await parseJsonBody(c)
  if (!body) return c.json({ error: 'Request body must be valid JSON' }, 400)

  interface ConfigViewRow { id: string; name: string; collection_id: string | null; columns_config: string | null; sort_config: string | null }
  const view = await db
    .prepare(`SELECT id, name, collection_id, columns_config, sort_config FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'`)
    .bind(id, tenantId)
    .first<ConfigViewRow>()
  if (!view) return c.json({ error: 'View not found' }, 404)
  if (!view.collection_id) return c.json({ error: 'View has no collection assigned' }, 400)

  // Fail-closed parse of the display type + config (the discriminated union).
  let config: ViewDisplayConfig
  try {
    config = parseDisplayConfig(JSON.stringify(body.config), String(body.display_type))
  } catch (err) {
    if (err instanceof DisplayConfigError) return c.json({ error: err.message }, 400)
    throw err
  }

  // MUST-FIX #5: the field picker's save omits `paginate`, so parse defaulted it to 'offset'.
  // Preserve the existing display's mode so a picker save can't silently revert a cursor display.
  const incomingPaginate = (body as { config?: { paginate?: unknown } } | null)?.config?.paginate
  if (incomingPaginate === undefined) {
    const existing = await new ViewDisplayRepository(db, tenantId).getDefault(id).catch(() => null)
    if (existing) config = { ...config, paginate: existing.config.paginate }
  }

  // MUST-FIX #2: cursor mode requires a keyset-serviceable view sort. Validate at config-set (loud
  // UX); the live embed also falls back to offset at render, so a later sort drift can't 500 it.
  if (config.paginate === 'cursor') {
    let sort: SortRule[] = []
    try {
      const parsedSort: unknown = JSON.parse(view.sort_config ?? '[]')
      if (Array.isArray(parsedSort)) sort = parsedSort as SortRule[]
    } catch {
      /* no sort → resolveCursorKeys applies the default */
    }
    // The doc engine keysets on structural columns only — no user-column admission
    // (matches the render-time gate in ViewService.runResolvedView).
    try {
      resolveCursorKeys(sort, undefined)
    } catch (err) {
      if (err instanceof CursorUnsupportedError) {
        return c.json(
          { error: `Cursor pagination requires sorting by updated_at, created_at, and/or id: ${err.message}` },
          400,
        )
      }
      throw err
    }
  }

  // Same safety bar as publish (the display may already be is_public=1).
  const tableColumns = await resolveCollectionColumns(db, view.collection_id)
  if (!tableColumns) return c.json({ error: 'Collection is not ready' }, 400)
  if (!tableColumns.includes('status')) {
    return c.json({ error: 'Collection has no status column' }, 400)
  }
  let projectedFields: string[] = []
  if (view.columns_config) {
    try {
      projectedFields = (JSON.parse(view.columns_config) as { fields?: string[] })?.fields ?? []
    } catch { /* treat as all */ }
  }
  const projection = projectedFields.length > 0 ? projectedFields : tableColumns
  if (displayVisibleColumns(config).length === 0) {
    return c.json({ error: 'The display config has no visible columns' }, 400)
  }
  try {
    assertColumnsInProjection(config, projection)
  } catch (err) {
    if (err instanceof DisplayConfigError) return c.json({ error: err.message }, 400)
    throw err
  }

  // Read the stored path BEFORE the write so a published table→cards switch clears
  // the embed cache at that path (else the stale table HTML serves until the TTL).
  const repo = new ViewDisplayRepository(db, tenantId)
  const before = await repo.getDefault(id).catch(() => null)
  await repo.setConfig(id, config, Date.now())
  await invalidateViewCaches(c.env.CACHE_KV, tenantId, { name: view.name, path: before?.path })

  return c.json({ message: 'Display config updated', display_type: config.type })
})

// POST /admin/views/:id/display/unpublish — close the public display (keeps the slug).
adminViewsRoutes.post('/:id/display/unpublish', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const tenantId = getRequestTenant(c)

  const view = await db
    .prepare(`SELECT id FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'`)
    .bind(id, tenantId)
    .first<{ id: string }>()
  if (!view) return c.json({ error: 'View not found' }, 404)

  // Capture the slug BEFORE flipping the gate so the cached embed can be cleared —
  // otherwise getByPath 404s live but the cached HTML would serve until the TTL.
  const display = await db
    .prepare(`SELECT path FROM view_displays WHERE view_id = ? AND tenant_id = ?`)
    .bind(id, tenantId)
    .first<{ path: string | null }>()

  await new ViewDisplayRepository(db, tenantId).unpublish(id, Date.now())
  await invalidateViewCaches(c.env.CACHE_KV, tenantId, { path: display?.path })
  return c.json({ message: 'Display unpublished' })
})

// GET /admin/views/:id — edit page
adminViewsRoutes.get('/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const user = c.get('user')
  const tenantId = getRequestTenant(c)

  // Don't match API sub-routes
  if (id === 'api') return c.notFound()

  interface ViewRow {
    id: string; name: string; display_name: string; description: string | null
    collection_id: string | null; filter_config: string | null
    sort_config: string | null; columns_config: string | null; page_size: number
    is_public: number
  }
  // status filter: the list hides soft-deleted views — the edit page must not resurrect
  // them by direct URL (polish item from the 2026-07-04 review).
  const view = await db.prepare("SELECT * FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'").bind(id, tenantId).first<ViewRow>()
  if (!view) {
    return c.html(renderViewEditorPage({
      isEdit: false,
      collections: await getActiveCollections(db),
      error: 'View not found',
      user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
      version: c.get('appVersion') as string | undefined,
    }))
  }

  const collections = await getActiveCollections(db)

  return c.html(renderViewEditorPage({
    id: view.id,
    name: view.name,
    display_name: view.display_name,
    description: view.description ?? undefined,
    collection_id: view.collection_id ?? undefined,
    filter_config: view.filter_config,
    sort_config: view.sort_config,
    columns_config: view.columns_config,
    page_size: view.page_size,
    is_public: view.is_public === 1,
    isEdit: true,
    collections,
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion') as string | undefined,
  }))
})

/** Body reader for the admin JSON routes: Hono's `c.req.json()` throws a raw SyntaxError on a
 *  malformed body, which would bubble as a 500 — an invalid REQUEST is the client's fault, so
 *  surface a 400 instead (admin-only surface; polish item from the 2026-07-04 review). Returns
 *  `null` when the body is not a JSON object/array. */
async function parseJsonBody(c: { req: { json(): Promise<unknown> } }): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await c.req.json()
    return body !== null && typeof body === 'object' ? (body as Record<string, unknown>) : null
  } catch {
    return null
  }
}

// ─────────────────────────────────────────────────────────────────────────
// API ROUTES — JSON responses, under /admin/views/api/
// ─────────────────────────────────────────────────────────────────────────

// GET /admin/views/api/ — list views (JSON)
adminViewsRoutes.get('/api/', async (c) => {
  const db = c.env.DB
  const tenantId = getRequestTenant(c)
  const collectionId = c.req.query('collection_id')

  if (collectionId) {
    const { results } = await db
      .prepare('SELECT * FROM views WHERE collection_id = ? AND tenant_id = ? AND status = ? ORDER BY created_at DESC')
      .bind(collectionId, tenantId, 'active')
      .all()
    return c.json({ data: results || [] })
  }

  const { results } = await db
    .prepare('SELECT * FROM views WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC')
    .bind(tenantId, 'active')
    .all()
  return c.json({ data: results || [] })
})

// POST /admin/views/api/ — create a view
// POST /api/preview — execute an UNSAVED draft config and return rows (Views MVP PR-3).
// The C1 correction: the editor's "live preview" was save-first because nothing ran an unsaved
// config. The builder posts the in-progress { collection_id, *_config (JSON strings), page_size };
// previewDraft runs the IDENTICAL pipeline as a saved view (no views row). JSON only.
adminViewsRoutes.post('/api/preview', async (c) => {
  const db = c.env.DB
  try {
    const body = (await parseJsonBody(c)) as ViewPreviewDraft | null
    if (!body) return c.json({ error: 'Request body must be valid JSON' }, 400)
    const svc = createViewService(db, getRequestTenant(c))
    const result = await svc.previewDraft(body, {})
    return c.json(result.json)
  } catch (err) {
    if (err instanceof ViewServiceError) {
      return c.json({ error: err.message }, err.statusCode as ContentfulStatusCode)
    }
    if (err instanceof FilterError) {
      return c.json({ error: err.message }, 400)
    }
    // The raw-JSON editor can post a config the doc model can't serve (e.g. _contains on a
    // numeric field) or an unserveable cursor sort — bypassing the builder's family-limited
    // dropdowns. Surface these as a 400, not an unhandled 500 (every other route handles them).
    if (err instanceof DocModelUnsupportedError || err instanceof CursorUnsupportedError) {
      return c.json({ error: err.message }, 400)
    }
    throw err
  }
})

adminViewsRoutes.post('/api', async (c) => {
  const db = c.env.DB
  const tenantId = getRequestTenant(c)
  const body = await parseJsonBody(c)
  if (!body) return c.json({ error: 'Request body must be valid JSON' }, 400)
  const user = c.get('user')

  const nameErr = validateName(body.name)
  if (nameErr) return c.json({ error: nameErr }, 400)

  if (body.collection_id) {
    const exists = await collectionExists(db, body.collection_id as string)
    if (!exists) {
      return c.json({ error: `Collection "${body.collection_id}" not found or deleted` }, 400)
    }
  }

  if (!isValidJson(body.filter_config)) return c.json({ error: 'filter_config must be an object or null' }, 400)
  if (!isValidJson(body.sort_config)) return c.json({ error: 'sort_config must be an object/array or null' }, 400)
  if (!isValidJson(body.columns_config)) return c.json({ error: 'columns_config must be an object or null' }, 400)

  const filterErr = validateFilterConfig(body.filter_config)
  if (filterErr) return c.json({ error: filterErr }, 400)

  // Collection/family-aware serveability: reject ops the document model can't serve at READ time
  // BEFORE the row is written (no c_* fallback here — a runtime failure would be a 500 on the embed).
  if (body.collection_id) {
    const families = await resolveFilterFamilies(db, body.collection_id as string)
    if (families) {
      const servErr = validateFilterServeability(body.filter_config, families)
      if (servErr) return c.json({ error: servErr }, 400)
    }
  }

  const now = Date.now()
  // Tenant-prefixed: `name` is only unique PER TENANT now, so two tenants creating a
  // same-named view would otherwise collide on this table's actual PRIMARY KEY (a
  // different, tenant-blind constraint than the UNIQUE(tenant_id, name) index). Length-
  // prefixing tenantId makes the tenant/name boundary unambiguous — a plain
  // `${tenantId}-${name}-view` concatenation lets tenant "a" naming a view "b-c" collide
  // with tenant "a-b" naming a view "c" (both derive "a-b-c-view"), silently denying one
  // tenant an available name with a misleading "already exists" error.
  const id = `${tenantId.length}:${tenantId}:${body.name}-view`

  // A soft-deleted view keeps its UNIQUE name (delete is status='deleted', not a row removal),
  // which would otherwise 409 an admin who deletes a view and recreates one with the same name.
  // Free the name by hard-removing the deleted row (+ its displays). An ACTIVE same-name view is
  // untouched here and still collides → the 409 below.
  const stale = await db
    .prepare("SELECT id FROM views WHERE name = ? AND tenant_id = ? AND status = 'deleted'")
    .bind(body.name as string, tenantId)
    .first<{ id: string }>()
  if (stale) {
    await db.batch([
      db.prepare('DELETE FROM view_displays WHERE view_id = ?').bind(stale.id),
      db.prepare('DELETE FROM views WHERE id = ?').bind(stale.id),
    ])
  }

  try {
    await db.prepare(`
      INSERT INTO views (id, tenant_id, name, display_name, description, collection_id, filter_config, sort_config, columns_config, page_size, is_default, is_public, status, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
    `).bind(
      id,
      tenantId,
      body.name,
      body.display_name || body.name,
      body.description || null,
      body.collection_id || null,
      body.filter_config ? JSON.stringify(body.filter_config) : null,
      body.sort_config ? JSON.stringify(body.sort_config) : null,
      body.columns_config ? JSON.stringify(body.columns_config) : null,
      validatePageSize(body.page_size),
      body.is_default ? 1 : 0,
      body.is_public ? 1 : 0, // PRIVATE by default; only an explicit opt-in exposes the public API
      user?.userId || null,
      now,
      now
    ).run()
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : ''
    if (errMessage.includes('UNIQUE') || errMessage.includes('unique')) {
      return c.json({ error: `A view named "${body.name}" already exists` }, 409)
    }
    throw err
  }

  // Auto-provision the view's default `table` display. Best-effort: the render
  // surface falls back to a derived default if this row is ever absent, so a
  // provisioning failure must not fail view creation.
  try {
    const displays = new ViewDisplayRepository(db, tenantId)
    const columnsFields = (body.columns_config as { fields?: string[] } | undefined)?.fields
    await displays.upsertDefault(
      id,
      deriveDefaultTableConfig({ columnsFields, pageSize: validatePageSize(body.page_size) }),
      now
    )
  } catch (err) {
    console.error('Failed to provision default view display:', err)
  }

  return c.json({ id, message: 'View created' }, 201)
})

// PUT /admin/views/api/:id — update a view
adminViewsRoutes.put('/api/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const tenantId = getRequestTenant(c)
  const body = await parseJsonBody(c)
  if (!body) return c.json({ error: 'Request body must be valid JSON' }, 400)

  const existing = await db
    .prepare("SELECT name, collection_id FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'")
    .bind(id, tenantId)
    .first<{ name: string; collection_id: string | null }>()
  if (!existing) {
    return c.json({ error: 'View not found' }, 404)
  }

  if (!isValidJson(body.filter_config)) return c.json({ error: 'filter_config must be an object or null' }, 400)
  if (!isValidJson(body.sort_config)) return c.json({ error: 'sort_config must be an object/array or null' }, 400)
  if (!isValidJson(body.columns_config)) return c.json({ error: 'columns_config must be an object or null' }, 400)

  const filterErr = validateFilterConfig(body.filter_config)
  if (filterErr) return c.json({ error: filterErr }, 400)

  // Same serveability gate as create — a filter edit must not sneak an unserveable op past save.
  if (existing.collection_id) {
    const families = await resolveFilterFamilies(db, existing.collection_id)
    if (families) {
      const servErr = validateFilterServeability(body.filter_config, families)
      if (servErr) return c.json({ error: servErr }, 400)
    }
  }

  const now = Date.now()

  await db.prepare(`
    UPDATE views SET
      display_name = ?, description = ?, filter_config = ?, sort_config = ?, columns_config = ?, page_size = ?, is_default = ?, is_public = ?, updated_at = ?
    WHERE id = ? AND tenant_id = ?
  `).bind(
    body.display_name || null,
    body.description || null,
    body.filter_config ? JSON.stringify(body.filter_config) : null,
    body.sort_config ? JSON.stringify(body.sort_config) : null,
    body.columns_config ? JSON.stringify(body.columns_config) : null,
    validatePageSize(body.page_size),
    body.is_default ? 1 : 0,
    body.is_public ? 1 : 0,
    now,
    id,
    tenantId
  ).run()

  // Keep the default `table` display in sync with the view's saved projection.
  // Best-effort (see the create handler).
  try {
    const displays = new ViewDisplayRepository(db, tenantId)
    const columnsFields = (body.columns_config as { fields?: string[] } | undefined)?.fields
    await displays.upsertDefault(
      id,
      deriveDefaultTableConfig({ columnsFields, pageSize: validatePageSize(body.page_size) }),
      now
    )
  } catch (err) {
    console.error('Failed to provision default view display:', err)
  }

  // The content hook can't see a config edit — invalidate this view's caches so a
  // narrowed filter/columns takes effect immediately on the public surfaces.
  const display = await db
    .prepare(`SELECT path FROM view_displays WHERE view_id = ? AND tenant_id = ?`)
    .bind(id, tenantId)
    .first<{ path: string | null }>()
  await invalidateViewCaches(c.env.CACHE_KV, tenantId, { name: existing.name, path: display?.path })

  return c.json({ message: 'View updated' })
})

// DELETE /admin/views/api/:id — soft-delete a view
adminViewsRoutes.delete('/api/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')!
  const tenantId = getRequestTenant(c)

  const existing = await db
    .prepare("SELECT name FROM views WHERE id = ? AND tenant_id = ? AND status = 'active'")
    .bind(id, tenantId)
    .first<{ name: string }>()
  if (!existing) {
    return c.json({ error: 'View not found' }, 404)
  }
  const display = await db
    .prepare(`SELECT path FROM view_displays WHERE view_id = ? AND tenant_id = ?`)
    .bind(id, tenantId)
    .first<{ path: string | null }>()

  await db.prepare("UPDATE views SET status = 'deleted', updated_at = ? WHERE id = ? AND tenant_id = ?")
    .bind(Date.now(), id, tenantId)
    .run()

  await invalidateViewCaches(c.env.CACHE_KV, tenantId, { name: existing.name, path: display?.path })

  return c.json({ message: 'View deleted' })
})

// GET /admin/views/api/collection-columns/:collectionName — column metadata for view editor
adminViewsRoutes.get('/api/collection-columns/:collectionName', async (c) => {
  const db = c.env.DB
  const collectionName = c.req.param('collectionName')!

  const resolved = await new DocumentCollectionResolver(db).columnsByName(collectionName)
  if (!resolved) {
    return c.json({ error: `Collection "${collectionName}" not found` }, 404)
  }

  // PR-4: name/fieldType/handler/operators (as before) + enumOptions + referenceTarget — the
  // typed value-widget data the visual builder needs (deep-review F5).
  const columns = buildColumnMeta(resolved.enrichedColumns, resolved.schemaProperties)

  return c.json({ columns })
})

export { adminViewsRoutes }
