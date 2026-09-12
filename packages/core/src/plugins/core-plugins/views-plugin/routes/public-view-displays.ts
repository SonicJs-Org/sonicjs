import { Hono } from 'hono'
import type { Bindings, Variables } from '../../../../app'
import { ViewServiceError, CursorUnsupportedError } from '../services/view-service'
import type { JsonEnvelope, CursorJsonEnvelope } from '../services/response-formatter'
import { createViewService } from './api-views'
import { ViewDisplayRepository } from '../services/view-display-repository'
import { displayVisibleColumns, serializeDisplayConfig } from '../services/display-config'
import { ViewCacheService, fingerprintConfig } from '../services/view-cache'
import { renderPublicViewDisplay } from '../templates/public-view-display.template'
import { rateLimit } from '../../../../middleware/rate-limit'
import { getRequestTenant } from '../../../../services/document-request-context'
import type { ContentfulStatusCode } from 'hono/utils/http-status'

const publicViewDisplaysRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

/** Cache only low pages (the hot set); deeper pages bypass to D1. */
const MAX_CACHED_EMBED_PAGE = 20

// Public, UNauthenticated surface — per-IP rate limited (graceful no-op without
// CACHE_KV). Gates every read on is_public = 1, forces published-only content,
// and renders only the explicit column whitelist.
publicViewDisplaysRoutes.use('*', rateLimit({ max: 60, windowMs: 60_000, keyPrefix: 'view-embed' }))

// Minimal chromeless error bodies (no admin layout, no JSON stack).
const notFoundHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Not found</title></head><body style="font-family:system-ui;padding:24px"><h1>Not found</h1><p>This display does not exist or is not public.</p></body></html>`
const unavailableHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Unavailable</title></head><body style="font-family:system-ui;padding:24px"><h1>Temporarily unavailable</h1></body></html>`

// GET /v/:slug — the published, chromeless, embeddable table/cards. `:slug` is
// EITHER the canonical `path` OR the unguessable share token (disjoint namespaces).
publicViewDisplaysRoutes.get('/:path', async (c) => {
  const slug = c.req.param('path')!
  const db = c.env.DB
  const tenantId = getRequestTenant(c)

  const display = await new ViewDisplayRepository(db, tenantId).getByPathOrToken(slug).catch(() => null)
  // Resolves a fail-closed-parsed config (table or cards), gated on is_public.
  // Any other state ⇒ not renderable ⇒ 404.
  if (!display) {
    return c.html(notFoundHtml, 404)
  }
  // A published display ALWAYS has a non-null `path` (the only is_public=1 writer
  // sets it). Cache + paginate against this CANONICAL path so token- and
  // path-access share one entry and the same invalidation. Defensive 500 if the
  // invariant is ever violated.
  const canonicalPath = display.path
  if (!canonicalPath) return c.html(unavailableHtml, 500)

  // The ONE visible set: feeds BOTH the SQL projection AND the template — no divergence.
  const visible = displayVisibleColumns(display.config)

  // Cursor mode is a per-display opt-in (PR-4). Cursor reads ?cursor=<token>; offset reads ?page=.
  const isCursor = display.config.paginate === 'cursor'
  const cursorToken = c.req.query('cursor') || undefined
  // Clamp page: floor at 1, cap so a deep `?page=` can't scan unbounded (offset only).
  const pageRaw = parseInt(c.req.query('page') ?? '1', 10)
  const page = Number.isFinite(pageRaw) ? Math.min(Math.max(1, pageRaw), 1000) : 1

  // Read-through embed cache in the DISJOINT `viewembed:` keyspace, keyed by the CANONICAL path +
  // a fingerprint of the WHOLE config (paginate included → offset/cursor keys never collide). Cursor
  // caches ONLY the first page (no token); token pages bypass — the token keyspace is unbounded.
  const cfg = fingerprintConfig(serializeDisplayConfig(display.config))
  const cacheKeyPage = isCursor ? 1 : page
  const cacheable = isCursor ? cursorToken === undefined : page <= MAX_CACHED_EMBED_PAGE
  const cache = c.env.CACHE_KV && cacheable ? new ViewCacheService(c.env.CACHE_KV) : null
  if (cache) {
    try {
      const hit = await cache.getEmbed(tenantId, canonicalPath, cfg, cacheKeyPage)
      if (hit !== null) return c.html(hit)
    } catch {
      /* cache read failed — fall through to D1 */
    }
  }

  const svc = createViewService(db, tenantId)
  let result: { json: JsonEnvelope | CursorJsonEnvelope }
  try {
    if (isCursor) {
      try {
        result = await svc.executePublicCursor(display.viewId, visible, display.config.pageSize, cursorToken)
      } catch (err) {
        // MUST-FIX #1: the view sort can drift non-structural (an unguarded PUT /admin/views/:id) →
        // executePublicCursor throws CursorUnsupportedError. Gracefully fall back to offset so the
        // LIVE embed never 500s (config-set validation is loud UX, never the sole guard).
        if (err instanceof CursorUnsupportedError) {
          result = await svc.executePublic(display.viewId, visible, display.config.pageSize, page)
        } else {
          throw err
        }
      }
    } else {
      result = await svc.executePublic(display.viewId, visible, display.config.pageSize, page)
    }
  } catch (err) {
    if (err instanceof ViewServiceError) {
      // Collection not ready / view gone — minimal body with the engine's code, no stack.
      return c.html(notFoundHtml, err.statusCode as ContentfulStatusCode)
    }
    return c.html(unavailableHtml, 500)
  }

  const { data: rows, meta } = result.json
  const html = renderPublicViewDisplay({
    title: meta.view,
    rows,
    meta,
    display:
      display.config.type === 'table'
        ? { kind: 'table', columns: visible }
        : { kind: 'cards', titleField: display.config.titleField, fields: display.config.fields },
  })

  if (cache) {
    try {
      await cache.setEmbed(tenantId, canonicalPath, cfg, cacheKeyPage, html)
    } catch {
      /* cache write failed — response still returned */
    }
  }
  return c.html(html)
})

export { publicViewDisplaysRoutes }
