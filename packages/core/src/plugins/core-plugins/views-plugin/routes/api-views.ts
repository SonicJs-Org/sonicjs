// views-plugin/routes/api-views.ts

import { Hono } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import type { Bindings, Variables } from '../../../../app'
import { ViewService, ViewServiceError, CursorUnsupportedError } from '../services/view-service'
import { DocumentQueryProvider, DocModelUnsupportedError } from '../services/document-query-provider'
import { ViewsDocumentRepository, d1Executor } from '../services/views-document-repository'
import { DocumentCollectionResolver } from '../services/view-collection-resolver'
import { ViewCacheService } from '../services/view-cache'
import { FilterError } from '../services/filter-handlers'
import { DocumentPermissionsService } from '../../../../services/document-permissions'
import { rateLimit } from '../../../../middleware/rate-limit'
import { getRequestTenant } from '../../../../services/document-request-context'
import type { ContentfulStatusCode } from 'hono/utils/http-status'

const apiViewsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Same budget as the /v/ embeds (60/min/IP). Without it this was the one public views
// surface with NO limit — and any non-`page` query param bypasses the KV cache by design,
// so an attacker could force uncached D1 reads with arbitrary json_extract sorts/filters
// (deep-review hardening item 2; on D1 the bill is rows read).
apiViewsRoutes.use('*', rateLimit({ max: 60, windowMs: 60_000, keyPrefix: 'views-api' }))

/** Cache only the bounded hot set: JSON, no filter/sort/limit/shorthand, low pages. */
const MAX_CACHED_PAGE = 20

/** Per-request service wiring — the doc-model engine is the only substrate here. */
export function createViewService(db: D1Database, tenantId: string = 'default'): ViewService {
  return new ViewService(
    db,
    // The permissions service lets anonymous reads honor per-document deny overrides (deny wins),
    // reusing the core ACL service rather than re-implementing it in the plugin.
    new DocumentQueryProvider(
      new ViewsDocumentRepository(d1Executor(db), tenantId),
      new DocumentPermissionsService(db),
      tenantId,
    ),
    new DocumentCollectionResolver(db, tenantId),
    tenantId,
  )
}

/**
 * Is this read the bounded, cacheable case? Only `page` (1..MAX) may vary — any
 * `filter`/`sort`/`limit`/`format`/shorthand param bypasses to D1. This caps each
 * view's keyspace at ≤ MAX entries (so an unauth caller can't mint unbounded KV
 * writes, and the single-page `invalidateView` list is always complete).
 */
function cacheablePage(query: Record<string, string>): number | null {
  const keys = Object.keys(query)
  if (!keys.every((k) => k === 'page')) return null
  const page = query.page === undefined ? 1 : parseInt(query.page, 10)
  if (!Number.isFinite(page) || page < 1 || page > MAX_CACHED_PAGE) return null
  return page
}

// GET /api/views/:name — public endpoint, no auth
apiViewsRoutes.get('/:name', async (c) => {
  const name = c.req.param('name')!
  const tenantId = getRequestTenant(c)
  const svc = createViewService(c.env.DB, tenantId)
  const query = c.req.query()

  // Read-through cache (opt-in via CACHE_KV; bounded keyspace). A cache fault must
  // never fail the request — it degrades to a live D1 read.
  const cachePage = c.env.CACHE_KV ? cacheablePage(query) : null
  const cache = cachePage !== null ? new ViewCacheService(c.env.CACHE_KV) : null
  const cacheParams: Record<string, string> = cachePage !== null ? { page: String(cachePage) } : {}
  if (cache) {
    try {
      const hit = await cache.get(tenantId, name, cacheParams)
      if (hit !== null) return c.body(hit, 200, { 'Content-Type': 'application/json' })
    } catch {
      /* cache read failed — fall through to D1 */
    }
  }

  try {
    // Public, unauthenticated endpoint: force published-only so drafts never leak, AND
    // require the view to be explicitly public (is_public=1) with a public-read collection
    // grant. A private view or a non-public collection 404s (execute throws NOT_FOUND),
    // so this endpoint never exposes anything the admin didn't opt into.
    const result = await svc.execute(name, query, { forcePublished: true, anonymousPublic: true })

    if ('csv' in result) {
      c.header('Content-Type', 'text/csv')
      c.header('Content-Disposition', `attachment; filename="${result.filename}"`)
      return c.body(result.csv)
    }

    if (cache) {
      try {
        await cache.set(tenantId, name, cacheParams, JSON.stringify(result.json))
      } catch {
        /* cache write failed — response still returned */
      }
    }
    return c.json(result.json)
  } catch (err) {
    if (err instanceof ViewServiceError) {
      return c.json({ error: err.message }, err.statusCode as ContentfulStatusCode)
    }
    if (err instanceof FilterError) {
      return c.json({ error: err.message }, 400)
    }
    // An unsupported/drifted cursor sort (multi-key non-structural, value-count mismatch) → 400,
    // not an unhandled 500. Malformed tokens already 400 via ViewServiceError above.
    if (err instanceof CursorUnsupportedError) {
      return c.json({ error: err.message }, 400)
    }
    // A view config the document model can't express (no fallback substrate exists here —
    // the port's C4): surface the reason as a 400, never an unhandled 500.
    if (err instanceof DocModelUnsupportedError) {
      return c.json({ error: err.message }, 400)
    }
    throw err
  }
})

export { apiViewsRoutes }
