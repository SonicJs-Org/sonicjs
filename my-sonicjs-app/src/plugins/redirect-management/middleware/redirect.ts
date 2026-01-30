import type { Context, Next } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeUrl, normalizeUrlWithQuery } from '../utils/url-normalizer'
import { RedirectCache, CacheEntry } from '../utils/cache'
import { RedirectService } from '../services/redirect'
import type { Redirect } from '../types'

// Module-level cache (singleton per worker instance)
let redirectCache: RedirectCache | null = null

interface RedirectMiddlewareOptions {
  cacheSize?: number  // Default 1000
}

export function createRedirectMiddleware(options: RedirectMiddlewareOptions = {}) {
  const cacheSize = options.cacheSize ?? 1000

  // Initialize cache on first call
  if (!redirectCache) {
    redirectCache = new RedirectCache(cacheSize)
  }

  return async (c: Context, next: Next) => {
    const db = c.env?.D1 as D1Database | undefined
    if (!db) {
      // No database, skip redirect processing
      await next()
      return
    }

    const url = new URL(c.req.url)
    const pathname = url.pathname

    // Normalize URL for matching
    const normalizedPath = normalizeUrl(pathname)

    // Check cache first (sub-millisecond)
    let cached = redirectCache.get(normalizedPath)

    if (!cached) {
      // Also try with full path + query for query-inclusive redirects
      const normalizedWithQuery = normalizeUrlWithQuery(url.pathname + url.search, true)
      cached = redirectCache.get(normalizedWithQuery)
    }

    if (!cached) {
      // Cache miss - lookup in database using RedirectService
      const redirectService = new RedirectService(db)
      const redirect = await redirectService.lookupBySource(normalizedPath)

      if (redirect && redirect.isActive) {
        // Cache the result
        cached = {
          id: redirect.id,
          destination: redirect.destination,
          statusCode: redirect.statusCode,
          isActive: redirect.isActive,
          matchType: redirect.matchType,
          includeQueryParams: redirect.includeQueryParams,
          preserveQueryParams: redirect.preserveQueryParams
        }
        redirectCache.set(normalizedPath, cached)

        // Also record hit asynchronously (don't block redirect)
        recordHitAsync(db, redirect.id)
      }
    }

    // Execute redirect if found and active
    if (cached && cached.isActive) {
      // Handle 410 Gone specially (not a redirect)
      if (cached.statusCode === 410) {
        return new Response(null, {
          status: 410,
          headers: {
            'Cache-Control': 'public, max-age=31536000'  // 410 is cacheable
          }
        })
      }

      // Build destination URL
      let destination = cached.destination

      // Preserve query params if configured
      if (cached.preserveQueryParams && url.search) {
        if (destination.includes('?')) {
          // Append to existing query
          destination += '&' + url.search.slice(1)
        } else {
          destination += url.search
        }
      }

      // Record hit asynchronously (cache hit path)
      recordHitAsync(c.env?.D1 as D1Database, cached.id)

      // Execute redirect
      return c.redirect(destination, cached.statusCode as 301 | 302 | 307 | 308)
    }

    // No redirect found or inactive - continue to next middleware
    await next()
  }
}

// Async hit recording (don't await - fire and forget)
function recordHitAsync(db: D1Database | undefined, redirectId: string): void {
  if (!db) return

  // Use waitUntil if available (Cloudflare Workers), otherwise fire-and-forget
  const promise = db
    .prepare(`
      INSERT INTO redirect_analytics (id, redirect_id, hit_count, last_hit_at, created_at, updated_at)
      VALUES (?, ?, 1, ?, ?, ?)
      ON CONFLICT(redirect_id) DO UPDATE SET
        hit_count = hit_count + 1,
        last_hit_at = excluded.last_hit_at,
        updated_at = excluded.updated_at
    `)
    .bind(
      crypto.randomUUID(),
      redirectId,
      Date.now(),
      Date.now(),
      Date.now()
    )
    .run()
    .catch(err => console.error('[RedirectMiddleware] Hit recording error:', err))

  // Don't await - let it run in background
}

// Cache invalidation function (call from service layer)
export function invalidateRedirectCache(): void {
  if (redirectCache) {
    redirectCache.clear()
  }
}

// Pre-warm cache function (call on startup)
export async function warmRedirectCache(db: D1Database): Promise<number> {
  if (!redirectCache) {
    redirectCache = new RedirectCache(1000)
  }

  try {
    const { results } = await db
      .prepare(`
        SELECT r.id, r.source, r.destination, r.status_code, r.is_active,
               r.match_type, r.include_query_params, r.preserve_query_params,
               COALESCE(a.hit_count, 0) as hit_count
        FROM redirects r
        LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
        WHERE r.is_active = 1
        ORDER BY hit_count DESC
        LIMIT 1000
      `)
      .all()

    for (const row of results) {
      const normalizedSource = normalizeUrl(row.source as string)
      redirectCache.set(normalizedSource, {
        id: row.id as string,
        destination: row.destination as string,
        statusCode: row.status_code as number,
        isActive: true,
        matchType: row.match_type as number,
        includeQueryParams: (row.include_query_params as number ?? 0) === 1,
        preserveQueryParams: (row.preserve_query_params as number ?? 0) === 1
      })
    }

    return results.length
  } catch (error) {
    console.error('[RedirectMiddleware] Cache warming error:', error)
    return 0
  }
}
