import type { Context, Next } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeUrl, normalizeUrlWithQuery } from '../utils/url-normalizer'
import { RedirectCache } from '../utils/cache'
import { RedirectService } from '../services/redirect'

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

  return async (c: Context, next: Next): Promise<Response | void> => {
    const url = new URL(c.req.url)
    const pathname = url.pathname

    // Skip redirect processing for admin routes
    if (pathname.startsWith('/admin/redirects')) {
      await next()
      return
    }

    const db = (c.env?.DB || c.get('db')) as D1Database | undefined
    if (!db) {
      // No database, skip redirect processing
      await next()
      return
    }

    // Normalize URL for matching
    const normalizedPath = normalizeUrl(pathname)

    // Check cache first (sub-millisecond)
    let cached = redirectCache?.get(normalizedPath)

    if (!cached) {
      // Also try with full path + query for query-inclusive redirects
      const normalizedWithQuery = normalizeUrlWithQuery(url.pathname + url.search, true)
      cached = redirectCache?.get(normalizedWithQuery)
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
          preserveQueryString: redirect.preserveQueryString,
          includeSubdomains: redirect.includeSubdomains,
          subpathMatching: redirect.subpathMatching,
          preservePathSuffix: redirect.preservePathSuffix
        }
        redirectCache?.set(normalizedPath, cached)

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

      // Preserve query string if configured (Cloudflare-aligned)
      if (cached.preserveQueryString && url.search) {
        if (destination.includes('?')) {
          // Append to existing query
          destination += '&' + url.search.slice(1)
        } else {
          destination += url.search
        }
      }

      // Handle subpath matching with path suffix preservation
      if (cached.subpathMatching && cached.preservePathSuffix) {
        // If the request path extends beyond the source pattern, append the suffix
        const sourcePath = normalizedPath
        const requestPath = pathname
        if (requestPath.length > sourcePath.length && requestPath.startsWith(sourcePath)) {
          const pathSuffix = requestPath.slice(sourcePath.length)
          if (destination.includes('?')) {
            // Insert before query string
            const [basePath, query] = destination.split('?')
            destination = basePath + pathSuffix + '?' + query
          } else {
            destination += pathSuffix
          }
        }
      }

      // Record hit asynchronously (cache hit path)
      recordHitAsync((c.env?.DB || c.get('db')) as D1Database, cached.id)

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
  void db
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
               r.match_type,
               COALESCE(r.preserve_query_string, 0) as preserve_query_string,
               COALESCE(r.include_subdomains, 0) as include_subdomains,
               COALESCE(r.subpath_matching, 0) as subpath_matching,
               COALESCE(r.preserve_path_suffix, 1) as preserve_path_suffix,
               COALESCE(a.hit_count, 0) as hit_count
        FROM redirects r
        LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
        WHERE r.is_active = 1 AND r.deleted_at IS NULL
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
        preserveQueryString: (row.preserve_query_string as number ?? 0) === 1,
        includeSubdomains: (row.include_subdomains as number ?? 0) === 1,
        subpathMatching: (row.subpath_matching as number ?? 0) === 1,
        preservePathSuffix: (row.preserve_path_suffix as number ?? 1) === 1
      })
    }

    return results.length
  } catch (error) {
    console.error('[RedirectMiddleware] Cache warming error:', error)
    return 0
  }
}
