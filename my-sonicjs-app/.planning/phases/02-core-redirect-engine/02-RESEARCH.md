# Phase 2: Core Redirect Engine - Research

**Researched:** 2026-01-30
**Domain:** HTTP redirect middleware, URL matching, LRU caching, validation algorithms
**Confidence:** HIGH

## Summary

This research investigated how to build the core redirect engine for SonicJS: middleware that intercepts incoming requests, matches URLs against stored redirect rules, validates configurations to prevent circular redirects, caches lookups for performance, and executes HTTP redirects with appropriate status codes. The investigation covered Hono middleware patterns, LRU cache implementations for Cloudflare Workers, URL normalization strategies, and circular redirect detection algorithms.

The standard approach uses Hono's middleware system where middleware can early-exit by returning a Response without calling `next()`. For redirects, use `c.redirect(destination, statusCode)` which accepts status codes 301, 302, 307, 308 (302 is default). For 410 Gone responses, return a Response object with status 410 and optional body. LRU caching should use tiny-lru or a simple Map-based implementation (since Workers have 128MB memory limit and LRU eviction can be manual). URL normalization for case-insensitivity and trailing slash handling should use lowercase comparison and strip trailing slashes before matching. Circular redirect detection uses a visited-set algorithm during chain traversal.

The SonicJS codebase already demonstrates the middleware pattern in `auth.ts` where `return c.redirect()` early-exits without calling `next()`. The redirect plugin foundation from Phase 1 provides the schema and service patterns to build upon. The middleware should be registered early in the request pipeline (high priority) to intercept requests before routing occurs.

**Primary recommendation:** Create redirect middleware using Hono's early-return pattern with `c.redirect(destination, statusCode)`, implement LRU cache using tiny-lru (1000 entries, invalidate on any change), normalize URLs to lowercase without trailing slashes before matching, and detect circular redirects using Set-based visited tracking.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Hono | ^4.11.7 | Middleware framework | Already used by SonicJS, provides `c.redirect()` with status code support |
| tiny-lru | ^11.4.7 | LRU cache | Lightweight (50kB), high performance, works in Cloudflare Workers, 1.2M weekly downloads |
| @cloudflare/workers-types | Latest | Type definitions | Provides D1Database types for database operations |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| normalize-url | ^8.x | URL normalization | For advanced URL normalization (optional - can hand-roll for simple cases) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| tiny-lru | lru-cache | lru-cache is more feature-rich but larger; tiny-lru is optimized for performance and size |
| tiny-lru | Map + manual eviction | Map is simpler but requires custom eviction logic; tiny-lru handles LRU automatically |
| normalize-url | Custom normalization | Custom is smaller but needs to handle edge cases; normalize-url is battle-tested |

**Installation:**
```bash
npm install tiny-lru
# Optional if needed:
npm install normalize-url
```

## Architecture Patterns

### Recommended Project Structure
```
src/plugins/redirect-management/
├── index.ts                    # Plugin entry point (already exists from Phase 1)
├── manifest.json               # Plugin metadata (already exists)
├── types.ts                    # Add: NormalizedUrl, CacheEntry, ValidationResult
├── services/
│   └── redirect.ts             # Extend: Add CRUD, lookup, validation methods
├── middleware/
│   └── redirect.ts             # NEW: Hono middleware for redirect interception
├── utils/
│   ├── url-normalizer.ts       # NEW: URL normalization functions
│   ├── circular-detector.ts    # NEW: Circular redirect detection
│   └── cache.ts                # NEW: LRU cache wrapper
└── test/
    └── redirect.spec.ts        # Tests for redirect execution
```

### Pattern 1: Hono Middleware Early Return
**What:** Middleware that intercepts requests and returns a redirect Response without calling `next()` to short-circuit the request pipeline.

**When to use:** For redirect interception - check URL, if match found, return redirect response.

**Example:**
```typescript
// Source: Hono docs + SonicJS auth.ts pattern
import { Context, Next } from 'hono'

export const redirectMiddleware = (options: { cache: LRUCache }) => {
  return async (c: Context, next: Next) => {
    const url = new URL(c.req.url)
    const normalizedPath = normalizeUrl(url.pathname)

    // Check cache first
    const cached = options.cache.get(normalizedPath)
    if (cached && cached.isActive) {
      // 410 Gone is special - return Response, not redirect
      if (cached.statusCode === 410) {
        return new Response(null, { status: 410 })
      }
      // Execute redirect - early return, no next()
      return c.redirect(cached.destination, cached.statusCode)
    }

    // No redirect found - continue to next middleware
    await next()
  }
}
```

### Pattern 2: URL Normalization for Matching
**What:** Normalize URLs before comparison to handle case sensitivity and trailing slashes consistently.

**When to use:** Always before URL matching to ensure `/Blog` matches `/blog` and `/page/` matches `/page`.

**Example:**
```typescript
// Source: normalize-url patterns + MDN URI normalization
export function normalizeUrl(url: string): string {
  // 1. Lowercase for case-insensitive matching
  let normalized = url.toLowerCase()

  // 2. Remove trailing slash (except root "/")
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1)
  }

  // 3. Handle encoded characters (optional based on requirements)
  // normalized = decodeURIComponent(normalized)

  return normalized
}

// For query parameter handling (configurable per redirect)
export function normalizeUrlWithQuery(url: string, includeQuery: boolean): string {
  const normalized = normalizeUrl(url)
  if (!includeQuery) {
    return normalized.split('?')[0]
  }
  return normalized
}
```

### Pattern 3: LRU Cache with Invalidation
**What:** Cache redirect lookups with LRU eviction and full invalidation on any change.

**When to use:** For sub-millisecond redirect lookups on cache hits.

**Example:**
```typescript
// Source: tiny-lru npm package
import { lru } from 'tiny-lru'

interface CacheEntry {
  id: string
  destination: string
  statusCode: number
  isActive: boolean
  matchType: number
  preserveQuery: boolean
}

// Create cache with 1000 max entries
const redirectCache = lru<CacheEntry>(1000)

// Pre-warm on startup
async function warmCache(db: D1Database): Promise<void> {
  const { results } = await db
    .prepare(`
      SELECT id, source, destination, status_code, is_active, match_type
      FROM redirects
      WHERE is_active = 1
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
      isActive: row.is_active === 1,
      matchType: row.match_type as number,
      preserveQuery: false // from additional column
    })
  }
}

// Invalidate entire cache on any change
function invalidateCache(): void {
  redirectCache.clear()
}
```

### Pattern 4: Circular Redirect Detection
**What:** Detect cycles (A->B->A) using Set-based visited tracking during redirect chain traversal.

**When to use:** At save time to prevent creation, and at runtime as safety net.

**Example:**
```typescript
// Source: Cycle detection algorithms (visited-set pattern)
interface ValidationResult {
  isValid: boolean
  error?: string
  chainLength?: number
  chainUrls?: string[]
}

export function detectCircularRedirect(
  source: string,
  destination: string,
  existingRedirects: Map<string, string>
): ValidationResult {
  const visited = new Set<string>()
  const chain: string[] = [source]
  let current = destination

  while (current) {
    // Normalize for comparison
    const normalized = normalizeUrl(current)

    // Circular: we've seen this URL before
    if (visited.has(normalized)) {
      return {
        isValid: false,
        error: `Circular redirect detected: ${chain.join(' -> ')} -> ${current}`,
        chainLength: chain.length,
        chainUrls: [...chain, current]
      }
    }

    // Check if this destination has its own redirect
    visited.add(normalized)
    chain.push(current)
    current = existingRedirects.get(normalized) || ''

    // Safety: max hop limit for runtime detection
    if (chain.length > 10) {
      return {
        isValid: false,
        error: `Redirect chain too long (max 10 hops): ${chain.slice(0, 5).join(' -> ')}...`,
        chainLength: chain.length,
        chainUrls: chain
      }
    }
  }

  // Warn if chain >= 3 hops
  if (chain.length >= 3) {
    return {
      isValid: true,
      chainLength: chain.length - 1, // Don't count source
      chainUrls: chain,
      error: `Warning: Redirect chain has ${chain.length - 1} hops`
    }
  }

  return { isValid: true, chainLength: chain.length - 1 }
}
```

### Anti-Patterns to Avoid
- **Query string in cache key without config:** Don't always include query strings in cache keys - this is configurable per redirect
- **Per-entry cache invalidation:** Don't try to invalidate individual entries - clear entire cache on any change for simplicity and consistency
- **Blocking circular detection at runtime:** Don't throw errors at runtime - break the loop with a fallback, log the issue
- **Case-sensitive matching by default:** Don't match URLs case-sensitively - normalize to lowercase first

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| LRU cache eviction | Manual Map management with eviction | tiny-lru | Edge cases: LRU ordering, memory limits, concurrent access |
| HTTP redirect response | Manual Response construction | `c.redirect(url, status)` | Hono handles Location header, correct status codes, caching headers |
| URL encoding/decoding | Custom decodeURIComponent chains | URL API + normalize-url | Edge cases: double encoding, special characters, internationalized URLs |

**Key insight:** The redirect execution itself is trivial (`c.redirect()`), but URL normalization and cache management have subtle edge cases. Use established patterns for normalization; build custom logic only for the redirect-specific business rules.

## Common Pitfalls

### Pitfall 1: Cache Key Mismatch
**What goes wrong:** Redirect doesn't fire because URL wasn't normalized the same way during lookup as during caching.
**Why it happens:** Different normalization applied when saving vs. when matching.
**How to avoid:** Single `normalizeUrl()` function used consistently in both paths.
**Warning signs:** Redirects work for some URLs but not case/slash variations.

### Pitfall 2: Query Parameter Handling Inconsistency
**What goes wrong:** Redirect matches/doesn't match unexpectedly based on query params.
**Why it happens:** Inconsistent handling of whether query params are part of the match.
**How to avoid:** Store `includeQueryParams` flag per redirect, apply during both caching and lookup.
**Warning signs:** Same path with different query strings behaves differently than expected.

### Pitfall 3: 410 Gone Treated as Redirect
**What goes wrong:** 410 responses include Location header or wrong body.
**Why it happens:** Using `c.redirect()` for 410 which sets Location header.
**How to avoid:** Return `new Response(null, { status: 410 })` directly for 410 status.
**Warning signs:** Browsers follow 410 as redirect, or body content appears unexpectedly.

### Pitfall 4: Middleware Registration Order
**What goes wrong:** Redirects fire after auth, or don't fire at all.
**Why it happens:** Middleware registered too late in the pipeline, or route handlers take precedence.
**How to avoid:** Register redirect middleware early (high priority), before route handlers.
**Warning signs:** Authenticated pages not redirected, or 404s instead of redirects.

### Pitfall 5: Runtime Circular Loop
**What goes wrong:** Browser shows "too many redirects" error.
**Why it happens:** Save-time validation missed a case, or redirects modified in ways that create loops.
**How to avoid:** Runtime hop counter (max 5-10 hops), break loop and log error.
**Warning signs:** Infinite redirect response, browser error page.

### Pitfall 6: Cache Not Invalidated
**What goes wrong:** Old redirect rule still fires after update/delete.
**Why it happens:** Forgot to call cache invalidation after database change.
**How to avoid:** Every CRUD operation on redirects table calls `cache.clear()`.
**Warning signs:** Redirects don't update until Worker restart.

## Code Examples

Verified patterns from official sources:

### Hono Redirect with Status Code
```typescript
// Source: https://hono.dev/docs/api/context
// Default is 302 (temporary redirect)
return c.redirect('/new-path')

// Permanent redirect (301)
return c.redirect('/new-path', 301)

// Temporary redirect preserving method (307)
return c.redirect('/new-path', 307)

// Permanent redirect preserving method (308)
return c.redirect('/new-path', 308)
```

### 410 Gone Response
```typescript
// Source: MDN Web Docs - HTTP 410
// 410 is NOT a redirect - return Response directly
return new Response(null, {
  status: 410,
  headers: {
    'Cache-Control': 'public, max-age=31536000' // 410 is cacheable
  }
})

// With optional body
return new Response('This page has been permanently removed.', {
  status: 410,
  headers: { 'Content-Type': 'text/plain' }
})
```

### LRU Cache Usage (tiny-lru)
```typescript
// Source: https://github.com/avoidwork/tiny-lru
import { lru } from 'tiny-lru'

// Create cache with max 1000 entries
const cache = lru(1000)

// Set value
cache.set('key', { value: 'data' })

// Get value (returns undefined if not found or evicted)
const value = cache.get('key')

// Check if exists
const exists = cache.has('key')

// Delete specific key
cache.delete('key')

// Clear entire cache
cache.clear()

// Get current size
const size = cache.size
```

### Database Lookup for Redirect
```typescript
// Source: SonicJS D1 patterns from contact-form plugin
async function lookupRedirect(db: D1Database, normalizedSource: string): Promise<Redirect | null> {
  const result = await db
    .prepare(`
      SELECT id, source, destination, match_type, status_code, is_active,
             include_query_params, preserve_query_params
      FROM redirects
      WHERE LOWER(source) = ? AND is_active = 1
      LIMIT 1
    `)
    .bind(normalizedSource)
    .first()

  if (!result) return null

  return {
    id: result.id as string,
    source: result.source as string,
    destination: result.destination as string,
    matchType: result.match_type as number,
    statusCode: result.status_code as number,
    isActive: result.is_active === 1,
    includeQueryParams: result.include_query_params === 1,
    preserveQueryParams: result.preserve_query_params === 1
  }
}
```

### Hit Count Increment
```typescript
// Source: SonicJS D1 patterns
async function incrementHitCount(db: D1Database, redirectId: string): Promise<void> {
  await db
    .prepare(`
      UPDATE redirect_analytics
      SET hit_count = hit_count + 1,
          last_hit_at = ?,
          updated_at = ?
      WHERE redirect_id = ?
    `)
    .bind(Date.now(), Date.now(), redirectId)
    .run()
}

// Or upsert pattern if analytics row might not exist
async function recordHit(db: D1Database, redirectId: string): Promise<void> {
  await db
    .prepare(`
      INSERT INTO redirect_analytics (id, redirect_id, hit_count, last_hit_at, created_at, updated_at)
      VALUES (?, ?, 1, ?, ?, ?)
      ON CONFLICT(redirect_id) DO UPDATE SET
        hit_count = hit_count + 1,
        last_hit_at = excluded.last_hit_at,
        updated_at = excluded.updated_at
    `)
    .bind(crypto.randomUUID(), redirectId, Date.now(), Date.now(), Date.now())
    .run()
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| 302 for all redirects | Use 307/308 for method preservation | HTTP/1.1 spec clarification | POST requests correctly redirected |
| Global regex matching | LRU cache + exact match fallback | Performance optimization | Sub-millisecond lookups |
| Synchronous cache check | Async with cache-aside pattern | Cloudflare Workers model | Compatible with edge runtime |

**Deprecated/outdated:**
- Using only 301/302: Modern browsers support 307/308 which preserve HTTP method
- Full table scan for redirects: Use indexed lookups + caching for performance
- Storing normalized URL in separate column: Normalize at runtime for consistency

## Open Questions

Things that couldn't be fully resolved:

1. **Query parameter sorting**
   - What we know: Query params can be sorted alphabetically for consistent matching
   - What's unclear: Whether SonicJS needs this level of normalization
   - Recommendation: Start simple (include/exclude query params), add sorting if needed

2. **Cloudflare KV vs. in-memory cache**
   - What we know: KV provides cross-Worker caching, in-memory is faster but Worker-local
   - What's unclear: Whether redirect cache needs to be shared across Workers
   - Recommendation: Use in-memory (tiny-lru) for now; KV adds latency and complexity

3. **Cache warming strategy**
   - What we know: Workers can warm cache on startup, but cold starts are common
   - What's unclear: Optimal batch size and ordering for pre-warming
   - Recommendation: Pre-warm top 1000 redirects by hit count; accept first-request latency for cold cache

4. **Partial/regex match performance**
   - What we know: Exact match is O(1) with hash lookup; regex requires iteration
   - What's unclear: Performance impact of regex matching at scale
   - Recommendation: Phase 2 focuses on exact match; defer partial/regex to Phase 3

## Sources

### Primary (HIGH confidence)
- Hono documentation (https://hono.dev/docs/guides/middleware) - Middleware patterns, early return
- Hono Context API (https://hono.dev/docs/api/context) - `c.redirect()` signature, status codes
- tiny-lru npm package (https://github.com/avoidwork/tiny-lru) - LRU cache API, performance characteristics
- SonicJS codebase (`/packages/core/src/middleware/auth.ts`) - Existing redirect pattern
- SonicJS codebase (`/packages/core/src/app.ts`) - Middleware registration order

### Secondary (MEDIUM confidence)
- normalize-url npm (https://github.com/sindresorhus/normalize-url) - URL normalization patterns
- MDN HTTP 410 (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/410) - 410 response handling
- Cloudflare Workers docs - Memory limits (128MB), caching patterns

### Tertiary (LOW confidence)
- Community patterns for redirect circular detection (based on standard cycle detection algorithms)
- Performance thresholds for "slow" redirects (< 1ms cache hit, < 10ms cache miss - reasonable estimates)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Hono patterns verified in SonicJS codebase, tiny-lru well-documented
- Architecture: HIGH - Middleware pattern proven in auth.ts, cache patterns standard
- Pitfalls: MEDIUM - Based on common redirect implementation issues, not SonicJS-specific verification
- URL normalization: MEDIUM - Standard patterns, but edge cases may emerge in practice

**Research date:** 2026-01-30
**Valid until:** 2026-02-28 (30 days - stable domain, established patterns)
