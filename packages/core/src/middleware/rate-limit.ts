import { Context, Next } from 'hono'

interface RateLimitOptions {
  max: number
  windowMs: number
  keyPrefix: string
}

interface RateLimitEntry {
  count: number
  resetAt: number
}

/**
 * The address this request is bucketed under.
 *
 * `cf-connecting-ip` is written by Cloudflare's edge and overwrites anything the client sent, so
 * it is authoritative and used whenever present. `x-forwarded-for` is not: it is a comma-separated
 * trail where each proxy *appends* the peer it accepted from, and the client controls everything
 * to the left of the first hop your own infrastructure added. Taking the header verbatim therefore
 * handed any caller on a non-Cloudflare deployment an unlimited bypass — prepend a fresh value per
 * request and every attempt lands in its own bucket, and even benign traffic split
 * `"1.2.3.4, 5.6.7.8"` from `"1.2.3.4"` into two counters for the same client.
 *
 * So take the RIGHTMOST hop: the one appended by the proxy nearest this worker, the only entry a
 * remote caller cannot forge. Behind several proxies that over-aggregates (everyone sharing the
 * last hop shares a bucket), which for a brute-force limiter is the safe direction to be wrong in.
 */
export function rateLimitClientKey(c: Context): string {
  const cf = c.req.header('cf-connecting-ip')?.trim()
  if (cf) return cf

  const forwarded = c.req.header('x-forwarded-for')
  if (forwarded) {
    const hops = forwarded.split(',').map((h) => h.trim()).filter(Boolean)
    const nearest = hops[hops.length - 1]
    if (nearest) return nearest
  }

  return 'unknown'
}

/**
 * KV-based sliding window rate limiter middleware.
 * Gracefully skips if CACHE_KV binding is not available.
 */
export function rateLimit(options: RateLimitOptions) {
  const { max, windowMs, keyPrefix } = options

  return async (c: Context, next: Next) => {
    const kv = (c.env as any)?.CACHE_KV
    if (!kv) {
      // No KV binding available — skip rate limiting
      return await next()
    }

    const ip = rateLimitClientKey(c)
    const key = `ratelimit:${keyPrefix}:${ip}`

    try {
      const now = Date.now()
      const stored = await kv.get(key, 'json') as RateLimitEntry | null

      let entry: RateLimitEntry
      if (stored && stored.resetAt > now) {
        entry = stored
      } else {
        entry = { count: 0, resetAt: now + windowMs }
      }

      entry.count++

      // Calculate TTL in seconds (KV expiration)
      const ttlSeconds = Math.ceil((entry.resetAt - now) / 1000)

      if (entry.count > max) {
        // Store the updated count even when rejecting
        await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.max(ttlSeconds, 60) })

        const retryAfter = Math.ceil((entry.resetAt - now) / 1000)
        c.header('Retry-After', String(retryAfter))
        c.header('X-RateLimit-Limit', String(max))
        c.header('X-RateLimit-Remaining', '0')
        c.header('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)))
        return c.json({ error: 'Too many requests. Please try again later.' }, 429)
      }

      await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.max(ttlSeconds, 60) })

      c.header('X-RateLimit-Limit', String(max))
      c.header('X-RateLimit-Remaining', String(max - entry.count))
      c.header('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)))

      return await next()
    } catch (error) {
      // Rate limiting should never break the app
      console.error('Rate limiter error (non-fatal):', error)
      return await next()
    }
  }
}
