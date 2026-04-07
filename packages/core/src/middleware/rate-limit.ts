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

    const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown'
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
