import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import { cors } from 'hono/cors'

/**
 * Tests for the CORS origin allowlist implementation.
 *
 * The CORS middleware is configured inline in routes/api.ts using hono/cors.
 * We recreate the same origin callback logic here to test it in isolation.
 */

// Replicate the exact origin callback from routes/api.ts
function createCorsOriginCallback() {
  return (origin: string, c: any): string | null => {
    const allowed = (c.env as any)?.CORS_ORIGINS as string | undefined
    if (!allowed) return null
    const list = allowed.split(',').map((s: string) => s.trim())
    return list.includes(origin) ? origin : null
  }
}

describe('CORS origin allowlist', () => {
  function createApp(corsOrigins?: string) {
    const app = new Hono<{ Bindings: { CORS_ORIGINS?: string } }>()

    app.use(
      '*',
      cors({
        origin: createCorsOriginCallback(),
        allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
      })
    )

    app.get('/api/test', (c) => c.json({ ok: true }))

    return app
  }

  describe('when CORS_ORIGINS is not set', () => {
    it('should not include Access-Control-Allow-Origin header', async () => {
      const app = createApp()
      const res = await app.request('/api/test', {
        headers: { Origin: 'https://evil.com' },
      })

      expect(res.status).toBe(200)
      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull()
    })

    it('should reject preflight requests from any origin', async () => {
      const app = createApp()
      const res = await app.request('/api/test', {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://evil.com',
          'Access-Control-Request-Method': 'POST',
        },
      })

      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull()
    })
  })

  describe('when CORS_ORIGINS is set to a single origin', () => {
    const ORIGINS = 'https://myapp.com'

    it('should allow requests from the configured origin', async () => {
      const app = createApp(ORIGINS)
      const res = await app.request(
        '/api/test',
        { headers: { Origin: 'https://myapp.com' } },
        { CORS_ORIGINS: ORIGINS }
      )

      expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://myapp.com'
      )
    })

    it('should reject requests from a non-configured origin', async () => {
      const app = createApp(ORIGINS)
      const res = await app.request(
        '/api/test',
        { headers: { Origin: 'https://evil.com' } },
        { CORS_ORIGINS: ORIGINS }
      )

      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull()
    })
  })

  describe('when CORS_ORIGINS is set to multiple origins', () => {
    const ORIGINS = 'https://app1.com, https://app2.com, http://localhost:8787'

    it('should allow requests from any listed origin', async () => {
      const app = createApp(ORIGINS)

      const res1 = await app.request(
        '/api/test',
        { headers: { Origin: 'https://app1.com' } },
        { CORS_ORIGINS: ORIGINS }
      )
      expect(res1.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://app1.com'
      )

      const res2 = await app.request(
        '/api/test',
        { headers: { Origin: 'https://app2.com' } },
        { CORS_ORIGINS: ORIGINS }
      )
      expect(res2.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://app2.com'
      )

      const res3 = await app.request(
        '/api/test',
        { headers: { Origin: 'http://localhost:8787' } },
        { CORS_ORIGINS: ORIGINS }
      )
      expect(res3.headers.get('Access-Control-Allow-Origin')).toBe(
        'http://localhost:8787'
      )
    })

    it('should reject requests from unlisted origins', async () => {
      const app = createApp(ORIGINS)
      const res = await app.request(
        '/api/test',
        { headers: { Origin: 'https://evil.com' } },
        { CORS_ORIGINS: ORIGINS }
      )

      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull()
    })
  })

  describe('preflight requests', () => {
    const ORIGINS = 'https://myapp.com'

    it('should handle OPTIONS preflight for allowed origin', async () => {
      const app = createApp(ORIGINS)
      const res = await app.request(
        '/api/test',
        {
          method: 'OPTIONS',
          headers: {
            Origin: 'https://myapp.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type',
          },
        },
        { CORS_ORIGINS: ORIGINS }
      )

      expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://myapp.com'
      )
      expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST')
    })

    it('should include X-API-Key in allowed headers', async () => {
      const app = createApp(ORIGINS)
      const res = await app.request(
        '/api/test',
        {
          method: 'OPTIONS',
          headers: {
            Origin: 'https://myapp.com',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'X-API-Key',
          },
        },
        { CORS_ORIGINS: ORIGINS }
      )

      expect(res.headers.get('Access-Control-Allow-Headers')).toContain(
        'X-API-Key'
      )
    })
  })

  describe('allowed methods', () => {
    const ORIGINS = 'https://myapp.com'

    it('should allow GET, POST, PUT, DELETE, OPTIONS methods', async () => {
      const app = createApp(ORIGINS)
      const res = await app.request(
        '/api/test',
        {
          method: 'OPTIONS',
          headers: {
            Origin: 'https://myapp.com',
            'Access-Control-Request-Method': 'DELETE',
          },
        },
        { CORS_ORIGINS: ORIGINS }
      )

      const allowedMethods = res.headers.get('Access-Control-Allow-Methods')
      expect(allowedMethods).toContain('GET')
      expect(allowedMethods).toContain('POST')
      expect(allowedMethods).toContain('PUT')
      expect(allowedMethods).toContain('DELETE')
      expect(allowedMethods).toContain('OPTIONS')
    })
  })

  describe('same-origin requests', () => {
    it('should work normally without Origin header (same-origin)', async () => {
      const app = createApp('https://myapp.com')
      const res = await app.request('/api/test', {}, { CORS_ORIGINS: 'https://myapp.com' })

      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body).toEqual({ ok: true })
    })
  })
})
