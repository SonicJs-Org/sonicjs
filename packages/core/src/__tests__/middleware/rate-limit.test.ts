import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Context, Next } from 'hono'
import { rateLimit } from '../../middleware/rate-limit'

describe('rateLimit middleware', () => {
  let mockNext: Next
  let mockKv: any

  beforeEach(() => {
    mockNext = vi.fn()
    mockKv = {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
    }
  })

  function createMockContext(overrides: {
    ip?: string
    kv?: any | null
  } = {}): any {
    const headers: Record<string, string> = {}
    return {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'cf-connecting-ip') return overrides.ip ?? '1.2.3.4'
          return undefined
        }),
      },
      env: {
        CACHE_KV: overrides.kv === null ? undefined : (overrides.kv ?? mockKv),
      },
      header: vi.fn().mockImplementation((key: string, value: string) => {
        headers[key] = value
      }),
      json: vi.fn().mockImplementation((body: any, status?: number) => ({ body, status })),
      _headers: headers,
    }
  }

  describe('when KV binding is not available', () => {
    it('should skip rate limiting and call next', async () => {
      const ctx = createMockContext({ kv: null })
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'test' })

      await middleware(ctx as Context, mockNext)

      expect(mockNext).toHaveBeenCalled()
      expect(ctx.json).not.toHaveBeenCalled()
    })
  })

  describe('when under the rate limit', () => {
    it('should allow the request and call next', async () => {
      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockNext).toHaveBeenCalled()
      expect(ctx.json).not.toHaveBeenCalled()
    })

    it('should set rate limit headers', async () => {
      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith('X-RateLimit-Limit', '5')
      expect(ctx.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '4')
      expect(ctx.header).toHaveBeenCalledWith(
        'X-RateLimit-Reset',
        expect.any(String)
      )
    })

    it('should store entry in KV with TTL', async () => {
      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockKv.put).toHaveBeenCalledWith(
        'ratelimit:login:1.2.3.4',
        expect.any(String),
        expect.objectContaining({ expirationTtl: expect.any(Number) })
      )
    })

    it('should decrement remaining count for subsequent requests', async () => {
      const now = Date.now()
      mockKv.get.mockResolvedValue({ count: 3, resetAt: now + 30000 })

      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockNext).toHaveBeenCalled()
      // count goes from 3 to 4, so remaining = 5 - 4 = 1
      expect(ctx.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '1')
    })
  })

  describe('when rate limit is exceeded', () => {
    it('should return 429 Too Many Requests', async () => {
      const now = Date.now()
      mockKv.get.mockResolvedValue({ count: 5, resetAt: now + 30000 })

      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(ctx.json).toHaveBeenCalledWith(
        { error: 'Too many requests. Please try again later.' },
        429
      )
    })

    it('should set Retry-After header', async () => {
      const now = Date.now()
      mockKv.get.mockResolvedValue({ count: 5, resetAt: now + 30000 })

      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith('Retry-After', expect.any(String))
      expect(ctx.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '0')
    })

    it('should still store the updated count in KV', async () => {
      const now = Date.now()
      mockKv.get.mockResolvedValue({ count: 5, resetAt: now + 30000 })

      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockKv.put).toHaveBeenCalled()
      const storedEntry = JSON.parse(mockKv.put.mock.calls[0][1])
      expect(storedEntry.count).toBe(6)
    })
  })

  describe('window expiration', () => {
    it('should reset count when window has expired', async () => {
      const pastTime = Date.now() - 10000
      mockKv.get.mockResolvedValue({ count: 100, resetAt: pastTime })

      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      // Window expired, so count resets to 1 (new window)
      expect(mockNext).toHaveBeenCalled()
      expect(ctx.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '4')
    })
  })

  describe('IP address extraction', () => {
    it('should use cf-connecting-ip header', async () => {
      const ctx = createMockContext({ ip: '10.0.0.1' })
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockKv.put).toHaveBeenCalledWith(
        'ratelimit:login:10.0.0.1',
        expect.any(String),
        expect.any(Object)
      )
    })

    it('should fall back to x-forwarded-for', async () => {
      const ctx = createMockContext()
      ctx.req.header = vi.fn().mockImplementation((name: string) => {
        if (name === 'x-forwarded-for') return '192.168.1.1'
        return undefined
      })

      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })
      await middleware(ctx as Context, mockNext)

      expect(mockKv.put).toHaveBeenCalledWith(
        'ratelimit:login:192.168.1.1',
        expect.any(String),
        expect.any(Object)
      )
    })

    it('should fall back to "unknown" when no IP headers present', async () => {
      const ctx = createMockContext()
      ctx.req.header = vi.fn().mockReturnValue(undefined)

      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })
      await middleware(ctx as Context, mockNext)

      expect(mockKv.put).toHaveBeenCalledWith(
        'ratelimit:login:unknown',
        expect.any(String),
        expect.any(Object)
      )
    })
  })

  describe('key prefix isolation', () => {
    it('should use different KV keys for different prefixes', async () => {
      const ctx1 = createMockContext()
      const ctx2 = createMockContext()

      const loginLimiter = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })
      const registerLimiter = rateLimit({ max: 3, windowMs: 60000, keyPrefix: 'register' })

      await loginLimiter(ctx1 as Context, mockNext)
      await registerLimiter(ctx2 as Context, mockNext)

      const keys = mockKv.put.mock.calls.map((c: any[]) => c[0])
      expect(keys).toContain('ratelimit:login:1.2.3.4')
      expect(keys).toContain('ratelimit:register:1.2.3.4')
    })
  })

  describe('error handling', () => {
    it('should gracefully continue on KV get error', async () => {
      mockKv.get.mockRejectedValue(new Error('KV unavailable'))

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockNext).toHaveBeenCalled()
      expect(consoleSpy).toHaveBeenCalledWith(
        'Rate limiter error (non-fatal):',
        expect.any(Error)
      )
      consoleSpy.mockRestore()
    })

    it('should gracefully continue on KV put error', async () => {
      mockKv.put.mockRejectedValue(new Error('KV write failed'))

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const ctx = createMockContext()
      const middleware = rateLimit({ max: 5, windowMs: 60000, keyPrefix: 'login' })

      await middleware(ctx as Context, mockNext)

      expect(mockNext).toHaveBeenCalled()
      consoleSpy.mockRestore()
    })
  })
})
