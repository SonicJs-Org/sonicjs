import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Context, Next } from 'hono'
import { securityHeadersMiddleware } from '../../middleware/security-headers'

describe('securityHeadersMiddleware', () => {
  let mockNext: Next
  let headers: Record<string, string>

  function createMockContext(env: Record<string, any> = {}): any {
    headers = {}
    return {
      env,
      header: vi.fn().mockImplementation((key: string, value: string) => {
        headers[key] = value
      }),
    }
  }

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should call next before setting headers', async () => {
    const ctx = createMockContext()
    const middleware = securityHeadersMiddleware()

    let nextCalledBeforeHeaders = false
    ;(mockNext as any).mockImplementation(() => {
      // At this point, no headers should be set yet
      nextCalledBeforeHeaders = Object.keys(headers).length === 0
    })

    await middleware(ctx as Context, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect(nextCalledBeforeHeaders).toBe(true)
  })

  describe('standard security headers', () => {
    it('should set X-Content-Type-Options to nosniff', async () => {
      const ctx = createMockContext()
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff')
    })

    it('should set X-Frame-Options to SAMEORIGIN', async () => {
      const ctx = createMockContext()
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith('X-Frame-Options', 'SAMEORIGIN')
    })

    it('should set Referrer-Policy to strict-origin-when-cross-origin', async () => {
      const ctx = createMockContext()
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith(
        'Referrer-Policy',
        'strict-origin-when-cross-origin'
      )
    })

    it('should set Permissions-Policy to restrict camera, microphone, and geolocation', async () => {
      const ctx = createMockContext()
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=()'
      )
    })
  })

  describe('HSTS (Strict-Transport-Security)', () => {
    it('should set HSTS when ENVIRONMENT is not set', async () => {
      const ctx = createMockContext({})
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains'
      )
    })

    it('should set HSTS when ENVIRONMENT is "production"', async () => {
      const ctx = createMockContext({ ENVIRONMENT: 'production' })
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains'
      )
    })

    it('should NOT set HSTS when ENVIRONMENT is "development"', async () => {
      const ctx = createMockContext({ ENVIRONMENT: 'development' })
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      const hstsCall = (ctx.header as any).mock.calls.find(
        (call: any[]) => call[0] === 'Strict-Transport-Security'
      )
      expect(hstsCall).toBeUndefined()
    })

    it('should set HSTS for staging environment', async () => {
      const ctx = createMockContext({ ENVIRONMENT: 'staging' })
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains'
      )
    })
  })

  describe('all headers together', () => {
    it('should set exactly 5 headers in production', async () => {
      const ctx = createMockContext({ ENVIRONMENT: 'production' })
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledTimes(5)
    })

    it('should set exactly 4 headers in development (no HSTS)', async () => {
      const ctx = createMockContext({ ENVIRONMENT: 'development' })
      const middleware = securityHeadersMiddleware()

      await middleware(ctx as Context, mockNext)

      expect(ctx.header).toHaveBeenCalledTimes(4)
    })
  })
})
