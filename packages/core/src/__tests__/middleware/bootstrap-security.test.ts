import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { verifySecurityConfig, isBetterAuthSessionPath } from '../../middleware/bootstrap'

describe('verifySecurityConfig', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('should not warn when all config is properly set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-random-secret-value-here',
      CORS_ORIGINS: 'https://mysite.com',
      ENVIRONMENT: 'production',
    })

    expect(warnSpy).not.toHaveBeenCalled()
  })

  it('should warn when JWT_SECRET is not set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      CORS_ORIGINS: 'http://localhost:8787',
      ENVIRONMENT: 'development',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('JWT_SECRET is not set')
    )
  })

  it('should warn when JWT_SECRET contains the default value', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'your-super-secret-jwt-key-change-in-production',
      CORS_ORIGINS: 'http://localhost:8787',
      ENVIRONMENT: 'development',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('JWT_SECRET contains the default value')
    )
  })

  it('should warn when CORS_ORIGINS is not set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-secret',
      ENVIRONMENT: 'development',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('CORS_ORIGINS is not set')
    )
  })

  it('should warn when ENVIRONMENT is not set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-secret',
      CORS_ORIGINS: 'http://localhost:8787',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('ENVIRONMENT is not set')
    )
  })

  it('should log multiple warnings when multiple items are missing', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
    })

    expect(warnSpy).toHaveBeenCalledTimes(3)
  })

  it('should throw in production when JWT_SECRET is not set', () => {
    expect(() => {
      verifySecurityConfig({
        DB: {} as D1Database,
        KV: {} as KVNamespace,
        CORS_ORIGINS: 'https://mysite.com',
        ENVIRONMENT: 'production',
      })
    }).toThrow('[SonicJS Security] CRITICAL')
  })

  it('should throw in production when JWT_SECRET is the default value', () => {
    expect(() => {
      verifySecurityConfig({
        DB: {} as D1Database,
        KV: {} as KVNamespace,
        JWT_SECRET: 'your-super-secret-jwt-key-change-in-production',
        CORS_ORIGINS: 'https://mysite.com',
        ENVIRONMENT: 'production',
      })
    }).toThrow('[SonicJS Security] CRITICAL')
  })

  it('should NOT throw in production when JWT_SECRET is properly set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-random-secret-value',
      ENVIRONMENT: 'production',
    })

    // Should warn about CORS_ORIGINS but not throw
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('CORS_ORIGINS is not set')
    )
  })

  it('should NOT throw in development even when JWT_SECRET is missing', () => {
    expect(() => {
      verifySecurityConfig({
        DB: {} as D1Database,
        KV: {} as KVNamespace,
        ENVIRONMENT: 'development',
      })
    }).not.toThrow()

    // Should still warn
    expect(warnSpy).toHaveBeenCalled()
  })
})

// The heavy cold-start bootstrap must not run on Better Auth's stateless session
// API — on a cold Cloudflare isolate the ~10s D1 bootstrap otherwise shares the
// request's CPU/time budget with scrypt password verification and returns a bare
// 500 (observed in CI as intermittent `BA sign-in failed: 500`). These endpoints
// only touch auth_* migration tables, so skipping bootstrap for them is safe.
describe('isBetterAuthSessionPath', () => {
  it('matches the sign-in path that 500s on cold start', () => {
    expect(isBetterAuthSessionPath('/auth/sign-in/email')).toBe(true)
  })

  it('matches every stateless Better Auth session endpoint', () => {
    const skipped = [
      '/auth/sign-in',
      '/auth/sign-in/email',
      '/auth/sign-up/email',
      '/auth/sign-out',
      '/auth/get-session',
      '/auth/callback/github',
      '/auth/token',
    ]
    for (const p of skipped) {
      expect(isBetterAuthSessionPath(p)).toBe(true)
    }
  })

  it('does NOT skip the login page render or the self-seeding endpoints', () => {
    // /auth/login is an HTML page; /auth/seed-admin seeds its own prerequisites;
    // neither is a hot cold-start path, and both still get the full bootstrap.
    const notSkipped = [
      '/auth/login',
      '/auth/login/form',
      '/auth/register',
      '/auth/seed-admin',
      '/auth/accept-invitation',
      '/admin',
      '/admin/content',
      '/',
    ]
    for (const p of notSkipped) {
      expect(isBetterAuthSessionPath(p)).toBe(false)
    }
  })

  it('does not match a substring collision like /auth/sign-in-history', () => {
    // Only exact segment or `/auth/<seg>/...` — not arbitrary prefixes.
    expect(isBetterAuthSessionPath('/auth/sign-in-history')).toBe(false)
  })
})
