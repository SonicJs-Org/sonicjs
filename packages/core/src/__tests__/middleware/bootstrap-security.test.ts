import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { verifySecurityConfig } from '../../middleware/bootstrap'

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
