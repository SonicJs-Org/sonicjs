/**
 * API System Routes Tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { apiSystemRoutes } from './api-system'
import { getCollectionRegistry, resetCollectionRegistry } from '../services/collection-registry'

// Mock environment bindings
function createMockEnv(overrides: Partial<{
  DB: any
  CACHE_KV: any
  MEDIA_BUCKET: any
  ENVIRONMENT: string
  EMAIL_QUEUE: any
  SENDGRID_API_KEY: string
  IMAGES_ACCOUNT_ID: string
  IMAGES_API_TOKEN: string
}> = {}) {
  return {
    DB: {
      prepare: vi.fn().mockReturnValue({
        first: vi.fn().mockResolvedValue({ '1': 1 }),
        all: vi.fn().mockResolvedValue({ results: [] }),
        bind: vi.fn().mockReturnThis()
      })
    },
    ENVIRONMENT: 'test',
    ...overrides
  }
}

// Create test app with mock environment
function createTestApp(env: any = createMockEnv()) {
  const app = new Hono()

  // Add middleware to set env
  app.use('*', async (c, next) => {
    c.env = env
    c.set('appVersion', '2.0.0')
    await next()
  })

  // Mount routes
  app.route('/api/system', apiSystemRoutes)

  return app
}

describe('API System Routes', () => {
  describe('GET /api/system/health', () => {
    it('should return healthy status when database is available', async () => {
      const env = createMockEnv()
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.status).toBe('healthy')
      expect(json.checks.database.status).toBe('healthy')
      expect(json.timestamp).toBeDefined()
    })

    it('should return degraded status when database fails', async () => {
      const env = createMockEnv({
        DB: {
          prepare: vi.fn().mockReturnValue({
            first: vi.fn().mockRejectedValue(new Error('DB Error'))
          })
        }
      })
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.status).toBe('degraded')
      expect(json.checks.database.status).toBe('unhealthy')
      consoleSpy.mockRestore()
    })

    it('should check KV when available', async () => {
      const env = createMockEnv({
        CACHE_KV: {
          get: vi.fn().mockResolvedValue(null)
        }
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(json.checks.cache.status).toBe('healthy')
      expect(json.checks.cache.latency).toBeGreaterThanOrEqual(0)
    })

    it('should report KV as not_configured when unavailable', async () => {
      const env = createMockEnv()
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(json.checks.cache.status).toBe('not_configured')
    })

    it('should check R2 when available', async () => {
      const env = createMockEnv({
        MEDIA_BUCKET: {
          head: vi.fn().mockResolvedValue(null)
        }
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(json.checks.storage.status).toBe('healthy')
    })

    it('should report R2 as not_configured when unavailable', async () => {
      const env = createMockEnv()
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(json.checks.storage.status).toBe('not_configured')
    })

    it('should handle errors during health check gracefully', async () => {
      // When DB.prepare throws, the inner try-catch catches it
      // and returns degraded status (200), not unhealthy (503)
      const env = createMockEnv({
        DB: {
          prepare: vi.fn().mockImplementation(() => {
            throw new Error('Fatal error')
          })
        }
      })
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      // The inner try-catch catches DB errors and returns degraded status
      expect(res.status).toBe(200)
      expect(json.status).toBe('degraded')
      expect(json.checks.database.status).toBe('unhealthy')
      consoleSpy.mockRestore()
    })

    it('should handle KV health check failure', async () => {
      const env = createMockEnv({
        CACHE_KV: {
          get: vi.fn().mockRejectedValue(new Error('KV Error'))
        }
      })
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const app = createTestApp(env)

      const res = await app.request('/api/system/health')
      const json = await res.json()

      expect(json.checks.cache.status).toBe('unhealthy')
      consoleSpy.mockRestore()
    })
  })

  describe('GET /api/system/info', () => {
    it('should return system information', async () => {
      const app = createTestApp()

      const res = await app.request('/api/system/info')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.name).toBe('SonicJS')
      expect(json.version).toBe('2.0.0')
      expect(json.description).toBeDefined()
      expect(json.endpoints).toBeDefined()
      expect(json.endpoints.api).toBe('/api')
      expect(json.endpoints.auth).toBe('/auth')
      expect(json.features).toBeDefined()
    })

    it('should show features based on available bindings', async () => {
      const env = createMockEnv({
        CACHE_KV: {},
        MEDIA_BUCKET: {}
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/info')
      const json = await res.json()

      expect(json.features.caching).toBe(true)
      expect(json.features.storage).toBe(true)
    })

    it('should show disabled features when bindings unavailable', async () => {
      const env = createMockEnv()
      const app = createTestApp(env)

      const res = await app.request('/api/system/info')
      const json = await res.json()

      expect(json.features.caching).toBe(false)
      expect(json.features.storage).toBe(false)
    })
  })

  describe('GET /api/system/stats', () => {
    afterEach(() => {
      resetCollectionRegistry()
    })

    it('should return system statistics', async () => {
      // Stats counts content from `documents` filtered by the registry's active,
      // non-internal collection type_ids — register one so the content query runs.
      getCollectionRegistry().register([
        { name: 'posts', displayName: 'Posts', schema: {} } as any,
      ])
      const env = createMockEnv({
        DB: {
          prepare: vi.fn().mockReturnValue({
            bind: vi.fn().mockReturnThis(),
            first: vi.fn()
              .mockResolvedValueOnce({ total_content: 100 })
              .mockResolvedValueOnce({ total_files: 50, total_size: 1024 * 1024 * 10 })
              .mockResolvedValueOnce({ total_users: 5 })
          })
        }
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/stats')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.content.total).toBe(100)
      expect(json.media.total_files).toBe(50)
      expect(json.media.total_size_bytes).toBe(1024 * 1024 * 10)
      expect(json.users.total).toBe(5)
      expect(json.timestamp).toBeDefined()
    })

    it('should handle null statistics gracefully', async () => {
      const env = createMockEnv({
        DB: {
          prepare: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(null)
          })
        }
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/stats')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.content.total).toBe(0)
      expect(json.media.total_files).toBe(0)
      expect(json.media.total_size_bytes).toBe(0)
      expect(json.users.total).toBe(0)
    })

    it('should return 500 on database error', async () => {
      const env = createMockEnv({
        DB: {
          prepare: vi.fn().mockReturnValue({
            first: vi.fn().mockRejectedValue(new Error('DB Error'))
          })
        }
      })
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const app = createTestApp(env)

      const res = await app.request('/api/system/stats')
      const json = await res.json()

      expect(res.status).toBe(500)
      expect(json.error).toBe('Failed to fetch system statistics')
      consoleSpy.mockRestore()
    })
  })

  describe('GET /api/system/ping', () => {
    it('should return pong with latency', async () => {
      const app = createTestApp()

      const res = await app.request('/api/system/ping')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.pong).toBe(true)
      expect(typeof json.latency).toBe('number')
      expect(json.timestamp).toBeDefined()
    })

    it('should return 503 on database failure', async () => {
      const env = createMockEnv({
        DB: {
          prepare: vi.fn().mockReturnValue({
            first: vi.fn().mockRejectedValue(new Error('Connection failed'))
          })
        }
      })
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const app = createTestApp(env)

      const res = await app.request('/api/system/ping')
      const json = await res.json()

      expect(res.status).toBe(503)
      expect(json.pong).toBe(false)
      expect(json.error).toBe('Database connection failed')
      consoleSpy.mockRestore()
    })
  })

  describe('GET /api/system/env', () => {
    it('should return environment information', async () => {
      const env = createMockEnv({
        ENVIRONMENT: 'production',
        DB: {},
        CACHE_KV: {},
        MEDIA_BUCKET: {},
        EMAIL_QUEUE: {},
        SENDGRID_API_KEY: 'key',
        IMAGES_ACCOUNT_ID: 'account',
        IMAGES_API_TOKEN: 'token'
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/env')
      const json = await res.json()

      expect(res.status).toBe(200)
      expect(json.environment).toBe('production')
      expect(json.features.database).toBe(true)
      expect(json.features.cache).toBe(true)
      expect(json.features.media_bucket).toBe(true)
      expect(json.features.email_queue).toBe(true)
      expect(json.features.sendgrid).toBe(true)
      expect(json.features.cloudflare_images).toBe(true)
    })

    it('should default environment to production', async () => {
      const env = createMockEnv()
      delete env.ENVIRONMENT
      const app = createTestApp(env)

      const res = await app.request('/api/system/env')
      const json = await res.json()

      expect(json.environment).toBe('production')
    })

    it('should show false for missing features', async () => {
      const env = createMockEnv()
      const app = createTestApp(env)

      const res = await app.request('/api/system/env')
      const json = await res.json()

      expect(json.features.cache).toBe(false)
      expect(json.features.media_bucket).toBe(false)
      expect(json.features.email_queue).toBe(false)
      expect(json.features.sendgrid).toBe(false)
      expect(json.features.cloudflare_images).toBe(false)
    })

    it('should require both IMAGES_ACCOUNT_ID and IMAGES_API_TOKEN for cloudflare_images', async () => {
      const env = createMockEnv({
        IMAGES_ACCOUNT_ID: 'account'
        // Missing IMAGES_API_TOKEN
      })
      const app = createTestApp(env)

      const res = await app.request('/api/system/env')
      const json = await res.json()

      expect(json.features.cloudflare_images).toBe(false)
    })
  })
})
