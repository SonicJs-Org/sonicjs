/**
 * Bootstrap Middleware Tests
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { Hono } from 'hono'
import { bootstrapMiddleware, resetBootstrap } from './bootstrap'

// Mock the services that bootstrap depends on
vi.mock('../services/collection-sync', () => ({
  syncCollections: vi.fn().mockResolvedValue([])
}))

vi.mock('../services/migrations', () => {
  const mockEnsureSchemaCompatibility = vi.fn().mockResolvedValue(undefined)
  return {
    MigrationService: vi.fn().mockImplementation(function() {
      this.ensureSchemaCompatibility = mockEnsureSchemaCompatibility
      return this
    })
  }
})

vi.mock('../services/plugin-bootstrap', () => {
  const mockIsBootstrapNeeded = vi.fn().mockResolvedValue(true)
  const mockBootstrapCorePlugins = vi.fn().mockResolvedValue(undefined)
  return {
    PluginBootstrapService: vi.fn().mockImplementation(function() {
      this.isBootstrapNeeded = mockIsBootstrapNeeded
      this.bootstrapCorePlugins = mockBootstrapCorePlugins
      return this
    })
  }
})

// Import the mocked modules after mocking
import { syncCollections } from '../services/collection-sync'
import { MigrationService } from '../services/migrations'
import { PluginBootstrapService } from '../services/plugin-bootstrap'

// Create mock environment
function createMockEnv() {
  return {
    DB: {
      prepare: vi.fn().mockReturnValue({
        first: vi.fn().mockResolvedValue(null),
        all: vi.fn().mockResolvedValue({ results: [] }),
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      })
    },
    KV: {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined)
    }
  }
}

describe('bootstrapMiddleware', () => {
  let consoleSpy: any
  let errorSpy: any

  beforeEach(() => {
    // Reset bootstrap state before each test
    resetBootstrap()
    vi.clearAllMocks()
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    consoleSpy.mockRestore()
    errorSpy.mockRestore()
  })

  it('should run bootstrap on first request', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test')

    expect(res.status).toBe(200)
    expect(consoleSpy).toHaveBeenCalledWith('[Bootstrap] Starting system initialization...')
    expect(consoleSpy).toHaveBeenCalledWith('[Bootstrap] System initialization completed')
    expect(MigrationService).toHaveBeenCalled()
    expect(syncCollections).toHaveBeenCalled()
    expect(PluginBootstrapService).toHaveBeenCalled()
  })

  it('should skip bootstrap on subsequent requests', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/test', (c) => c.json({ ok: true }))

    // First request - runs bootstrap
    await app.request('/test')
    vi.clearAllMocks()

    // Second request - should skip bootstrap
    const res = await app.request('/test')

    expect(res.status).toBe(200)
    expect(consoleSpy).not.toHaveBeenCalledWith('[Bootstrap] Starting system initialization...')
    expect(MigrationService).not.toHaveBeenCalled()
  })

  it('should skip bootstrap for static assets', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/images/test.png', (c) => c.json({ ok: true }))
    app.get('/assets/style.css', (c) => c.json({ ok: true }))

    await app.request('/images/test.png')
    expect(MigrationService).not.toHaveBeenCalled()

    await app.request('/assets/style.css')
    expect(MigrationService).not.toHaveBeenCalled()
  })

  it('should skip bootstrap for health check', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/health', (c) => c.json({ ok: true }))

    await app.request('/health')
    expect(MigrationService).not.toHaveBeenCalled()
  })

  it('should skip bootstrap for .js files', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/script.js', (c) => c.text('console.log("test")'))

    await app.request('/script.js')
    expect(MigrationService).not.toHaveBeenCalled()
  })

  it('should skip bootstrap for .css files', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/style.css', (c) => c.text('body {}'))

    await app.request('/style.css')
    expect(MigrationService).not.toHaveBeenCalled()
  })

  it('should skip bootstrap for .ico files', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/favicon.ico', (c) => c.text(''))

    await app.request('/favicon.ico')
    expect(MigrationService).not.toHaveBeenCalled()
  })

  it('should continue even if collection sync fails', async () => {
    const app = new Hono()
    const env = createMockEnv()
    vi.mocked(syncCollections).mockRejectedValueOnce(new Error('Sync failed'))

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test')

    expect(res.status).toBe(200)
    expect(errorSpy).toHaveBeenCalledWith('[Bootstrap] Error syncing collections:', expect.any(Error))
    expect(consoleSpy).toHaveBeenCalledWith('[Bootstrap] System initialization completed')
  })

  it('should skip plugin bootstrap when disableAll is true', async () => {
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware({ plugins: { disableAll: true } }))
    app.get('/test', (c) => c.json({ ok: true }))

    await app.request('/test')

    expect(PluginBootstrapService).not.toHaveBeenCalled()
    expect(consoleSpy).toHaveBeenCalledWith('[Bootstrap] Plugin bootstrap skipped (disableAll is true)')
  })

  it('should continue on fatal bootstrap error', async () => {
    const app = new Hono()
    const env = createMockEnv()

    // Make MigrationService constructor throw
    vi.mocked(MigrationService).mockImplementationOnce(() => {
      throw new Error('Fatal error')
    })

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/test', (c) => c.json({ ok: true }))

    const res = await app.request('/test')

    // Should still return 200 - app continues despite bootstrap error
    expect(res.status).toBe(200)
    expect(errorSpy).toHaveBeenCalledWith('[Bootstrap] Error during system initialization:', expect.any(Error))
  })
})

describe('resetBootstrap', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    resetBootstrap()
  })

  it('should allow bootstrap to run again after reset', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const app = new Hono()
    const env = createMockEnv()

    app.use('*', async (c, next) => {
      c.env = env as any
      await next()
    })
    app.use('*', bootstrapMiddleware())
    app.get('/test', (c) => c.json({ ok: true }))

    // First request - runs bootstrap
    await app.request('/test')
    expect(MigrationService).toHaveBeenCalledTimes(1)

    // Reset bootstrap
    resetBootstrap()
    vi.clearAllMocks()

    // Second request after reset - should run bootstrap again
    await app.request('/test')
    expect(MigrationService).toHaveBeenCalledTimes(1)

    consoleSpy.mockRestore()
  })
})
