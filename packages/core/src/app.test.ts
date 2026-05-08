/**
 * Integration smoke test for createSonicJSApp + plugins.register.
 *
 * Exercises the full pipeline (bootstrap → security headers → CSRF → admin
 * auth wall → user-plugin mounting → /admin catch-alls) and verifies that
 * plugin routes mount and resolve correctly, are not shadowed by the core
 * /admin/* catch-alls, and that ordering between user middleware and routes
 * holds end-to-end.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('./services/collection-sync', () => ({
  syncCollections: vi.fn().mockResolvedValue([]),
  syncAllFormCollections: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('./services/migrations', () => ({
  MigrationService: vi.fn().mockImplementation(function (this: any) {
    this.runPendingMigrations = vi.fn().mockResolvedValue(undefined)
    return this
  }),
}))

vi.mock('./services/plugin-bootstrap', () => ({
  PluginBootstrapService: vi.fn().mockImplementation(function (this: any) {
    this.isBootstrapNeeded = vi.fn().mockResolvedValue(false)
    this.bootstrapCorePlugins = vi.fn().mockResolvedValue(undefined)
    return this
  }),
}))

import { createSonicJSApp } from './app'
import { resetBootstrap } from './middleware/bootstrap'
import type { Plugin } from './plugins/types'

function createMockEnv() {
  const stmt = {
    first: vi.fn().mockResolvedValue(null),
    all: vi.fn().mockResolvedValue({ results: [] }),
    bind: vi.fn().mockReturnThis(),
    run: vi.fn().mockResolvedValue({ success: true }),
  }
  return {
    DB: { prepare: vi.fn().mockReturnValue(stmt) },
    CACHE_KV: {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
      delete: vi.fn().mockResolvedValue(undefined),
      list: vi.fn().mockResolvedValue({ keys: [] }),
    },
    MEDIA_BUCKET: { get: vi.fn().mockResolvedValue(null) },
    ASSETS: { fetch: vi.fn() },
    JWT_SECRET: 'test-secret-for-integration-test-only',
    ENVIRONMENT: 'development',
    CORS_ORIGINS: '*',
  }
}

async function request(app: any, path: string, init?: RequestInit) {
  const env = createMockEnv()
  return app.request(path, init, env)
}

describe('createSonicJSApp + plugins.register', () => {
  beforeEach(() => {
    resetBootstrap()
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('mounts a public plugin route and returns its response', async () => {
    const handler = new Hono().get('/ping', (c) => c.json({ from: 'plugin' }))
    const plugin: Plugin = {
      name: 'smoke-plugin',
      version: '1.0.0',
      routes: [{ path: '/api/smoke', handler }],
    }

    const app = createSonicJSApp({
      plugins: { register: [plugin] },
    })

    const res = await request(app, '/api/smoke/ping')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ from: 'plugin' })
  })

  it('plugin route at /admin/plugins/<name> is NOT shadowed by core /admin catch-all', async () => {
    // The plugin claims a sub-path under /admin/plugins/. Without correct
    // ordering, core's `app.route('/admin/plugins', adminPluginRoutes)` would
    // match first and return its own 404. With correct ordering, the plugin
    // handler runs — but because /admin/* is gated by requireAuth(), an
    // unauthenticated request hits 401, which proves the route was found.
    const handler = new Hono().get('/settings', (c) => c.json({ ok: true }))
    const plugin: Plugin = {
      name: 'admin-plugin',
      version: '1.0.0',
      routes: [{ path: '/admin/plugins/admin-plugin', handler }],
    }

    const app = createSonicJSApp({
      plugins: { register: [plugin] },
    })

    const res = await request(app, '/admin/plugins/admin-plugin/settings')
    // 401 (auth required) means the route matched and the auth middleware
    // gated it. 404 would mean the catch-all swallowed it (regression).
    expect([200, 302, 401]).toContain(res.status)
    expect(res.status).not.toBe(404)
  })

  it('plugin middleware runs in priority order before plugin routes', async () => {
    const order: string[] = []
    const handler = new Hono().get('/check', (c) => c.json({ order }))

    const plugin: Plugin = {
      name: 'ordered-plugin',
      version: '1.0.0',
      middleware: [
        {
          name: 'second',
          global: true,
          priority: 10,
          handler: async (_c, next) => {
            order.push('second')
            await next()
          },
        },
        {
          name: 'first',
          global: true,
          priority: 1,
          handler: async (_c, next) => {
            order.push('first')
            await next()
          },
        },
      ],
      routes: [{ path: '/api/order', handler }],
    }

    const app = createSonicJSApp({
      plugins: { register: [plugin] },
    })

    const res = await request(app, '/api/order/check')
    expect(res.status).toBe(200)
    const body = (await res.json()) as { order: string[] }
    expect(body.order).toEqual(['first', 'second'])
  })

  it('omitting plugins.register works (empty array equivalent)', async () => {
    const app = createSonicJSApp({})
    const res = await request(app, '/health')
    expect(res.status).toBe(200)
    const body = (await res.json()) as { status: string }
    expect(body.status).toBe('running')
  })

  it('multiple registered plugins all mount', async () => {
    const a = new Hono().get('/', (c) => c.text('a'))
    const b = new Hono().get('/', (c) => c.text('b'))

    const app = createSonicJSApp({
      plugins: {
        register: [
          { name: 'a', version: '1.0.0', routes: [{ path: '/api/a', handler: a }] },
          { name: 'b', version: '1.0.0', routes: [{ path: '/api/b', handler: b }] },
        ],
      },
    })

    expect(await (await request(app, '/api/a')).text()).toBe('a')
    expect(await (await request(app, '/api/b')).text()).toBe('b')
  })
})
