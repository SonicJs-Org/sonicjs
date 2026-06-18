// @ts-nocheck
// Integration test for per-collection cache TTL on GET /api/:collection.
// Mounts real apiRoutes over real SQLite (D1 shim), registers a collection with a
// `cache: { enabled, ttl }` override, and asserts MISS → HIT plus the custom TTL header.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { getCollectionRegistry } from '../../services/collection-registry'
import { clearAllCacheInstances } from '../../services/cache'

// isPluginActive returns true so the route's `cacheEnabled` middleware turns caching on.
vi.mock('../../middleware', () => ({
  optionalAuth: () => async (_c: any, next: any) => next(),
  isPluginActive: async () => true,
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import apiRoutes from '../../routes/api'

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    c.set('startTime', Date.now())
    await next()
  })
  app.route('/api', apiRoutes)
  return app
}

describe('GET /api/:collection — per-collection cache TTL', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    await clearAllCacheInstances()
    getCollectionRegistry().clear()
    getCollectionRegistry().register([
      {
        name: 'blog_post',
        displayName: 'Blog Post',
        slug: 'blog-posts',
        schema: { type: 'object', properties: { title: { type: 'string' } } },
        isActive: true,
        managed: true,
        cache: { enabled: true, ttl: 600 },
      },
      {
        name: 'no_cache_thing',
        displayName: 'No Cache Thing',
        slug: 'no-cache-things',
        schema: { type: 'object', properties: { title: { type: 'string' } } },
        isActive: true,
        managed: true,
        cache: { enabled: false },
      },
    ])

    db = createTestD1()
    const svc = new DocumentsService(db, { tenantId: 'default', queryableFields: [] })
    await svc.create({ typeId: 'blog_post', tenantId: 'default', title: 'Post One', slug: 'post-one', data: {}, publishOnCreate: true })
    await svc.create({ typeId: 'blog_post', tenantId: 'default', title: 'Post Two', slug: 'post-two', data: {}, publishOnCreate: true })
    await svc.create({ typeId: 'no_cache_thing', tenantId: 'default', title: 'Uncached', slug: 'uncached', data: {}, publishOnCreate: true })

    app = buildApp(db)
  })

  afterEach(() => {
    db.close()
    getCollectionRegistry().clear()
  })

  it('first call is a MISS, second call is a HIT (cache wired up)', async () => {
    const first = await app.request('/api/blog-posts')
    expect(first.status).toBe(200)
    expect(first.headers.get('X-Cache-Status')).toBe('MISS')
    expect(first.headers.get('X-Cache-TTL')).toBe('600')

    const firstBody = await first.json()
    expect(firstBody.data.map((d: any) => d.slug).sort()).toEqual(['post-one', 'post-two'])

    const second = await app.request('/api/blog-posts')
    expect(second.status).toBe(200)
    expect(second.headers.get('X-Cache-Status')).toBe('HIT')

    const secondBody = await second.json()
    expect(secondBody.data.map((d: any) => d.slug).sort()).toEqual(['post-one', 'post-two'])
    expect(secondBody.meta.cache?.hit).toBe(true)
  })

  it('writes are visible to the plugin stats registry (admin dashboard source)', async () => {
    const { getAllCacheStats } = await import('../../plugins/cache/services/cache')
    await app.request('/api/blog-posts')
    await app.request('/api/blog-posts')

    const stats = getAllCacheStats() as Record<string, any>
    expect(stats.api).toBeDefined()
    // Two reads, both for the same key → 1 miss + 1 hit, entryCount stays at 1.
    expect(stats.api.entryCount).toBeGreaterThanOrEqual(1)
    expect(stats.api.memoryHits + stats.api.kvHits).toBeGreaterThanOrEqual(1)
  })

  it('honors collection override cache.enabled=false (always MISS, never sets cache)', async () => {
    const first = await app.request('/api/no-cache-things')
    const second = await app.request('/api/no-cache-things')
    expect(first.headers.get('X-Cache-Status')).toBe('MISS')
    expect(second.headers.get('X-Cache-Status')).toBe('MISS')
  })
})
