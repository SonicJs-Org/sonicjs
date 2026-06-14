// @ts-nocheck
// Integration tests for the public content API flipped to read `documents` (legacy content
// decommission, step 2). Mounts the real apiRoutes over real SQLite (collections + documents) with
// auth stubbed. Verifies: document-backed content is served, drafts hidden from anon, ONE row per
// root, data-field filter parity (json_extract), stable response shape, and the privileged view.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'

const h = vi.hoisted(() => ({ user: undefined }))
vi.mock('../../middleware', () => ({
  optionalAuth: () => async (c: any, next: any) => { if (h.user) c.set('user', h.user); await next() },
  isPluginActive: async () => false,
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import apiRoutes from '../../routes/api'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'

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

describe('public content API → documents (decommission step 2)', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    h.user = undefined
    db = createTestD1()
    // Collections are code-only now (no DB table) — register in the in-memory registry.
    getCollectionRegistry().register([{ name: 'news', displayName: 'News', schema: {} }])
    const svc = new DocumentsService(db, { tenantId: 'default', queryableFields: [] })
    await svc.create({ typeId: 'news', tenantId: 'default', title: 'Published News', slug: 'pub-news', data: { category: 'tech' }, publishOnCreate: true })
    await svc.create({ typeId: 'news', tenantId: 'default', title: 'Draft News', slug: 'draft-news', data: { category: 'tech' } }) // not published
    app = buildApp(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  async function get(path: string) {
    const res = await app.request(path)
    return { status: res.status, body: await res.json() }
  }

  it('collection-scoped read returns only published docs to anon, with stable shape', async () => {
    const { status, body } = await get('/api/collections/news/content')
    expect(status).toBe(200)
    expect(body.data).toHaveLength(1)
    const item = body.data[0]
    expect(item.title).toBe('Published News')
    expect(item.slug).toBe('pub-news')
    expect(item.collectionId).toBe('news') // code-only collection: id === name
    expect(item.data.category).toBe('tech')
    expect(typeof item.id).toBe('string') // == document root id
  })

  it('/api/content?collection= returns only published docs to anon', async () => {
    const { body } = await get('/api/content?collection=news')
    expect(body.data.map((d: any) => d.slug)).toEqual(['pub-news'])
  })

  it('data-field filters carry over (json_extract on documents.data)', async () => {
    const tech = await get('/api/content?collection=news&filter[data.category]=tech')
    expect(tech.body.data.map((d: any) => d.slug)).toEqual(['pub-news'])
    const other = await get('/api/content?collection=news&filter[data.category]=other')
    expect(other.body.data).toHaveLength(0)
  })

  it('returns ONE row per root even after a new draft is saved on a published item', async () => {
    const svc = new DocumentsService(db, { tenantId: 'default', queryableFields: [] })
    const pub = db.raw.prepare("SELECT root_id FROM documents WHERE slug='pub-news' AND is_published=1").get()
    await svc.saveDraft(pub.root_id, { data: { category: 'tech', edited: true } }) // v2 draft; v1 stays published
    const { body } = await get('/api/collections/news/content')
    expect(body.data).toHaveLength(1) // only the published revision, not both versions
    expect(body.data[0].slug).toBe('pub-news')
  })

  it('privileged (admin) sees drafts too (current-draft view)', async () => {
    h.user = { userId: 'u1', email: 'a@b.c', role: 'admin' }
    const { body } = await get('/api/collections/news/content')
    expect(body.data.map((d: any) => d.slug).sort()).toEqual(['draft-news', 'pub-news'])
  })
})
