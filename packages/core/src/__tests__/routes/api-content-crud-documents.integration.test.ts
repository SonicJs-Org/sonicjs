// @ts-nocheck
// Integration tests for the programmatic content CRUD API flipped to documents (legacy content
// decommission). Mounts the real apiContentCrudRoutes over real SQLite (collections + documents)
// with auth stubbed: POST creates a document, GET /:id resolves by root id, PUT saves a draft +
// syncs publish, DELETE soft-deletes, and duplicate slugs are rejected.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => { c.set('user', { userId: 'u1', email: 'a@b.c', role: 'admin' }); await next() },
  requireRole: () => async (_c: any, next: any) => next(),
  // GET /:id is public (optionalAuth). Leave the caller anonymous so it resolves the published row.
  optionalAuth: () => async (_c: any, next: any) => next(),
}))

import apiContentCrudRoutes from '../../routes/api-content-crud'

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => { (c as any).env = { DB: db }; await next() })
  app.route('/api/content', apiContentCrudRoutes)
  return app
}

const json = (method: string, body: any) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

describe('api-content-crud → documents (decommission step)', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    db = createTestD1()
    db.raw.prepare("INSERT INTO collections (id,name,display_name,schema,is_active,source_type,created_at,updated_at) VALUES ('blog-post-id','blog_post','Blog Post','{}',1,NULL,1,1)").run()
    await bootstrapDocumentTypes(db)
    app = buildApp(db)
  })
  afterEach(() => db.close())

  it('POST creates a document (not a content row), published, and GET /:id resolves it', async () => {
    const res = await app.request('/api/content', json('POST', { collectionId: 'blog-post-id', title: 'Hello', slug: 'hello', status: 'published', data: { body: 'x' } }))
    expect(res.status).toBe(201)
    const created = (await res.json()).data
    expect(created.collectionId).toBe('blog-post-id')

    // stored as a published blog_post document
    const doc = db.raw.prepare("SELECT * FROM documents WHERE type_id='blog_post' AND slug='hello'").get()
    expect(doc).toBeTruthy()
    expect(doc.is_published).toBe(1)
    expect(doc.root_id).toBe(created.id)

    const getRes = await app.request(`/api/content/${created.id}`)
    expect(getRes.status).toBe(200)
    expect((await getRes.json()).data.slug).toBe('hello')
  })

  it('rejects a duplicate slug with 409', async () => {
    await app.request('/api/content', json('POST', { collectionId: 'blog-post-id', title: 'A', slug: 'dup', data: {} }))
    const res = await app.request('/api/content', json('POST', { collectionId: 'blog-post-id', title: 'B', slug: 'dup', data: {} }))
    expect(res.status).toBe(409)
  })

  it('PUT saves a new draft and republishes it', async () => {
    const created = (await (await app.request('/api/content', json('POST', { collectionId: 'blog-post-id', title: 'V1', slug: 'v', status: 'published', data: {} }))).json()).data
    const res = await app.request(`/api/content/${created.id}`, json('PUT', { data: { body: 'v2' }, status: 'published' }))
    expect(res.status).toBe(200)
    expect(db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(created.id).n).toBe(2)
    expect(db.raw.prepare('SELECT version_number v FROM documents WHERE root_id=? AND is_published=1').get(created.id).v).toBe(2)
  })

  it('DELETE soft-deletes every version row of the root', async () => {
    const created = (await (await app.request('/api/content', json('POST', { collectionId: 'blog-post-id', title: 'Del', slug: 'del', data: {} }))).json()).data
    const res = await app.request(`/api/content/${created.id}`, { method: 'DELETE' })
    expect(res.status).toBe(200)
    expect(db.raw.prepare('SELECT deleted_at FROM documents WHERE root_id=?').get(created.id).deleted_at).not.toBeNull()
  })
})
