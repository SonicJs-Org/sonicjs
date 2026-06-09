// @ts-nocheck
// Route-level integration tests for the document admin API. Mounts the real adminDocumentsRoutes on
// a Hono app backed by a real-SQLite D1 (migrations 043+044), with auth middleware stubbed and the
// principal role driven per-test. This exercises the actual handlers end to end — create/list/get/
// saveDraft/publish/unpublish/delete + the Phase 2b per-document ACL (403 on deny) — which the unit
// suite (pure logic) and type-check cannot cover.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

// Drives the principal role the stubbed auth sets; tests flip it to assert ACL denials.
const h = vi.hoisted(() => ({ role: 'admin' }))
vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import adminDocumentsRoutes from '../../routes/admin-documents'

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    c.set('user', { userId: 'u1', email: 'a@b.c', role: h.role, exp: 0, iat: 0 })
    await next()
  })
  app.route('/admin/documents', adminDocumentsRoutes)
  return app
}

const post = (body: any) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
const put = (body: any) => ({ method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

describe('admin-documents routes — integration (real SQLite)', () => {
  let db: any
  let app: any
  beforeEach(async () => {
    h.role = 'admin'
    db = createTestD1()
    await bootstrapDocumentTypes(db)
    app = buildApp(db)
  })
  afterEach(() => db.close())

  async function createBlogPost(extra: any = {}) {
    const res = await app.request('/admin/documents', post({ typeId: 'blog_post', title: 'Q', data: { author: 'Ada', difficulty: 'beginner' }, ...extra }))
    return { res, body: await res.json() }
  }

  it('creates a blog_post, lists it, and reads it by id', async () => {
    const { res, body } = await createBlogPost({ title: 'Q1' })
    expect(res.status).toBe(201)
    expect(body.data.typeId).toBe('blog_post')
    expect(body.data.versionNumber).toBe(1)

    const list = await (await app.request('/admin/documents?type=blog_post')).json()
    expect(list.data.some((d: any) => d.id === body.data.id)).toBe(true)

    const getRes = await app.request(`/admin/documents/${body.data.id}`)
    expect(getRes.status).toBe(200)
    expect((await getRes.json()).data.id).toBe(body.data.id)
  })

  it('rejects an unknown document type with 400', async () => {
    const res = await app.request('/admin/documents', post({ typeId: 'nope', data: {} }))
    expect(res.status).toBe(400)
  })

  it('save-draft creates v2 and keeps the published revision live', async () => {
    const { body } = await createBlogPost({ title: 'V1', publishOnCreate: true })
    const rootId = body.data.rootId
    const r = await app.request(`/admin/documents/${rootId}`, put({ data: { author: 'Ada', difficulty: 'advanced' } }))
    expect(r.status).toBe(200)
    expect((await r.json()).data.versionNumber).toBe(2)
    expect(db.raw.prepare('SELECT version_number FROM documents WHERE root_id=? AND is_published=1').get(rootId).version_number).toBe(1)
  })

  it('publish flips is_published on the target row', async () => {
    const { body } = await createBlogPost()
    const r = await app.request(`/admin/documents/${body.data.id}/publish`, { method: 'POST' })
    expect(r.status).toBe(200)
    expect(db.raw.prepare('SELECT is_published FROM documents WHERE id=?').get(body.data.id).is_published).toBe(1)
  })

  it('soft-deletes a non-PII document', async () => {
    const { body } = await createBlogPost()
    const r = await app.request(`/admin/documents/${body.data.id}`, { method: 'DELETE' })
    expect(r.status).toBe(200)
    expect(db.raw.prepare('SELECT deleted_at FROM documents WHERE id=?').get(body.data.id).deleted_at).not.toBeNull()
  })

  // ── Phase 2b ACL: blog_post base grants give viewer only 'read' ─────────────
  it('viewer is denied create (403)', async () => {
    h.role = 'viewer'
    const res = await app.request('/admin/documents', post({ typeId: 'blog_post', data: { author: 'Ada', difficulty: 'beginner' } }))
    expect(res.status).toBe(403)
  })

  it('viewer is denied update and publish (403)', async () => {
    const { body } = await createBlogPost() // as admin
    h.role = 'viewer'
    const upd = await app.request(`/admin/documents/${body.data.rootId}`, put({ data: { author: 'Ada', difficulty: 'advanced' } }))
    expect(upd.status).toBe(403)
    const pub = await app.request(`/admin/documents/${body.data.id}/publish`, { method: 'POST' })
    expect(pub.status).toBe(403)
  })

  it('editor is allowed to create and publish', async () => {
    h.role = 'editor'
    const { res, body } = await createBlogPost()
    expect(res.status).toBe(201)
    const pub = await app.request(`/admin/documents/${body.data.id}/publish`, { method: 'POST' })
    expect(pub.status).toBe(200)
  })
})
