// @ts-nocheck
// Integration tests for admin-media routes (document-authoritative, slice 3).
// Upload is document-primary; legacy `media` writes are best-effort (table may be absent in harness).
// Real SQLite (document tables only), R2 + auth stubbed.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => {
    c.set('user', { userId: 'u1', email: 'a@b.c', role: 'admin' })
    await next()
  },
  requireRole: () => async (_c: any, next: any) => next(),
}))

import { adminMediaRoutes } from '../../routes/admin-media'

function buildApp(db: any, bucket: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db, MEDIA_BUCKET: bucket }
    await next()
  })
  app.route('/admin/media', adminMediaRoutes)
  return app
}

describe('admin-media — document-authoritative upload + reference-aware delete (slice 3)', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    db = createTestD1()
    await bootstrapDocumentTypes(db)
    const bucket = { put: async () => ({}), get: async () => null, delete: async () => {} }
    app = buildApp(db, bucket)
  })
  afterEach(() => db.close())

  async function upload(name = 'doc.txt') {
    const fd = new FormData()
    fd.append('files', new Blob(['data'], { type: 'text/plain' }), name)
    fd.append('folder', 'uploads')
    return app.request('/admin/media/upload', { method: 'POST', body: fd })
  }

  it('upload creates a media_asset document (document-primary)', async () => {
    const res = await upload()
    expect(res.status).toBe(200)
    // Document is primary — must exist with correct fields.
    const doc = db.raw.prepare("SELECT q_media_mime m, data, root_id FROM documents WHERE type_id='media_asset'").get()
    expect(doc).toBeTruthy()
    expect(doc.m).toBe('text/plain')
    expect(JSON.parse(doc.data).originalName).toBe('doc.txt')
  })

  it('delete succeeds when there are no strong references', async () => {
    await upload('free.txt')
    const docRoot = db.raw.prepare("SELECT root_id FROM documents WHERE type_id='media_asset'").get()
    const rootId = docRoot.root_id

    const res = await app.request(`/admin/media/${rootId}`, { method: 'DELETE' })
    expect(res.status).toBe(200)
    // Document must be soft-deleted.
    const doc = db.raw.prepare('SELECT deleted_at FROM documents WHERE root_id=?').get(rootId)
    expect(doc.deleted_at).not.toBeNull()
  })

  it('delete is BLOCKED when the backing document has a strong inbound reference', async () => {
    await upload('used.txt')
    const docRoot = db.raw.prepare("SELECT root_id FROM documents WHERE type_id='media_asset'").get()
    const rootId = docRoot.root_id

    // A live consumer doc + a STRONG reference to the media root.
    db.raw.prepare("INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at) VALUES ('faq2','faq2','FAQ2','{}','[]','{}','system',1,1,1,1,1)").run()
    db.raw.prepare("INSERT INTO documents (id,root_id,type_id,is_current_draft,is_published,data,created_at,updated_at) VALUES ('c1','c1','faq2',1,1,'{}',1,1)").run()
    db.raw.prepare("INSERT INTO document_references (id,tenant_id,from_root_id,from_document_id,field_name,ordinal,to_root_id,ref_strength,created_at) VALUES ('r1','default','c1','c1','image',0,?,'strong',1)").run(rootId)

    const res = await app.request(`/admin/media/${rootId}`, { method: 'DELETE' })
    expect(res.status).toBe(200)
    expect(await res.text()).toMatch(/cannot be deleted/i)
    // Document must NOT be soft-deleted.
    const doc = db.raw.prepare('SELECT deleted_at FROM documents WHERE root_id=?').get(rootId)
    expect(doc.deleted_at).toBeNull()
  })
})
