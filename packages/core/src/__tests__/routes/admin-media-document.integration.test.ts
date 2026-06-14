// @ts-nocheck
// Integration tests for the document-authoritative admin media routes: upload writes a media_asset
// document (greenfield has no legacy `media` table), the public id is the document root id, and
// reference-aware delete blocks hard-delete when a strong inbound reference exists. R2 + auth stubbed.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { MEDIA_QUERYABLE } from '../../services/media-documents'

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

describe('admin-media — document mirror + reference-aware delete (Phase 6 slice 2)', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    db = createTestD1()
    await bootstrapDocumentTypes(db)
    // Migrations ship only the base documents schema; add the media_asset q_media_* generated columns.
    await db.applyScalarSchema('media_asset', MEDIA_QUERYABLE)
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

  // The public media id is the media_asset document root id (no legacy `media` table on greenfield).
  const mediaRootId = () => db.raw.prepare("SELECT root_id r FROM documents WHERE type_id='media_asset' AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1").get().r

  it('upload writes a media_asset document with generated columns', async () => {
    const res = await upload()
    expect(res.status).toBe(200)
    const doc = db.raw.prepare("SELECT q_media_mime m, q_media_folder f, data FROM documents WHERE type_id='media_asset'").get()
    expect(doc).toBeTruthy()
    expect(doc.m).toBe('text/plain')
    expect(doc.f).toBe('uploads')
    expect(JSON.parse(doc.data).originalName).toBe('doc.txt')
    // No legacy media row on the greenfield (document-model) schema.
    expect(db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='media'").get()).toBeFalsy()
  })

  it('delete succeeds when there are no strong references (soft-deletes the document)', async () => {
    await upload('free.txt')
    const id = mediaRootId()
    const res = await app.request(`/admin/media/${id}`, { method: 'DELETE' })
    expect(res.status).toBe(200)
    expect(db.raw.prepare("SELECT deleted_at FROM documents WHERE root_id=? AND type_id='media_asset'").get(id).deleted_at).not.toBeNull()
  })

  it('delete is BLOCKED when the backing document has a strong inbound reference', async () => {
    await upload('used.txt')
    const id = mediaRootId()

    // A live consumer doc + a STRONG reference to the media root.
    db.raw.prepare("INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at) VALUES ('faq2','faq2','FAQ2','{}','[]','{}','system',1,1,1,1,1)").run()
    db.raw.prepare("INSERT INTO documents (id,root_id,type_id,is_current_draft,is_published,data,created_at,updated_at) VALUES ('c1','c1','faq2',1,1,'{}',1,1)").run()
    db.raw.prepare("INSERT INTO document_references (id,tenant_id,from_root_id,from_document_id,field_name,ordinal,to_root_id,ref_strength,created_at) VALUES ('r1','default','c1','c1','image',0,?, 'strong',1)").run(id)

    const res = await app.request(`/admin/media/${id}`, { method: 'DELETE' })
    expect(res.status).toBe(200)
    expect(await res.text()).toMatch(/cannot be deleted/i)
    // Document NOT soft-deleted.
    expect(db.raw.prepare("SELECT deleted_at FROM documents WHERE root_id=? AND type_id='media_asset'").get(id).deleted_at).toBeNull()
  })
})
