// @ts-nocheck
// Integration test for api-media routes (document-authoritative, slice 3).
// Upload is document-primary; legacy `media` writes are best-effort (table may be absent).
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
}))

import { apiMediaRoutes } from '../../routes/api-media'

function buildApp(db: any, bucket: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db, MEDIA_BUCKET: bucket, BUCKET_NAME: 'test-bucket' }
    await next()
  })
  app.route('/api/media', apiMediaRoutes)
  return app
}

describe('api-media — document-authoritative upload + delete (slice 3)', () => {
  let db: any
  let app: any
  let putKeys: string[]

  beforeEach(async () => {
    db = createTestD1()
    await bootstrapDocumentTypes(db)
    putKeys = []
    const bucket = { put: async (k: string) => { putKeys.push(k); return {} }, get: async () => null, delete: async () => {} }
    app = buildApp(db, bucket)
  })
  afterEach(() => db.close())

  it('upload creates a media_asset document with generated columns; id = document rootId', async () => {
    const fd = new FormData()
    fd.append('file', new Blob(['hello world'], { type: 'text/plain' }), 'notes.txt')
    fd.append('folder', 'uploads')

    const res = await app.request('/api/media/upload', { method: 'POST', body: fd })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.success).toBe(true)
    expect(body.file.id).toBeTruthy()

    // R2 received the bytes.
    expect(putKeys).toHaveLength(1)

    // Document must exist with correct generated columns.
    const doc = db.raw.prepare("SELECT q_media_mime m, q_media_folder f, data, root_id, is_published FROM documents WHERE type_id='media_asset'").get()
    expect(doc).toBeTruthy()
    expect(doc.m).toBe('text/plain')
    expect(doc.f).toBe('uploads')
    expect(doc.is_published).toBe(1)
    const data = JSON.parse(doc.data)
    expect(data.originalName).toBe('notes.txt')
    expect(data.r2Key).toContain('uploads/')

    // Returned id = document rootId.
    expect(body.file.id).toBe(doc.root_id)
  })

  it('upload-multiple creates one document per file', async () => {
    const fd = new FormData()
    fd.append('files', new Blob(['a'], { type: 'text/plain' }), 'a.txt')
    fd.append('files', new Blob(['b'], { type: 'text/plain' }), 'b.txt')
    fd.append('folder', 'uploads')

    const res = await app.request('/api/media/upload-multiple', { method: 'POST', body: fd })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.uploaded).toHaveLength(2)

    const count = db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE type_id='media_asset'").get().n
    expect(count).toBe(2)
  })

  it('delete soft-deletes the document', async () => {
    const fd = new FormData()
    fd.append('file', new Blob(['x'], { type: 'text/plain' }), 'del.txt')
    fd.append('folder', 'uploads')

    const upload = await app.request('/api/media/upload', { method: 'POST', body: fd })
    const { file } = await upload.json()

    const del = await app.request(`/api/media/${file.id}`, { method: 'DELETE' })
    expect(del.status).toBe(200)

    const doc = db.raw.prepare('SELECT deleted_at FROM documents WHERE root_id=?').get(file.id)
    expect(doc.deleted_at).not.toBeNull()
  })

  it('bulk-delete soft-deletes multiple documents', async () => {
    const ids: string[] = []
    for (const name of ['x.txt', 'y.txt']) {
      const fd = new FormData()
      fd.append('files', new Blob([name], { type: 'text/plain' }), name)
      fd.append('folder', 'uploads')
      const res = await app.request('/api/media/upload-multiple', { method: 'POST', body: fd })
      const body = await res.json()
      ids.push(body.uploaded[0].id)
    }

    const del = await app.request('/api/media/bulk-delete', { method: 'POST', body: JSON.stringify({ fileIds: ids }), headers: { 'Content-Type': 'application/json' } })
    expect(del.status).toBe(200)
    const body = await del.json()
    expect(body.deleted).toHaveLength(2)

    for (const id of ids) {
      const doc = db.raw.prepare('SELECT deleted_at FROM documents WHERE root_id=?').get(id)
      expect(doc.deleted_at).not.toBeNull()
    }
  })
})
