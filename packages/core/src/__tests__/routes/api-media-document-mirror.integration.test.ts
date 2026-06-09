// @ts-nocheck
// Integration test for Phase 6 slice 1: the media upload path mirrors each upload into a media_asset
// document (dual-write) while still writing the legacy `media` row. Mounts the real apiMediaRoutes
// over real SQLite (document tables + a media table) with R2 and auth stubbed.
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

describe('api-media upload → media_asset document mirror (Phase 6)', () => {
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

  it('writes the legacy media row AND a media_asset document with generated columns', async () => {
    const fd = new FormData()
    fd.append('file', new Blob(['hello world'], { type: 'text/plain' }), 'notes.txt')
    fd.append('folder', 'uploads')

    const res = await app.request('/api/media/upload', { method: 'POST', body: fd })
    expect(res.status).toBe(200)
    expect((await res.json()).success).toBe(true)

    // R2 received the bytes.
    expect(putKeys).toHaveLength(1)

    // Legacy media row still written (library reads this until slice 2).
    expect(db.raw.prepare('SELECT COUNT(*) n FROM media').get().n).toBe(1)

    // Mirrored media_asset document with q_media_* generated columns populated.
    const doc = db.raw.prepare("SELECT q_media_mime m, q_media_folder f, data, is_published FROM documents WHERE type_id='media_asset'").get()
    expect(doc).toBeTruthy()
    expect(doc.m).toBe('text/plain')
    expect(doc.f).toBe('uploads')
    expect(doc.is_published).toBe(1)
    const data = JSON.parse(doc.data)
    expect(data.originalName).toBe('notes.txt')
    expect(data.r2Key).toContain('uploads/')
  })
})
