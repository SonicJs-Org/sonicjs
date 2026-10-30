// @ts-nocheck
// Regression for the user-reported bug: "when i create new document in draft, it was
// automatically published." Default content is now only the code-defined `blog_post` type. This test
// drives the real admin-content POST route with the black "Save" button (action='save') and the
// Status dropdown on 'draft'. It must store a
// draft (is_published=0), never auto-publish.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import adminContentRoutes from '../../routes/admin-content'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'

const BLOG_SCHEMA = JSON.stringify({
  type: 'object',
  properties: {
    title: { type: 'string', title: 'Title', required: true },
    slug: { type: 'string', title: 'Slug', required: true },
    content: { type: 'string', title: 'Content' },
    author: { type: 'string', title: 'Author' },
    difficulty: { type: 'string', title: 'Difficulty' },
  },
  required: ['title', 'slug', 'content', 'author', 'difficulty'],
})

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    c.set('user', { userId: 'u1', email: 'a@b.c', role: 'admin', exp: 0, iat: 0 })
    c.set('appVersion', 'test')
    await next()
  })
  app.route('/admin/content', adminContentRoutes)
  return app
}

function form(obj: Record<string, string>) {
  const fd = new FormData()
  for (const [k, v] of Object.entries(obj)) fd.append(k, v)
  return fd
}

describe('admin-content blog_post (code-defined doc type) — create-as-draft regression', () => {
  let db: any
  let app: any
  // collection_id in the form maps to document_types.id in the v3 architecture.
  const COLL = 'blog_post'

  beforeEach(async () => {
    db = createTestD1()
    // Collections are code-only now (id === name) — register in the in-memory registry.
    getCollectionRegistry().register([{ name: COLL, displayName: 'Blog Post', description: 'Blog posts', schema: JSON.parse(BLOG_SCHEMA) }])
    await bootstrapDocumentTypes(db)
    app = buildApp(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  function createBlogPost(slug: string, status: string, action: string) {
    return app.request('/admin/content', {
      method: 'POST',
      body: form({ collection_id: COLL, title: `Post ${slug}`, slug, content: '<p>hi</p>', author: 'Ada', difficulty: 'beginner', status, action }),
    })
  }

  it('black "Save" button + Status=draft → stored as DRAFT (is_published=0), not auto-published', async () => {
    const res = await createBlogPost('breaking', 'draft', 'save')
    expect([200, 302]).toContain(res.status)
    const doc = db.raw.prepare("SELECT is_published, is_current_draft, status FROM documents WHERE type_id='blog_post' AND slug='breaking'").get()
    expect(doc).toBeTruthy()
    expect(doc.is_published).toBe(0)
    expect(doc.is_current_draft).toBe(1)
    expect(doc.status).toBe('draft')
    // The document-model schema has no legacy `content` table — its absence is the proof the write went to documents.
    expect(db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='content'").get()).toBeFalsy()
  })

  it('green "Save & Publish" button → published (this is the only path that should publish)', async () => {
    const res = await createBlogPost('launch', 'draft', 'save_and_publish') // dropdown still 'draft', button forces publish
    expect([200, 302]).toContain(res.status)
    const doc = db.raw.prepare("SELECT is_published, status FROM documents WHERE type_id='blog_post' AND slug='launch'").get()
    expect(doc.is_published).toBe(1)
  })
})
