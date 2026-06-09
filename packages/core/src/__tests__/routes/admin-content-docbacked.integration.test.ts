// @ts-nocheck
// Route-level integration tests for the Option B branches in admin-content: a collection whose name
// matches a registered document type (blog_post) is document-backed — the rich /admin/content editor
// stays, but create/list/edit/update route to the documents table. Mounts the real adminContentRoutes
// on a Hono app over real SQLite (consolidated greenfield schema).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import adminContentRoutes from '../../routes/admin-content'

const BLOG_SCHEMA = JSON.stringify({
  type: 'object',
  properties: {
    title: { type: 'string', title: 'Title', required: true },
    slug: { type: 'string', title: 'Slug', required: true },
    content: { type: 'string', title: 'Content', required: true },
    author: { type: 'string', title: 'Author', required: true },
    difficulty: { type: 'string', title: 'Difficulty', enum: ['beginner', 'advanced'], required: true },
    excerpt: { type: 'string', title: 'Excerpt' },
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

describe('admin-content Option B (document-backed blog_post) — integration', () => {
  let db: any
  let app: any
  // collection_id in the form maps to a document_types.id in the v3 architecture.
  // Use the document type id ('blog_post') — not the legacy collections.id ('bp').
  const COLL = 'blog_post'

  beforeEach(async () => {
    db = createTestD1()
    db.raw.prepare("INSERT INTO users (id,email,username,first_name,last_name,role,is_active,created_at,updated_at) VALUES ('u1','a@b.c','admin','Ada','Lovelace','admin',1,1,1)").run()
    db.raw.prepare("INSERT INTO collections (id,name,display_name,description,schema,is_active,managed,created_at,updated_at) VALUES (?,?,?,?,?,1,1,1,1)")
      .run(COLL, 'blog_post', 'Blog Posts', 'Blog', BLOG_SCHEMA)
    await bootstrapDocumentTypes(db) // registers the blog_post document type
    app = buildApp(db)
  })
  afterEach(() => db.close())

  async function createPost(slug: string, status = 'published') {
    return app.request('/admin/content', {
      method: 'POST',
      body: form({
        collection_id: COLL, title: `Post ${slug}`, slug, content: '<p>body</p>',
        author: 'Ada', difficulty: 'advanced', excerpt: 'x', status,
        action: status === 'published' ? 'save_and_publish' : 'save',
      }),
    })
  }

  it('create as DRAFT stays unpublished (regression: new draft must not auto-publish)', async () => {
    const res = await createPost('mydraft', 'draft')
    expect([200, 302]).toContain(res.status)
    const doc = db.raw.prepare("SELECT is_published, is_current_draft, status FROM documents WHERE slug='mydraft'").get()
    expect(doc.is_published).toBe(0)
    expect(doc.is_current_draft).toBe(1)
    expect(doc.status).toBe('draft')
  })

  it('create routes to the documents table (not content)', async () => {
    const res = await createPost('hello')
    expect([200, 302]).toContain(res.status)

    const doc = db.raw.prepare("SELECT title, slug, is_published, q_blog_difficulty d, q_blog_author a FROM documents WHERE type_id='blog_post' AND slug='hello'").get()
    expect(doc).toBeTruthy()
    expect(doc.is_published).toBe(1)
    expect(doc.d).toBe('advanced')
    expect(doc.a).toBe('Ada')
    expect(db.raw.prepare('SELECT COUNT(*) AS count FROM content').get().count).toBe(0)
  })

  it('list (model=blog_post) reads from documents and shows the post', async () => {
    await createPost('listed')
    const res = await app.request('/admin/content?model=blog_post')
    expect(res.status).toBe(200)
    const htmlText = await res.text()
    expect(htmlText).toContain('Post listed')
  })

  it('edit form loads the document into the rich content editor', async () => {
    await createPost('editme')
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE slug='editme'").get().r
    const res = await app.request(`/admin/content/${rootId}/edit`)
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('Post editme')
  })

  it('update creates a new version and republishes it (v2 becomes the live revision)', async () => {
    await createPost('updateme') // v1 published
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE slug='updateme'").get().r
    const res = await app.request(`/admin/content/${rootId}`, {
      method: 'PUT',
      body: form({ _method: 'PUT', collection_id: COLL, title: 'Post updateme v2', slug: 'updateme', content: '<p>v2</p>', author: 'Ada', difficulty: 'beginner', status: 'published' }),
    })
    expect([200, 302]).toContain(res.status)
    // A new version exists and exactly one published row, now at v2.
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=?").get(rootId).n).toBe(2)
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1").get(rootId).n).toBe(1)
    expect(db.raw.prepare("SELECT version_number v FROM documents WHERE root_id=? AND is_published=1").get(rootId).v).toBe(2)
  })

  it('update with status=draft unpublishes the live revision (consistent status semantics)', async () => {
    await createPost('draftme') // v1 published
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE slug='draftme'").get().r
    const res = await app.request(`/admin/content/${rootId}`, {
      method: 'PUT',
      body: form({ _method: 'PUT', collection_id: COLL, title: 'Post draftme v2', slug: 'draftme', content: '<p>v2</p>', author: 'Ada', difficulty: 'beginner', status: 'draft' }),
    })
    expect([200, 302]).toContain(res.status)
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1").get(rootId).n).toBe(0)
  })

  it('all-view lists document rows without requiring a legacy content table', async () => {
    await createPost('inall')
    const res = await app.request('/admin/content?model=all')
    expect(res.status).toBe(200)
    const htmlText = await res.text()
    expect(htmlText).toContain('Post inall') // blog document
    expect(db.raw.prepare('SELECT COUNT(*) AS count FROM content').get().count).toBe(0)
  })

  // ── D33: bulk actions must operate on document-backed root ids, not silently no-op ──────────
  const rootOf = (slug: string) => db.raw.prepare("SELECT root_id r FROM documents WHERE slug=?").get(slug).r
  const bulk = (action: string, ids: string[]) =>
    app.request('/admin/content/bulk-action', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action, ids }) })

  it('D33: bulk publish publishes document-backed roots', async () => {
    await createPost('bp-a', 'draft')
    await createPost('bp-b', 'draft')
    const ids = ['bp-a', 'bp-b'].map(rootOf)
    const res = await bulk('publish', ids)
    expect(res.status).toBe(200)
    expect((await res.json()).success).toBe(true)
    for (const id of ids) {
      expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1").get(id).n).toBe(1)
    }
  })

  it('D33: bulk move-to-draft unpublishes document-backed roots', async () => {
    await createPost('bd-a') // published
    await createPost('bd-b')
    const ids = ['bd-a', 'bd-b'].map(rootOf)
    expect((await bulk('draft', ids)).status).toBe(200)
    for (const id of ids) {
      expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1").get(id).n).toBe(0)
    }
  })

  it('D33: bulk delete soft-deletes document-backed roots', async () => {
    await createPost('del-a')
    await createPost('del-b')
    const ids = ['del-a', 'del-b'].map(rootOf)
    expect((await bulk('delete', ids)).status).toBe(200)
    for (const id of ids) {
      expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND deleted_at IS NOT NULL").get(id).n).toBeGreaterThan(0)
    }
  })
})
