// @ts-nocheck
// Route-level integration tests for the Option B branches in admin-content: a collection whose name
// matches a registered document type (blog_post) is document-backed — the rich /admin/content editor
// stays, but create/list/edit/update route to the documents table. Mounts the real adminContentRoutes
// on a Hono app over real SQLite (consolidated greenfield schema).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import adminContentRoutes from '../../routes/admin-content'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'
import { registerCollections } from '../../services/collection-loader'

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
    // Collections are code-only now (id === name) — register in the in-memory registry.
    getCollectionRegistry().register([{ name: 'blog_post', displayName: 'Blog Posts', description: 'Blog', schema: JSON.parse(BLOG_SCHEMA), versioning: true }])
    await bootstrapDocumentTypes(db) // registers the blog_post document type
    app = buildApp(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

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
    // The document-model schema has no legacy `content` table at all — its absence is the proof the write went to documents.
    expect(db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='content'").get()).toBeFalsy()
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

  it('update saves a new draft and publishes it (versioning=true)', async () => {
    await createPost('updateme') // v1 published
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE slug='updateme'").get().r
    const res = await app.request(`/admin/content/${rootId}`, {
      method: 'PUT',
      body: form({ _method: 'PUT', collection_id: COLL, title: 'Post updateme v2', slug: 'updateme', content: '<p>v2</p>', author: 'Ada', difficulty: 'beginner', status: 'published' }),
    })
    expect([200, 302]).toContain(res.status)
    // blog_post has versioning=true → saveDraft creates v2, publish() publishes v2. Two rows exist.
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=?").get(rootId).n).toBe(2)
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1").get(rootId).n).toBe(1)
  })

  it('update title is reflected on the all-view content list', async () => {
    await createPost('titlecheck') // v1 published with title "Post titlecheck"
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE slug='titlecheck'").get().r

    // Update title to something new
    const res = await app.request(`/admin/content/${rootId}`, {
      method: 'PUT',
      body: form({ _method: 'PUT', collection_id: COLL, title: 'Brand New Title', slug: 'titlecheck', content: '<p>v2</p>', author: 'Ada', difficulty: 'beginner', status: 'published', action: 'save_and_close' }),
    })
    expect([200, 302]).toContain(res.status)

    // Verify title persisted in DB on the current draft row
    const draft = db.raw.prepare("SELECT title FROM documents WHERE root_id=? AND is_current_draft=1").get(rootId)
    expect(draft.title).toBe('Brand New Title')

    // Verify the all-view list renders the updated title
    const listRes = await app.request('/admin/content')
    expect(listRes.status).toBe(200)
    const listHtml = await listRes.text()
    expect(listHtml).toContain('Brand New Title')
    expect(listHtml).not.toContain('Post titlecheck')
  })

  it('save-and-close redirects to unfiltered /admin/content (no collection param)', async () => {
    await createPost('redirect-test')
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE slug='redirect-test'").get().r
    const res = await app.request(`/admin/content/${rootId}`, {
      method: 'PUT',
      body: form({ _method: 'PUT', collection_id: COLL, title: 'Redirect Test', slug: 'redirect-test', content: '<p>v2</p>', author: 'Ada', difficulty: 'beginner', status: 'published', action: 'save_and_close' }),
    })
    // Should redirect (302) or return HX-Redirect header
    if (res.status === 302) {
      const location = res.headers.get('Location') || ''
      expect(location).toBe('/admin/content')
      expect(location).not.toContain('collection=')
    } else {
      const hxRedirect = res.headers.get('HX-Redirect') || ''
      expect(hxRedirect).toBe('/admin/content')
      expect(hxRedirect).not.toContain('collection=')
    }
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
    // The document-model schema has no legacy `content` table at all — its absence is the proof the write went to documents.
    expect(db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='content'").get()).toBeFalsy()
  })

  // ── All-view capped count + paging input (D1 overload fix) ─────────────────────────────────
  // The All view counts at most `offset + limit * 10` matches. Below the cap it shows the exact
  // total; above it, a lower bound rendered as "N+" in BOTH the header badge and the footer.
  describe('all-view capped count', () => {
    const footerTotal = (html: string) => /<span[^>]*>(\d+\+?)<\/span> results/.exec(html)?.[1]
    const badgeTotal = (html: string) => /(\d+\+?) items?<\/span>/.exec(html)?.[1]
    const list = async (qs: string) => {
      const res = await app.request(`/admin/content?model=all${qs}`)
      expect(res.status).toBe(200)
      return res.text()
    }

    beforeEach(async () => {
      for (let i = 0; i < 25; i++) await createPost(`cap-${i}`)
    })

    it('shows the exact total (no "+") when matches fit inside the count window', async () => {
      const html = await list('&limit=100') // cap = 1000
      const total = footerTotal(html)
      expect(total).toMatch(/^\d+$/)
      expect(Number(total)).toBe(25)
      expect(badgeTotal(html)).toBe(total)
    })

    it('shows a lower bound "N+" in footer and header badge when the cap is hit', async () => {
      const html = await list('&limit=2') // page 1 → cap = 0 + 2*10 = 20 < 25 posts
      expect(footerTotal(html)).toBe('20+')
      expect(badgeTotal(html)).toBe('20+')
    })

    it('grows the count window as the user pages forward', async () => {
      const exact = Number(footerTotal(await list('&limit=100')))
      const html = await list('&limit=2&page=4') // offset 6 → cap = 26
      const expected = exact > 26 ? '26+' : String(exact)
      expect(footerTotal(html)).toBe(expected)
      expect(badgeTotal(html)).toBe(expected)
    })

    it('clamps invalid paging input instead of running an unbounded count', async () => {
      // limit=-1 previously produced cap -10 → LIMIT -9 (unlimited) and a negative total.
      expect(footerTotal(await list('&limit=-1'))).toBe('10+') // clamped to limit=1 → cap 10
      expect(footerTotal(await list('&limit=0'))).toBe('10+')
      const exact = footerTotal(await list('&limit=100'))
      // Garbage → default 20 (cap 200 > 25 posts → exact); oversized → clamped to 100.
      expect(footerTotal(await list('&limit=abc'))).toBe(exact)
      expect(footerTotal(await list('&limit=100000'))).toBe(exact)
      // Non-positive page → page 1 (the first 2 rows, cap 20).
      expect(footerTotal(await list('&limit=2&page=-5'))).toBe('20+')
      expect(footerTotal(await list('&limit=2&page=0'))).toBe('20+')
    })

    it('clamps very deep pages to the max offset instead of skipping millions of rows', async () => {
      // limit=100 → last allowed page = 10_000 / 100 + 1 = 101; page=100000 clamps there.
      const html = await list('&limit=100&page=100000')
      expect(html).toContain('No content found') // offset 10_000 > 25 posts → empty page, not an error
      // Footer "Showing 10001 to …": page clamped to 101 (offset 10_000), not 100000 (offset 9,999,900).
      expect(html).toMatch(/Showing <span[^>]*>10001<\/span>/)
    })

    it('all-view lists nothing when no visible document types remain (never internal ones)', async () => {
    await createPost('hidden-when-internal')
    // Mark every type internal: the registry then yields no visible types. An empty type filter used
    // to mean "unrestricted" and listed every document, internal/auth-owned ones included.
    db.raw.prepare(`UPDATE document_types SET settings = json_set(COALESCE(settings,'{}'), '$.internal', json('true'))`).run()
    const res = await app.request('/admin/content?model=all')
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).not.toContain('Post hidden-when-internal')
    expect(html).toContain('No content found')
  })
  })

  it('does NOT offer internal/auth-owned types as content models in the filter dropdown', async () => {
    const res = await app.request('/admin/content')
    expect(res.status).toBe(200)
    const htmlText = await res.text()
    // User-defined collection IS selectable.
    expect(htmlText).toContain('value="blog_post"')
    // Internal (settings.internal) / auth-owned (isAuth) types seeded by bootstrapDocumentTypes must NOT leak in.
    for (const internal of ['user_profile', 'site_settings', 'plugin', 'tenant', 'media_asset']) {
      expect(htmlText).not.toContain(`value="${internal}"`)
    }
  })

  it('does NOT offer internal/auth-owned types on the new-content collection selector', async () => {
    const res = await app.request('/admin/content/new')
    expect(res.status).toBe(200)
    const htmlText = await res.text()
    // The user-defined collection IS offered.
    expect(htmlText).toContain('/admin/content/new?collection=blog_post')
    // Internal/auth types must NOT appear as create-new-content options.
    for (const internal of ['user_profile', 'site_settings', 'plugin', 'tenant', 'media_asset', 'rbac_role']) {
      expect(htmlText).not.toContain(`?collection=${internal}`)
    }
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

// ── Collections without a title field (use name) — title derivation bug ─────

const NAME_ONLY_SCHEMA = JSON.stringify({
  type: 'object',
  properties: {
    name: { type: 'string', title: 'Name', required: true },
    emoji: { type: 'string', title: 'Emoji' },
    description: { type: 'string', title: 'Description' },
  },
  required: ['name'],
})

describe('admin-content title derivation from data.name field', () => {
  let db: any
  let app: any
  const COLL = 'example'

  beforeEach(async () => {
    db = createTestD1()
    const exampleCol = { name: 'example', displayName: 'Example', description: 'No title field', schema: JSON.parse(NAME_ONLY_SCHEMA) }
    registerCollections([exampleCol])
    getCollectionRegistry().register([exampleCol])
    await bootstrapDocumentTypes(db)
    await autoRegisterCollectionDocumentTypes(db)
    app = buildApp(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  function createExample(name: string) {
    return app.request('/admin/content', {
      method: 'POST',
      body: form({ collection_id: COLL, name, emoji: '😈', description: 'test', status: 'published', action: 'save_and_publish' }),
    })
  }

  it('create derives documents.title from data.name when no title field exists', async () => {
    const res = await createExample('Cruel')
    expect([200, 302]).toContain(res.status)
    const row = db.raw.prepare("SELECT title FROM documents WHERE type_id='example' AND is_current_draft=1").get()
    expect(row, 'document row must exist after create').toBeTruthy()
    expect(row.title).toBe('Cruel')
  })

  it('update reflects changed name in list title (not stale DB title)', async () => {
    await createExample('Cruel')
    const rootId = db.raw.prepare("SELECT root_id r FROM documents WHERE type_id='example'").get().r

    // Update name from "Cruel" to "Vicious"
    const res = await app.request(`/admin/content/${rootId}`, {
      method: 'PUT',
      body: form({ _method: 'PUT', collection_id: COLL, name: 'Vicious', emoji: '😈', description: 'updated', status: 'published', action: 'save_and_close' }),
    })
    expect([200, 302]).toContain(res.status)

    // DB title column must be "Vicious" (not stale "Cruel")
    const draft = db.raw.prepare("SELECT title FROM documents WHERE root_id=? AND is_current_draft=1").get(rootId)
    expect(draft.title).toBe('Vicious')

    // All-view list must show the updated name
    const listRes = await app.request('/admin/content')
    expect(listRes.status).toBe(200)
    const listHtml = await listRes.text()
    expect(listHtml).toContain('Vicious')
    expect(listHtml).not.toContain('>Cruel<')
  })
})
