// @ts-nocheck
// Route-level integration tests for the document-backed PUBLIC + CRUD content API (legacy `content`
// decommission). Mounts the real apiRoutes (which includes api-content-crud) on a Hono app over real
// SQLite (full doc schema via migrations 043/044). These lock in the §7 regression-audit fixes:
//   D29 — timestamps returned in MILLISECONDS (documents store seconds)
//   D30 — GET /:id resolves a DRAFT for privileged callers (404 for anon)
//   D31 — ?collection_id= and sort-by-collection_id no longer 500
//   D32 — ?status= honored for privileged callers (published vs draft)
//   D37 — slug uniqueness considers a still-served published row
//   D38 — PUT without an explicit status preserves the published state
//   D39 — soft-deleted roots: PUT 404s, a second DELETE 404s
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

// optionalAuth/requireAuth/requireRole come from ../middleware (barrel) which re-exports ./auth. Mock
// ./auth so optionalAuth derives the role from a test header (no JWT needed) and the write guards pass.
vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
  optionalAuth: () => async (c: any, next: any) => {
    const role = c.req.header('x-test-role')
    if (role) c.set('user', { userId: 'u1', email: 'a@b.c', role })
    await next()
  },
}))

import apiRoutes from '../../routes/api'
import { DocumentsService } from '../../services/documents'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'

const BLOG_SCHEMA = JSON.stringify({
  type: 'object',
  properties: {
    title: { type: 'string', title: 'Title', required: true },
    slug: { type: 'string', title: 'Slug', required: true },
    content: { type: 'string', title: 'Content' },
    author: { type: 'string', title: 'Author' },
  },
  required: ['title', 'slug'],
})

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    await next()
  })
  app.route('/api', apiRoutes)
  return app
}

const json = (role?: string) => ({
  'content-type': 'application/json',
  ...(role ? { 'x-test-role': role } : {}),
})

describe('document-backed content API — regression-audit fixes (§7)', () => {
  let db: any
  let app: any
  // Collections are code-only now (id === name). The doc type id is the collection id.
  const COLL = 'blog_post'

  async function post(body: any, role = 'admin') {
    return app.request('/api/content', { method: 'POST', headers: json(role), body: JSON.stringify(body) })
  }
  async function put(rootId: string, body: any, role = 'admin') {
    return app.request(`/api/content/${rootId}`, { method: 'PUT', headers: json(role), body: JSON.stringify(body) })
  }
  async function del(rootId: string, role = 'admin') {
    return app.request(`/api/content/${rootId}`, { method: 'DELETE', headers: json(role) })
  }
  const rootOf = (slug: string) =>
    db.raw.prepare("SELECT root_id r FROM documents WHERE slug=? ORDER BY version_number DESC LIMIT 1").get(slug)?.r

  beforeEach(async () => {
    db = createTestD1()
    getCollectionRegistry().register([{ name: 'blog_post', displayName: 'Blog Posts', description: 'Blog', schema: JSON.parse(BLOG_SCHEMA) }])
    await bootstrapDocumentTypes(db) // registers the blog_post document type → collection is doc-backed
    app = buildApp(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  // ── D29 ──────────────────────────────────────────────────────────────────
  it('D29: POST + list + GET return timestamps in MILLISECONDS (documents store seconds)', async () => {
    const res = await post({ collectionId: COLL, title: 'TS Post', slug: 'ts-post', status: 'published', data: {} })
    expect(res.status).toBe(201)
    const created = (await res.json()).data
    const storedSec = db.raw.prepare("SELECT created_at c FROM documents WHERE slug='ts-post' AND is_published=1").get().c
    expect(storedSec).toBeLessThan(1e11)          // seconds in the table
    expect(created.created_at).toBe(storedSec * 1000) // milliseconds in the API response
    expect(created.created_at).toBeGreaterThan(1e12)

    const listRes = await app.request('/api/content?collection=blog_post')
    const item = (await listRes.json()).data.find((d: any) => d.slug === 'ts-post')
    expect(item.created_at).toBe(storedSec * 1000)

    const getRes = await app.request(`/api/content/${created.id}`, { headers: json('admin') })
    expect((await getRes.json()).data.created_at).toBe(storedSec * 1000)
  })

  // ── D30 ──────────────────────────────────────────────────────────────────
  it('D30: GET /:id returns a DRAFT for privileged callers but 404 for anon', async () => {
    const res = await post({ collectionId: COLL, title: 'Draft One', slug: 'draft-one', status: 'draft', data: {} })
    const rootId = (await res.json()).data.id

    const priv = await app.request(`/api/content/${rootId}`, { headers: json('admin') })
    expect(priv.status).toBe(200)
    expect((await priv.json()).data.slug).toBe('draft-one')

    const anon = await app.request(`/api/content/${rootId}`)
    expect(anon.status).toBe(404)
  })

  // ── D31 ──────────────────────────────────────────────────────────────────
  it('D31: ?collection_id= filter and sort-by-collection_id return 200 (not 500)', async () => {
    await post({ collectionId: COLL, title: 'Cid Post', slug: 'cid-post', status: 'published', data: {} })

    const byId = await app.request(`/api/content?collection_id=${COLL}`)
    expect(byId.status).toBe(200)
    const body = await byId.json()
    expect(body.data.some((d: any) => d.slug === 'cid-post')).toBe(true)
    expect(body.data.every((d: any) => d.collectionId === COLL)).toBe(true)

    const sorted = await app.request(`/api/content?sort=${encodeURIComponent(JSON.stringify([{ field: 'collection_id', order: 'asc' }]))}`)
    expect(sorted.status).toBe(200)
  })

  // ── D32 ──────────────────────────────────────────────────────────────────
  it('D32: privileged ?status= filter selects published vs draft', async () => {
    await post({ collectionId: COLL, title: 'Pub', slug: 'pub-1', status: 'published', data: {} })
    await post({ collectionId: COLL, title: 'Dft', slug: 'dft-1', status: 'draft', data: {} })

    const pub = await app.request('/api/content?collection=blog_post&status=published', { headers: json('admin') })
    const pubSlugs = (await pub.json()).data.map((d: any) => d.slug)
    expect(pubSlugs).toContain('pub-1')
    expect(pubSlugs).not.toContain('dft-1')

    const dft = await app.request('/api/content?collection=blog_post&status=draft', { headers: json('admin') })
    const dftSlugs = (await dft.json()).data.map((d: any) => d.slug)
    expect(dftSlugs).toContain('dft-1')
    expect(dftSlugs).not.toContain('pub-1')
  })

  // ── D37 ──────────────────────────────────────────────────────────────────
  it('D37: a slug served by a published row is rejected as a duplicate', async () => {
    const created = await post({ collectionId: COLL, title: 'First', slug: 'taken', status: 'published', data: {} })
    const rootId = (await created.json()).data.id
    // An editor saves a RENAMED draft without publishing: the published v1 still serves "taken" while
    // the current draft moves to "taken-v2". The old check (is_current_draft only) missed the published
    // slug → "taken" read as available.
    await new DocumentsService(db, { tenantId: 'default' }).saveDraft(rootId, { slug: 'taken-v2', title: 'First v2' }, 'u1')
    expect(db.raw.prepare("SELECT slug FROM documents WHERE root_id=? AND is_published=1").get(rootId).slug).toBe('taken')
    expect(db.raw.prepare("SELECT slug FROM documents WHERE root_id=? AND is_current_draft=1").get(rootId).slug).toBe('taken-v2')

    const dup = await post({ collectionId: COLL, title: 'Clash', slug: 'taken', status: 'published', data: {} })
    expect(dup.status).toBe(409)
  })

  // ── D38 ──────────────────────────────────────────────────────────────────
  it('D38: PUT without a status keeps a published item published', async () => {
    const res = await post({ collectionId: COLL, title: 'Live', slug: 'live', status: 'published', data: {} })
    const rootId = (await res.json()).data.id
    const putRes = await put(rootId, { title: 'Live edited', data: { content: 'x' } }) // no status field
    expect(putRes.status).toBe(200)
    expect((await putRes.json()).data.status).toBe('published')
    // exactly one published row still serves the root
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1").get(rootId).n).toBe(1)
    // anon can still read it
    const anon = await app.request(`/api/content/${rootId}`)
    expect(anon.status).toBe(200)
    expect((await anon.json()).data.title).toBe('Live edited')
  })

  // ── D39 ──────────────────────────────────────────────────────────────────
  it('D39: a second DELETE 404s and PUT cannot resurrect a soft-deleted root', async () => {
    const res = await post({ collectionId: COLL, title: 'Doomed', slug: 'doomed', status: 'published', data: {} })
    const rootId = (await res.json()).data.id

    expect((await del(rootId)).status).toBe(200)
    expect((await del(rootId)).status).toBe(404)
    expect((await put(rootId, { title: 'zombie' })).status).toBe(404)
  })
})
