// @ts-nocheck
// Public content API status-visibility policy — now document-backed (legacy content decommission).
// Rewritten from SQL-param assertions (old content-table impl) to behavior assertions against real
// SQLite: the policy is unchanged (anon/viewer/author see only published; admin/editor see drafts),
// it's just enforced via documents (is_published / is_current_draft) instead of a content status filter.
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import apiRoutes from '../../routes/api'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'

// In production app.ts mounts a global Better Auth session middleware that populates c.get('user').
// optionalAuth() is a no-op, so this harness must inject the caller the same way.
let testUser: { userId: string; email: string; role: string } | undefined

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db, KV: {} }
    c.set('startTime', Date.now())
    if (testUser) c.set('user', testUser)
    await next()
  })
  app.route('/api', apiRoutes)
  return app
}

describe('Public content API status policy (documents-backed)', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    vi.restoreAllMocks()
    testUser = undefined
    db = createTestD1()
    getCollectionRegistry().register([{ name: 'pages', displayName: 'Pages', schema: {} }])
    const svc = new DocumentsService(db, { tenantId: 'default', queryableFields: [] })
    await svc.create({ typeId: 'pages', tenantId: 'default', title: 'Published', slug: 'published', data: {}, publishOnCreate: true })
    await svc.create({ typeId: 'pages', tenantId: 'default', title: 'Draft', slug: 'draft', data: {} })
    app = buildApp(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry(); testUser = undefined })

  const authAs = (role: string) => { testUser = { userId: 'u', email: 'e@f.g', role } }

  const slugs = (body: any) => (body.data ?? []).map((d: any) => d.slug).sort()

  it('forces anonymous /api/content requests to published (ignores ?status=draft)', async () => {
    const res = await app.request('/api/content?collection=pages&status=draft')
    expect(res.status).toBe(200)
    expect(slugs(await res.json())).toEqual(['published'])
  })

  it('forces anonymous collection content to published even with raw where status filters', async () => {
    const where = encodeURIComponent(JSON.stringify({ or: [{ field: 'status', operator: 'not_equals', value: 'published' }] }))
    const res = await app.request(`/api/collections/pages/content?where=${where}`)
    expect(res.status).toBe(200)
    expect(slugs(await res.json())).toEqual(['published'])
  })

  it('preserves draft visibility for authenticated admin requests', async () => {
    authAs('admin')
    const res = await app.request('/api/content?collection=pages', { headers: { Cookie: 'auth_token=valid' } })
    expect(slugs(await res.json())).toEqual(['draft', 'published'])
  })

  it('forces published filtering for authenticated viewer requests', async () => {
    authAs('viewer')
    const res = await app.request('/api/content?collection=pages', { headers: { Cookie: 'auth_token=valid' } })
    expect(slugs(await res.json())).toEqual(['published'])
  })

  it('forces published filtering for authenticated author requests', async () => {
    authAs('author')
    const res = await app.request('/api/content?collection=pages&status=archived', { headers: { Cookie: 'auth_token=valid' } })
    expect(slugs(await res.json())).toEqual(['published'])
  })
})
