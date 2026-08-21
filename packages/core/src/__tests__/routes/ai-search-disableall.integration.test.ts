// @ts-nocheck
// Behavioral proof that the public /api/search endpoint works on a plugins-off ("bare core") deploy.
//
// #1058 promoted /api/search OUT of the ai-search plugin and mounted it as a CORE route in app.ts,
// BEFORE the generic /api/:collection catch-all. This is what lets a `disableAll: true` deploy — where
// every plugin (core and user) is off — still serve search: the endpoint no longer depends on plugin
// registration, and it wins over the collection catch-all instead of being shadowed by it.
//
// This test reconstructs that exact topology WITHOUT createSonicJSApp() (which transitively imports
// better-auth and is therefore quarantined from CI — see vitest.config.ts), by mounting the real route
// modules over a real D1 (SQLite) shim with auth middleware stubbed, the established pattern in
// api-public-content-documents.integration.test.ts. The literal "route is present under disableAll"
// assertion lives in plugins/mount-integration.test.ts (route-table introspection over the app factory).
//
// Two properties are locked in:
//   1. Results  — with search mounted as core (plugins off), an anonymous POST /api/search returns
//                 published documents (D5 public-read allowlist), i.e. search is functional, not just wired.
//   2. Ordering — reversing the mount order (catch-all first) re-introduces the historical shadow: the
//                 request falls through to /api/:collection's requireAuth and 401s. This proves the test
//                 is actually sensitive to the regression it guards.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'

// Stub the core middleware so importing the generic content router does not pull in better-auth.
// requireAuth() mirrors production: 401 for an anonymous caller — the exact response that shadowed
// /api/search on `main` before the core-promotion.
const h = vi.hoisted(() => ({ user: undefined as undefined | { userId: string; email: string; role: string } }))
vi.mock('../../middleware', () => ({
  optionalAuth: () => async (c: any, next: any) => { if (h.user) c.set('user', h.user); await next() },
  isPluginActive: async () => false,
  requireAuth: () => async (c: any, next: any) => {
    if (!c.get('user')) return c.json({ error: 'Authentication required' }, 401)
    await next()
  },
  requireRole: () => async (_c: any, next: any) => next(),
}))

import apiRoutes from '../../routes/api'
import aiSearchApiRoutes from '../../plugins/core-plugins/ai-search-plugin/routes/api'

const FTS_FIELDS = [{ name: 'body', kind: 'fulltext' }]

/**
 * Build a bare-core app: NO plugins mounted, only the core content router (`/api`) plus the
 * core-promoted search route (`/api/search`). `searchFirst` picks the mount order — true is the
 * shipped (correct) order, false reproduces the pre-#1058 shadow.
 */
function buildBareCoreApp(db: any, searchFirst: boolean) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    c.set('tenantId', 'default')
    await next()
  })
  if (searchFirst) {
    app.route('/api/search', aiSearchApiRoutes)
    app.route('/api', apiRoutes)
  } else {
    app.route('/api', apiRoutes)
    app.route('/api/search', aiSearchApiRoutes)
  }
  return app
}

async function seedPublishedArticle(db: any) {
  // Public-readable type (baseGrants.public:['read']) so the anonymous D5 allowlist admits it.
  db.raw
    .prepare(
      `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
       VALUES ('article','article','Article','{}','[]','{"baseGrants":{"public":["read"]}}','system',1,1,1,1,1)`,
    )
    .run()
  const docs = new DocumentsService(db, {
    queryableFields: FTS_FIELDS,
    tenantId: 'default',
    typeSchemaVersion: 1,
    versioning: false,
  })
  const doc = await docs.create(
    { typeId: 'article', tenantId: 'default', title: 'Telescope Guide', slug: 'tg', data: { body: 'stars and galaxies' } },
    'u1',
  )
  await docs.publish(doc.id, 'u1')
  return doc
}

async function search(app: any) {
  const res = await app.request('/api/search', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'telescope', mode: 'keyword' }),
  })
  return res
}

describe('/api/search on a plugins-off (disableAll) deploy — core-promotion, #1058', () => {
  let db: any
  let published: any

  beforeEach(async () => {
    h.user = undefined
    db = createTestD1()
    published = await seedPublishedArticle(db)
  })
  afterEach(() => db.close())

  it('anonymous POST /api/search returns published results with no plugins mounted', async () => {
    const res = await search(buildBareCoreApp(db, /* searchFirst */ true))

    // 401 here would mean the request fell through to /api/:collection (the shadow); 200 proves the
    // core search route wins even though not a single plugin is mounted.
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.success).toBe(true) // search envelope, not the collection error shape
    expect(json.data.mode).toBe('keyword')
    expect(json.data.results.map((r: any) => r.id)).toContain(published.id)
  })

  it('regression guard: the pre-#1058 mount order shadows /api/search back to a 401', async () => {
    const res = await search(buildBareCoreApp(db, /* searchFirst */ false))
    expect(res.status).toBe(401) // /api/:collection requireAuth — the exact bug the ordering fixes
  })
})
