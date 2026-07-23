/**
 * Assembled gate tests — the plugin's security controls against a real (SQLite)
 * D1 and live requests through the actual admin sub-app.
 *
 * Proves the B3 deactivate→404 gate in BOTH directions, the auth gate, and that
 * the spec endpoint inherits both gates.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { apiDocsAdminRoutes, API_DOCS_PLUGIN_ID } from '../routes/admin'
import { invalidatePluginStatusCache } from '../../../../middleware/plugin-middleware'
import { createTestD1, type TestD1 } from '../../../../__tests__/utils/d1-sqlite'

let db: TestD1

const ADMIN = { userId: 'u1', email: 'admin@test.local', role: 'admin' }

/** Seed the plugin's `documents` row with a given active/inactive status. */
function seedStatus(status: 'active' | 'inactive') {
  db.raw
    .prepare(
      `INSERT INTO documents (id, root_id, type_id, slug, tenant_id, is_current_draft, data)
       VALUES (?, ?, 'plugin', ?, 'default', 1, ?)`,
    )
    .run('doc-apidocs', 'root-apidocs', API_DOCS_PLUGIN_ID, JSON.stringify({ status }))
}

/** Build the sub-app with an optional injected user, and make one request. */
function request(path: string, opts: { user?: typeof ADMIN; accept?: string } = {}) {
  const app = new Hono<{ Bindings: { DB: unknown }; Variables: { user?: typeof ADMIN } }>()
  app.use('*', async (c, next) => {
    if (opts.user) c.set('user', opts.user)
    await next()
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test env binding
  app.route('/admin/plugins/api-docs', apiDocsAdminRoutes as any)
  return app.request(path, { headers: opts.accept ? { Accept: opts.accept } : {} }, { DB: db })
}

beforeEach(() => {
  db = createTestD1()
  // The per-isolate status cache is module-level; clear it so each test's seed
  // is authoritative (the exact caveat documented on the gate).
  invalidatePluginStatusCache(API_DOCS_PLUGIN_ID)
})

afterEach(() => {
  db.close()
  invalidatePluginStatusCache(API_DOCS_PLUGIN_ID)
})

describe('api-docs admin gate', () => {
  it('404s the page when the plugin is deactivated (no active row)', async () => {
    // no seed → not active
    const res = await request('/admin/plugins/api-docs', { user: ADMIN })
    expect(res.status).toBe(404)
  })

  it('404s the page when the plugin row is explicitly inactive', async () => {
    seedStatus('inactive')
    const res = await request('/admin/plugins/api-docs', { user: ADMIN })
    expect(res.status).toBe(404)
  })

  it('serves the page (200) when active + authenticated', async () => {
    seedStatus('active')
    const res = await request('/admin/plugins/api-docs', { user: ADMIN })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('API Reference')
  })

  it('401s an unauthenticated request (auth gate runs first)', async () => {
    seedStatus('active')
    const res = await request('/admin/plugins/api-docs', { accept: 'application/json' })
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: 'Authentication required' })
  })

  it('serves the OpenAPI spec (200 JSON) when active + authed', async () => {
    seedStatus('active')
    const res = await request('/admin/plugins/api-docs/openapi.json', { user: ADMIN })
    expect(res.status).toBe(200)
    const spec = (await res.json()) as { openapi: string; info: { title: string } }
    expect(spec.openapi).toBe('3.0.0')
    expect(spec.info.title).toBe('SonicJS AI API')
  })

  it('404s the spec when deactivated (spec inherits the gate)', async () => {
    const res = await request('/admin/plugins/api-docs/openapi.json', { user: ADMIN })
    expect(res.status).toBe(404)
  })
})
