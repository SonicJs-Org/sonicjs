// Regression coverage for the per-isolate registry cache going stale (CI run 39582792718,
// 70-multi-tenant "switching the active tenant updates the current-tenant indicator").
//
// `loadTenantState` caches the tenant registry per isolate for 30s, and on an /admin request only
// the plugin's *activation flag* is re-read on a cache hit — the registry is kept. A tenant created
// on another isolate is therefore unknown here, `resolveTenantSlug` rejects the switcher's cookie
// because the slug is not in the registry, and the request silently serves as 'default'. These
// tests drive the middleware through a real Hono app with a mock D1 whose `auth_tenant` rows change
// between requests while the cache stays warm.
import { describe, it, expect, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { tenantMiddleware, invalidateTenantCache } from '../../../../middleware/tenant'

type TenantRow = { slug: string; name: string; status: string; domain: string | null }

function mockDb(tenants: TenantRow[]) {
  const counts = { plugin: 0, registry: 0 }
  const db = {
    rows: tenants,
    counts,
    prepare(sql: string) {
      const isPlugin = sql.includes("type_id = 'plugin'")
      const isRegistry = sql.includes('FROM auth_tenant')
      return {
        bind() {
          return this
        },
        async first() {
          if (!isPlugin) return null
          counts.plugin++
          return { data: JSON.stringify({ settings: {} }) }
        },
        async all() {
          if (!isRegistry) return { results: [] }
          counts.registry++
          return { results: db.rows }
        },
      }
    },
  }
  return db
}

function appWith(db: ReturnType<typeof mockDb>) {
  const app = new Hono()
  app.use('*', tenantMiddleware())
  app.get('/admin/tenants', (c) => c.json({ tenant: c.get('tenantId' as never) }))
  app.get('/api/thing', (c) => c.json({ tenant: c.get('tenantId' as never) }))
  const call = async (path: string, cookie?: string) => {
    const res = await app.request(
      path,
      { headers: cookie ? { Cookie: `sonicjs-tenant=${cookie}` } : {} },
      { DB: db } as never
    )
    return (await res.json()) as { tenant: string }
  }
  return { call }
}

describe('tenant registry staleness across isolates', () => {
  beforeEach(() => {
    invalidateTenantCache()
  })

  it('resolves a tenant that appeared in the registry after this isolate cached it', async () => {
    const db = mockDb([
      { slug: 'default', name: 'Default', status: 'active', domain: null },
      { slug: 'acme1', name: 'Acme One', status: 'active', domain: null },
    ])
    const { call } = appWith(db)

    // Warm the cache on a slug this isolate does know.
    expect((await call('/admin/tenants', 'acme1')).tenant).toBe('acme1')
    const registryReadsAfterWarm = db.counts.registry

    // Another isolate creates acme2. This isolate's cache is still inside its 30s TTL.
    db.rows = [...db.rows, { slug: 'acme2', name: 'Acme Two', status: 'active', domain: null }]

    expect((await call('/admin/tenants', 'acme2')).tenant).toBe('acme2')
    expect(db.counts.registry).toBeGreaterThan(registryReadsAfterWarm)
  })

  it('does not re-read the registry for a slug it already holds', async () => {
    const db = mockDb([
      { slug: 'default', name: 'Default', status: 'active', domain: null },
      { slug: 'acme1', name: 'Acme One', status: 'active', domain: null },
    ])
    const { call } = appWith(db)

    await call('/admin/tenants', 'acme1')
    const registryReadsAfterWarm = db.counts.registry

    await call('/admin/tenants', 'acme1')
    expect(db.counts.registry).toBe(registryReadsAfterWarm)
  })

  it('leaves public and API traffic on the cached fast path', async () => {
    const db = mockDb([{ slug: 'default', name: 'Default', status: 'active', domain: null }])
    const { call } = appWith(db)

    // Warm the cache, then ask for a slug the registry has never held. An unauthenticated caller
    // must not be able to force a registry reload by guessing slugs.
    await call('/api/thing')
    const registryReadsAfterWarm = db.counts.registry

    expect((await call('/api/thing', 'whatever')).tenant).toBe('default')
    expect(db.counts.registry).toBe(registryReadsAfterWarm)
  })

  it('still falls back to default when the slug does not exist anywhere', async () => {
    const db = mockDb([{ slug: 'default', name: 'Default', status: 'active', domain: null }])
    const { call } = appWith(db)

    expect((await call('/admin/tenants', 'ghost')).tenant).toBe('default')
  })

  it('does not resolve a tenant that exists but is inactive', async () => {
    const db = mockDb([
      { slug: 'default', name: 'Default', status: 'active', domain: null },
      { slug: 'frozen', name: 'Frozen', status: 'inactive', domain: null },
    ])
    const { call } = appWith(db)

    expect((await call('/admin/tenants', 'frozen')).tenant).toBe('default')
  })
})
