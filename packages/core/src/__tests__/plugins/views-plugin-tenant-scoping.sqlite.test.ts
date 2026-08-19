/**
 * Real-SQLite coverage for Views' tenant scoping — the re-ground this branch needed on top of
 * the original port. Before this: `views`/`view_displays` had no `tenant_id` column at all, so
 * on a multi-tenant install every tenant could see, edit, and publish over every other tenant's
 * views/displays, and `name`/`path` were globally unique (blocking two tenants from ever using
 * the same one). These tests prove: (1) per-tenant uniqueness actually works (not just doesn't
 * error — a same-named/pathed row in tenant A must not affect tenant B), (2) admin routes are
 * tenant-scoped end to end, (3) the public embed route resolves the correct tenant's row when
 * two tenants share a path, (4) cache keys don't cross tenants, (5) the self-heal migration
 * correctly upgrades a pre-tenant-scoping installation without losing data.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import { VIEWS_MIGRATION_STATEMENTS, ensureViewsTenantUniqueness } from '../../plugins/core-plugins/views-plugin/migrations'
import { adminViewsRoutes } from '../../plugins/core-plugins/views-plugin/routes/admin-views'
import { publicViewDisplaysRoutes } from '../../plugins/core-plugins/views-plugin/routes/public-view-displays'
import { ViewDisplayRepository } from '../../plugins/core-plugins/views-plugin/services/view-display-repository'
import { ViewCacheService } from '../../plugins/core-plugins/views-plugin/services/view-cache'

let db: TestD1
const asD1 = (): D1Database => db as unknown as D1Database

async function provisionFreshSchema(): Promise<void> {
  for (const stmt of VIEWS_MIGRATION_STATEMENTS) await db.prepare(stmt).run()
}

function insertView(
  id: string,
  tenantId: string,
  name: string,
  extra: { isPublic?: boolean; collectionId?: string | null } = {},
): Promise<unknown> {
  return db
    .prepare(
      `INSERT INTO views (id, tenant_id, name, display_name, collection_id, page_size, is_public, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 25, ?, 'active', 1, 1)`,
    )
    .bind(id, tenantId, name, name, extra.collectionId ?? null, extra.isPublic ? 1 : 0)
    .run()
}

/** A document type with a public-read grant (registered once, NOT tenant-scoped) + one
 *  published document PER TENANT (documents ARE tenant-scoped) — collection_id for embed
 *  tests (executePublic's collection-grant backstop requires this to serve anything). Distinct
 *  titles per tenant let a test assert the embed actually returned that tenant's own content,
 *  not just "some" row. */
const PUBLIC_TYPE = 'pub-roster'
async function seedPublicCollectionType(): Promise<void> {
  await db
    .prepare(
      `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
       VALUES (?,?,?,'{}','[]',?,'system',1,0,1,1,1)`,
    )
    .bind(PUBLIC_TYPE, PUBLIC_TYPE, 'Public Roster', JSON.stringify({ baseGrants: { public: ['read'] } }))
    .run()
}
async function seedPublicDoc(tenantId: string, title: string): Promise<void> {
  const { DocumentsService } = await import('../../services/documents')
  const svc = new DocumentsService(asD1(), { queryableFields: [], tenantId, typeSchemaVersion: 1, versioning: false })
  await svc.create(
    { typeId: PUBLIC_TYPE, tenantId, locale: 'default', parentRootId: '', slug: title.toLowerCase(), title, zone: null, sortOrder: 0, visible: true, data: {}, metadata: {}, publishOnCreate: true },
    'u1',
  )
}

function insertDisplay(id: string, tenantId: string, viewId: string, path: string, shareToken: string): Promise<unknown> {
  return db
    .prepare(
      `INSERT INTO view_displays (id, tenant_id, view_id, display_type, path, config, is_public, share_token, created_at, updated_at)
       VALUES (?, ?, ?, 'table', ?, '{"type":"table","version":1,"columns":["title"],"pageSize":25,"paginate":"offset"}', 1, ?, 1, 1)`,
    )
    .bind(id, tenantId, viewId, path, shareToken)
    .run()
}

/** A minimal Hono app that mimics tenantMiddleware's contract: sets c.get('tenantId') from a
 *  header, exactly what getRequestTenant() reads — real production wiring, not a stand-in. */
function buildApp(): Hono {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: asD1(), CACHE_KV: undefined }
    c.set('tenantId', c.req.header('x-tenant') ?? 'default')
    c.set('user', { userId: 'u1', email: 'a@b.c', role: 'admin' })
    await next()
  })
  app.route('/admin/views', adminViewsRoutes)
  app.route('/v', publicViewDisplaysRoutes)
  return app
}

describe('Views — tenant scoping', () => {
  beforeEach(async () => {
    db = createTestD1()
    await provisionFreshSchema()
  })
  afterEach(() => db.close())

  describe('per-tenant uniqueness', () => {
    it('two tenants can each have a view named the same thing', async () => {
      await insertView('v-a', 'tenant-a', 'employees')
      await expect(insertView('v-b', 'tenant-b', 'employees')).resolves.toBeTruthy()
    })

    it('the same tenant still cannot reuse a name (constraint survives the per-tenant scoping)', async () => {
      await insertView('v-1', 'tenant-a', 'employees')
      await expect(insertView('v-2', 'tenant-a', 'employees')).rejects.toThrow(/UNIQUE/i)
    })

    it('two tenants can each publish a display at the same path', async () => {
      await insertView('v-a', 'tenant-a', 'team')
      await insertView('v-b', 'tenant-b', 'team')
      await insertDisplay('d-a', 'tenant-a', 'v-a', 'team-directory', '_tokenaaaaaaaaaaaaaaaaaaaaaaaaaa')
      await expect(
        insertDisplay('d-b', 'tenant-b', 'v-b', 'team-directory', '_tokenbbbbbbbbbbbbbbbbbbbbbbbbbb'),
      ).resolves.toBeTruthy()
    })

    it('the same tenant still cannot reuse a path', async () => {
      await insertView('v-1', 'tenant-a', 'v1')
      await insertView('v-2', 'tenant-a', 'v2')
      await insertDisplay('d-1', 'tenant-a', 'v-1', 'team-directory', '_tokenaaaaaaaaaaaaaaaaaaaaaaaaaa')
      await expect(
        insertDisplay('d-2', 'tenant-a', 'v-2', 'team-directory', '_tokenbbbbbbbbbbbbbbbbbbbbbbbbbb'),
      ).rejects.toThrow(/UNIQUE/i)
    })

    it('share_token stays globally unique across tenants (deliberately not tenant-scoped)', async () => {
      await insertView('v-a', 'tenant-a', 'view-a')
      await insertView('v-b', 'tenant-b', 'view-b')
      await insertDisplay('d-a', 'tenant-a', 'v-a', 'path-a', '_sharedtoken00000000000000000000')
      await expect(
        insertDisplay('d-b', 'tenant-b', 'v-b', 'path-b', '_sharedtoken00000000000000000000'),
      ).rejects.toThrow(/UNIQUE/i)
    })
  })

  describe('admin routes are tenant-scoped end to end', () => {
    it('GET /admin/views/api/ only lists the requesting tenant\'s views', async () => {
      await insertView('v-a', 'tenant-a', 'alpha')
      await insertView('v-b', 'tenant-b', 'beta')
      const app = buildApp()

      const resA = await app.request('/admin/views/api/', { headers: { 'x-tenant': 'tenant-a' } })
      const dataA = (await resA.json()) as { data: Array<{ name: string }> }
      expect(dataA.data.map((v) => v.name)).toEqual(['alpha'])

      const resB = await app.request('/admin/views/api/', { headers: { 'x-tenant': 'tenant-b' } })
      const dataB = (await resB.json()) as { data: Array<{ name: string }> }
      expect(dataB.data.map((v) => v.name)).toEqual(['beta'])
    })

    it('a tenant cannot GET, PUT, or DELETE another tenant\'s view by id', async () => {
      await insertView('v-a', 'tenant-a', 'alpha')
      const app = buildApp()

      const getRes = await app.request('/admin/views/v-a', { headers: { 'x-tenant': 'tenant-b', Accept: 'text/html' } })
      // Not-found path renders the editor page with an error, not a 404 status — assert on content.
      expect(await getRes.text()).toContain('View not found')

      const putRes = await app.request('/admin/views/api/v-a', {
        method: 'PUT',
        headers: { 'x-tenant': 'tenant-b', 'Content-Type': 'application/json' },
        body: JSON.stringify({ display_name: 'hijacked' }),
      })
      expect(putRes.status).toBe(404)

      const delRes = await app.request('/admin/views/api/v-a', { method: 'DELETE', headers: { 'x-tenant': 'tenant-b' } })
      expect(delRes.status).toBe(404)

      // Prove tenant-a's row is genuinely untouched, not just that the request 404'd.
      const row = await db.prepare('SELECT display_name, status FROM views WHERE id = ?').bind('v-a').first<{ display_name: string; status: string }>()
      expect(row?.display_name).toBe('alpha')
      expect(row?.status).toBe('active')
    })

    it('POST /admin/views/api creates the view under the requesting tenant, not "default"', async () => {
      const app = buildApp()
      const res = await app.request('/admin/views/api', {
        method: 'POST',
        headers: { 'x-tenant': 'tenant-a', 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'roster' }),
      })
      expect(res.status).toBe(201)
      const row = await db.prepare('SELECT tenant_id FROM views WHERE name = ?').bind('roster').first<{ tenant_id: string }>()
      expect(row?.tenant_id).toBe('tenant-a')

      // And a second tenant can create a view with the SAME name without colliding.
      const res2 = await app.request('/admin/views/api', {
        method: 'POST',
        headers: { 'x-tenant': 'tenant-b', 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'roster' }),
      })
      expect(res2.status).toBe(201)
    })

    it('id derivation is unambiguous across (tenant, name) pairs that would collide under naive concatenation', async () => {
      // Found in review: a plain `${tenantId}-${name}-view` id lets tenant "acme" naming a view
      // "eu-sales" collide with tenant "acme-eu" naming a view "sales" (both derive
      // "acme-eu-sales-view"). Length-prefixing the tenant makes the boundary unambiguous — both
      // creates must succeed, and each must land in its own actual tenant's row.
      const app = buildApp()
      const res1 = await app.request('/admin/views/api', {
        method: 'POST',
        headers: { 'x-tenant': 'acme', 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'eu-sales' }),
      })
      expect(res1.status).toBe(201)

      const res2 = await app.request('/admin/views/api', {
        method: 'POST',
        headers: { 'x-tenant': 'acme-eu', 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'sales' }),
      })
      expect(res2.status, `should not collide with tenant "acme"'s "eu-sales" view: ${JSON.stringify(await res2.json())}`).toBe(201)

      const rowAcme = await db.prepare("SELECT tenant_id, name FROM views WHERE tenant_id = 'acme'").first<{ tenant_id: string; name: string }>()
      expect(rowAcme).toEqual({ tenant_id: 'acme', name: 'eu-sales' })
      const rowAcmeEu = await db.prepare("SELECT tenant_id, name FROM views WHERE tenant_id = 'acme-eu'").first<{ tenant_id: string; name: string }>()
      expect(rowAcmeEu).toEqual({ tenant_id: 'acme-eu', name: 'sales' })
    })
  })

  describe('the public embed route resolves the correct tenant when paths collide', () => {
    it('GET /v/:path serves tenant A\'s content for tenant A, tenant B\'s for tenant B', async () => {
      await seedPublicCollectionType()
      await seedPublicDoc('tenant-a', 'Row For Tenant A')
      await seedPublicDoc('tenant-b', 'Row For Tenant B')
      await insertView('v-a', 'tenant-a', 'roster-a', { collectionId: PUBLIC_TYPE })
      await insertView('v-b', 'tenant-b', 'roster-b', { collectionId: PUBLIC_TYPE })
      // Same path, two different tenants, two different (fake) share tokens.
      await insertDisplay('d-a', 'tenant-a', 'v-a', 'shared-path', '_tokenaaaaaaaaaaaaaaaaaaaaaaaaaa')
      await insertDisplay('d-b', 'tenant-b', 'v-b', 'shared-path', '_tokenbbbbbbbbbbbbbbbbbbbbbbbbbb')

      const app = buildApp()
      const resA = await app.request('/v/shared-path', { headers: { 'x-tenant': 'tenant-a' } })
      const resB = await app.request('/v/shared-path', { headers: { 'x-tenant': 'tenant-b' } })

      expect(resA.status).toBe(200)
      expect(resB.status).toBe(200)
      const htmlA = await resA.text()
      const htmlB = await resB.text()
      // The point of the test: same path, but each tenant's request rendered ITS OWN data —
      // not whichever row happened to be inserted first, and not a leak of the other tenant's.
      expect(htmlA).toContain('Row For Tenant A')
      expect(htmlA).not.toContain('Row For Tenant B')
      expect(htmlB).toContain('Row For Tenant B')
      expect(htmlB).not.toContain('Row For Tenant A')
    })

    it('a request with no tenant match 404s rather than falling through to another tenant\'s row', async () => {
      await seedPublicCollectionType()
      await seedPublicDoc('tenant-a', 'Row For Tenant A')
      await insertView('v-a', 'tenant-a', 'roster-a', { collectionId: PUBLIC_TYPE })
      await insertDisplay('d-a', 'tenant-a', 'v-a', 'only-in-a', '_tokenaaaaaaaaaaaaaaaaaaaaaaaaaa')

      const app = buildApp()
      const res = await app.request('/v/only-in-a', { headers: { 'x-tenant': 'tenant-b' } })
      expect(res.status).toBe(404)
    })
  })

  describe('cache keys do not cross tenants', () => {
    it('buildKey/buildEmbedKey differ by tenant for the same view/path', () => {
      const keyA = ViewCacheService.buildKey('tenant-a', 'roster', { page: '1' })
      const keyB = ViewCacheService.buildKey('tenant-b', 'roster', { page: '1' })
      expect(keyA).not.toBe(keyB)

      const embedA = ViewCacheService.buildEmbedKey('tenant-a', 'shared-path', 'cfg1', 1)
      const embedB = ViewCacheService.buildEmbedKey('tenant-b', 'shared-path', 'cfg1', 1)
      expect(embedA).not.toBe(embedB)
    })

    it('a cached response written for tenant A is not read back for tenant B', async () => {
      const store = new Map<string, string>()
      const kv = {
        get: async (key: string) => store.get(key) ?? null,
        put: async (key: string, value: string) => { store.set(key, value) },
        list: async () => ({ keys: [] }),
        delete: async () => {},
      } as unknown as KVNamespace
      const cache = new ViewCacheService(kv)

      await cache.set('tenant-a', 'roster', { page: '1' }, JSON.stringify({ data: ['secret-a'] }))
      const hitForB = await cache.get('tenant-b', 'roster', { page: '1' })
      expect(hitForB).toBeNull()

      const hitForA = await cache.get('tenant-a', 'roster', { page: '1' })
      expect(hitForA).toContain('secret-a')
    })
  })

  describe('self-heal: upgrading a pre-tenant-scoping install', () => {
    /** The OLD schema — global UNIQUE(name), global unique path index, no tenant_id column —
     *  exactly what this branch shipped with before this rebuild. */
    async function provisionLegacySchema(): Promise<void> {
      // beforeEach already provisioned the current (tenant-scoped) schema — drop it so this
      // block can exercise the self-heal against a genuinely OLD table shape instead.
      await db.prepare(`DROP TABLE IF EXISTS view_displays`).run()
      await db.prepare(`DROP TABLE IF EXISTS views`).run()
      await db.prepare(`
        CREATE TABLE views (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL UNIQUE,
          display_name TEXT,
          description TEXT,
          collection_id TEXT,
          filter_config TEXT,
          sort_config TEXT,
          columns_config TEXT,
          page_size INTEGER DEFAULT 25,
          is_default INTEGER DEFAULT 0,
          is_public INTEGER NOT NULL DEFAULT 0,
          status TEXT DEFAULT 'active',
          created_by TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `).run()
      await db.prepare(`
        CREATE TABLE view_displays (
          id TEXT PRIMARY KEY,
          view_id TEXT NOT NULL REFERENCES views(id) ON DELETE CASCADE,
          display_type TEXT NOT NULL,
          path TEXT,
          config TEXT NOT NULL,
          is_public INTEGER NOT NULL DEFAULT 0,
          share_token TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `).run()
      await db.prepare(`CREATE UNIQUE INDEX idx_view_displays_path ON view_displays(path) WHERE path IS NOT NULL`).run()
      await db.prepare(`CREATE UNIQUE INDEX idx_view_displays_share_token ON view_displays(share_token) WHERE share_token IS NOT NULL`).run()
    }

    it('preserves existing rows, defaults them to the default tenant, and rebuilds uniqueness as per-tenant', async () => {
      await provisionLegacySchema()
      await db.prepare(
        `INSERT INTO views (id, name, display_name, is_public, status, created_at, updated_at) VALUES ('v-legacy', 'legacy-view', 'Legacy', 1, 'active', 1, 1)`,
      ).run()
      await db.prepare(
        `INSERT INTO view_displays (id, view_id, display_type, path, config, is_public, created_at, updated_at)
         VALUES ('d-legacy', 'v-legacy', 'table', 'legacy-path', '{}', 1, 1, 1)`,
      ).run()

      // Also add the tenant_id column the way ADD COLUMN self-heal would (independent step in
      // onBoot, before the rebuild runs) — exercises the real ordering, not a shortcut.
      await db.prepare(`ALTER TABLE views ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`).run().catch(() => {})
      await db.prepare(`ALTER TABLE view_displays ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`).run().catch(() => {})

      await ensureViewsTenantUniqueness(asD1())

      // Data survived.
      const view = await db.prepare('SELECT id, name, tenant_id, is_public FROM views WHERE id = ?').bind('v-legacy').first<{ id: string; name: string; tenant_id: string; is_public: number }>()
      expect(view).toEqual({ id: 'v-legacy', name: 'legacy-view', tenant_id: 'default', is_public: 1 })
      const display = await db.prepare('SELECT id, path, tenant_id FROM view_displays WHERE id = ?').bind('d-legacy').first<{ id: string; path: string; tenant_id: string }>()
      expect(display).toEqual({ id: 'd-legacy', path: 'legacy-path', tenant_id: 'default' })

      // The rebuild actually happened — a second tenant can now reuse the same name/path.
      await insertView('v-a', 'tenant-a', 'legacy-view')
      await expect(insertDisplay('d-a', 'tenant-a', 'v-a', 'legacy-path', '_tokencccccccccccccccccccccccccc')).resolves.toBeTruthy()
    })

    it('is idempotent — running it twice does not error or duplicate data', async () => {
      await provisionLegacySchema()
      await db.prepare(`ALTER TABLE views ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`).run().catch(() => {})
      await db.prepare(`ALTER TABLE view_displays ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`).run().catch(() => {})
      await db.prepare(
        `INSERT INTO views (id, name, display_name, is_public, status, created_at, updated_at) VALUES ('v-1', 'once', 'Once', 0, 'active', 1, 1)`,
      ).run()

      await ensureViewsTenantUniqueness(asD1())
      await ensureViewsTenantUniqueness(asD1())

      const count = await db.prepare('SELECT COUNT(*) n FROM views').first<{ n: number }>()
      expect(count?.n).toBe(1)
    })

    it('a fresh install (already on the new schema) is a no-op', async () => {
      // provisionFreshSchema() already ran in beforeEach — this just proves calling the
      // self-heal again on an up-to-date schema doesn't error or alter anything.
      await insertView('v-1', 'tenant-a', 'already-current')
      await ensureViewsTenantUniqueness(asD1())
      const row = await db.prepare('SELECT tenant_id FROM views WHERE id = ?').bind('v-1').first<{ tenant_id: string }>()
      expect(row?.tenant_id).toBe('tenant-a')
    })
  })
})
