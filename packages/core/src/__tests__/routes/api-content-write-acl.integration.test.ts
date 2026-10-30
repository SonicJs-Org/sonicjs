// @ts-nocheck
// Content-API writes (/api/:collection and /api/content) must pass the document ACL, and must never
// reach internal/auth-owned types. Real SQLite, real apiRoutes, real requireRole; only the session is faked.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware/auth', async (importOriginal) => {
  const actual: any = await importOriginal()
  return {
    ...actual,
    requireAuth: () => async (c: any, next: any) => (c.get('user') ? next() : c.json({ error: 'Authentication required' }, 401)),
    optionalAuth: () => async (_c: any, next: any) => next(),
  }
})

vi.mock('../../plugins/hooks/dispatch-event', async (importOriginal) => {
  const actual: any = await importOriginal()
  return { ...actual, dispatchHookEvent: vi.fn(actual.dispatchHookEvent) }
})

import apiRoutes from '../../routes/api'
import { dispatchHookEvent } from '../../plugins/hooks/dispatch-event'
import { CacheService } from '../../services/cache'
import { RbacService } from '../../services/rbac'
import { getJwtExpirySecondsFromDb } from '../../middleware/auth'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'
import { tenantMiddleware } from '../../middleware/tenant'

const SCHEMA = { type: 'object', properties: { title: { type: 'string' }, slug: { type: 'string' } } }

describe('content API writes enforce the document ACL', () => {
  let db: any
  let app: any
  const req = (method: string, path: string, role: string, body?: any, user = 'u1', extra: Record<string, string> = {}) =>
    app.request(path, {
      method,
      headers: { 'content-type': 'application/json', 'x-test-role': role, 'x-test-user': user, ...extra },
      body: body ? JSON.stringify(body) : undefined,
    })
  const rootOf = (type: string, slug: string) =>
    db.raw.prepare('SELECT root_id r FROM documents WHERE type_id=? AND slug=? ORDER BY version_number DESC LIMIT 1').get(type, slug)?.r
  const isDeleted = (root: string) =>
    db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=? AND deleted_at IS NOT NULL').get(root).n > 0
  const titleOf = (root: string) =>
    db.raw.prepare('SELECT title t FROM documents WHERE root_id=? AND is_current_draft=1').get(root)?.t
  const isPublished = (root: string) =>
    db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1').get(root).n > 0
  const seedPost = async (slug: string, status = 'published') => {
    expect((await req('POST', '/api/blog_post', 'admin', { title: slug, slug, status })).status).toBe(201)
    return rootOf('blog_post', slug)
  }

  beforeEach(async () => {
    db = createTestD1()
    getCollectionRegistry().register([
      { name: 'blog_post', displayName: 'Blog Posts', description: '', schema: SCHEMA },
      // Collection-level grant: authors may create and edit, but not publish or delete.
      { name: 'notes', displayName: 'Notes', description: '', schema: SCHEMA, access: { author: ['read', 'create', 'update'] } },
    ])
    await bootstrapDocumentTypes(db)
    await autoRegisterCollectionDocumentTypes(db)
    const addUser = (id: string, role: string) =>
      db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role) VALUES (?, ?, 0, 0, 'F', 'L', ?)").run(id, `${id}@x.y`, role)
    addUser('AdminId', 'admin')
    addUser('AuthorId', 'author')
    const rbac = new RbacService(db)
    await rbac.ensureSystemRbacSeed()
    await rbac.setUserRoles('AdminId', ['role-admin'])
    app = new Hono()
    app.use('*', async (c, next) => {
      ;(c as any).env = { DB: db }
      const role = c.req.header('x-test-role')
      if (role) c.set('user', { userId: c.req.header('x-test-user') ?? 'u1', email: 'x@y.z', role, isSuperAdmin: !!c.req.header('x-test-super') })
      await next()
    })
    // The real tenant middleware, as in app.ts: it sets tenantRole on every authed request.
    app.use('*', tenantMiddleware())
    // Stand-in for an active multi-tenant plugin: the request tenant and the caller's role in it.
    app.use('*', async (c, next) => {
      if (c.req.header('x-test-tenant')) {
        c.set('tenantId', c.req.header('x-test-tenant'))
        c.set('tenantRole', c.req.header('x-test-tenant-role'))
      }
      await next()
    })
    app.route('/api', apiRoutes)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  it('create needs the type-level create grant', async () => {
    expect((await req('POST', '/api/blog_post', 'author', { title: 'a', slug: 'a' })).status).toBe(403)
    expect((await req('POST', '/api/content', 'author', { collectionId: 'blog_post', title: 'b', slug: 'b' })).status).toBe(403)
    expect(rootOf('blog_post', 'a')).toBeUndefined()
    expect(rootOf('blog_post', 'b')).toBeUndefined()
    expect((await req('POST', '/api/blog_post', 'editor', { title: 'e', slug: 'e', status: 'published' })).status).toBe(201)
    expect((await req('POST', '/api/content', 'editor', { collectionId: 'blog_post', title: 'f', slug: 'f' })).status).toBe(201)
  })

  it('delete is allowed by an RBAC role grant and refused once the grant is removed', async () => {
    // baseGrants give editor no delete on blog_post; the seeded RBAC editor role grants document_type:* delete.
    await new RbacService(db).setUserRoles('u1', ['role-editor'])
    const a = await seedPost('a')
    expect((await req('DELETE', `/api/blog_post/${a}`, 'editor')).status).toBe(200)
    expect(isDeleted(a)).toBe(true)

    await new RbacService(db).setRoleGrants('role-editor', [{ resource: 'document_type:*', verb: 'update' }])
    const b = await seedPost('b')
    expect((await req('DELETE', `/api/blog_post/${b}`, 'editor')).status).toBe(403)
    expect((await req('DELETE', `/api/content/${b}`, 'editor')).status).toBe(403)
    expect(isDeleted(b)).toBe(false)
    expect((await req('DELETE', `/api/content/${b}`, 'admin')).status).toBe(200)
  })

  it('a per-document deny beats an RBAC grant', async () => {
    await new RbacService(db).setUserRoles('u1', ['role-editor'])
    const root = await seedPost('kept')
    db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES ('p2','default',?,'role','editor','delete','deny')").run(root)
    expect((await req('DELETE', `/api/blog_post/${root}`, 'editor')).status).toBe(403)
    expect((await req('DELETE', `/api/content/${root}`, 'editor')).status).toBe(403)
    expect(isDeleted(root)).toBe(false)
    const other = await seedPost('other')
    expect((await req('DELETE', `/api/blog_post/${other}`, 'editor')).status).toBe(200)
  })

  it('/api/:collection writes land in default, so they are judged by the global role', async () => {
    const root = await seedPost('tenanted')
    const acmeAdmin = { 'x-test-tenant': 'acme', 'x-test-tenant-role': 'admin' }
    expect((await req('DELETE', `/api/blog_post/${root}`, 'author', undefined, 'u1', acmeAdmin)).status).toBe(403)
    expect((await req('POST', '/api/blog_post', 'author', { title: 't', slug: 't', status: 'published' }, 'u1', acmeAdmin)).status).toBe(403)
    expect(isDeleted(root)).toBe(false)
    // …and a global admin isn't demoted by a lesser role in the active tenant.
    const acmeViewer = { 'x-test-tenant': 'acme', 'x-test-tenant-role': 'viewer' }
    expect((await req('POST', '/api/blog_post', 'admin', { title: 'v', slug: 'v' }, 'u1', acmeViewer)).status).toBe(201)
  })

  it('a per-document deny override blocks update on both routes', async () => {
    const root = await seedPost('locked')
    db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES ('p1','default',?,'role','editor','update','deny')").run(root)
    expect((await req('PUT', `/api/blog_post/${root}`, 'editor', { title: 'x' })).status).toBe(403)
    expect((await req('PUT', `/api/content/${root}`, 'editor', { title: 'y' })).status).toBe(403)
    expect(titleOf(root)).toBe('locked')
    const other = await seedPost('open')
    expect((await req('PUT', `/api/blog_post/${other}`, 'editor', { title: 'edited' })).status).toBe(200)
    expect(titleOf(other)).toBe('edited')
  })

  it('collection access grants are honored, and publish state changes need publish', async () => {
    expect((await req('POST', '/api/notes', 'author', { title: 'n', slug: 'n' })).status).toBe(201)
    expect((await req('POST', '/api/notes', 'author', { title: 'p', slug: 'p', status: 'published' })).status).toBe(403)
    const draft = rootOf('notes', 'n')
    expect((await req('PUT', `/api/notes/${draft}`, 'author', { title: 'n2' })).status).toBe(200)

    const live = (await (await req('POST', '/api/notes', 'admin', { title: 'live', slug: 'live', status: 'published' })).json()).data.id
    // No status on a published doc republishes it; 'draft' unpublishes it. Both need publish.
    expect((await req('PUT', `/api/notes/${live}`, 'author', { title: 'changed' })).status).toBe(403)
    expect((await req('PUT', `/api/content/${live}`, 'author', { status: 'draft' })).status).toBe(403)
    expect(titleOf(live)).toBe('live')
    expect(isPublished(live)).toBe(true)
    expect((await req('DELETE', `/api/notes/${draft}`, 'author')).status).toBe(403)
  })

  it('RBAC documents are not writable through the content API, even by admin', async () => {
    const rbac = new RbacService(db)
    await rbac.setUserRoles('AuthorId', ['role-authenticated'])
    const userRoles = rootOf('rbac_user_roles', 'AuthorId')
    for (const role of ['author', 'admin']) {
      expect((await req('PUT', `/api/rbac_user_roles/${userRoles}`, role, { data: { roleIds: ['role-admin'] } }, 'AuthorId')).status).toBe(404)
      expect((await req('PUT', `/api/content/${userRoles}`, role, { data: { roleIds: ['role-admin'] } }, 'AuthorId')).status).toBe(404)
    }
    expect(await rbac.can('AuthorId', 'document_type:site_settings', 'manage')).toBe(false)

    const adminRole = rootOf('rbac_role', 'role-admin')
    expect((await req('DELETE', `/api/rbac_role/${adminRole}`, 'editor')).status).toBe(404)
    expect((await req('DELETE', `/api/content/${adminRole}`, 'admin')).status).toBe(404)
    expect(isDeleted(adminRole)).toBe(false)
    expect((await req('POST', '/api/rbac_user_roles', 'admin', { title: 't', slug: 'someone', data: { roleIds: ['role-admin'] } })).status).toBe(404)
  })

  it('site_settings cannot be planted (JWT lifetime stays put)', async () => {
    const before = await getJwtExpirySecondsFromDb(db, {})
    for (const role of ['author', 'admin']) {
      expect((await req('POST', '/api/site_settings', role, { title: 'security', slug: 'security', data: { jwtExpiresIn: '3650d' } })).status).toBe(404)
      expect((await req('POST', '/api/content', role, { collectionId: 'site_settings', title: 'security', slug: 'security', data: { jwtExpiresIn: '3650d' } })).status).toBe(404)
    }
    expect(await getJwtExpirySecondsFromDb(db, {})).toBe(before)
    expect(rootOf('site_settings', 'security')).toBeUndefined()
  })

  // Every revision of a root, so a refused write can be shown to leave no partial change.
  const snapshot = (root: string) =>
    db.raw.prepare('SELECT id, version_number, title, is_current_draft, is_published, deleted_at FROM documents WHERE root_id=? ORDER BY version_number').all(root)
  const writeHooks = () => vi.mocked(dispatchHookEvent).mock.calls.filter(([, event]) => event !== 'content:read')
  const refused = async (root: string | null, calls: Array<() => Promise<Response>>, status = 403) => {
    const before = root ? snapshot(root) : null
    const rows = db.raw.prepare('SELECT COUNT(*) n FROM documents').get().n
    const acl = db.raw.prepare('SELECT * FROM document_permissions ORDER BY id').all()
    vi.mocked(dispatchHookEvent).mockClear()
    const invalidate = vi.spyOn(CacheService.prototype, 'invalidate')
    try {
      for (const call of calls) expect((await call()).status).toBe(status)
      if (root) expect(snapshot(root)).toEqual(before)
      expect(db.raw.prepare('SELECT COUNT(*) n FROM documents').get().n).toBe(rows)
      expect(db.raw.prepare('SELECT * FROM document_permissions ORDER BY id').all()).toEqual(acl)
      expect(writeHooks()).toEqual([])
      expect(invalidate).not.toHaveBeenCalled()
    } finally {
      invalidate.mockRestore()
    }
  }
  const allWrites = (role: string, root: string, user = 'u1', type = 'blog_post') => [
    () => req('POST', `/api/${type}`, role, { title: 'x', slug: 'x-new' }, user),
    () => req('POST', '/api/content', role, { collectionId: type, title: 'y', slug: 'y-new' }, user),
    () => req('PUT', `/api/${type}/${root}`, role, { title: 'x' }, user),
    () => req('PUT', `/api/content/${root}`, role, { title: 'y' }, user),
    () => req('DELETE', `/api/${type}/${root}`, role, undefined, user),
    () => req('DELETE', `/api/content/${root}`, role, undefined, user),
  ]

  it('anonymous and viewer callers are refused on all six write routes', async () => {
    const root = await seedPost('guarded')
    const anon = (method: string, path: string, body?: any) =>
      app.request(path, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
    await refused(root, [
      () => anon('POST', '/api/blog_post', { title: 'a', slug: 'a' }),
      () => anon('POST', '/api/content', { collectionId: 'blog_post', title: 'a', slug: 'a' }),
      () => anon('PUT', `/api/blog_post/${root}`, { title: 'a' }),
      () => anon('PUT', `/api/content/${root}`, { title: 'a' }),
      () => anon('DELETE', `/api/blog_post/${root}`),
      () => anon('DELETE', `/api/content/${root}`),
    ], 401)
    await refused(root, allWrites('viewer', root))
  })

  it('author has no blog grant, and an editor with no RBAC role cannot delete', async () => {
    const root = await seedPost('authored')
    await refused(root, allWrites('author', root))
    await refused(root, [
      () => req('DELETE', `/api/blog_post/${root}`, 'editor'),
      () => req('DELETE', `/api/content/${root}`, 'editor'),
    ])
  })

  it('admin can create, update, publish, unpublish and delete on both routes', async () => {
    for (const [create, item] of [
      [(b: any) => req('POST', '/api/blog_post', 'admin', b), (id: string) => `/api/blog_post/${id}`],
      [(b: any) => req('POST', '/api/content', 'admin', { collectionId: 'blog_post', ...b }), (id: string) => `/api/content/${id}`],
    ] as const) {
      const res = await create({ title: 'c', slug: `c-${Math.random().toString(36).slice(2)}` })
      expect(res.status).toBe(201)
      const id = (await res.json()).data.id
      expect((await req('PUT', item(id), 'admin', { title: 'u' })).status).toBe(200)
      expect(titleOf(id)).toBe('u')
      expect((await req('PUT', item(id), 'admin', { status: 'published' })).status).toBe(200)
      expect(isPublished(id)).toBe(true)
      expect((await req('PUT', item(id), 'admin', { status: 'draft' })).status).toBe(200)
      expect(isPublished(id)).toBe(false)
      expect((await req('DELETE', item(id), 'admin')).status).toBe(200)
      expect(isDeleted(id)).toBe(true)
    }
  })

  it('media assets are not writable through the content API; they go through the media routes', async () => {
    for (const role of ['author', 'admin']) {
      await refused(null, [
        () => req('POST', '/api/media_asset', role, { title: 'm', slug: 'm' }),
        () => req('POST', '/api/content', role, { collectionId: 'media_asset', title: 'm', slug: 'm' }),
      ], 404)
    }
  })

  it('a deny aimed at the user wins, and so does deny over an explicit allow', async () => {
    const root = await seedPost('user-deny')
    db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES ('d1','default',?,'user','u1','update','deny')").run(root)
    await refused(root, [
      () => req('PUT', `/api/blog_post/${root}`, 'editor', { title: 'x' }),
      () => req('PUT', `/api/content/${root}`, 'editor', { title: 'x' }),
    ])
    expect((await req('PUT', `/api/content/${root}`, 'editor', { title: 'other editor' }, 'u2')).status).toBe(200)

    const mixed = await seedPost('mixed', 'draft')
    const grant = db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES (?, 'default', ?, ?, ?, 'update', ?)")
    grant.run('a1', mixed, 'user', 'AuthorId', 'allow')
    // The allow alone lets an author with no base grant edit…
    expect((await req('PUT', `/api/content/${mixed}`, 'author', { title: 'allowed' }, 'AuthorId')).status).toBe(200)
    // …a role deny on the same document overrides it.
    grant.run('d2', mixed, 'role', 'author', 'deny')
    await refused(mixed, [
      () => req('PUT', `/api/blog_post/${mixed}`, 'author', { title: 'x' }, 'AuthorId'),
      () => req('PUT', `/api/content/${mixed}`, 'author', { title: 'x' }, 'AuthorId'),
    ])
  })

  it('a per-document deny beats an RBAC update grant too', async () => {
    await new RbacService(db).setUserRoles('u1', ['role-editor'])
    const root = await seedPost('rbac-update')
    db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES ('d3','default',?,'role','editor','update','deny')").run(root)
    await refused(root, [
      () => req('PUT', `/api/blog_post/${root}`, 'editor', { title: 'x' }),
      () => req('PUT', `/api/content/${root}`, 'editor', { title: 'x' }),
    ])
  })

  it('publishing a draft needs publish; a refused publish leaves the draft untouched', async () => {
    expect((await req('POST', '/api/notes', 'author', { title: 'd', slug: 'd' })).status).toBe(201)
    const draft = rootOf('notes', 'd')
    await refused(draft, [
      () => req('PUT', `/api/notes/${draft}`, 'author', { title: 'pub', status: 'published' }),
      () => req('PUT', `/api/content/${draft}`, 'author', { title: 'pub', status: 'published' }),
    ])
    await refused(null, [
      () => req('POST', '/api/content', 'author', { collectionId: 'notes', title: 'p2', slug: 'p2', status: 'published' }),
    ])
    expect(isPublished(draft)).toBe(false)
  })

  it("RBAC 'own' scope reaches the caller's own documents only", async () => {
    const rbac = new RbacService(db)
    await rbac.setUserRoles('AuthorId', ['role-authenticated'])
    await rbac.setRoleGrants('role-authenticated', ['create', 'update', 'delete'].map((verb) => ({ resource: 'document_type:blog_post', verb, scope: 'own' as const })))
    expect((await req('POST', '/api/content', 'author', { collectionId: 'blog_post', title: 'mine', slug: 'mine' }, 'AuthorId')).status).toBe(201)
    const mine = rootOf('blog_post', 'mine')
    expect((await req('POST', '/api/blog_post', 'admin', { title: 'theirs', slug: 'theirs' }, 'AdminId')).status).toBe(201)
    const theirs = rootOf('blog_post', 'theirs')
    await refused(theirs, [
      () => req('PUT', `/api/blog_post/${theirs}`, 'author', { title: 'x' }, 'AuthorId'),
      () => req('PUT', `/api/content/${theirs}`, 'author', { title: 'x' }, 'AuthorId'),
      () => req('DELETE', `/api/blog_post/${theirs}`, 'author', undefined, 'AuthorId'),
      () => req('DELETE', `/api/content/${theirs}`, 'author', undefined, 'AuthorId'),
    ])
    expect((await req('PUT', `/api/blog_post/${mine}`, 'author', { title: 'edited' }, 'AuthorId')).status).toBe(200)
    expect((await req('DELETE', `/api/content/${mine}`, 'author', undefined, 'AuthorId')).status).toBe(200)
    expect(isDeleted(mine)).toBe(true)
  })

  it('/api/content judges the caller by their role in the request tenant', async () => {
    const acme = (tenantRole: string) => ({ 'x-test-tenant': 'acme', 'x-test-tenant-role': tenantRole })
    await refused(null, [
      () => req('POST', '/api/content', 'admin', { collectionId: 'blog_post', title: 'v', slug: 'v' }, 'u1', acme('viewer')),
    ])
    expect((await req('POST', '/api/content', 'author', { collectionId: 'blog_post', title: 'e', slug: 'e' }, 'u1', acme('editor'))).status).toBe(201)
    expect(db.raw.prepare("SELECT tenant_id t FROM documents WHERE slug='e'").get().t).toBe('acme')
  })

  it("a tenant role's own scope stays inside the caller's documents in that tenant", async () => {
    await new RbacService(db).setRoleGrants('role-authenticated', ['create', 'update'].map((verb) => ({ resource: 'document_type:notes', verb, scope: 'own' as const })))
    const acmeMember = { 'x-test-tenant': 'acme', 'x-test-tenant-role': 'authenticated' }
    const create = async (user: string, slug: string) =>
      (await (await req('POST', '/api/content', 'author', { collectionId: 'notes', title: slug, slug }, user, acmeMember)).json()).data.id
    const mine = await create('u1', 'm')
    const theirs = await create('u2', 't')
    await refused(theirs, [() => req('PUT', `/api/content/${theirs}`, 'author', { title: 'x' }, 'u1', acmeMember)])
    expect((await req('PUT', `/api/content/${mine}`, 'author', { title: 'edited' }, 'u1', acmeMember)).status).toBe(200)
  })

  it('a super-admin is judged by their own RBAC roles in any tenant', async () => {
    const asSuper = { 'x-test-tenant': 'acme', 'x-test-tenant-role': 'viewer', 'x-test-super': '1' }
    expect((await req('POST', '/api/content', 'admin', { collectionId: 'blog_post', title: 's', slug: 's' }, 'AdminId', asSuper)).status).toBe(201)
  })

  it('wrong collection in the URL, deleted roots and inactive types all 404', async () => {
    const post = await seedPost('typed')
    await refused(post, [
      () => req('PUT', `/api/notes/${post}`, 'admin', { title: 'x' }),
      () => req('DELETE', `/api/notes/${post}`, 'admin'),
    ], 404)

    const gone = await seedPost('gone')
    expect((await req('DELETE', `/api/blog_post/${gone}`, 'admin')).status).toBe(200)
    await refused(gone, [
      () => req('PUT', `/api/blog_post/${gone}`, 'admin', { title: 'x' }),
      () => req('PUT', `/api/content/${gone}`, 'admin', { title: 'x' }),
      () => req('DELETE', `/api/blog_post/${gone}`, 'admin'),
      () => req('DELETE', `/api/content/${gone}`, 'admin'),
    ], 404)

    const note = (await (await req('POST', '/api/notes', 'admin', { title: 'n', slug: 'n' })).json()).data.id
    db.raw.prepare("UPDATE document_types SET is_active=0 WHERE id='notes'").run()
    await refused(note, allWrites('admin', note, 'u1', 'notes'), 404)
  })

  it('PII types can be created and edited, but not soft-deleted', async () => {
    db.raw.prepare("UPDATE document_types SET settings=json_set(settings, '$.pii', json('true')) WHERE id='notes'").run()
    expect((await req('POST', '/api/content', 'admin', { collectionId: 'notes', title: 'q', slug: 'q' })).status).toBe(201)
    const note = (await (await req('POST', '/api/notes', 'admin', { title: 'p', slug: 'p' })).json()).data.id
    expect((await req('PUT', `/api/content/${note}`, 'admin', { title: 'edited' })).status).toBe(200)
    expect((await req('PUT', `/api/notes/${note}`, 'admin', { title: 'edited again' })).status).toBe(200)
    expect(titleOf(note)).toBe('edited again')
    await refused(note, [
      () => req('DELETE', `/api/notes/${note}`, 'admin'),
      () => req('DELETE', `/api/content/${note}`, 'admin'),
    ], 404)
  })
})
