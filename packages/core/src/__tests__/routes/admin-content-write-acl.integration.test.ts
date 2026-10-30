// @ts-nocheck
// /admin/content writes go through the same write policy as the content API: document ACL or RBAC
// grant, deny wins, internal types refused, and /documents/:typeId/* must match the row's real type.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import adminContentRoutes from '../../routes/admin-content'
import { RbacService } from '../../services/rbac'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'
import { tenantMiddleware } from '../../middleware/tenant'

const SCHEMA = { type: 'object', properties: { title: { type: 'string', title: 'Title' }, slug: { type: 'string', title: 'Slug' } } }

const form = (obj: Record<string, string>) => {
  const fd = new FormData()
  for (const [k, v] of Object.entries(obj)) fd.append(k, v)
  return fd
}

describe('/admin/content writes enforce the write policy', () => {
  let db: any
  let app: any
  const as = (role: string, user = 'EditorId') => ({ 'x-test-role': role, 'x-test-user': user })
  const rootOf = (type: string, slug: string) =>
    db.raw.prepare('SELECT root_id r FROM documents WHERE type_id=? AND slug=? ORDER BY version_number DESC LIMIT 1').get(type, slug)?.r
  const draftIdOf = (root: string) => db.raw.prepare('SELECT id FROM documents WHERE root_id=? AND is_current_draft=1').get(root).id
  const isDeleted = (root: string) =>
    db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=? AND deleted_at IS NOT NULL').get(root).n > 0
  const count = (type: string) => db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE type_id=?').get(type).n
  const userFor: Record<string, string> = { admin: 'AdminId', editor: 'EditorId', author: 'AuthorId' }
  const createPost = (slug: string, role = 'admin', extra: Record<string, string> = {}, user = userFor[role]) =>
    app.request('/admin/content', {
      method: 'POST', headers: { ...as(role, user), ...extra },
      body: form({ collection_id: 'blog_post', title: slug, slug, status: 'draft', action: 'save' }),
    })

  beforeEach(async () => {
    db = createTestD1()
    getCollectionRegistry().register([{ name: 'blog_post', displayName: 'Blog Posts', description: '', schema: SCHEMA }])
    await bootstrapDocumentTypes(db)
    const addUser = (id: string, role: string) =>
      db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role) VALUES (?, ?, 0, 0, 'F', 'L', ?)").run(id, `${id}@x.y`, role)
    addUser('AdminId', 'admin')
    addUser('EditorId', 'editor')
    addUser('AuthorId', 'author')
    const rbac = new RbacService(db)
    await rbac.ensureSystemRbacSeed()
    await rbac.setUserRoles('AdminId', ['role-admin'])
    await rbac.setUserRoles('EditorId', ['role-editor'])
    app = new Hono()
    app.use('*', async (c, next) => {
      ;(c as any).env = { DB: db }
      const role = c.req.header('x-test-role')
      if (role) c.set('user', { userId: c.req.header('x-test-user'), email: 'x@y.z', role, exp: 0, iat: 0 })
      c.set('appVersion', 'test')
      await next()
    })
    app.use('*', tenantMiddleware())
    app.route('/admin/content', adminContentRoutes)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  it('editor cannot mint an RBAC role assignment or plant site_settings', async () => {
    const before = count('rbac_user_roles')
    const mint = await app.request('/admin/content/documents/rbac_user_roles/new', {
      method: 'POST', headers: as('editor'), body: form({ title: 'x', slug: 'EditorId', data: JSON.stringify({ roleIds: ['role-admin'] }) }),
    })
    expect(mint.status).toBe(404)
    expect(count('rbac_user_roles')).toBe(before)
    expect(await new RbacService(db).can('EditorId', 'rbac', 'manage')).toBe(false)

    const plant = await app.request('/admin/content/documents/site_settings/new', {
      method: 'POST', headers: as('editor'), body: form({ title: 'security', slug: 'security' }),
    })
    expect(plant.status).toBe(404)
    expect(rootOf('site_settings', 'security')).toBeUndefined()
  })

  it('/documents/:typeId/* refuses a document of a different type', async () => {
    const adminRole = rootOf('rbac_role', 'role-admin')
    const versionId = draftIdOf(adminRole)
    for (const action of ['publish', 'unpublish']) {
      const res = await app.request(`/admin/content/documents/blog_post/${versionId}/${action}`, { method: 'POST', headers: as('editor') })
      expect(res.status).toBe(404)
    }
    await app.request(`/admin/content/documents/blog_post/${adminRole}/delete`, { method: 'POST', headers: as('editor'), body: form({}) })
    const save = await app.request(`/admin/content/documents/blog_post/${adminRole}`, {
      method: 'POST', headers: as('editor'), body: form({ _method: 'PUT', title: 'pwned' }),
    })
    expect(save.status).toBe(404)
    expect(isDeleted(adminRole)).toBe(false)
    expect(await new RbacService(db).isGrantedForRole('admin', 'rbac', 'manage')).toBe(true)
  })

  it('internal documents are not editable, duplicable or bulk-deletable', async () => {
    const userRoles = rootOf('rbac_user_roles', 'EditorId')
    const put = await app.request(`/admin/content/${userRoles}`, { method: 'PUT', headers: as('admin', 'AdminId'), body: form({ title: 'x' }) })
    expect(put.status).toBe(404)
    expect(db.raw.prepare('SELECT data FROM documents WHERE root_id=? AND is_current_draft=1').get(userRoles).data).toContain('role-editor')

    const dup = await app.request('/admin/content/duplicate', { method: 'POST', headers: as('admin', 'AdminId'), body: form({ id: userRoles }) })
    expect(dup.status).toBe(404)

    const post = (await createPost('mixed')).status
    expect([200, 302]).toContain(post)
    const bulk = await app.request('/admin/content/bulk-action', {
      method: 'POST', headers: { ...as('editor'), 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'delete', ids: [rootOf('blog_post', 'mixed'), userRoles] }),
    })
    expect(bulk.status).toBe(403)
    expect(isDeleted(userRoles) || isDeleted(rootOf('blog_post', 'mixed'))).toBe(false)
  })

  it('content writes follow grants: editor allowed, author refused, deny override wins', async () => {
    expect([200, 302]).toContain((await createPost('ok', 'editor')).status)
    expect((await createPost('nope', 'author')).status).toBe(403)
    expect(rootOf('blog_post', 'nope')).toBeUndefined()

    const root = rootOf('blog_post', 'ok')
    db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES ('p1','default',?,'role','editor','delete','deny')").run(root)
    expect((await app.request(`/admin/content/${root}`, { method: 'DELETE', headers: as('editor') })).status).toBe(403)
    const bulk = await app.request('/admin/content/bulk-action', {
      method: 'POST', headers: { ...as('editor'), 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'delete', ids: [root] }),
    })
    expect(bulk.status).toBe(403)
    for (const path of [`/admin/content/${root}/delete`, `/admin/content/documents/blog_post/${root}/delete`]) {
      expect((await app.request(path, { method: 'POST', headers: as('editor'), body: form({}) })).status).toBe(403)
    }
    expect(isDeleted(root)).toBe(false)

    await createPost('gone')
    expect((await app.request(`/admin/content/${rootOf('blog_post', 'gone')}`, { method: 'DELETE', headers: as('editor') })).status).toBe(200)
    expect(isDeleted(rootOf('blog_post', 'gone'))).toBe(true)
  })

  it('htmx callers get an alert appended to <body> and nothing is written', async () => {
    const res = await createPost('htmx-nope', 'author', { 'HX-Request': 'true' })
    expect(res.status).toBe(200)
    expect(res.headers.get('HX-Retarget')).toBe('body')
    expect(await res.text()).toContain('You do not have permission')
    expect(rootOf('blog_post', 'htmx-nope')).toBeUndefined()
  })

  it('RBAC is judged by the roles the user holds, not by the legacy role label', async () => {
    const rbac = new RbacService(db)
    // A custom role: auth_user.role projects to 'viewer', but the user's own roles grant blog_post writes.
    await rbac.createRole('writer', 'Writer')
    await rbac.setRoleGrants('role-writer', [
      { resource: 'portal', verb: 'access' },
      { resource: 'document_type:blog_post', verb: 'create' },
      { resource: 'document_type:blog_post', verb: 'update' },
    ])
    db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role) VALUES ('WriterId','w@x.y',0,0,'F','L','viewer')").run()
    await rbac.setUserRoles('WriterId', ['role-writer'])
    expect([200, 302]).toContain((await createPost('by-writer', 'viewer', {}, 'WriterId')).status)

    // A role merely *named* viewer grants nothing to users who don't hold it.
    await rbac.createRole('viewer', 'Viewer')
    await rbac.setRoleGrants('role-viewer', [{ resource: 'document_type:*', verb: 'delete' }])
    db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role) VALUES ('AliceId','a@x.y',0,0,'F','L','viewer')").run()
    await rbac.setUserRoles('AliceId', ['role-authenticated'])
    const post = rootOf('blog_post', 'by-writer')
    expect((await app.request(`/admin/content/${post}`, { method: 'DELETE', headers: as('viewer', 'AliceId') })).status).toBe(403)
    expect(isDeleted(post)).toBe(false)
  })

  it('update on a live doc needs publish; the writer role has none', async () => {
    const rbac = new RbacService(db)
    await rbac.createRole('writer', 'Writer')
    await rbac.setRoleGrants('role-writer', [{ resource: 'document_type:blog_post', verb: 'update' }])
    db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role) VALUES ('WriterId','w@x.y',0,0,'F','L','viewer')").run()
    await rbac.setUserRoles('WriterId', ['role-writer'])
    const res = await app.request('/admin/content', {
      method: 'POST', headers: as('admin', 'AdminId'),
      body: form({ collection_id: 'blog_post', title: 'live', slug: 'live', status: 'published', action: 'save_and_publish' }),
    })
    expect([200, 302]).toContain(res.status)
    const live = rootOf('blog_post', 'live')
    const put = await app.request(`/admin/content/${live}`, { method: 'PUT', headers: as('viewer', 'WriterId'), body: form({ title: 'changed', slug: 'live' }) })
    expect(put.status).toBe(403)
    expect(db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1').get(live).n).toBe(1)
  })

  it("RBAC 'own' scope only reaches the user's own documents", async () => {
    await new RbacService(db).setRoleGrants('role-editor', [
      { resource: 'portal', verb: 'access' },
      { resource: 'document_type:*', verb: 'delete', scope: 'own' },
    ])
    await createPost('admins', 'admin')
    await createPost('editors', 'editor')
    const admins = rootOf('blog_post', 'admins')
    const editors = rootOf('blog_post', 'editors')
    expect((await app.request(`/admin/content/${admins}`, { method: 'DELETE', headers: as('editor') })).status).toBe(403)
    expect((await app.request(`/admin/content/${editors}`, { method: 'DELETE', headers: as('editor') })).status).toBe(200)
    expect(isDeleted(admins)).toBe(false)
    expect(isDeleted(editors)).toBe(true)
  })

  it('duplicate needs read on the source, not just create', async () => {
    await createPost('secret', 'admin')
    const root = rootOf('blog_post', 'secret')
    db.raw.prepare("INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect) VALUES ('rd','default',?,'role','editor','read','deny')").run(root)
    const before = count('blog_post')
    const dup = await app.request('/admin/content/duplicate', { method: 'POST', headers: as('editor'), body: form({ id: root }) })
    expect(dup.status).toBe(403)
    expect(count('blog_post')).toBe(before)
  })

  it('PII documents are hard-erased by admin delete, single, confirmation page and bulk', async () => {
    const { DocumentTypeRegistry } = await import('../../services/document-type-registry')
    const { DocumentsService } = await import('../../services/documents')
    await new DocumentTypeRegistry(db).register({
      id: 'contact', name: 'contact', displayName: 'Contact', description: '', source: 'system',
      schema: { type: 'object' }, queryableFields: [],
      settings: { pii: true, baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] } },
    })
    const svc = new DocumentsService(db, { tenantId: 'default' })
    const one = await svc.create({ typeId: 'contact', tenantId: 'default', locale: 'default', slug: 'one', data: { email: 'a@b.c' } }, 'AdminId')
    const two = await svc.create({ typeId: 'contact', tenantId: 'default', locale: 'default', slug: 'two', data: { email: 'd@e.f' } }, 'AdminId')
    const three = await svc.create({ typeId: 'contact', tenantId: 'default', locale: 'default', slug: 'three', data: { email: 'g@h.i' } }, 'AdminId')
    const rows = (root: string) => db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(root).n

    expect((await app.request(`/admin/content/${one.rootId}`, { method: 'DELETE', headers: as('admin', 'AdminId') })).status).toBe(200)
    expect(rows(one.rootId)).toBe(0)
    expect((await app.request(`/admin/content/${three.rootId}/delete`, { method: 'POST', headers: as('admin', 'AdminId'), body: form({}) })).status).toBe(302)
    expect(rows(three.rootId)).toBe(0)
    const bulk = await app.request('/admin/content/bulk-action', {
      method: 'POST', headers: { ...as('admin', 'AdminId'), 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'delete', ids: [two.rootId] }),
    })
    expect((await bulk.json()).success).toBe(true)
    expect(rows(two.rootId)).toBe(0)
  })
})
