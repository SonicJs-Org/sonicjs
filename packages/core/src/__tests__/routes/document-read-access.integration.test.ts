// @ts-nocheck
// /api/documents, MCP reads and AI search honour a read grant on any RBAC role the user holds, as
// /api/content does — for collection types only. Real SQLite, real RbacService; only the session is faked.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../services/document-types-seed'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'
import { RbacService } from '../../services/rbac'
import { DocumentsService } from '../../services/documents'
import { DocumentPermissionsService } from '../../services/document-permissions'
import { DocumentTypeRegistry } from '../../services/document-type-registry'
import { createDocumentReadAccess } from '../../services/document-read-access'
import apiDocumentsRoutes from '../../routes/api-documents'
import { execList, execGet } from '../../plugins/core-plugins/mcp-plugin/tools/documents'
import { AISearchService } from '../../plugins/core-plugins/ai-search-plugin/services/ai-search'
import siteSettings from '../../collections/site-settings.collection'

describe('document reads use every held RBAC role', () => {
  let db: any
  let app: any
  let rootId: string
  const addUser = (id: string, role: string) =>
    db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role, is_active) VALUES (?, ?, 0, 0, 'F', 'L', ?, 1)").run(id, `${id}@x.y`, role)
  const principals = (id: string) => [{ type: 'user', id }, { type: 'role', id: db.raw.prepare('SELECT role FROM auth_user WHERE id=?').get(id).role }]
  const get = (path: string, userId?: string) => app.request(path, { headers: userId ? { 'x-test-user': userId } : {} })
  const listSlugs = async (type: string, userId?: string) => (await (await get(`/api/documents?type=${type}`, userId)).json()).data.map((d: any) => d.slug)
  const mcpCtx = (id: string) => ({ db, tenantId: 'default', principalSet: principals(id), listLimit: 50, redactFields: [] })
  const search = (id: string, query = 'Note one') =>
    new AISearchService(db, undefined, undefined, 'default')
      .searchKeyword({ query, mode: 'keyword' }, { enabled: true, selected_collections: [], results_limit: 20 }, principals(id))
      .then((r: any) => r.results.map((x: any) => x.title))

  beforeEach(async () => {
    db = createTestD1()
    // No base grant for viewers here, so only the RBAC grant on role-z can open it.
    getCollectionRegistry().register([
      { name: 'notes', displayName: 'Notes', schema: { type: 'object', properties: { title: { type: 'string' } } }, access: { viewer: [] } },
    ])
    await bootstrapDocumentTypes(db)
    await autoRegisterCollectionDocumentTypes(db)
    const rbac = new RbacService(db)
    await rbac.ensureSystemRbacSeed()
    addUser('AdminId', 'admin')
    await rbac.setUserRoles('AdminId', ['role-admin'])
    await rbac.createRole('a', 'A')
    await rbac.createRole('z', 'Z')
    await rbac.setRoleGrants('role-z', [{ resource: 'document_type:notes', verb: 'read' }])
    addUser('Multi', 'viewer')
    await rbac.setUserRoles('Multi', ['role-a', 'role-z'])
    addUser('OnlyA', 'viewer')
    await rbac.setUserRoles('OnlyA', ['role-a'])
    addUser('Authd', 'viewer')
    await rbac.setUserRoles('Authd', ['role-authenticated'])
    const docs = new DocumentsService(db)
    const doc = await docs.create({ typeId: 'notes', title: 'Note one', slug: 'n1', data: { title: 'Note one' } })
    await docs.publish(doc.id)
    rootId = doc.rootId
    app = new Hono()
    app.use('*', async (c: any, next: any) => {
      c.env = { DB: db }
      const userId = c.req.header('x-test-user')
      if (userId) c.set('user', { userId, email: `${userId}@x.y`, role: db.raw.prepare('SELECT role FROM auth_user WHERE id=?').get(userId).role })
      await next()
    })
    app.route('/api/documents', apiDocumentsRoutes)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  it('/api/documents: a grant on a non-primary role opens list, root and id reads', async () => {
    expect(db.raw.prepare("SELECT role FROM auth_user WHERE id='Multi'").get().role).toBe('role-a')
    expect(await listSlugs('notes', 'Multi')).toEqual(['n1'])
    expect((await get(`/api/documents/root/${rootId}`, 'Multi')).status).toBe(200)
    expect((await get(`/api/documents/${rootId}`, 'Multi')).status).toBe(200)
  })

  it('/api/documents: users and visitors without the grant are still refused', async () => {
    for (const user of ['OnlyA', undefined]) {
      expect(await listSlugs('notes', user)).toEqual([])
      expect((await get(`/api/documents/root/${rootId}`, user)).status).toBe(404)
    }
  })

  it('MCP list and get', async () => {
    expect((await execList(mcpCtx('Multi'), 'notes', {})).map((d) => d.slug)).toEqual(['n1'])
    expect((await execGet(mcpCtx('Multi'), 'notes', { id: rootId })).slug).toBe('n1')
    expect(await execList(mcpCtx('OnlyA'), 'notes', {})).toEqual([])
    await expect(execGet(mcpCtx('OnlyA'), 'notes', { id: rootId })).rejects.toThrow(/not found/i)
  })

  it('MCP: a role grant opens published rows, not drafts', async () => {
    const draft = await new DocumentsService(db).create({ typeId: 'notes', title: 'Draft', slug: 'd1', data: {} })
    expect((await execList(mcpCtx('AdminId'), 'notes', { status: 'draft' })).map((d) => d.slug)).toContain('d1')
    expect(await execList(mcpCtx('Multi'), 'notes', { status: 'draft' })).toEqual([])
    await expect(execGet(mcpCtx('Multi'), 'notes', { id: draft.id })).rejects.toThrow(/not found/i)
  })

  it('AI search (keyword)', async () => {
    expect(await search('Multi')).toEqual(['Note one'])
    expect(await search('OnlyA')).toEqual([])
  })

  it('a per-document deny still wins over the role grant', async () => {
    await new DocumentPermissionsService(db).grantPermission({
      tenantId: 'default', rootId, principalType: 'user', principalId: 'Multi', permission: 'read', effect: 'deny',
    })
    expect(await listSlugs('notes', 'Multi')).toEqual([])
    expect((await get(`/api/documents/root/${rootId}`, 'Multi')).status).toBe(404)
  })

  it('a deny keyed to a held role that is not the label also wins', async () => {
    await new DocumentPermissionsService(db).grantPermission({
      tenantId: 'default', rootId, principalType: 'role', principalId: 'role-z', permission: 'read', effect: 'deny',
    })
    expect(await listSlugs('notes', 'Multi')).toEqual([])
  })

  it('RBAC grants open active collection types only', async () => {
    await new DocumentTypeRegistry(db).register({
      id: 'plain_thing', name: 'plain_thing', displayName: 'Plain', source: 'system',
      schema: { type: 'object', properties: {} }, settings: { baseGrants: { admin: ['read'] } },
    })
    const plain = await new DocumentsService(db).create({ typeId: 'plain_thing', title: 'P', slug: 'p1', data: {} })
    await new DocumentsService(db).publish(plain.id)
    const access = (id: string) => createDocumentReadAccess(db, principals(id), 'default')
    const type = async (id: string) => new DocumentTypeRegistry(db).findById(id)
    expect(await access('AdminId').canRead(plain.rootId, await type('plain_thing'), 'default', true)).toBe(true)
    expect(await access('Authd').canRead(plain.rootId, await type('plain_thing'), 'default', true)).toBe(false)

    getCollectionRegistry().getByName('notes').isActive = false
    expect(await access('Multi').canRead(rootId, await type('notes'), 'default', true)).toBe(false)
  })

  it('a role grant never opens an internal, pii, auth or deactivated type', async () => {
    const notes = await new DocumentTypeRegistry(db).findById('notes')
    const can = (t: any) => createDocumentReadAccess(db, principals('Multi'), 'default').canRead(rootId, t, 'default', true)
    expect(await can(notes)).toBe(true)
    expect(await can({ ...notes, settings: { ...notes.settings, internal: true } })).toBe(false)
    expect(await can({ ...notes, settings: { ...notes.settings, pii: true } })).toBe(false)
    expect(await can({ ...notes, isAuth: true })).toBe(false)
    expect(await can({ ...notes, isActive: false })).toBe(false)
  })

  it('document_type:* does not open site settings, an internal collection', async () => {
    getCollectionRegistry().register([siteSettings])
    const doc = await new DocumentsService(db).create({ typeId: 'site_settings', title: 'General', slug: 'general', data: {} })
    await new DocumentsService(db).publish(doc.id)
    expect(await listSlugs('site_settings', 'AdminId')).toEqual(['general'])
    expect(await listSlugs('site_settings', 'Authd')).toEqual([])
  })

  it('a role grant does not open an expired row through MCP or search', async () => {
    const docs = new DocumentsService(db)
    const old = await docs.create({ typeId: 'notes', title: 'Old note', slug: 'old', data: {}, expiresAt: 1 })
    await docs.publish(old.id)
    await expect(execGet(mcpCtx('Multi'), 'notes', { id: old.rootId })).rejects.toThrow(/not found/i)
    expect(await search('Multi', 'Old note')).toEqual([])
    expect((await execGet(mcpCtx('Multi'), 'notes', { id: rootId })).slug).toBe('n1')
  })

  it('a read grant scoped to own rows does not open every row', async () => {
    const rbac = new RbacService(db)
    await rbac.createRole('own', 'Own')
    await rbac.setRoleGrants('role-own', [{ resource: 'document_type:notes', verb: 'read', scope: 'own' }])
    addUser('OwnOnly', 'viewer')
    await rbac.setUserRoles('OwnOnly', ['role-own'])
    expect(await listSlugs('notes', 'OwnOnly')).toEqual([])
  })

  it('document_type:* on a seeded role never opens internal types', async () => {
    // role-authenticated is seeded with document_type:* read; it opens the collection, not rbac_user_roles.
    expect(await listSlugs('notes', 'Authd')).toEqual(['n1'])
    const row = db.raw.prepare("SELECT root_id FROM documents WHERE type_id='rbac_user_roles' AND slug='Authd'").get()
    const type = await new DocumentTypeRegistry(db).findById('rbac_user_roles')
    expect(await createDocumentReadAccess(db, principals('Authd'), 'default').canRead(row.root_id, type, 'default', true)).toBe(false)
    expect(await createDocumentReadAccess(db, principals('AdminId'), 'default').canRead(row.root_id, type, 'default', true)).toBe(true)
  })

  it('outside the default tenant held roles do not count', async () => {
    const type = await new DocumentTypeRegistry(db).findById('notes')
    expect(await createDocumentReadAccess(db, principals('Multi'), 'default').canRead(rootId, type, 'default', true)).toBe(true)
    expect(await createDocumentReadAccess(db, principals('Multi'), 'acme').canRead(rootId, type, 'default', true)).toBe(false)
  })

  it('outside the default tenant a role label does not pick up the global role of that name', async () => {
    const notes = await new DocumentTypeRegistry(db).findById('notes')
    const closed = { ...notes, settings: { ...notes.settings, baseGrants: { admin: ['read'] } } }
    const editor = [{ type: 'user', id: 'Ed' }, { type: 'role', id: 'editor' }]
    expect(await createDocumentReadAccess(db, editor, 'default').canRead(rootId, closed, 'default', true)).toBe(true)
    expect(await createDocumentReadAccess(db, editor, 'acme').canRead(rootId, closed, 'acme', true)).toBe(false)
  })

  it('a held role id does not pick up the grants of another role named after it', async () => {
    const rbac = new RbacService(db)
    await rbac.createRole('zeta', 'Zeta')
    await rbac.createRole('q', 'Q')
    await rbac.updateRole('role-q', 'Q', '', 'role-zeta')
    await rbac.setRoleGrants('role-q', [{ resource: 'document_type:notes', verb: 'read' }])
    addUser('Zeta', 'viewer')
    await rbac.setUserRoles('Zeta', ['role-zeta'])
    expect(await listSlugs('notes', 'Zeta')).toEqual([])
  })

  it('MCP get by root id returns the published version when old versions are kept', async () => {
    const docs = new DocumentsService(db, { versioning: true })
    const v1 = await docs.create({ typeId: 'notes', title: 'Kept v1', slug: 'kept', data: {} })
    await docs.publish(v1.id)
    const v2 = await docs.saveDraft(v1.rootId, { title: 'Kept v2', data: {} })
    await docs.publish(v2.id)
    expect(db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(v1.rootId).n).toBe(2)
    expect((await execGet(mcpCtx('Multi'), 'notes', { id: v1.rootId })).title).toBe('Kept v2')
  })
})
