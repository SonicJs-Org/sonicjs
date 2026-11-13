// @ts-nocheck
// Content API reads honour every RBAC role a user holds, not only the one projected into
// auth_user.role. Real SQLite, real RbacService; only the session is faked.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
  optionalAuth: () => async (c: any, next: any) => {
    const userId = c.req.header('x-test-user')
    if (userId) {
      const row = c.env.DB.raw.prepare('SELECT role FROM auth_user WHERE id=?').get(userId)
      c.set('user', { userId, email: `${userId}@x.y`, role: row.role })
    }
    await next()
  },
}))

import apiRoutes from '../../routes/api'
import { RbacService } from '../../services/rbac'
import { DocumentsService } from '../../services/documents'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'

describe('content API reads use every held RBAC role', () => {
  let db: any
  let app: any
  let rbac: RbacService
  const addUser = (id: string, role: string) =>
    db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role, is_active) VALUES (?, ?, 0, 0, 'F', 'L', ?, 1)").run(id, `${id}@x.y`, role)
  const read = (path: string, userId: string) => app.request(path, { headers: { 'x-test-user': userId } })

  beforeEach(async () => {
    db = createTestD1()
    getCollectionRegistry().register([
      { name: 'notes', displayName: 'Notes', schema: { type: 'object', properties: { title: { type: 'string' } } } },
    ])
    await bootstrapDocumentTypes(db)
    rbac = new RbacService(db)
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
    const docs = new DocumentsService(db)
    const doc = await docs.create({ typeId: 'notes', title: 'N1', slug: 'n1', data: { title: 'N1' } })
    await docs.publish(doc.rootId ?? doc.id)
    app = new Hono()
    app.use('*', async (c, next) => {
      ;(c as any).env = { DB: db }
      const tenant = c.req.header('x-test-tenant')
      if (tenant) c.set('tenantId', tenant)
      await next()
    })
    app.route('/api', apiRoutes)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  it('a read granted only by a non-primary role is allowed', async () => {
    expect(db.raw.prepare("SELECT role FROM auth_user WHERE id='Multi'").get().role).toBe('role-a')
    const res = await read('/api/collections/notes/content', 'Multi')
    expect(res.status).toBe(200)
    expect((await res.json()).data.map((d: any) => d.slug)).toContain('n1')
    expect((await read('/api/notes', 'Multi')).status).toBe(200)
  })

  it('outside the default tenant only the tenant role counts', async () => {
    const res = await app.request('/api/notes', { headers: { 'x-test-user': 'Multi', 'x-test-tenant': 'acme' } })
    expect(res.status).toBe(403)
  })

  it('an own-scoped grant on a held role does not open the type', async () => {
    await rbac.createRole('own', 'Own')
    await rbac.setRoleGrants('role-own', [{ resource: 'document_type:notes', verb: 'read', scope: 'own' }])
    addUser('OwnOnly', 'viewer')
    await rbac.setUserRoles('OwnOnly', ['role-a', 'role-own'])
    expect((await read('/api/notes', 'OwnOnly')).status).toBe(403)
    expect((await read('/api/collections/notes/content', 'OwnOnly')).status).toBe(403)
  })

  it('a held document_type:* grant does not open an internal collection', async () => {
    const schema = { type: 'object', properties: {} }
    getCollectionRegistry().register([
      { name: 'members', displayName: 'Members', schema, access: { viewer: [] } },
      { name: 'secrets', displayName: 'Secrets', schema, access: { viewer: [] }, internal: true },
    ])
    addUser('Authd', 'viewer')
    await rbac.setUserRoles('Authd', ['role-a', 'role-authenticated'])
    expect((await read('/api/members', 'Authd')).status).toBe(200)
    expect((await read('/api/secrets', 'Authd')).status).toBe(403)
    expect((await read('/api/collections/secrets/content', 'Authd')).status).toBe(403)
  })

  it('a user without the grant is still refused', async () => {
    expect((await read('/api/collections/notes/content', 'OnlyA')).status).toBe(403)
    expect((await read('/api/notes', 'OnlyA')).status).toBe(403)
  })
})
