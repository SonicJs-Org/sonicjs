// @ts-nocheck
// Admin user create/edit/invite assign RBAC roles (not just the auth_user.role label), and the edit form
// never defaults to Administrator. Real SQLite, real RbacService; only the session is faked.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'

vi.mock('../../middleware', async (importOriginal) => {
  const actual: any = await importOriginal()
  return {
    ...actual,
    requireAuth: () => async (c: any, next: any) => {
      c.set('user', { userId: 'AdminId', email: 'admin@x.y', role: 'admin' })
      await next()
    },
    requireRole: () => async (_c: any, next: any) => next(),
    logActivity: vi.fn(),
  }
})

import { userRoutes } from '../../routes/admin-users'
import { RbacService } from '../../services/rbac'

const form = (obj: Record<string, string>) => {
  const fd = new FormData()
  for (const [k, v] of Object.entries(obj)) fd.append(k, v)
  return fd
}

describe('admin users assign RBAC roles', () => {
  let db: any
  let app: any
  let rbac: RbacService
  let kv: Map<string, string>
  const label = (id: string) => db.raw.prepare('SELECT role FROM auth_user WHERE id=?').get(id)?.role
  const rolesOf = async (id: string) => (await rbac.getRolesForUser(id)).map((r) => r.id).sort()
  const addUser = (id: string, role: string) =>
    db.raw.prepare("INSERT INTO auth_user (id, email, created_at, updated_at, first_name, last_name, role, is_active) VALUES (?, ?, 0, 0, 'F', 'L', ?, 1)").run(id, `${id}@x.y`, role)
  const editPage = async (id: string) => (await app.request(`/admin/users/${id}/edit`)).text()
  const selected = (html: string) => html.match(/<option value="([^"]*)"\s*selected>/)?.[1]
  const save = (id: string, role: string, extra: Record<string, string> = {}) =>
    app.request(`/admin/users/${id}`, {
      method: 'PUT',
      body: form({ first_name: 'F', last_name: 'L', email: `${id}@x.y`, phone: '555', role, is_active: '1', ...extra }),
    })
  const shownRole = (html: string) => html.match(/name="shown_role" value="([^"]*)"/)?.[1]

  beforeEach(async () => {
    db = createTestD1()
    rbac = new RbacService(db)
    await rbac.ensureSystemRbacSeed()
    addUser('AdminId', 'admin')
    await rbac.setUserRoles('AdminId', ['role-admin'])
    app = new Hono()
    kv = new Map()
    const CACHE_KV = { get: async (k) => kv.get(k) ?? null, put: async (k, v) => { kv.set(k, v) }, delete: async (k) => { kv.delete(k) } }
    app.use('*', async (c, next) => { (c as any).env = { DB: db, CACHE_KV }; await next() })
    app.route('/admin', userRoutes)
  })
  afterEach(() => db.close())

  it('create assigns the RBAC role and its legacy label', async () => {
    const res = await app.request('/admin/users/new', {
      method: 'POST',
      body: form({ first_name: 'E', last_name: 'D', email: 'ed@x.y', password: 'Password123!', confirm_password: 'Password123!', role: 'role-editor', is_active: '1' }),
    })
    expect(res.headers.get('HX-Redirect')).toContain('/admin/users')
    const id = db.raw.prepare("SELECT id FROM auth_user WHERE email='ed@x.y'").get().id
    expect(await rolesOf(id)).toEqual(['role-editor'])
    expect(label(id)).toBe('editor')
  })

  it('create refuses an unknown role instead of falling back to Administrator', async () => {
    const res = await app.request('/admin/users/new', {
      method: 'POST',
      body: form({ first_name: 'X', last_name: 'Y', email: 'x@x.y', password: 'Password123!', confirm_password: 'Password123!', role: 'nope' }),
    })
    expect(await res.text()).toContain('valid role')
    expect(db.raw.prepare("SELECT COUNT(*) n FROM auth_user WHERE email='x@x.y'").get().n).toBe(0)
  })

  it('a user with no role shows "No role" and stays roleless when another field is saved', async () => {
    addUser('SignedUp', 'viewer')
    expect(selected(await editPage('SignedUp'))).toBe('')
    expect(await (await save('SignedUp', '')).text()).toContain('updated successfully')
    expect(await rolesOf('SignedUp')).toEqual([])
    expect(label('SignedUp')).toBe('viewer')
  })

  it('changing the role keeps the user’s other roles', async () => {
    addUser('Multi', 'editor')
    await rbac.setUserRoles('Multi', ['role-authenticated', 'role-editor'])
    expect(selected(await editPage('Multi'))).toBe('role-editor')
    await save('Multi', 'role-public')
    expect(await rolesOf('Multi')).toEqual(['role-authenticated', 'role-public'])
    expect(label('Multi')).toBe('role-authenticated')
  })

  it('users saved by the old form are repaired on their next save', async () => {
    // Created by the old form: role id in the label, no RBAC membership.
    addUser('Broken', 'role-editor')
    expect(selected(await editPage('Broken'))).toBe('role-editor')
    await save('Broken', 'role-editor')
    expect(await rolesOf('Broken')).toEqual(['role-editor'])
    expect(label('Broken')).toBe('editor')

    // Edited by the old form: still an editor in RBAC, but labelled role-admin.
    addUser('Relabelled', 'role-admin')
    await rbac.setUserRoles('Relabelled', ['role-editor'])
    db.raw.prepare("UPDATE auth_user SET role='role-admin' WHERE id='Relabelled'").run()
    expect(selected(await editPage('Relabelled'))).toBe('role-editor')
    await save('Relabelled', 'role-editor')
    expect(label('Relabelled')).toBe('editor')
  })

  it('users the old form relabelled role-admin are not repaired into admins', async () => {
    addUser('Victim', 'role-admin')
    expect(selected(await editPage('Victim'))).toBe('')
    await save('Victim', '')
    expect(await rolesOf('Victim')).toEqual([])
    expect(label('Victim')).toBe('viewer')
  })

  it('a plain name label is not turned into a role on save', async () => {
    await rbac.createRole('viewer', 'Viewer')
    addUser('Plain', 'viewer')
    expect(selected(await editPage('Plain'))).toBe('')
    await save('Plain', '')
    expect(await rolesOf('Plain')).toEqual([])
    expect(label('Plain')).toBe('viewer')
  })

  it('saving an unknown user id is a 404 and assigns nothing', async () => {
    const res = await save('Ghost', 'role-editor')
    expect(res.status).toBe(404)
    expect(await rolesOf('Ghost')).toEqual([])
  })

  it('a refused role assignment does not leave a created or invited user behind', async () => {
    db.raw.prepare("UPDATE auth_user SET is_active = 0 WHERE id = 'AdminId'").run()
    const res = await app.request('/admin/users/new', {
      method: 'POST',
      body: form({ first_name: 'N', last_name: 'R', email: 'nr@x.y', password: 'Password123!', confirm_password: 'Password123!', role: 'role-editor', is_active: '1' }),
    })
    expect(await res.text()).toContain('Refusing to update roles')
    const inv = await app.request('/admin/invite-user', { method: 'POST', body: form({ email: 'ni@x.y', first_name: 'N', last_name: 'I', role: 'role-editor' }) })
    expect(inv.status).toBe(400)
    expect(db.raw.prepare("SELECT COUNT(*) n FROM auth_user WHERE email IN ('nr@x.y', 'ni@x.y')").get().n).toBe(0)
    expect(db.raw.prepare("SELECT COUNT(*) n FROM auth_account WHERE user_id NOT IN (SELECT id FROM auth_user)").get().n).toBe(0)
  })

  it('repeated saves keep the label, and custom role names cannot pose as legacy labels', async () => {
    await rbac.createRole('author', 'Author')
    await rbac.createRole('moderator', 'Moderator')
    addUser('Custom', 'viewer')
    await rbac.setUserRoles('Custom', ['role-moderator', 'role-author'])
    expect(label('Custom')).toBe('role-author')
    for (let i = 0; i < 3; i++) {
      await save('Custom', selected(await editPage('Custom')))
      expect(label('Custom')).toBe('role-author')
    }
    expect(await rolesOf('Custom')).toEqual(['role-author', 'role-moderator'])
  })

  it('an unknown role on edit is refused and nothing changes', async () => {
    addUser('Ed', 'editor')
    await rbac.setUserRoles('Ed', ['role-editor'])
    expect(await (await save('Ed', 'nope')).text()).toContain('valid role')
    expect(await rolesOf('Ed')).toEqual(['role-editor'])
    expect(db.raw.prepare("SELECT phone FROM auth_user WHERE id='Ed'").get().phone).toBeNull()
  })

  it('the last admin cannot remove their own admin role', async () => {
    const text = await (await save('AdminId', 'role-editor')).text()
    expect(text).toContain('Refusing to update roles')
    expect(await rolesOf('AdminId')).toEqual(['role-admin'])
    expect(label('AdminId')).toBe('admin')
  })

  it('a role change clears the user’s cached permissions', async () => {
    addUser('Demoted', 'admin')
    await rbac.setUserRoles('Demoted', ['role-admin'])
    kv.set('rbac:perms:Demoted', '["rbac:manage"]')
    await save('Demoted', 'role-editor')
    expect(kv.has('rbac:perms:Demoted')).toBe(false)
  })

  it('saving the open form a second time keeps the user’s other roles', async () => {
    await rbac.createRole('custom', 'Custom')
    await rbac.createRole('x', 'X')
    addUser('Twice', 'editor')
    await rbac.setUserRoles('Twice', ['role-custom', 'role-editor'])
    const first = await (await save('Twice', 'role-x', { shown_role: shownRole(await editPage('Twice')) })).text()
    expect(await rolesOf('Twice')).toEqual(['role-custom', 'role-x'])
    expect(shownRole(first)).toBe('role-x')
    // The label is now role-custom; the form, still open, says it shows role-x.
    await save('Twice', 'role-x', { shown_role: shownRole(first) })
    expect(await rolesOf('Twice')).toEqual(['role-custom', 'role-x'])
  })

  it('a user labelled admin with no RBAC role keeps the label when another field is saved', async () => {
    addUser('LabelAdmin', 'admin')
    expect(await editPage('LabelAdmin')).toContain('Legacy label: admin.')
    expect(await (await save('LabelAdmin', '')).text()).toContain('updated successfully')
    expect(label('LabelAdmin')).toBe('admin')
  })

  it('API clients may send role names', async () => {
    const inv = await app.request('/admin/invite-user', { method: 'POST', body: form({ email: 'n1@x.y', first_name: 'I', last_name: 'N', role: 'editor' }) })
    expect(await rolesOf((await inv.json()).user.id)).toEqual(['role-editor'])
    addUser('Named', 'viewer')
    await save('Named', 'editor')
    expect(await rolesOf('Named')).toEqual(['role-editor'])
    await app.request('/admin/users/new', {
      method: 'POST',
      body: form({ first_name: 'V', last_name: 'W', email: 'vw@x.y', password: 'Password123!', confirm_password: 'Password123!', role: 'viewer', is_active: '1' }),
    })
    const vw = db.raw.prepare("SELECT id, role FROM auth_user WHERE email='vw@x.y'").get()
    expect(vw.role).toBe('viewer')
    expect(db.raw.prepare("SELECT COUNT(*) n FROM documents WHERE type_id='rbac_user_roles' AND slug=?").get(vw.id).n).toBe(0)
  })

  it('saving a custom-role user without a role change leaves their roles untouched', async () => {
    await rbac.createRole('author', 'Author')
    addUser('Steady', 'viewer')
    await rbac.setUserRoles('Steady', ['role-author'])
    kv.set('rbac:perms:Steady', '["x"]')
    await save('Steady', 'role-author')
    expect(kv.has('rbac:perms:Steady')).toBe(true)
  })

  it('a role id wins over another role whose name matches it', async () => {
    await rbac.createRole('zeta', 'Zeta')
    await rbac.createRole('q', 'Q')
    await rbac.updateRole('role-q', 'Q', '', 'role-zeta')
    addUser('Picked', 'viewer')
    await save('Picked', 'role-zeta')
    expect(await rolesOf('Picked')).toEqual(['role-zeta'])
  })

  it('invite validates the role and assigns it', async () => {
    const bad = await app.request('/admin/invite-user', { method: 'POST', body: form({ email: 'i1@x.y', first_name: 'I', last_name: 'N', role: 'nope' }) })
    expect(bad.status).toBe(400)
    const ok = await app.request('/admin/invite-user', { method: 'POST', body: form({ email: 'i2@x.y', first_name: 'I', last_name: 'N', role: 'role-editor' }) })
    expect(ok.status).toBe(200)
    const id = (await ok.json()).user.id
    expect(await rolesOf(id)).toEqual(['role-editor'])
    expect(label(id)).toBe('editor')
  })
})
