// @ts-nocheck
// Real-SQLite coverage for the multi-tenant plugin's TenantService. Exercises actual SQL against
// the Better Auth `auth_tenant` table — slug/domain uniqueness, reserved slugs, the default-tenant
// guards, and the delete-blocked-while-owning-docs guard. Mock tests can't verify any of this (R10).
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../../../../__tests__/utils/d1-sqlite'
import { TenantService } from '../services/tenant-service'

describe('TenantService — real SQLite', () => {
  let db
  let svc
  beforeEach(async () => {
    db = createTestD1()
    svc = new TenantService(db)
  })
  afterEach(() => db.close())

  it('ensureDefaultTenant is idempotent and creates one active default row', async () => {
    const a = await svc.ensureDefaultTenant()
    const b = await svc.ensureDefaultTenant()
    expect(a.slug).toBe('default')
    expect(a.status).toBe('active')
    expect(b.slug).toBe('default')
    const rows = db.raw.prepare("SELECT COUNT(*) c FROM auth_tenant WHERE slug='default'").get()
    expect(rows.c).toBe(1)
  })

  it('createTenant persists row with status and normalized domain', async () => {
    const t = await svc.createTenant({ name: 'Acme Inc', slug: 'acme', domain: 'Acme.Example.com' })
    expect(t.slug).toBe('acme')
    expect(t.status).toBe('active')
    expect(t.domain).toBe('acme.example.com') // normalized lowercase

    const row = db.raw.prepare("SELECT status s, domain d FROM auth_tenant WHERE slug='acme'").get()
    expect(row.s).toBe('active')
    expect(row.d).toBe('acme.example.com')
  })

  it('getTenantByDomain matches on the normalized domain column', async () => {
    await svc.createTenant({ name: 'Acme', slug: 'acme', domain: 'acme.example.com' })
    const found = await svc.getTenantByDomain('ACME.example.com')
    expect(found?.slug).toBe('acme')
    expect(await svc.getTenantByDomain('nope.example.com')).toBeNull()
  })

  it('rejects invalid slugs, reserved slugs, and the default slug', async () => {
    await expect(svc.createTenant({ name: 'Bad', slug: 'Has Spaces' })).rejects.toThrow(/lowercase/)
    await expect(svc.createTenant({ name: 'Admin', slug: 'admin' })).rejects.toThrow(/reserved/)
    await expect(svc.createTenant({ name: 'Default', slug: 'default' })).rejects.toThrow(/built-in/)
  })

  it('rejects duplicate slug and duplicate domain', async () => {
    await svc.createTenant({ name: 'Acme', slug: 'acme', domain: 'acme.example.com' })
    await expect(svc.createTenant({ name: 'Acme 2', slug: 'acme' })).rejects.toThrow(/already exists/)
    await expect(svc.createTenant({ name: 'Beta', slug: 'beta', domain: 'acme.example.com' })).rejects.toThrow(/already mapped/)
  })

  it('updateTenant changes name/domain/status; refuses to deactivate default', async () => {
    await svc.ensureDefaultTenant()
    await svc.createTenant({ name: 'Acme', slug: 'acme' })
    const updated = await svc.updateTenant('acme', { name: 'Acme Corp', status: 'inactive', domain: 'acme.io' })
    expect(updated.name).toBe('Acme Corp')
    expect(updated.status).toBe('inactive')
    expect(updated.domain).toBe('acme.io')
    await expect(svc.updateTenant('default', { status: 'inactive' })).rejects.toThrow(/cannot be deactivated/)
  })

  it('listTenants returns default first then alphabetical', async () => {
    await svc.ensureDefaultTenant()
    await svc.createTenant({ name: 'Zeta', slug: 'zeta' })
    await svc.createTenant({ name: 'Alpha', slug: 'alpha' })
    const list = await svc.listTenants()
    expect(list.map((t) => t.slug)).toEqual(['default', 'alpha', 'zeta'])
  })

  it('deleteTenant refuses the default tenant', async () => {
    await svc.ensureDefaultTenant()
    await expect(svc.deleteTenant('default')).rejects.toThrow(/cannot be deleted/)
  })

  it('membership: addMember enrolls a user; isMember/listMemberSlugs reflect it', async () => {
    // FK targets — a tenant row and a user row.
    await svc.createTenant({ name: 'Acme', slug: 'acme' })
    await svc.createTenant({ name: 'Beta', slug: 'beta' })
    db.raw.prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
       VALUES ('u1','u1@example.com','U','One',1,1)`
    ).run()

    expect(await svc.isMember('u1', 'acme')).toBe(false)
    // 'default' is always allowed without a row.
    expect(await svc.isMember('u1', 'default')).toBe(true)

    await svc.addMember('acme', 'u1', 'admin', 'u1@example.com')
    expect(await svc.isMember('u1', 'acme')).toBe(true)
    expect(await svc.isMember('u1', 'beta')).toBe(false)
    expect((await svc.listMemberSlugs('u1')).sort()).toEqual(['acme'])

    // Idempotent — second add does not duplicate (UNIQUE(tenant_id,user_id)).
    await svc.addMember('acme', 'u1', 'admin', 'u1@example.com')
    expect((await svc.listMemberSlugs('u1'))).toEqual(['acme'])

    // Per-tenant roles: admin in acme, viewer in beta (same user, different roles).
    await svc.addMember('beta', 'u1', 'viewer')
    expect((await svc.listMemberSlugs('u1')).sort()).toEqual(['acme', 'beta'])
    expect(await svc.getMemberRole('u1', 'acme')).toBe('admin')
    expect(await svc.getMemberRole('u1', 'beta')).toBe('viewer')
    expect(await svc.getMemberRole('u1', 'nope')).toBeNull()
    const roles = await svc.listMemberRoles('u1')
    expect(roles.get('acme')).toBe('admin')
    expect(roles.get('beta')).toBe('viewer')
  })

  it('member management: add-by-email, listMembers, setMemberRole, removeMember + lockout guards', async () => {
    await svc.createTenant({ name: 'Acme', slug: 'acme' })
    const mkUser = (id: string, email: string) =>
      db.raw.prepare(
        `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
         VALUES (?, ?, 'F', 'L', 1, 1)`
      ).run(id, email)
    mkUser('owner1', 'owner@example.com')
    mkUser('ed1', 'ed@example.com')

    // Seed an admin so the tenant is not adminless.
    await svc.addMember('acme', 'owner1', 'admin', 'owner@example.com')

    // Add by email with a role.
    await svc.addMemberByEmail('acme', 'ED@example.com', 'editor')
    const members = await svc.listMembers('acme')
    expect(members.map((m) => m.email).sort()).toEqual(['ed@example.com', 'owner@example.com'])
    expect(members.find((m) => m.email === 'ed@example.com')?.role).toBe('editor')
    // admin sorts first.
    expect(members[0].role).toBe('admin')

    // Unknown email + duplicate + bad role are rejected.
    await expect(svc.addMemberByEmail('acme', 'ghost@example.com', 'viewer')).rejects.toThrow(/No user found/)
    await expect(svc.addMemberByEmail('acme', 'ed@example.com', 'viewer')).rejects.toThrow(/already a member/)
    await expect(svc.addMemberByEmail('acme', 'owner@example.com', 'superuser')).rejects.toThrow(/Invalid role/)

    // Change role.
    await svc.setMemberRole('acme', 'ed1', 'viewer')
    expect(await svc.getMemberRole('ed1', 'acme')).toBe('viewer')

    // Lockout guard: cannot demote or remove the last admin.
    await expect(svc.setMemberRole('acme', 'owner1', 'viewer')).rejects.toThrow(/last admin/)
    await expect(svc.removeMember('acme', 'owner1')).rejects.toThrow(/last admin/)

    // Promote ed to admin → now two admins → owner can be removed.
    await svc.setMemberRole('acme', 'ed1', 'admin')
    await svc.removeMember('acme', 'owner1')
    expect((await svc.listMembers('acme')).map((m) => m.email)).toEqual(['ed@example.com'])
  })

  it('user-centric: listUserMemberships + listAssignmentsByRole', async () => {
    await svc.createTenant({ name: 'Acme', slug: 'acme' })
    await svc.createTenant({ name: 'Beta', slug: 'beta' })
    db.raw.prepare(`INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at) VALUES ('u1','u1@x.com','U','One',1,1)`).run()
    db.raw.prepare(`INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at) VALUES ('u2','u2@x.com','U','Two',1,1)`).run()

    await svc.addMember('acme', 'u1', 'admin', 'u1@x.com')
    await svc.addMember('beta', 'u1', 'viewer', 'u1@x.com')
    await svc.addMember('acme', 'u2', 'viewer', 'u2@x.com')

    // User-centric: u1 belongs to acme(admin) + beta(viewer).
    const u1 = await svc.listUserMemberships('u1')
    expect(u1.map((m) => `${m.slug}:${m.role}`).sort()).toEqual(['acme:admin', 'beta:viewer'])
    expect(u1.find((m) => m.slug === 'acme')?.name).toBe('Acme')
    expect(await svc.listUserMemberships('u2')).toEqual([{ slug: 'acme', name: 'Acme', role: 'viewer' }])

    // Role-centric: 'viewer' assigned to u1@beta and u2@acme.
    const viewers = await svc.listAssignmentsByRole('viewer')
    expect(viewers.map((a) => `${a.email}@${a.slug}`).sort()).toEqual(['u1@x.com@beta', 'u2@x.com@acme'])
    expect((await svc.listAssignmentsByRole('admin')).map((a) => a.email)).toEqual(['u1@x.com'])
    expect(await svc.listAssignmentsByRole('author')).toEqual([])
  })

  it('invitations: create → accept (email must match) → membership; revoke + duplicate + expiry guards', async () => {
    await svc.createTenant({ name: 'Acme', slug: 'acme' })
    db.raw.prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
       VALUES ('invitee', 'invitee@example.com', 'In', 'Vitee', 1, 1)`
    ).run()

    // Create a pending invitation.
    const token = await svc.createInvitation('acme', 'Invitee@example.com', 'editor', null)
    expect((await svc.listInvitations('acme')).map((i) => i.email)).toEqual(['invitee@example.com'])

    // Duplicate pending invite is rejected; bad role rejected.
    await expect(svc.createInvitation('acme', 'invitee@example.com', 'viewer')).rejects.toThrow(/already exists/)
    await expect(svc.createInvitation('acme', 'x@example.com', 'root')).rejects.toThrow(/Invalid role/)

    // Accept with a mismatched email is refused (no token-only binding).
    await expect(svc.acceptInvitation(token, 'invitee', 'someone-else@example.com')).rejects.toThrow(/different email/)

    // Accept with the matching email → member with the invited role; invitation leaves 'pending'.
    const res = await svc.acceptInvitation(token, 'invitee', 'invitee@example.com')
    expect(res).toEqual({ slug: 'acme', role: 'editor' })
    expect(await svc.getMemberRole('invitee', 'acme')).toBe('editor')
    expect(await svc.listInvitations('acme')).toEqual([])

    // Re-accepting a used invitation fails.
    await expect(svc.acceptInvitation(token, 'invitee', 'invitee@example.com')).rejects.toThrow(/invalid or already used/)

    // Inviting an existing member is rejected.
    await expect(svc.createInvitation('acme', 'invitee@example.com', 'viewer')).rejects.toThrow(/already a member/)

    // Revoke drops a pending invite from the list.
    const t2 = await svc.createInvitation('acme', 'another@example.com', 'viewer')
    expect((await svc.listInvitations('acme')).length).toBe(1)
    await svc.revokeInvitation('acme', t2)
    expect(await svc.listInvitations('acme')).toEqual([])

    // Expired invitation cannot be accepted.
    db.raw.prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
       VALUES ('late', 'late@example.com', 'La', 'Te', 1, 1)`
    ).run()
    const t3 = await svc.createInvitation('acme', 'late@example.com', 'viewer')
    db.raw.prepare("UPDATE auth_tenant_invitation SET expires_at = 1 WHERE id = ?").run(t3)
    await expect(svc.acceptInvitation(t3, 'late', 'late@example.com')).rejects.toThrow(/expired/)
  })

  it('deleteTenant is blocked while the tenant owns documents, allowed once empty', async () => {
    await svc.createTenant({ name: 'Acme', slug: 'acme' })
    // Seed a content document owned by tenant 'acme'.
    db.raw.prepare(
      `INSERT INTO documents (id, root_id, type_id, version_number, is_current_draft, is_published, status,
        parent_root_id, slug, title, tenant_id, locale, translation_group_id, data, metadata, created_at, updated_at)
       VALUES ('d1','d1','blog_post',1,1,1,'published','','post-1','Post','acme','default','','{}','{}',1,1)`
    ).run()

    await expect(svc.deleteTenant('acme')).rejects.toThrow(/still owns 1 document/)
    expect(await svc.countDocumentsForTenant('acme')).toBe(1)

    // Soft-delete the doc, then deletion succeeds.
    db.raw.prepare("UPDATE documents SET deleted_at=2 WHERE id='d1'").run()
    expect(await svc.countDocumentsForTenant('acme')).toBe(0)
    await svc.deleteTenant('acme')
    expect(await svc.getTenantBySlug('acme')).toBeNull()
  })
})
