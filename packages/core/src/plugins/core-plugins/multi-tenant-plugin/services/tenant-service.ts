/**
 * TenantService — Better Auth `auth_tenant` table is the tenant registry (organization plugin).
 *
 * Tenants are rows in `auth_tenant` (BA organization model, modelName remapped). SonicJS-specific
 * resolution fields (`status`, `domain`, `notes`) are BA `additionalFields` on the same table.
 * Content ownership stays on `documents.tenant_id` (slug) — `countDocumentsForTenant` reads it to
 * fail-close deletes. Timestamps are ms (auth-table convention; BA writes Date → timestamp_ms).
 */
import type { D1Database } from '@cloudflare/workers-types'
import { invalidateTenantCache } from '../../../../middleware/tenant'

export interface TenantData {
  /** Tenant id == auth_tenant.slug (the document tenant_id scope). */
  slug: string
  name: string
  domain: string | null
  status: 'active' | 'inactive'
  notes: string
  createdAt: number
  updatedAt: number
}

export const DEFAULT_TENANT_SLUG = 'default'

/** Slugs that would collide with routing or platform conventions. */
export const RESERVED_TENANT_SLUGS = ['www', 'admin', 'api', 'auth', 'assets', 'static', 'invitations', 'users', 'roles']

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Role names the document ACL understands (per-tenant member roles). */
export const VALID_MEMBER_ROLES = ['admin', 'editor', 'author', 'viewer'] as const
export type MemberRole = (typeof VALID_MEMBER_ROLES)[number]

export function isValidMemberRole(role: string): role is MemberRole {
  return (VALID_MEMBER_ROLES as readonly string[]).includes(role)
}

export interface TenantMember {
  userId: string
  email: string
  name: string
  role: string
  createdAt: number
}

export interface TenantInvitation {
  id: string
  email: string
  role: string
  status: string
  expiresAt: number
  createdAt: number
}

/** Pending invitations live this long (ms) before they expire. */
const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000

export function isValidTenantSlug(slug: string): boolean {
  return SLUG_PATTERN.test(slug)
}

export class TenantService {
  constructor(private db: D1Database) {}

  async listTenants(): Promise<TenantData[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM auth_tenant
      ORDER BY CASE WHEN slug = 'default' THEN 0 ELSE 1 END, name ASC
    `).all()
    return (results || []).map(mapRowToTenant)
  }

  async getTenantBySlug(slug: string): Promise<TenantData | null> {
    const row = await this.db.prepare(`SELECT * FROM auth_tenant WHERE slug = ?`).bind(slug).first()
    return row ? mapRowToTenant(row) : null
  }

  async getTenantByDomain(host: string): Promise<TenantData | null> {
    const row = await this.db.prepare(`SELECT * FROM auth_tenant WHERE domain = ?`)
      .bind(host.toLowerCase()).first()
    return row ? mapRowToTenant(row) : null
  }

  /**
   * Idempotently creates the 'default' tenant record so the registry always reflects the tenant
   * every pre-existing document belongs to.
   */
  async ensureDefaultTenant(): Promise<TenantData> {
    const existing = await this.getTenantBySlug(DEFAULT_TENANT_SLUG)
    if (existing) return existing
    return this.insertTenant({ name: 'Default', slug: DEFAULT_TENANT_SLUG, domain: null, notes: 'Built-in default tenant. All documents belong here until other tenants are used.' })
  }

  async createTenant(input: { name: string; slug: string; domain?: string | null; notes?: string }): Promise<TenantData> {
    const slug = input.slug.trim().toLowerCase()
    const name = input.name.trim()
    if (!name) throw new Error('Tenant name is required')
    if (!isValidTenantSlug(slug)) throw new Error('Slug must be lowercase letters, numbers and hyphens (max 63 chars)')
    if (slug === DEFAULT_TENANT_SLUG) throw new Error(`'${DEFAULT_TENANT_SLUG}' is the built-in tenant`)
    if (RESERVED_TENANT_SLUGS.includes(slug)) throw new Error(`'${slug}' is a reserved slug`)
    if (await this.getTenantBySlug(slug)) throw new Error(`A tenant with slug '${slug}' already exists`)

    const domain = normalizeDomain(input.domain)
    if (domain) {
      const owner = await this.getTenantByDomain(domain)
      if (owner) throw new Error(`Domain '${domain}' is already mapped to tenant '${owner.slug}'`)
    }

    return this.insertTenant({ name, slug, domain, notes: input.notes?.trim() ?? '' })
  }

  async updateTenant(slug: string, patch: { name?: string; domain?: string | null; status?: 'active' | 'inactive'; notes?: string }): Promise<TenantData> {
    const tenant = await this.getTenantBySlug(slug)
    if (!tenant) throw new Error('Tenant not found')
    if (slug === DEFAULT_TENANT_SLUG && patch.status === 'inactive') {
      throw new Error('The default tenant cannot be deactivated')
    }

    const name = patch.name !== undefined ? patch.name.trim() : tenant.name
    if (!name) throw new Error('Tenant name is required')
    const domain = patch.domain !== undefined ? normalizeDomain(patch.domain) : tenant.domain
    if (domain && domain !== tenant.domain) {
      const owner = await this.getTenantByDomain(domain)
      if (owner && owner.slug !== slug) throw new Error(`Domain '${domain}' is already mapped to tenant '${owner.slug}'`)
    }
    const status = patch.status ?? tenant.status
    const notes = patch.notes !== undefined ? patch.notes.trim() : tenant.notes

    const now = Date.now()
    await this.db.prepare(`
      UPDATE auth_tenant
      SET name = ?, domain = ?, status = ?, notes = ?, updated_at = ?
      WHERE slug = ?
    `).bind(name, domain, status, notes, now, slug).run()

    invalidateTenantCache()
    const updated = await this.getTenantBySlug(slug)
    if (!updated) throw new Error('Tenant not found')
    return updated
  }

  /**
   * Deletes a tenant record. Fail-closed: refuses the default tenant and any tenant that still
   * owns documents — the admin must move or erase the tenant's content first (no silent cascade).
   */
  async deleteTenant(slug: string): Promise<void> {
    if (slug === DEFAULT_TENANT_SLUG) throw new Error('The default tenant cannot be deleted')
    const tenant = await this.getTenantBySlug(slug)
    if (!tenant) throw new Error('Tenant not found')

    const docCount = await this.countDocumentsForTenant(slug)
    if (docCount > 0) {
      throw new Error(`Tenant '${slug}' still owns ${docCount} document(s). Delete or migrate its content first.`)
    }

    // Hard delete the registry row (auth_tenant_member rows cascade via FK).
    await this.db.prepare(`DELETE FROM auth_tenant WHERE slug = ?`).bind(slug).run()
    invalidateTenantCache()
  }

  // ─── Membership (auth_tenant_member) ───────────────────────────────────────
  // Tenant resolution and the admin switcher are gated on membership: an authed user may only
  // resolve/switch into tenants they belong to (the 'default' tenant is always open). member rows
  // reference auth_tenant.id (UUID); callers work in slugs, so these join through auth_tenant.

  /** Slugs the user is a member of (excludes the always-open 'default'). */
  async listMemberSlugs(userId: string): Promise<string[]> {
    const { results } = await this.db.prepare(`
      SELECT t.slug FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ?
    `).bind(userId).all()
    return (results || []).map((r: any) => r.slug as string)
  }

  /** slug -> the user's role IN that tenant (per-tenant RBAC). Excludes 'default'. */
  async listMemberRoles(userId: string): Promise<Map<string, string>> {
    const { results } = await this.db.prepare(`
      SELECT t.slug, m.role FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ?
    `).bind(userId).all()
    return new Map((results || []).map((r: any) => [r.slug as string, (r.role as string) || 'viewer']))
  }

  /** A user's tenant memberships joined with tenant details (user-centric view). */
  async listUserMemberships(userId: string): Promise<Array<{ slug: string; name: string; role: string }>> {
    const { results } = await this.db.prepare(`
      SELECT t.slug, t.name AS tenant_name, m.role
      FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ?
      ORDER BY CASE WHEN t.slug = 'default' THEN 0 ELSE 1 END, t.name ASC
    `).bind(userId).all()
    return (results || []).map((r: any) => ({ slug: r.slug, name: r.tenant_name || r.slug, role: r.role || 'viewer' }))
  }

  /** All (tenant, user) assignments holding a given role — powers the roles "where used" view. */
  async listAssignmentsByRole(role: string): Promise<Array<{ slug: string; tenantName: string; userId: string; email: string }>> {
    const { results } = await this.db.prepare(`
      SELECT t.slug, t.name AS tenant_name, u.id AS user_id, u.email
      FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      JOIN auth_user u ON u.id = m.user_id
      WHERE m.role = ?
      ORDER BY t.name ASC, u.email ASC
    `).bind(role).all()
    return (results || []).map((r: any) => ({ slug: r.slug, tenantName: r.tenant_name || r.slug, userId: r.user_id, email: r.email }))
  }

  /** The user's role in a tenant, or null if not a member. */
  async getMemberRole(userId: string, slug: string): Promise<string | null> {
    const row = await this.db.prepare(`
      SELECT m.role FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ? AND t.slug = ? LIMIT 1
    `).bind(userId, slug).first() as { role?: string } | null
    return row ? (row.role || 'viewer') : null
  }

  /** True if the user may access the tenant. 'default' is always allowed. */
  async isMember(userId: string, slug: string): Promise<boolean> {
    if (slug === DEFAULT_TENANT_SLUG) return true
    const row = await this.db.prepare(`
      SELECT 1 FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ? AND t.slug = ? LIMIT 1
    `).bind(userId, slug).first()
    return !!row
  }

  /** Idempotently grants a user membership of a tenant (UNIQUE(tenant_id,user_id)). */
  async addMember(slug: string, userId: string, role = 'member', email: string | null = null): Promise<void> {
    const tenant = await this.db.prepare('SELECT id FROM auth_tenant WHERE slug = ?')
      .bind(slug).first() as { id?: string } | null
    if (!tenant?.id) throw new Error('Tenant not found')
    const id = crypto.randomUUID()
    const now = Date.now()
    await this.db.prepare(`
      INSERT OR IGNORE INTO auth_tenant_member (id, tenant_id, user_id, role, email, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(id, tenant.id, userId, role, email, now, now).run()
  }

  /** Members of a tenant joined with user details, ordered admins-first then by email. */
  async listMembers(slug: string): Promise<TenantMember[]> {
    const { results } = await this.db.prepare(`
      SELECT u.id AS user_id, u.email, u.first_name, u.last_name, m.role, m.created_at
      FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      JOIN auth_user u ON u.id = m.user_id
      WHERE t.slug = ?
      ORDER BY CASE WHEN m.role = 'admin' THEN 0 ELSE 1 END, u.email ASC
    `).bind(slug).all()
    return (results || []).map((r: any) => ({
      userId: r.user_id,
      email: r.email,
      name: [r.first_name, r.last_name].filter(Boolean).join(' ').trim() || r.email,
      role: r.role || 'viewer',
      createdAt: Number(r.created_at),
    }))
  }

  /** Add a member by their email address (the admin-facing flow). */
  async addMemberByEmail(slug: string, email: string, role: string): Promise<void> {
    const normalized = email.trim().toLowerCase()
    if (!normalized) throw new Error('Email is required')
    if (!isValidMemberRole(role)) throw new Error(`Invalid role '${role}'`)
    const tenant = await this.getTenantBySlug(slug)
    if (!tenant) throw new Error('Tenant not found')

    const user = await this.db.prepare('SELECT id, email FROM auth_user WHERE lower(email) = ?')
      .bind(normalized).first() as { id?: string; email?: string } | null
    if (!user?.id) throw new Error(`No user found with email '${email}'`)
    const existing = await this.db.prepare(`
      SELECT 1 FROM auth_tenant_member m JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ? AND t.slug = ? LIMIT 1
    `).bind(user.id, slug).first()
    if (existing) throw new Error(`${email} is already a member of '${slug}'`)

    await this.addMember(slug, user.id, role, user.email ?? normalized)
  }

  /** Change a member's role. Refuses to demote the last admin (lockout guard). */
  async setMemberRole(slug: string, userId: string, role: string): Promise<void> {
    if (!isValidMemberRole(role)) throw new Error(`Invalid role '${role}'`)
    const current = await this.getMemberRole(userId, slug)
    if (current === null) throw new Error('Member not found')
    if (current === 'admin' && role !== 'admin' && (await this.adminCount(slug)) <= 1) {
      throw new Error('Cannot demote the last admin of a tenant')
    }
    const now = Date.now()
    await this.db.prepare(`
      UPDATE auth_tenant_member SET role = ?, updated_at = ?
      WHERE tenant_id = (SELECT id FROM auth_tenant WHERE slug = ?) AND user_id = ?
    `).bind(role, now, slug, userId).run()
  }

  /** Remove a member. Refuses to remove the last admin (lockout guard). */
  async removeMember(slug: string, userId: string): Promise<void> {
    const current = await this.getMemberRole(userId, slug)
    if (current === null) throw new Error('Member not found')
    if (current === 'admin' && (await this.adminCount(slug)) <= 1) {
      throw new Error('Cannot remove the last admin of a tenant')
    }
    await this.db.prepare(`
      DELETE FROM auth_tenant_member
      WHERE tenant_id = (SELECT id FROM auth_tenant WHERE slug = ?) AND user_id = ?
    `).bind(slug, userId).run()
  }

  /** Count admin-role members of a tenant. */
  private async adminCount(slug: string): Promise<number> {
    const row = await this.db.prepare(`
      SELECT COUNT(*) AS c FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE t.slug = ? AND m.role = 'admin'
    `).bind(slug).first() as { c?: number } | null
    return row?.c ?? 0
  }

  // ─── Invitations (auth_tenant_invitation) ──────────────────────────────────
  // Invite an email to a tenant with a per-tenant role. The pending row's id doubles as the accept
  // token. Accepting requires the invitee to be signed in with the invited email — it never trusts
  // the token alone to bind an arbitrary account.

  /** Create a pending invitation. Returns the invitation id (the accept token). */
  async createInvitation(slug: string, email: string, role: string, inviterId: string | null): Promise<string> {
    const normalized = email.trim().toLowerCase()
    if (!normalized) throw new Error('Email is required')
    if (!isValidMemberRole(role)) throw new Error(`Invalid role '${role}'`)
    const tenant = await this.getTenantBySlug(slug)
    if (!tenant) throw new Error('Tenant not found')

    const existingUser = await this.db.prepare('SELECT id FROM auth_user WHERE lower(email) = ?')
      .bind(normalized).first() as { id?: string } | null
    if (existingUser?.id) {
      const alreadyMember = await this.db.prepare(`
        SELECT 1 FROM auth_tenant_member m JOIN auth_tenant t ON t.id = m.tenant_id
        WHERE m.user_id = ? AND t.slug = ? LIMIT 1
      `).bind(existingUser.id, slug).first()
      if (alreadyMember) throw new Error(`${email} is already a member of '${slug}'`)
    }
    const pending = await this.db.prepare(`
      SELECT i.id FROM auth_tenant_invitation i
      JOIN auth_tenant t ON t.id = i.tenant_id
      WHERE t.slug = ? AND lower(i.email) = ? AND i.status = 'pending' LIMIT 1
    `).bind(slug, normalized).first()
    if (pending) throw new Error(`A pending invitation for ${email} already exists`)

    const id = crypto.randomUUID()
    const now = Date.now()
    // R5: 9 columns / 9 ? — verified.
    await this.db.prepare(`
      INSERT INTO auth_tenant_invitation (id, tenant_id, email, role, status, expires_at, inviter_id, created_at, updated_at)
      VALUES (?, (SELECT id FROM auth_tenant WHERE slug = ?), ?, ?, 'pending', ?, ?, ?, ?)
    `).bind(id, slug, normalized, role, now + INVITATION_TTL_MS, inviterId, now, now).run()
    return id
  }

  /** Pending (non-expired) invitations for a tenant. */
  async listInvitations(slug: string): Promise<TenantInvitation[]> {
    const { results } = await this.db.prepare(`
      SELECT i.id, i.email, i.role, i.status, i.expires_at, i.created_at
      FROM auth_tenant_invitation i
      JOIN auth_tenant t ON t.id = i.tenant_id
      WHERE t.slug = ? AND i.status = 'pending'
      ORDER BY i.created_at DESC
    `).bind(slug).all()
    return (results || []).map((r: any) => ({
      id: r.id, email: r.email, role: r.role || 'viewer', status: r.status,
      expiresAt: Number(r.expires_at), createdAt: Number(r.created_at),
    }))
  }

  /** Revoke (cancel) a pending invitation by id, scoped to the tenant. */
  async revokeInvitation(slug: string, id: string): Promise<void> {
    await this.db.prepare(`
      UPDATE auth_tenant_invitation SET status = 'revoked', updated_at = ?
      WHERE id = ? AND tenant_id = (SELECT id FROM auth_tenant WHERE slug = ?) AND status = 'pending'
    `).bind(Date.now(), id, slug).run()
  }

  /**
   * Accept an invitation. Fail-closed: the token must be a pending, non-expired invitation AND the
   * accepting user's email must match the invited email. On success the user becomes a member with
   * the invited role and the invitation is marked accepted.
   */
  async acceptInvitation(token: string, userId: string, userEmail: string): Promise<{ slug: string; role: string }> {
    const row = await this.db.prepare(`
      SELECT i.id, i.email, i.role, i.status, i.expires_at, t.slug
      FROM auth_tenant_invitation i
      JOIN auth_tenant t ON t.id = i.tenant_id
      WHERE i.id = ?
    `).bind(token).first() as
      { id?: string; email?: string; role?: string; status?: string; expires_at?: number; slug?: string } | null

    if (!row?.id || row.status !== 'pending') throw new Error('Invitation is invalid or already used')
    if (Number(row.expires_at) < Date.now()) {
      await this.db.prepare("UPDATE auth_tenant_invitation SET status = 'expired', updated_at = ? WHERE id = ?")
        .bind(Date.now(), token).run()
      throw new Error('Invitation has expired')
    }
    if ((row.email ?? '').toLowerCase() !== userEmail.trim().toLowerCase()) {
      throw new Error('This invitation is for a different email address')
    }

    const slug = row.slug!
    const role = row.role || 'viewer'
    await this.addMember(slug, userId, role, userEmail)
    await this.db.prepare("UPDATE auth_tenant_invitation SET status = 'accepted', updated_at = ? WHERE id = ?")
      .bind(Date.now(), token).run()
    return { slug, role }
  }

  /** Live documents owned by the tenant (all types — content, media, plugin data, …). */
  async countDocumentsForTenant(slug: string): Promise<number> {
    const row = await this.db.prepare(
      'SELECT COUNT(*) as count FROM documents WHERE tenant_id = ? AND deleted_at IS NULL'
    ).bind(slug).first() as { count?: number } | null
    return row?.count ?? 0
  }

  private async insertTenant(input: { name: string; slug: string; domain: string | null; notes: string }): Promise<TenantData> {
    const id = crypto.randomUUID()
    const now = Date.now()
    // R5: 9 columns / 9 ? — verified.
    await this.db.prepare(`
      INSERT INTO auth_tenant (id, name, slug, status, domain, notes, metadata, created_at, updated_at)
      VALUES (?, ?, ?, 'active', ?, ?, '{}', ?, ?)
    `).bind(id, input.name, input.slug, input.domain, input.notes, now, now).run()

    invalidateTenantCache()
    const created = await this.getTenantBySlug(input.slug)
    if (!created) throw new Error('Failed to create tenant')
    return created
  }
}

function normalizeDomain(domain: string | null | undefined): string | null {
  const trimmed = domain?.trim().toLowerCase() ?? ''
  return trimmed === '' ? null : trimmed
}

function mapRowToTenant(row: any): TenantData {
  return {
    slug: row.slug,
    name: row.name || row.slug,
    domain: row.domain || null,
    status: row.status === 'inactive' ? 'inactive' : 'active',
    notes: row.notes || '',
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
  }
}
