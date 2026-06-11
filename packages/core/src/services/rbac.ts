/**
 * Dynamic RBAC service — document-backed.
 *
 * Roles, verbs, and user-role assignments are stored as `is_auth` documents
 * (slug-addressed) instead of relational tables:
 *   rbac_role        slug = roleId,  data = { name, displayName, description, isSystem, grants:[{resource,verb,scope}] }
 *   rbac_verb        slug = verbId,  data = { name, description, isSystem, sortOrder }
 *   rbac_user_roles  slug = userId,  data = { roleIds:[] }
 * Grants are embedded in the role document (no separate join type); user-role
 * assignments are embedded in a per-user document. Resources are still computed:
 * a fixed set of system resources plus one `document_type:<name>` per type.
 *
 * Wildcards: resource '*' / 'document_type:*', verb '*' / 'manage' (implies all).
 * Scope: 'any' beats 'own' beats 'none'.
 *
 * The public API is unchanged from the relational implementation, so callers
 * (admin-rbac routes, permission checks) need no changes.
 */
import { DocumentsService } from './documents'

export interface RbacRole {
  id: string
  name: string
  display_name: string
  description: string | null
  is_system: number
}
export interface RbacVerb {
  id: string
  name: string
  description: string | null
  is_system: number
  sort_order: number
}
export interface RbacResource {
  key: string // e.g. 'content' or 'collection:blog_posts'
  label: string
  group: 'system' | 'document_type'
}
export type PermissionScope = 'none' | 'own' | 'any'
export interface Grant {
  role_id: string
  resource: string
  verb: string
  scope: Exclude<PermissionScope, 'none'>
}

interface GrantData { resource: string; verb: string; scope?: PermissionScope }
interface RoleData { name: string; displayName: string; description?: string | null; isSystem?: boolean; grants?: GrantData[] }
interface VerbData { name: string; description?: string | null; isSystem?: boolean; sortOrder?: number }
interface UserRolesData { roleIds?: string[] }
interface DocRow { id: string; root_id: string; slug: string | null; data: string }

const TENANT = 'default'
const T_ROLE = 'rbac_role'
const T_VERB = 'rbac_verb'
const T_USER_ROLES = 'rbac_user_roles'

const SYSTEM_RESOURCES: RbacResource[] = [
  { key: '*', label: 'All resources', group: 'system' },
  { key: 'portal', label: 'Admin Portal', group: 'system' },
  { key: 'dashboard', label: 'Dashboard', group: 'system' },
  { key: 'rbac', label: 'Roles & Permissions', group: 'system' },
  { key: 'documents', label: 'Documents', group: 'system' as const },
  { key: 'document_types', label: 'Document Types', group: 'system' as const },
  { key: 'email', label: 'Email Management', group: 'system' },
  { key: 'users', label: 'Users', group: 'system' },
  { key: 'settings', label: 'Settings', group: 'system' },
  { key: 'logs', label: 'Logs', group: 'system' },
]

export class RbacService {
  // Precedence for projecting the user's RBAC roles back onto the legacy
  // users.role compat column (highest privilege first). Only `admin` is
  // hardcoded as a seeded role — `editor` is listed here purely so that if an
  // administrator chooses to recreate a role named `editor`, legacy code that
  // still gates on the `editor` label keeps working.
  private static readonly LEGACY_ROLE_PRECEDENCE = ['admin', 'editor']

  private _docs?: DocumentsService

  constructor(private db: D1Database, private kv?: KVNamespace) {}

  // ── Document access helpers ──────────────────────────────────────────────────

  private docs(): DocumentsService {
    if (!this._docs) {
      this._docs = new DocumentsService(this.db, { tenantId: TENANT, maxVersionsPerRoot: 1, queryableFields: [] })
    }
    return this._docs
  }

  private parse<T>(row: DocRow): { id: string; rootId: string; slug: string; data: T } {
    let data: T
    try { data = JSON.parse(row.data) as T } catch { data = {} as T }
    return { id: row.id, rootId: row.root_id, slug: row.slug ?? '', data }
  }

  private async listDocs<T>(typeId: string): Promise<Array<{ id: string; rootId: string; slug: string; data: T }>> {
    const res = await this.db
      .prepare(
        `SELECT id, root_id, slug, data FROM documents
         WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL`,
      )
      .bind(typeId, TENANT)
      .all<DocRow>()
    return (res.results ?? []).map((r) => this.parse<T>(r))
  }

  private async getDoc<T>(typeId: string, slug: string): Promise<{ id: string; rootId: string; data: T } | null> {
    const row = await this.db
      .prepare(
        `SELECT id, root_id, slug, data FROM documents
         WHERE type_id = ? AND tenant_id = ? AND slug = ? AND is_current_draft = 1 AND deleted_at IS NULL`,
      )
      .bind(typeId, TENANT, slug)
      .first<DocRow>()
    return row ? this.parse<T>(row) : null
  }

  private async upsertDoc(typeId: string, slug: string, data: unknown, title: string | null): Promise<void> {
    const existing = await this.db
      .prepare(
        `SELECT root_id FROM documents
         WHERE type_id = ? AND tenant_id = ? AND slug = ? AND is_current_draft = 1 AND deleted_at IS NULL`,
      )
      .bind(typeId, TENANT, slug)
      .first<{ root_id: string }>()
    const payload = data as Record<string, unknown>
    if (existing?.root_id) {
      await this.docs().saveDraft(existing.root_id, { data: payload, title })
    } else {
      await this.docs().create({
        typeId,
        tenantId: TENANT,
        locale: 'default',
        parentRootId: '',
        slug,
        title,
        sortOrder: 0,
        visible: true,
        data: payload,
        metadata: {},
        ownerId: null,
        publishOnCreate: false,
      })
    }
  }

  private async deleteDoc(typeId: string, slug: string): Promise<void> {
    const doc = await this.getDoc(typeId, slug)
    if (doc) await this.docs().softDelete(doc.id)
  }

  private roleToRow(d: { slug: string; data: RoleData }): RbacRole {
    return {
      id: d.slug,
      name: d.data.name,
      display_name: d.data.displayName,
      description: d.data.description ?? null,
      is_system: d.data.isSystem ? 1 : 0,
    }
  }

  // ── Reads ────────────────────────────────────────────────────────────────────

  async getRoles(): Promise<RbacRole[]> {
    const docs = await this.listDocs<RoleData>(T_ROLE)
    return docs
      .map((d) => this.roleToRow(d))
      .sort((a, b) => b.is_system - a.is_system || a.name.localeCompare(b.name))
  }

  async getVerbs(): Promise<RbacVerb[]> {
    const docs = await this.listDocs<VerbData>(T_VERB)
    return docs
      .map((d) => ({
        id: d.slug,
        name: d.data.name,
        description: d.data.description ?? null,
        is_system: d.data.isSystem ? 1 : 0,
        sort_order: d.data.sortOrder ?? 100,
      }))
      .sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name))
  }

  /** System resources + one `document_type:<name>` per active document type. */
  async getResources(): Promise<RbacResource[]> {
    const types = (
      await this.db
        .prepare('SELECT name, display_name FROM document_types WHERE is_active = 1 ORDER BY name')
        .all<{ name: string; display_name: string }>()
    ).results as Array<{ name: string; display_name: string }>
    const documentTypeResources: RbacResource[] = [
      { key: 'document_type:*', label: 'All document types', group: 'document_type' },
      ...types.map((t) => ({
        key: `document_type:${t.name}`,
        label: t.display_name || t.name,
        group: 'document_type' as const,
      })),
    ]
    return [...SYSTEM_RESOURCES, ...documentTypeResources]
  }

  async getGrants(): Promise<Grant[]> {
    const roles = await this.listDocs<RoleData>(T_ROLE)
    const out: Grant[] = []
    for (const r of roles) {
      for (const g of r.data.grants ?? []) {
        out.push({ role_id: r.slug, resource: g.resource, verb: g.verb, scope: g.scope === 'own' ? 'own' : 'any' })
      }
    }
    return out
  }

  async getRolesForUser(userId: string): Promise<RbacRole[]> {
    const ur = await this.getDoc<UserRolesData>(T_USER_ROLES, userId)
    const roleIds = new Set(ur?.data.roleIds ?? [])
    if (roleIds.size === 0) return []
    const roles = await this.listDocs<RoleData>(T_ROLE)
    return roles.filter((r) => roleIds.has(r.slug)).map((d) => this.roleToRow(d))
  }

  /** Grants attached to a set of role ids (from the embedded role grants). */
  private async grantsForRoleIds(roleIds: string[]): Promise<Array<{ resource: string; verb: string; scope: PermissionScope }>> {
    if (roleIds.length === 0) return []
    const want = new Set(roleIds)
    const roles = await this.listDocs<RoleData>(T_ROLE)
    const out: Array<{ resource: string; verb: string; scope: PermissionScope }> = []
    for (const r of roles) {
      if (!want.has(r.slug)) continue
      for (const g of r.data.grants ?? []) {
        out.push({ resource: g.resource, verb: g.verb, scope: g.scope === 'own' ? 'own' : 'any' })
      }
    }
    return out
  }

  /** Does a single grant row satisfy the requested (resource, verb)? */
  private grantMatches(g: { resource: string; verb: string }, resource: string, verb: string): boolean {
    const resourceOk =
      g.resource === '*' ||
      g.resource === resource ||
      (g.resource === 'document_type:*' && resource.startsWith('document_type:'))
    if (!resourceOk) return false
    return g.verb === '*' || g.verb === verb || g.verb === 'manage'
  }

  private strongestScope(scopes: PermissionScope[]): PermissionScope {
    if (scopes.includes('any')) return 'any'
    if (scopes.includes('own')) return 'own'
    return 'none'
  }

  /** Can the user perform `verb` on `resource`? Reads the live grant matrix. */
  async can(userId: string, resource: string, verb: string): Promise<boolean> {
    return (await this.getPermissionScope(userId, resource, verb)) !== 'none'
  }

  /** Highest scope granted to the user for `resource:verb`. */
  async getPermissionScope(userId: string, resource: string, verb: string): Promise<PermissionScope> {
    const ur = await this.getDoc<UserRolesData>(T_USER_ROLES, userId)
    const grants = await this.grantsForRoleIds(ur?.data.roleIds ?? [])
    return this.strongestScope(
      grants.filter((g) => this.grantMatches(g, resource, verb)).map((g) => (g.scope === 'own' ? 'own' : 'any')),
    )
  }

  /** Flattened, human-readable permission list for a user. Cached in KV for 60 s. */
  async permissionsForUser(userId: string): Promise<string[]> {
    if (this.kv) {
      const cached = await this.kv.get(`rbac:perms:${userId}`)
      if (cached !== null) return JSON.parse(cached) as string[]
    }
    const ur = await this.getDoc<UserRolesData>(T_USER_ROLES, userId)
    const roleIds = ur?.data.roleIds ?? []
    if (roleIds.length === 0) return []
    const grants = await this.grantsForRoleIds(roleIds)
    const resources = await this.getResources()
    const verbs = await this.getVerbs()
    const out = new Set<string>()
    for (const r of resources) {
      for (const v of verbs) {
        if (grants.some((g) => this.grantMatches(g, r.key, v.name))) out.add(`${r.key}:${v.name}`)
      }
    }
    const result = [...out].sort()
    if (this.kv) {
      await this.kv.put(`rbac:perms:${userId}`, JSON.stringify(result), { expirationTtl: 60 })
    }
    return result
  }

  // ── Mutations ──────────────────────────────────────────────────────────────

  async createRole(name: string, displayName: string, description = ''): Promise<void> {
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    const id = `role-${slug}`
    await this.upsertDoc(
      T_ROLE,
      id,
      { name: name.toLowerCase(), displayName, description, isSystem: false, grants: [] } satisfies RoleData,
      displayName,
    )
  }

  async deleteRole(roleId: string): Promise<void> {
    const role = await this.getDoc<RoleData>(T_ROLE, roleId)
    if (!role || role.data.isSystem) return // System roles cannot be deleted.
    await this.deleteDoc(T_ROLE, roleId)
  }

  /**
   * Update a role's display name and description. The `name` (slug) can only be
   * changed for custom roles — system role names are referenced by the legacy
   * mapping, so they stay fixed.
   */
  async updateRole(roleId: string, displayName: string, description = '', name?: string): Promise<void> {
    const role = await this.getDoc<RoleData>(T_ROLE, roleId)
    if (!role) return
    const next: RoleData = { ...role.data, displayName, description }
    if (!role.data.isSystem && name) {
      next.name = name.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    }
    await this.upsertDoc(T_ROLE, roleId, next, displayName)
  }

  /** Update displayName + portal access in a single write to avoid double-saveDraft FK issues. */
  async updateRoleAndPortalAccess(
    roleId: string,
    displayName: string,
    name: string | undefined,
    portalEnabled: boolean,
    description?: string,
  ): Promise<void> {
    const role = await this.getDoc<RoleData>(T_ROLE, roleId)
    if (!role) return
    const next: RoleData = { ...role.data, displayName, description: description ?? role.data.description ?? '' }
    if (!role.data.isSystem && name) {
      next.name = name.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    }
    const grants = (next.grants ?? []).filter((g) => !(g.resource === 'portal' && g.verb === 'access'))
    if (portalEnabled) grants.push({ resource: 'portal', verb: 'access', scope: 'any' })
    next.grants = grants
    await this.upsertDoc(T_ROLE, roleId, next, displayName)
  }

  async createVerb(name: string, description = ''): Promise<void> {
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    const id = `verb-${slug}`
    await this.upsertDoc(
      T_VERB,
      id,
      { name: name.toLowerCase(), description, isSystem: false, sortOrder: 100 } satisfies VerbData,
      name,
    )
  }

  async deleteVerb(verbId: string): Promise<void> {
    const verb = await this.getDoc<VerbData>(T_VERB, verbId)
    if (!verb || verb.data.isSystem) return
    await this.deleteDoc(T_VERB, verbId)
  }

  /** Replace all grants for one role with the supplied (resource, verb, scope) rows. */
  async setRoleGrants(
    roleId: string,
    pairs: Array<{ resource: string; verb: string; scope?: Exclude<PermissionScope, 'none'> }>,
  ): Promise<void> {
    const role = await this.getDoc<RoleData>(T_ROLE, roleId)
    if (!role) return
    const grants: GrantData[] = pairs.map((p) => ({ resource: p.resource, verb: p.verb, scope: p.scope === 'own' ? 'own' : 'any' }))
    await this.upsertDoc(T_ROLE, roleId, { ...role.data, grants } satisfies RoleData, role.data.displayName)
  }

  /**
   * Count active users (optionally excluding one) who hold BOTH an effective
   * portal:access grant and an effective rbac:manage grant — the users who could
   * recover from a permission lockout. Powers the self-lockout guard.
   */
  async countPortalAdmins(excludeUserId?: string): Promise<number> {
    const active = (
      await this.db.prepare('SELECT id FROM auth_user WHERE is_active = 1').all<{ id: string }>()
    ).results as Array<{ id: string }>
    const activeIds = new Set(active.map((u) => u.id))

    // role id -> its grants
    const roles = await this.listDocs<RoleData>(T_ROLE)
    const grantsByRole = new Map<string, GrantData[]>(roles.map((r) => [r.slug, r.data.grants ?? []]))

    const userRoles = await this.listDocs<UserRolesData>(T_USER_ROLES)
    let count = 0
    for (const ur of userRoles) {
      const userId = ur.slug
      if (!activeIds.has(userId)) continue
      if (excludeUserId && userId === excludeUserId) continue
      let portal = false
      let rbac = false
      for (const rid of ur.data.roleIds ?? []) {
        for (const g of grantsByRole.get(rid) ?? []) {
          if (this.grantMatches(g, 'portal', 'access')) portal = true
          if (this.grantMatches(g, 'rbac', 'manage')) rbac = true
        }
      }
      if (portal && rbac) count++
    }
    return count
  }

  /**
   * Replace a user's RBAC role assignments. The `rbac_user_roles` document is the
   * single source of truth for authorization; the legacy `auth_user.role` column
   * is kept as a derived projection (highest-precedence system role, else
   * 'viewer') so the two never diverge.
   */
  async setUserRoles(userId: string, roleIds: string[]): Promise<void> {
    const allRoles = await this.listDocs<RoleData>(T_ROLE)
    const byId = new Map(allRoles.map((r) => [r.slug, r.data]))
    const names = roleIds.map((id) => byId.get(id)?.name).filter((n): n is string => !!n)
    const primaryRole = RbacService.LEGACY_ROLE_PRECEDENCE.find((r) => names.includes(r)) || 'viewer'

    // Self-lockout guard: never leave zero active users who can BOTH enter the
    // portal and manage RBAC (the minimum needed to recover).
    const newGrants: GrantData[] = []
    for (const id of roleIds) for (const g of byId.get(id)?.grants ?? []) newGrants.push(g)
    const userWillBeAdmin =
      newGrants.some((g) => this.grantMatches(g, 'portal', 'access')) &&
      newGrants.some((g) => this.grantMatches(g, 'rbac', 'manage'))
    if (!userWillBeAdmin && (await this.countPortalAdmins(userId)) === 0) {
      throw new Error(
        'Refusing to update roles: this would leave no user able to manage Roles & Permissions and access the portal. Grant another user portal access + Roles & Permissions first.',
      )
    }

    await this.upsertDoc(T_USER_ROLES, userId, { roleIds } satisfies UserRolesData, null)
    // Keep the legacy auth_user.role column in lockstep as a projection of RBAC.
    await this.db.prepare('UPDATE auth_user SET role = ?, updated_at = ? WHERE id = ?').bind(primaryRole, Date.now(), userId).run()
    if (this.kv) await this.kv.delete(`rbac:perms:${userId}`)
  }

  async setRolePortalAccess(roleId: string, enabled: boolean): Promise<void> {
    const role = await this.getDoc<RoleData>(T_ROLE, roleId)
    if (!role) return
    const grants = (role.data.grants ?? []).filter((g) => !(g.resource === 'portal' && g.verb === 'access'))
    if (enabled) grants.push({ resource: 'portal', verb: 'access', scope: 'any' })
    await this.upsertDoc(T_ROLE, roleId, { ...role.data, grants } satisfies RoleData, role.data.displayName)
  }

  // ── Bootstrap helpers ────────────────────────────────────────────────────────

  /**
   * Seed the system roles, verbs, and their grants as documents. Idempotent —
   * existing roles/verbs (by slug) are left untouched. Replaces the INSERT OR
   * IGNORE seeds that lived in migration 0001. Call at bootstrap, after the rbac
   * document types are registered.
   */
  async ensureSystemRbacSeed(): Promise<void> {
    // `admin` is the only hardcoded SYSTEM role (locked, undeletable). `editor`
    // is seeded as a non-system example so a fresh install has a usable second
    // role out of the box, but an administrator can edit, rename, or delete it.
    const roles: Array<RoleData & { id: string }> = [
      { id: 'role-admin', name: 'admin', displayName: 'Administrator', description: 'Full access to everything', isSystem: true,
        grants: [
          { resource: '*', verb: 'manage' }, { resource: 'portal', verb: 'access' }, { resource: 'rbac', verb: 'manage' },
          { resource: 'document_types', verb: 'manage' }, { resource: 'email', verb: 'manage' }, { resource: 'users', verb: 'manage' },
        ] },
      { id: 'role-editor', name: 'editor', displayName: 'Editor', description: 'Manage documents across all types', isSystem: false,
        grants: [
          { resource: 'portal', verb: 'access' },
          { resource: 'documents', verb: 'manage' },
          { resource: 'document_type:*', verb: 'read' },
          { resource: 'document_type:*', verb: 'create' },
          { resource: 'document_type:*', verb: 'update' },
          { resource: 'document_type:*', verb: 'delete' },
          { resource: 'settings', verb: 'read' },
        ] },
    ]
    const verbs: Array<VerbData & { id: string }> = [
      { id: 'verb-access', name: 'access', description: 'Enter or use a portal/resource', isSystem: true, sortOrder: 5 },
      { id: 'verb-read', name: 'read', description: 'View a resource', isSystem: true, sortOrder: 10 },
      { id: 'verb-create', name: 'create', description: 'Create a resource', isSystem: true, sortOrder: 20 },
      { id: 'verb-update', name: 'update', description: 'Edit a resource', isSystem: true, sortOrder: 30 },
      { id: 'verb-delete', name: 'delete', description: 'Remove a resource', isSystem: true, sortOrder: 40 },
      { id: 'verb-manage', name: 'manage', description: 'Full control (implies all verbs)', isSystem: true, sortOrder: 50 },
    ]

    for (const r of roles) {
      if (await this.getDoc(T_ROLE, r.id)) continue
      const { id, ...data } = r
      await this.upsertDoc(T_ROLE, id, data, r.displayName)
    }
    for (const v of verbs) {
      if (await this.getDoc(T_VERB, v.id)) continue
      const { id, ...data } = v
      await this.upsertDoc(T_VERB, id, data, v.name)
    }
  }

  /** Assign a role to a user by role name (e.g. 'admin'), preserving existing roles. */
  async addUserRoleByName(userId: string, roleName: string): Promise<void> {
    const roles = await this.listDocs<RoleData>(T_ROLE)
    const role = roles.find((r) => r.data.name === roleName.toLowerCase())
    if (!role) return
    const ur = await this.getDoc<UserRolesData>(T_USER_ROLES, userId)
    const roleIds = new Set(ur?.data.roleIds ?? [])
    if (roleIds.has(role.slug)) return
    roleIds.add(role.slug)
    await this.setUserRoles(userId, [...roleIds])
  }
}
