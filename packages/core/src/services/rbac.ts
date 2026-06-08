/**
 * Dynamic RBAC service.
 *
 * Roles and verbs are stored and editable at runtime. Resources are computed:
 * a fixed set of system resources plus one `collection:<name>` per collection,
 * so new collections automatically get permissions. Grants are (role, resource,
 * verb, scope) rows with wildcard support:
 *   resource '*'            → all resources
 *   resource 'collection:*' → all collections
 *   verb '*'                → all verbs
 *   verb 'manage'           → implies every verb on that resource
 *   scope 'any'             → any matching object
 *   scope 'own'             → only objects owned by the current user
 */

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
  group: 'system' | 'collection'
}
export type PermissionScope = 'none' | 'own' | 'any'
export interface Grant {
  role_id: string
  resource: string
  verb: string
  scope: Exclude<PermissionScope, 'none'>
}

const SYSTEM_RESOURCES: RbacResource[] = [
  { key: '*', label: 'All resources', group: 'system' },
  { key: 'portal', label: 'Admin Portal', group: 'system' },
  { key: 'dashboard', label: 'Dashboard', group: 'system' },
  { key: 'rbac', label: 'Roles & Permissions', group: 'system' },
  { key: 'content', label: 'Content', group: 'system' },
  { key: 'collections', label: 'Collection Schemas', group: 'system' },
  { key: 'media', label: 'Media', group: 'system' },
  { key: 'email', label: 'Email Management', group: 'system' },
  { key: 'users', label: 'Users', group: 'system' },
  { key: 'settings', label: 'Settings', group: 'system' },
  { key: 'plugins', label: 'Plugins', group: 'system' },
  { key: 'logs', label: 'Logs', group: 'system' },
]

export class RbacService {
  // Precedence for projecting the user's RBAC roles back onto the legacy
  // users.role compat column (highest privilege first). System roles only;
  // custom roles never become the projection.
  private static readonly LEGACY_ROLE_PRECEDENCE = ['admin', 'editor', 'author', 'viewer']

  constructor(private db: D1Database, private kv?: KVNamespace) {}

  private async all<T>(sql: string, ...binds: unknown[]): Promise<T[]> {
    const stmt = binds.length ? this.db.prepare(sql).bind(...binds) : this.db.prepare(sql)
    return (await stmt.all()).results as T[]
  }

  async getRoles(): Promise<RbacRole[]> {
    return this.all<RbacRole>('SELECT * FROM rbac_roles ORDER BY is_system DESC, name')
  }

  async getVerbs(): Promise<RbacVerb[]> {
    return this.all<RbacVerb>('SELECT * FROM rbac_verbs ORDER BY sort_order, name')
  }

  /** System resources + one `collection:<name>` per active collection, plus a
   *  `collection:*` row representing "all collections". */
  async getResources(): Promise<RbacResource[]> {
    const cols = await this.all<{ name: string; display_name: string }>(
      'SELECT name, display_name FROM collections WHERE is_active = 1 ORDER BY name'
    )
    const collectionResources: RbacResource[] = [
      { key: 'collection:*', label: 'All collections', group: 'collection' },
      ...cols.map((c) => ({
        key: `collection:${c.name}`,
        label: c.display_name || c.name,
        group: 'collection' as const,
      })),
    ]
    return [...SYSTEM_RESOURCES, ...collectionResources]
  }

  async getGrants(): Promise<Grant[]> {
    return this.all<Grant>("SELECT role_id, resource, verb, COALESCE(scope, 'any') as scope FROM rbac_role_grants")
  }

  async getRolesForUser(userId: string): Promise<RbacRole[]> {
    return this.all<RbacRole>(
      `SELECT r.* FROM rbac_user_roles ur JOIN rbac_roles r ON r.id = ur.role_id WHERE ur.user_id = ?`,
      userId
    )
  }

  /** Does a single grant row satisfy the requested (resource, verb)? */
  private grantMatches(g: { resource: string; verb: string }, resource: string, verb: string): boolean {
    const resourceOk =
      g.resource === '*' ||
      g.resource === resource ||
      (g.resource === 'collection:*' && resource.startsWith('collection:'))
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

  /**
   * Highest scope granted to the user for `resource:verb`.
   * `any` beats `own`; no matching grant is `none`.
   */
  async getPermissionScope(userId: string, resource: string, verb: string): Promise<PermissionScope> {
    const rows = await this.all<{ resource: string; verb: string; scope: PermissionScope }>(
      `SELECT g.resource, g.verb, COALESCE(g.scope, 'any') as scope FROM rbac_user_roles ur
       JOIN rbac_role_grants g ON g.role_id = ur.role_id
       WHERE ur.user_id = ?`,
      userId
    )
    return this.strongestScope(
      rows.filter((g) => this.grantMatches(g, resource, verb)).map((g) => (g.scope === 'own' ? 'own' : 'any'))
    )
  }

  /** Flattened, human-readable permission list for a user (expanded vs resources).
   *  Result is cached in KV for 60 s when a KVNamespace is provided. */
  async permissionsForUser(userId: string): Promise<string[]> {
    if (this.kv) {
      const cached = await this.kv.get(`rbac:perms:${userId}`)
      if (cached !== null) return JSON.parse(cached) as string[]
    }
    const roles = await this.getRolesForUser(userId)
    if (roles.length === 0) return []
    const grants = await this.all<{ resource: string; verb: string; scope: PermissionScope }>(
      `SELECT g.resource, g.verb, COALESCE(g.scope, 'any') as scope FROM rbac_user_roles ur
       JOIN rbac_role_grants g ON g.role_id = ur.role_id WHERE ur.user_id = ?`,
      userId
    )
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
    const id = `role-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
    await this.db
      .prepare(
        'INSERT INTO rbac_roles (id, name, display_name, description, is_system) VALUES (?, ?, ?, ?, 0)'
      )
      .bind(id, name.toLowerCase(), displayName, description)
      .run()
  }

  async deleteRole(roleId: string): Promise<void> {
    // System roles cannot be deleted.
    await this.db.prepare("DELETE FROM rbac_roles WHERE id = ? AND is_system = 0").bind(roleId).run()
  }

  /**
   * Update a role's display name and description. The `name` (slug) can only be
   * changed for custom roles — system role names are referenced by users.role
   * and the legacy mapping, so they stay fixed.
   */
  async updateRole(roleId: string, displayName: string, description = '', name?: string): Promise<void> {
    const role = (await this.db
      .prepare('SELECT is_system FROM rbac_roles WHERE id = ?')
      .bind(roleId)
      .first()) as { is_system: number } | null
    if (!role) return
    if (role.is_system === 0 && name) {
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-')
      await this.db
        .prepare('UPDATE rbac_roles SET display_name = ?, description = ?, name = ?, updated_at = ? WHERE id = ?')
        .bind(displayName, description, slug, Date.now(), roleId)
        .run()
    } else {
      await this.db
        .prepare('UPDATE rbac_roles SET display_name = ?, description = ?, updated_at = ? WHERE id = ?')
        .bind(displayName, description, Date.now(), roleId)
        .run()
    }
  }

  async createVerb(name: string, description = ''): Promise<void> {
    const id = `verb-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
    await this.db
      .prepare('INSERT INTO rbac_verbs (id, name, description, is_system, sort_order) VALUES (?, ?, ?, 0, 100)')
      .bind(id, name.toLowerCase(), description)
      .run()
  }

  async deleteVerb(verbId: string): Promise<void> {
    await this.db.prepare("DELETE FROM rbac_verbs WHERE id = ? AND is_system = 0").bind(verbId).run()
  }

  /** Replace all grants for one role with the supplied (resource, verb, scope) rows. */
  async setRoleGrants(
    roleId: string,
    pairs: Array<{ resource: string; verb: string; scope?: Exclude<PermissionScope, 'none'> }>
  ): Promise<void> {
    const stmts = [this.db.prepare('DELETE FROM rbac_role_grants WHERE role_id = ?').bind(roleId)]
    for (const p of pairs) {
      const scope = p.scope === 'own' ? 'own' : 'any'
      stmts.push(
        this.db
          .prepare('INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb, scope) VALUES (?, ?, ?, ?)')
          .bind(roleId, p.resource, p.verb, scope)
      )
    }
    await this.db.batch(stmts)
  }

  /**
   * Count active users (optionally excluding one) who hold BOTH an effective
   * portal:access grant and an effective rbac:manage grant — i.e. the users who
   * could recover the system from a permission lockout. Powers the self-lockout
   * guard in setUserRoles. Resolves wildcards via grantMatches (so a renamed
   * Administrator role with *:manage still counts).
   */
  async countPortalAdmins(excludeUserId?: string): Promise<number> {
    const rows = await this.all<{ user_id: string; resource: string; verb: string }>(
      `SELECT ur.user_id as user_id, g.resource as resource, g.verb as verb
       FROM rbac_user_roles ur
       JOIN rbac_role_grants g ON g.role_id = ur.role_id
       JOIN users u ON u.id = ur.user_id
       WHERE u.is_active = 1`
    )
    const byUser = new Map<string, { portal: boolean; rbac: boolean }>()
    for (const r of rows) {
      if (excludeUserId && r.user_id === excludeUserId) continue
      const e = byUser.get(r.user_id) || { portal: false, rbac: false }
      if (this.grantMatches(r, 'portal', 'access')) e.portal = true
      if (this.grantMatches(r, 'rbac', 'manage')) e.rbac = true
      byUser.set(r.user_id, e)
    }
    let count = 0
    for (const e of byUser.values()) if (e.portal && e.rbac) count++
    return count
  }

  /**
   * Replace a user's RBAC role assignments. `rbac_user_roles` is the single
   * source of truth for authorization; the legacy `users.role` column is kept
   * only as a derived *projection* of those roles (compat for older queries and
   * the session shape) so the two can never diverge. The projected value is the
   * highest-precedence system role the user holds, or 'viewer' if they hold none
   * (custom roles never become the projection — authorization uses RBAC, not
   * this string). Done in one batch so the projection is always consistent.
   */
  async setUserRoles(userId: string, roleIds: string[]): Promise<void> {
    let names: string[] = []
    if (roleIds.length) {
      const placeholders = roleIds.map(() => '?').join(',')
      names = (
        await this.all<{ name: string }>(`SELECT name FROM rbac_roles WHERE id IN (${placeholders})`, ...roleIds)
      ).map((r) => r.name)
    }
    const primaryRole = RbacService.LEGACY_ROLE_PRECEDENCE.find((r) => names.includes(r)) || 'viewer'

    // Self-lockout guard: never let a role change leave zero active users who can
    // BOTH enter the portal and manage RBAC (the minimum needed to recover).
    const newGrants = roleIds.length
      ? await this.all<{ resource: string; verb: string }>(
          `SELECT resource, verb FROM rbac_role_grants WHERE role_id IN (${roleIds.map(() => '?').join(',')})`,
          ...roleIds
        )
      : []
    const userWillBeAdmin =
      newGrants.some((g) => this.grantMatches(g, 'portal', 'access')) &&
      newGrants.some((g) => this.grantMatches(g, 'rbac', 'manage'))
    if (!userWillBeAdmin && (await this.countPortalAdmins(userId)) === 0) {
      throw new Error(
        'Refusing to update roles: this would leave no user able to manage Roles & Permissions and access the portal. Grant another user portal access + Roles & Permissions first.'
      )
    }

    const stmts = [this.db.prepare('DELETE FROM rbac_user_roles WHERE user_id = ?').bind(userId)]
    for (const rid of roleIds) {
      stmts.push(
        this.db
          .prepare('INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id) VALUES (?, ?)')
          .bind(userId, rid)
      )
    }
    // Keep the legacy users.role column in lockstep as a projection of RBAC.
    stmts.push(
      this.db.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?').bind(primaryRole, Date.now(), userId)
    )
    await this.db.batch(stmts)
    if (this.kv) await this.kv.delete(`rbac:perms:${userId}`)
  }

  async setRolePortalAccess(roleId: string, enabled: boolean): Promise<void> {
    if (enabled) {
      await this.db
        .prepare('INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb, scope) VALUES (?, ?, ?, ?)')
        .bind(roleId, 'portal', 'access', 'any')
        .run()
      return
    }

    await this.db
      .prepare('DELETE FROM rbac_role_grants WHERE role_id = ? AND resource = ? AND verb = ?')
      .bind(roleId, 'portal', 'access')
      .run()
  }
}
