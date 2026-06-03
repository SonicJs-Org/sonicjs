/**
 * Dynamic RBAC service.
 *
 * Roles and verbs are stored and editable at runtime. Resources are computed:
 * a fixed set of system resources plus one `collection:<name>` per collection,
 * so new collections automatically get permissions. Grants are (role, resource,
 * verb) triples with wildcard support:
 *   resource '*'            → all resources
 *   resource 'collection:*' → all collections
 *   verb '*'                → all verbs
 *   verb 'manage'           → implies every verb on that resource
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
export interface Grant {
  role_id: string
  resource: string
  verb: string
}

const SYSTEM_RESOURCES: RbacResource[] = [
  { key: '*', label: 'All resources', group: 'system' },
  { key: 'portal', label: 'Admin Portal', group: 'system' },
  { key: 'rbac', label: 'Roles & Permissions', group: 'system' },
  { key: 'content', label: 'Content', group: 'system' },
  { key: 'collections', label: 'Collection Schemas', group: 'system' },
  { key: 'media', label: 'Media', group: 'system' },
  { key: 'email', label: 'Email Management', group: 'system' },
  { key: 'users', label: 'Users', group: 'system' },
  { key: 'collections', label: 'Collections (schema)', group: 'system' },
  { key: 'settings', label: 'Settings', group: 'system' },
  { key: 'plugins', label: 'Plugins', group: 'system' },
]

export class RbacService {
  constructor(private db: D1Database) {}

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
    return this.all<Grant>('SELECT role_id, resource, verb FROM rbac_role_grants')
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

  /** Can the user perform `verb` on `resource`? Reads the live grant matrix. */
  async can(userId: string, resource: string, verb: string): Promise<boolean> {
    const rows = await this.all<{ resource: string; verb: string }>(
      `SELECT g.resource, g.verb FROM rbac_user_roles ur
       JOIN rbac_role_grants g ON g.role_id = ur.role_id
       WHERE ur.user_id = ?`,
      userId
    )
    return rows.some((g) => this.grantMatches(g, resource, verb))
  }

  /** Flattened, human-readable permission list for a user (expanded vs resources). */
  async permissionsForUser(userId: string): Promise<string[]> {
    const roles = await this.getRolesForUser(userId)
    if (roles.length === 0) return []
    const grants = await this.all<{ resource: string; verb: string }>(
      `SELECT g.resource, g.verb FROM rbac_user_roles ur
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
    return [...out].sort()
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

  /** Replace all grants for one role with the supplied (resource, verb) pairs. */
  async setRoleGrants(roleId: string, pairs: Array<{ resource: string; verb: string }>): Promise<void> {
    const stmts = [this.db.prepare('DELETE FROM rbac_role_grants WHERE role_id = ?').bind(roleId)]
    for (const p of pairs) {
      stmts.push(
        this.db
          .prepare('INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb) VALUES (?, ?, ?)')
          .bind(roleId, p.resource, p.verb)
      )
    }
    await this.db.batch(stmts)
  }

  async setUserRoles(userId: string, roleIds: string[]): Promise<void> {
    const stmts = [this.db.prepare('DELETE FROM rbac_user_roles WHERE user_id = ?').bind(userId)]
    for (const rid of roleIds) {
      stmts.push(
        this.db
          .prepare('INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id) VALUES (?, ?)')
          .bind(userId, rid)
      )
    }
    await this.db.batch(stmts)
  }
}
