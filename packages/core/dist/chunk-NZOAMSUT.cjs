'use strict';

// src/services/rbac.ts
var SYSTEM_RESOURCES = [
  { key: "*", label: "All resources", group: "system" },
  { key: "portal", label: "Admin Portal", group: "system" },
  { key: "dashboard", label: "Dashboard", group: "system" },
  { key: "rbac", label: "Roles & Permissions", group: "system" },
  { key: "content", label: "Content", group: "system" },
  { key: "collections", label: "Collection Schemas", group: "system" },
  { key: "media", label: "Media", group: "system" },
  { key: "email", label: "Email Management", group: "system" },
  { key: "users", label: "Users", group: "system" },
  { key: "settings", label: "Settings", group: "system" },
  { key: "plugins", label: "Plugins", group: "system" }
];
var RbacService = class _RbacService {
  constructor(db) {
    this.db = db;
  }
  // Precedence for projecting the user's RBAC roles back onto the legacy
  // users.role compat column (highest privilege first). System roles only;
  // custom roles never become the projection.
  static LEGACY_ROLE_PRECEDENCE = ["admin", "editor", "author", "viewer"];
  async all(sql, ...binds) {
    const stmt = binds.length ? this.db.prepare(sql).bind(...binds) : this.db.prepare(sql);
    return (await stmt.all()).results;
  }
  async getRoles() {
    return this.all("SELECT * FROM rbac_roles ORDER BY is_system DESC, name");
  }
  async getVerbs() {
    return this.all("SELECT * FROM rbac_verbs ORDER BY sort_order, name");
  }
  /** System resources + one `collection:<name>` per active collection, plus a
   *  `collection:*` row representing "all collections". */
  async getResources() {
    const cols = await this.all(
      "SELECT name, display_name FROM collections WHERE is_active = 1 ORDER BY name"
    );
    const collectionResources = [
      { key: "collection:*", label: "All collections", group: "collection" },
      ...cols.map((c) => ({
        key: `collection:${c.name}`,
        label: c.display_name || c.name,
        group: "collection"
      }))
    ];
    return [...SYSTEM_RESOURCES, ...collectionResources];
  }
  async getGrants() {
    return this.all("SELECT role_id, resource, verb, COALESCE(scope, 'any') as scope FROM rbac_role_grants");
  }
  async getRolesForUser(userId) {
    return this.all(
      `SELECT r.* FROM rbac_user_roles ur JOIN rbac_roles r ON r.id = ur.role_id WHERE ur.user_id = ?`,
      userId
    );
  }
  /** Does a single grant row satisfy the requested (resource, verb)? */
  grantMatches(g, resource, verb) {
    const resourceOk = g.resource === "*" || g.resource === resource || g.resource === "collection:*" && resource.startsWith("collection:");
    if (!resourceOk) return false;
    return g.verb === "*" || g.verb === verb || g.verb === "manage";
  }
  strongestScope(scopes) {
    if (scopes.includes("any")) return "any";
    if (scopes.includes("own")) return "own";
    return "none";
  }
  /** Can the user perform `verb` on `resource`? Reads the live grant matrix. */
  async can(userId, resource, verb) {
    return await this.getPermissionScope(userId, resource, verb) !== "none";
  }
  /**
   * Highest scope granted to the user for `resource:verb`.
   * `any` beats `own`; no matching grant is `none`.
   */
  async getPermissionScope(userId, resource, verb) {
    const rows = await this.all(
      `SELECT g.resource, g.verb, COALESCE(g.scope, 'any') as scope FROM rbac_user_roles ur
       JOIN rbac_role_grants g ON g.role_id = ur.role_id
       WHERE ur.user_id = ?`,
      userId
    );
    return this.strongestScope(
      rows.filter((g) => this.grantMatches(g, resource, verb)).map((g) => g.scope === "own" ? "own" : "any")
    );
  }
  /** Flattened, human-readable permission list for a user (expanded vs resources). */
  async permissionsForUser(userId) {
    const roles = await this.getRolesForUser(userId);
    if (roles.length === 0) return [];
    const grants = await this.all(
      `SELECT g.resource, g.verb, COALESCE(g.scope, 'any') as scope FROM rbac_user_roles ur
       JOIN rbac_role_grants g ON g.role_id = ur.role_id WHERE ur.user_id = ?`,
      userId
    );
    const resources = await this.getResources();
    const verbs = await this.getVerbs();
    const out = /* @__PURE__ */ new Set();
    for (const r of resources) {
      for (const v of verbs) {
        if (grants.some((g) => this.grantMatches(g, r.key, v.name))) out.add(`${r.key}:${v.name}`);
      }
    }
    return [...out].sort();
  }
  // ── Mutations ──────────────────────────────────────────────────────────────
  async createRole(name, displayName, description = "") {
    const id = `role-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    await this.db.prepare(
      "INSERT INTO rbac_roles (id, name, display_name, description, is_system) VALUES (?, ?, ?, ?, 0)"
    ).bind(id, name.toLowerCase(), displayName, description).run();
  }
  async deleteRole(roleId) {
    await this.db.prepare("DELETE FROM rbac_roles WHERE id = ? AND is_system = 0").bind(roleId).run();
  }
  /**
   * Update a role's display name and description. The `name` (slug) can only be
   * changed for custom roles — system role names are referenced by users.role
   * and the legacy mapping, so they stay fixed.
   */
  async updateRole(roleId, displayName, description = "", name) {
    const role = await this.db.prepare("SELECT is_system FROM rbac_roles WHERE id = ?").bind(roleId).first();
    if (!role) return;
    if (role.is_system === 0 && name) {
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
      await this.db.prepare("UPDATE rbac_roles SET display_name = ?, description = ?, name = ?, updated_at = ? WHERE id = ?").bind(displayName, description, slug, Date.now(), roleId).run();
    } else {
      await this.db.prepare("UPDATE rbac_roles SET display_name = ?, description = ?, updated_at = ? WHERE id = ?").bind(displayName, description, Date.now(), roleId).run();
    }
  }
  async createVerb(name, description = "") {
    const id = `verb-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    await this.db.prepare("INSERT INTO rbac_verbs (id, name, description, is_system, sort_order) VALUES (?, ?, ?, 0, 100)").bind(id, name.toLowerCase(), description).run();
  }
  async deleteVerb(verbId) {
    await this.db.prepare("DELETE FROM rbac_verbs WHERE id = ? AND is_system = 0").bind(verbId).run();
  }
  /** Replace all grants for one role with the supplied (resource, verb, scope) rows. */
  async setRoleGrants(roleId, pairs) {
    const stmts = [this.db.prepare("DELETE FROM rbac_role_grants WHERE role_id = ?").bind(roleId)];
    for (const p of pairs) {
      const scope = p.scope === "own" ? "own" : "any";
      stmts.push(
        this.db.prepare("INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb, scope) VALUES (?, ?, ?, ?)").bind(roleId, p.resource, p.verb, scope)
      );
    }
    await this.db.batch(stmts);
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
  async setUserRoles(userId, roleIds) {
    let names = [];
    if (roleIds.length) {
      const placeholders = roleIds.map(() => "?").join(",");
      names = (await this.all(`SELECT name FROM rbac_roles WHERE id IN (${placeholders})`, ...roleIds)).map((r) => r.name);
    }
    const primaryRole = _RbacService.LEGACY_ROLE_PRECEDENCE.find((r) => names.includes(r)) || "viewer";
    const stmts = [this.db.prepare("DELETE FROM rbac_user_roles WHERE user_id = ?").bind(userId)];
    for (const rid of roleIds) {
      stmts.push(
        this.db.prepare("INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id) VALUES (?, ?)").bind(userId, rid)
      );
    }
    stmts.push(
      this.db.prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").bind(primaryRole, Date.now(), userId)
    );
    await this.db.batch(stmts);
  }
  async setRolePortalAccess(roleId, enabled) {
    if (enabled) {
      await this.db.prepare("INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb, scope) VALUES (?, ?, ?, ?)").bind(roleId, "portal", "access", "any").run();
      return;
    }
    await this.db.prepare("DELETE FROM rbac_role_grants WHERE role_id = ? AND resource = ? AND verb = ?").bind(roleId, "portal", "access").run();
  }
};

exports.RbacService = RbacService;
//# sourceMappingURL=chunk-NZOAMSUT.cjs.map
//# sourceMappingURL=chunk-NZOAMSUT.cjs.map