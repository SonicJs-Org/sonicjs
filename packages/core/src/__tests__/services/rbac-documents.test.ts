// @ts-nocheck
// RBAC service — document-backed implementation. Roles/verbs/grants/user-roles live as
// is_auth documents (rbac_role / rbac_verb / rbac_user_roles) instead of auth_rbac_* tables.
// Exercises the real SQL (0001+0002 migrations) through DocumentsService, covering the
// security-critical paths: grant matching, manage/wildcard implication, scope precedence,
// the self-lockout guard, and the legacy auth_user.role projection.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { RbacService } from '../../services/rbac'

const MIGRATIONS = join(dirname(fileURLToPath(import.meta.url)), '../../../migrations')

function normalize(v) {
  if (v === undefined || v === null) return null
  if (typeof v === 'boolean') return v ? 1 : 0
  return v
}
class Stmt {
  constructor(sqlite, sql, binds = []) { this.sqlite = sqlite; this.sql = sql; this.binds = binds }
  bind(...a) { return new Stmt(this.sqlite, this.sql, a.map(normalize)) }
  async run() { const i = this.sqlite.prepare(this.sql).run(...this.binds); return { success: true, meta: { changes: i.changes } } }
  async all() { return { results: this.sqlite.prepare(this.sql).all(...this.binds), success: true, meta: {} } }
  async first(col) { const r = this.sqlite.prepare(this.sql).get(...this.binds); return r == null ? null : (col ? r[col] : r) }
  exec() { this.sqlite.prepare(this.sql).run(...this.binds) }
}
function makeDb() {
  const sqlite = new Database(':memory:')
  sqlite.pragma('foreign_keys = OFF')
  for (const m of ['0001_core.sql', '0002_documents.sql']) sqlite.exec(readFileSync(join(MIGRATIONS, m), 'utf8'))
  // Register the rbac document types (documents.type_id references document_types).
  for (const id of ['rbac_role', 'rbac_verb', 'rbac_user_roles']) {
    sqlite.prepare(
      `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,is_auth,created_at,updated_at)
       VALUES (?,?,?,'{}','[]','{}','system',1,1,1,1,1,1)`,
    ).run(id, id, id)
  }
  const db = {
    raw: sqlite,
    prepare: (sql) => new Stmt(sqlite, sql),
    async batch(stmts) { const tx = sqlite.transaction((ss) => { for (const s of ss) s.exec() }); tx(stmts); return stmts.map(() => ({ success: true, results: [] })) },
    close: () => sqlite.close(),
  }
  return db
}
function addUser(db, id, active = 1) {
  const now = Date.now()
  db.raw.prepare(
    `INSERT INTO auth_user (id, email, email_verified, created_at, updated_at, first_name, last_name, role, is_active)
     VALUES (?, ?, 1, ?, ?, 'f', 'l', 'viewer', ?)`,
  ).run(id, `${id}@t.co`, now, now, active)
}
async function addAdmin(db, rbac, id = 'admin') {
  addUser(db, id)
  await rbac.addUserRoleByName(id, 'admin')
}

describe('RbacService — document-backed', () => {
  let db
  beforeEach(async () => { db = makeDb(); await new RbacService(db).ensureSystemRbacSeed() })
  afterEach(() => db.close())

  it('seeds admin (locked system role) + editor/authenticated/public (deletable example roles) + 6 verbs, idempotently', async () => {
    const rbac = new RbacService(db)
    const roles = await rbac.getRoles()
    expect(roles.map((r) => r.name).sort()).toEqual(['admin', 'authenticated', 'editor', 'public'])
    // `admin` is the only hardcoded SYSTEM role; others are deletable examples.
    expect(roles.find((r) => r.name === 'admin')?.is_system).toBe(1)
    expect(roles.find((r) => r.name === 'editor')?.is_system).toBe(0)
    expect(roles.find((r) => r.name === 'authenticated')?.is_system).toBe(0)
    expect(roles.find((r) => r.name === 'public')?.is_system).toBe(0)
    expect((await rbac.getVerbs()).map((v) => v.name)).toEqual(['access', 'read', 'create', 'update', 'delete', 'manage'])
    // Re-seed: still exactly 4 roles (no duplicate documents).
    await rbac.ensureSystemRbacSeed()
    expect((await rbac.getRoles()).length).toBe(4)
    const n = db.raw.prepare("SELECT COUNT(*) c FROM documents WHERE type_id='rbac_role' AND is_current_draft=1").get().c
    expect(n).toBe(4)
  })

  it('seeded editor role is deletable (only admin is locked)', async () => {
    const rbac = new RbacService(db)
    await rbac.deleteRole('role-editor')
    expect((await rbac.getRoles()).some((r) => r.id === 'role-editor')).toBe(false)
    // Admin survives delete attempt because it is a system role.
    await rbac.deleteRole('role-admin')
    expect((await rbac.getRoles()).some((r) => r.id === 'role-admin')).toBe(true)
  })

  it('admin manage grant implies every verb on every resource', async () => {
    const rbac = new RbacService(db)
    addUser(db, 'u-admin')
    await rbac.addUserRoleByName('u-admin', 'admin')
    expect(await rbac.can('u-admin', 'rbac', 'manage')).toBe(true)
    expect(await rbac.can('u-admin', 'settings', 'delete')).toBe(true) // '*' + manage
    expect(await rbac.can('u-admin', 'document_type:blog_post', 'create')).toBe(true)
    // Legacy projection updated.
    expect(db.raw.prepare("SELECT role FROM auth_user WHERE id='u-admin'").get().role).toBe('admin')
  })

  it('editor can manage documents and access the portal', async () => {
    const rbac = new RbacService(db)
    await addAdmin(db, rbac)
    addUser(db, 'u-editor')
    await rbac.addUserRoleByName('u-editor', 'editor')
    expect(await rbac.can('u-editor', 'documents', 'read')).toBe(true)
    expect(await rbac.can('u-editor', 'documents', 'delete')).toBe(true)
    expect(await rbac.can('u-editor', 'document_type:blog_post', 'read')).toBe(true) // document_type:* wildcard
    expect(await rbac.can('u-editor', 'portal', 'access')).toBe(true)
  })

  it('setRoleGrants replaces a role grant set and is reflected in checks', async () => {
    const rbac = new RbacService(db)
    await addAdmin(db, rbac)
    addUser(db, 'u1')
    await rbac.addUserRoleByName('u1', 'editor')
    expect(await rbac.can('u1', 'email', 'manage')).toBe(false)
    await rbac.setRoleGrants('role-editor', [{ resource: 'email', verb: 'manage' }])
    expect(await rbac.can('u1', 'email', 'manage')).toBe(true)
    expect(await rbac.can('u1', 'documents', 'read')).toBe(false) // old grants replaced
  })

  it('updates role display name and portal access in one write', async () => {
    const rbac = new RbacService(db)
    await addAdmin(db, rbac)
    await rbac.updateRoleAndPortalAccess('role-editor', 'Managing Editor', undefined, false)
    let roles = await rbac.getRoles()
    expect(roles.find((r) => r.id === 'role-editor')?.display_name).toBe('Managing Editor')
    addUser(db, 'u-editor')
    await rbac.addUserRoleByName('u-editor', 'editor')
    expect(await rbac.can('u-editor', 'portal', 'access')).toBe(false)

    await rbac.updateRoleAndPortalAccess('role-editor', 'Editor', undefined, true)
    roles = await rbac.getRoles()
    expect(roles.find((r) => r.id === 'role-editor')?.display_name).toBe('Editor')
    expect(await rbac.can('u-editor', 'portal', 'access')).toBe(true)
  })

  it('self-lockout guard blocks removing the last portal+rbac admin', async () => {
    const rbac = new RbacService(db)
    addUser(db, 'only-admin')
    await rbac.addUserRoleByName('only-admin', 'admin')
    // Demoting the sole admin to editor must throw because editor lacks rbac:manage.
    await expect(rbac.setUserRoles('only-admin', ['role-editor'])).rejects.toThrow(/Refusing to update roles/)
    // A second admin makes it safe.
    addUser(db, 'admin2')
    await rbac.addUserRoleByName('admin2', 'admin')
    await expect(rbac.setUserRoles('only-admin', ['role-editor'])).resolves.toBeUndefined()
    expect(await rbac.can('only-admin', 'rbac', 'manage')).toBe(false)
  })

  it('custom role create/delete; system roles cannot be deleted', async () => {
    const rbac = new RbacService(db)
    await rbac.createRole('Marketing', 'Marketing Team')
    expect((await rbac.getRoles()).some((r) => r.id === 'role-marketing')).toBe(true)
    await rbac.deleteRole('role-marketing')
    expect((await rbac.getRoles()).some((r) => r.id === 'role-marketing')).toBe(false)
    // System role survives a delete attempt.
    await rbac.deleteRole('role-admin')
    expect((await rbac.getRoles()).some((r) => r.id === 'role-admin')).toBe(true)
  })

  // ─── isGrantedForRole ─────────────────────────────────────────────────────────
  // Covers the two-system ACL fix: RBAC dynamic grants must be checked alongside
  // code-time baseGrants so admin UI changes take effect immediately.

  it('isGrantedForRole returns false for unknown role', async () => {
    const rbac = new RbacService(db)
    expect(await rbac.isGrantedForRole('role-nonexistent', 'document_type:example', 'read')).toBe(false)
  })

  it('isGrantedForRole returns false for role with no matching grant', async () => {
    const rbac = new RbacService(db)
    // Public role is seeded with zero grants by default.
    expect(await rbac.isGrantedForRole('role-public', 'document_type:example', 'read')).toBe(false)
    expect(await rbac.isGrantedForRole('public', 'document_type:example', 'read')).toBe(false)
  })

  it('isGrantedForRole matches by slug (role-public) after setRoleGrants', async () => {
    const rbac = new RbacService(db)
    await rbac.setRoleGrants('role-public', [{ resource: 'document_type:example', verb: 'read' }])
    expect(await rbac.isGrantedForRole('role-public', 'document_type:example', 'read')).toBe(true)
  })

  it('isGrantedForRole matches by name (public) after setRoleGrants', async () => {
    const rbac = new RbacService(db)
    await rbac.setRoleGrants('role-public', [{ resource: 'document_type:example', verb: 'read' }])
    expect(await rbac.isGrantedForRole('public', 'document_type:example', 'read')).toBe(true)
  })

  it('isGrantedForRole respects wildcard resource (document_type:*)', async () => {
    const rbac = new RbacService(db)
    await rbac.setRoleGrants('role-public', [{ resource: 'document_type:*', verb: 'read' }])
    expect(await rbac.isGrantedForRole('role-public', 'document_type:example', 'read')).toBe(true)
    expect(await rbac.isGrantedForRole('role-public', 'document_type:blog_post', 'read')).toBe(true)
  })

  it('isGrantedForRole is false after grants are cleared', async () => {
    const rbac = new RbacService(db)
    await rbac.setRoleGrants('role-public', [{ resource: 'document_type:example', verb: 'read' }])
    expect(await rbac.isGrantedForRole('role-public', 'document_type:example', 'read')).toBe(true)
    await rbac.setRoleGrants('role-public', [])
    expect(await rbac.isGrantedForRole('role-public', 'document_type:example', 'read')).toBe(false)
  })

  it('isGrantedForRole verb mismatch returns false', async () => {
    const rbac = new RbacService(db)
    await rbac.setRoleGrants('role-public', [{ resource: 'document_type:example', verb: 'read' }])
    expect(await rbac.isGrantedForRole('role-public', 'document_type:example', 'create')).toBe(false)
  })
})
