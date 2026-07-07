import { D1Database } from '@cloudflare/workers-types'
import { nanoid } from 'nanoid'
import type {
  Permission,
  PrincipalRef,
  PrincipalType,
  DocumentPermissionRow,
  DocumentTypeSettings,
} from '../schemas/document'

export class DocumentPermissionsService {
  constructor(private db: D1Database) {}

  // Deny wins. Overrides beat base grants. Empty ACL falls back to base grants.
  async isAllowed(
    principalSet: PrincipalRef[],
    rootId: string,
    permission: Permission,
    typeSettings: DocumentTypeSettings,
    tenantId: string,
  ): Promise<boolean> {
    const overrides = await this.getDocumentPermissions(rootId, principalSet, permission, tenantId)

    if (overrides.some(p => p.effect === 'deny')) return false
    if (overrides.some(p => p.effect === 'allow')) return true

    return this.baseGrantAllows(typeSettings, principalSet, permission)
  }

  // Pure sync version for use in unit tests / when permissions are already loaded.
  isAllowedSync(
    principalSet: PrincipalRef[],
    overrides: Pick<DocumentPermissionRow, 'effect'>[],
    permission: Permission,
    typeSettings: DocumentTypeSettings,
  ): boolean {
    if (overrides.some(p => p.effect === 'deny')) return false
    if (overrides.some(p => p.effect === 'allow')) return true
    return this.baseGrantAllows(typeSettings, principalSet, permission)
  }

  private baseGrantAllows(
    typeSettings: DocumentTypeSettings,
    principalSet: PrincipalRef[],
    permission: Permission,
  ): boolean {
    const baseGrants = typeSettings.baseGrants ?? {}
    for (const principal of principalSet) {
      if (principal.type === 'public') {
        const publicGrants = baseGrants['public'] ?? []
        if (publicGrants.includes(permission)) return true
      } else if (principal.type === 'role') {
        // 'public' in baseGrants is reserved for anonymous { type: 'public', id: '*' } access only.
        // An authenticated user whose role name happens to be 'public' must not inherit anonymous
        // grants — doing so would allow a logged-in "public" role user to bypass ACL the same way
        // an unauthenticated visitor does, defeating per-role grant isolation.
        if (principal.id === 'public') continue
        const roleGrants = baseGrants[principal.id] ?? []
        if (roleGrants.includes(permission)) return true
      }
    }
    return false
  }

  async getDocumentPermissions(
    rootId: string,
    principalSet: PrincipalRef[],
    permission: Permission,
    tenantId: string,
  ): Promise<DocumentPermissionRow[]> {
    if (principalSet.length === 0) return []

    // Build WHERE clauses for each principal (using OR, staying within param limit)
    const clauses: string[] = []
    const params: (string | number)[] = [tenantId, rootId, permission]

    for (const p of principalSet) {
      clauses.push('(principal_type = ? AND principal_id = ?)')
      params.push(p.type, p.id)
    }

    const sql = `
      SELECT * FROM document_permissions
      WHERE tenant_id = ?
        AND root_id = ?
        AND permission = ?
        AND (${clauses.join(' OR ')})
    `

    const result = await this.db.prepare(sql).bind(...params).all()
    return (result.results ?? []) as unknown as DocumentPermissionRow[]
  }

  async grantPermission(opts: {
    tenantId: string
    rootId: string
    principalType: PrincipalType
    principalId: string
    permission: Permission
    effect?: 'allow' | 'deny'
    createdBy?: string
  }): Promise<void> {
    const { tenantId, rootId, principalType, principalId, permission, effect = 'allow', createdBy } = opts
    const now = Math.floor(Date.now() / 1000)
    const id = nanoid()

    await this.db
      .prepare(
        `INSERT INTO document_permissions (id, tenant_id, root_id, principal_type, principal_id, permission, effect, inherited, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
         ON CONFLICT(root_id, principal_type, principal_id, permission) DO UPDATE SET effect = excluded.effect`,
      )
      .bind(id, tenantId, rootId, principalType, principalId, permission, effect, now, createdBy ?? null)
      .run()
  }

  async revokePermission(opts: {
    tenantId: string
    rootId: string
    principalType: PrincipalType
    principalId: string
    permission: Permission
  }): Promise<void> {
    const { tenantId, rootId, principalType, principalId, permission } = opts
    await this.db
      .prepare(
        `DELETE FROM document_permissions
         WHERE tenant_id = ? AND root_id = ? AND principal_type = ? AND principal_id = ? AND permission = ?`,
      )
      .bind(tenantId, rootId, principalType, principalId, permission)
      .run()
  }

  async deleteAllPermissionsForRoot(rootId: string, tenantId: string): Promise<void> {
    await this.db
      .prepare('DELETE FROM document_permissions WHERE tenant_id = ? AND root_id = ?')
      .bind(tenantId, rootId)
      .run()
  }
}
