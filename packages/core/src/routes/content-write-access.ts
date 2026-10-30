import type { Context } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import type { DocumentType, Permission, PrincipalRef } from '../schemas/document'
import { DocumentPermissionsService } from '../services/document-permissions'
import { RbacService } from '../services/rbac'
import { getDocumentRequestContext } from '../services/document-request-context'

// Per-document deny wins; otherwise the document ACL or the caller's RBAC grants allow, the same two
// sources reads use. Internal, auth-owned and inactive types are never writable via content routes.
export async function contentWriteRefusal(
  c: Context,
  db: D1Database,
  docType: DocumentType | null | undefined,
  rootId: string,
  permissions: Permission[],
  // Routes that always write to 'default' must judge the caller by their global role, not the request tenant's.
  writesToDefaultTenant = false,
): Promise<403 | 404 | null> {
  if (!docType || !docType.isActive || docType.settings?.internal || docType.isAuth) return 404

  const ctx = getDocumentRequestContext(c)
  if (!ctx.userId) return 403
  const user = c.get('user') as { role?: string; isSuperAdmin?: boolean } | undefined
  const tenantId = writesToDefaultTenant ? 'default' : ctx.tenantId
  // tenantMiddleware sets tenantRole on every request; only a non-default tenant's membership role
  // replaces the user's own RBAC roles.
  const tenantRole = tenantId !== 'default' && !user?.isSuperAdmin ? (c.get('tenantRole') as string | undefined) : undefined
  const role = tenantRole ?? user?.role
  const principalSet: PrincipalRef[] = [{ type: 'user', id: ctx.userId }]
  if (role) principalSet.push({ type: 'role', id: role })

  const acl = new DocumentPermissionsService(db)
  const rbac = new RbacService(db)
  const resource = `document_type:${docType.id}`
  for (const permission of permissions) {
    const overrides = rootId ? await acl.getDocumentPermissions(rootId, principalSet, permission, tenantId) : []
    if (acl.isAllowedSync(principalSet, overrides, permission, docType.settings ?? {})) continue
    if (overrides.some((o) => o.effect === 'deny')) return 403
    // A tenant membership role is a label; globally, the user's own rbac_user_roles decide.
    const scope = tenantRole
      ? await rbac.getRoleScope(tenantRole, resource, permission)
      : await rbac.getPermissionScope(ctx.userId, resource, permission)
    if (scope === 'any') continue
    if (scope === 'own' && (!rootId || (await ownsDocument(db, rootId, ctx.userId, tenantId)))) continue
    return 403
  }
  return null
}

async function ownsDocument(db: D1Database, rootId: string, userId: string, tenantId: string): Promise<boolean> {
  const first = await db
    .prepare('SELECT owner_id, created_by FROM documents WHERE root_id = ? AND tenant_id = ? ORDER BY version_number ASC LIMIT 1')
    .bind(rootId, tenantId)
    .first<{ owner_id: string | null; created_by: string | null }>()
  return !!first && (first.owner_id ?? first.created_by) === userId
}
