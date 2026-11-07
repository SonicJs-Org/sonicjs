import type { D1Database } from '@cloudflare/workers-types'
import type { DocumentType, PrincipalRef } from '../schemas/document'
import { DocumentPermissionsService } from './document-permissions'
import { RbacService } from './rbac'
import { getCollectionRegistry } from './collection-registry'

// The role principal is one projected label; RBAC assignments are global, so only the default tenant uses them.
export async function heldRoleIds(db: D1Database, principalSet: PrincipalRef[], tenantId: string): Promise<string[]> {
  const user = principalSet.find((p) => p.type === 'user')
  if (!user || tenantId !== 'default') return []
  return (await new RbacService(db).getRolesForUser(user.id)).map((r) => r.id)
}

// Document ACL first, then a `document_type:<type>` read grant on any role the caller holds. RBAC grants
// open published rows of active collections only, since the seeded roles grant `document_type:*`.
export function createDocumentReadAccess(db: D1Database, principalSet: PrincipalRef[], requestTenant: string) {
  const perms = new DocumentPermissionsService(db)
  let principals: Promise<PrincipalRef[]> | undefined
  const typeGrants = new Map<string, Promise<boolean>>()

  // Every held role joins the principal set, so a deny keyed to any of them applies.
  const allPrincipals = () => (principals ??= heldRoleIds(db, principalSet, requestTenant).then((ids) => {
    const have = new Set(principalSet.filter((p) => p.type === 'role').map((p) => p.id))
    return [...principalSet, ...ids.filter((id) => !have.has(id)).map((id) => ({ type: 'role' as const, id }))]
  }))

  const rbacGrants = (typeId: string): Promise<boolean> => {
    let granted = typeGrants.get(typeId)
    if (!granted) {
      granted = allPrincipals().then((ps) => new RbacService(db).anyRoleGrants(
        ps.filter((p) => p.type === 'role').map((p) => p.id), `document_type:${typeId}`, 'read'))
      typeGrants.set(typeId, granted)
    }
    return granted
  }

  return {
    /** `docTenant` is where the row lives (the global pool for `settings.global` types). */
    async canRead(rootId: string, docType: DocumentType, docTenant: string, published = true): Promise<boolean> {
      const ps = await allPrincipals()
      const overrides = await perms.getDocumentPermissions(rootId, ps, 'read', docTenant)
      if (perms.isAllowedSync(ps, overrides, 'read', docType.settings)) return true
      if (!published || overrides.some((o) => o.effect === 'deny')) return false
      const s = docType.settings
      const collection = getCollectionRegistry().getByName(docType.id)
      if (!collection || collection.isActive === false || !docType.isActive || s.internal || s.pii || docType.isAuth) return false
      return rbacGrants(docType.id)
    },
  }
}
