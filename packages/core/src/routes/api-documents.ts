import { Hono } from 'hono'
import type { Bindings, Variables } from '../app'
import { DocumentRepository } from '../services/document-repository'
import { DocumentTypeRegistry } from '../services/document-type-registry'
import { getDocumentRequestContext, effectiveTenantForType } from '../services/document-request-context'
import type { D1Database } from '@cloudflare/workers-types'
import type { PrincipalRef } from '../schemas/document'

// Resolve the row's type and evaluate read ACL for the given principal set. A published-but-restricted
// document (or a non-public type like contact_message) returns false → caller responds 404 (D5).
async function aclAllowsRead(
  db: D1Database,
  tenantId: string,
  principalSet: PrincipalRef[],
  row: { type_id: string; root_id: string },
  preloadedType?: any,
): Promise<boolean> {
  const docType = preloadedType ?? await new DocumentTypeRegistry(db).findById(row.type_id)
  if (!docType) return false
  return new DocumentRepository(db, tenantId).isAllowed(principalSet, row.root_id, 'read', docType.settings)
}

const apiDocumentsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// ─── List published documents ─────────────────────────────────────────────────
// GET /api/documents?type=faq&locale=en&limit=20&cursor_updated_at=…&cursor_id=…
// Scalar filters: ?filter[category]=general  (maps to q_faq_category)
// Facet filters:  ?facet[tags]=homepage
apiDocumentsRoutes.get('/', async (c) => {
  try {
    const db = c.env.DB
    const { tenantId, principalSet } = getDocumentRequestContext(c)
    const now = Math.floor(Date.now() / 1000)

    const typeId = c.req.query('type') ?? ''
    const locale = c.req.query('locale') ?? 'default'
    const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10) || 50, 200)
    const cursorUpdatedAt = c.req.query('cursor_updated_at') ? parseInt(c.req.query('cursor_updated_at')!, 10) : undefined
    const cursorId = c.req.query('cursor_id') ?? undefined

    if (!typeId) {
      return c.json({ error: 'type query parameter is required' }, 400)
    }

    // Resolve queryable fields for scalar/facet filter mapping.
    const registry = new DocumentTypeRegistry(db)
    const docType = await registry.findById(typeId)
    if (!docType || !docType.isActive) {
      return c.json({ error: 'Unknown document type' }, 400)
    }

    const queryableFields = docType.queryableFields ?? []
    const scalarColumns = new Map(
      queryableFields.filter(f => f.kind === 'scalar' && f.column).map(f => [f.name, f.column!])
    )
    const facetFields = new Set(queryableFields.filter(f => f.kind === 'facet').map(f => f.name))

    // Parse filter params
    const rawQuery = new URLSearchParams(c.req.url.split('?')[1] ?? '')
    const scalarFilters: Array<{ column: string; value: string }> = []
    const facetFilter: { field: string; value: string } | null = (() => {
      for (const [key, value] of rawQuery.entries()) {
        const m = key.match(/^facet\[(.+)\]$/)
        const fieldName = m?.[1]
        if (fieldName && facetFields.has(fieldName)) return { field: fieldName, value }
      }
      return null
    })()

    for (const [key, value] of rawQuery.entries()) {
      const m = key.match(/^filter\[(.+)\]$/)
      const fieldName = m?.[1]
      if (fieldName && scalarColumns.has(fieldName)) {
        scalarFilters.push({ column: scalarColumns.get(fieldName)!, value })
      }
    }

    // Sort column: default updated_at/id cursor; allow queryable scalar sorts.
    const sortField = c.req.query('sort') ?? 'updated_at'
    const sortColumn = sortField !== 'updated_at' ? scalarColumns.get(sortField) ?? null : null
    const sortDir = (c.req.query('dir') ?? 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC'

    // Single source of list SQL: the tenant-scoped repository chokepoint (R4/D10). No inline SQL.
    // Global types read from the shared pool regardless of the request tenant (G5).
    const repo = new DocumentRepository(db, effectiveTenantForType(tenantId, docType.settings))
    const docs = await repo.list({
      typeId, status: 'published', timeWindow: true, now, locale, limit,
      cursorUpdatedAt, cursorId,
      scalarFilters, facetFilter: facetFilter ?? undefined, sortColumn, sortDir,
    })

    const items = docs.map(d => ({
      id: d.id,
      rootId: d.rootId,
      typeId: d.typeId,
      title: d.title,
      slug: d.slug,
      path: d.path,
      locale: d.locale,
      publishedAt: d.publishedAt,
      updatedAt: d.updatedAt,
      data: d.data,
    }))

    // ACL: published reads still flow through isAllowed as the resolved principal (public for anon),
    // so a published-but-restricted document is hidden (D5). nextCursor is computed from the RAW page
    // so pagination advances even when some rows are filtered out by ACL.
    const allowed = await Promise.all(
      items.map(it => repo.isAllowed(principalSet, it.rootId, 'read', docType.settings)),
    )
    const visible = items.filter((_, i) => allowed[i])

    const lastItem = items[items.length - 1]
    const nextCursor = items.length === limit && lastItem
      ? { cursor_updated_at: lastItem.updatedAt, cursor_id: lastItem.id }
      : null

    return c.json({ data: visible, pagination: { limit, nextCursor } })
  } catch (error) {
    console.error('Error listing published documents:', error)
    return c.json({ error: 'Failed to list documents' }, 500)
  }
})

// ─── Get published document by root ID ──────────────────────────────────────
apiDocumentsRoutes.get('/root/:rootId', async (c) => {
  try {
    const db = c.env.DB
    const { tenantId, principalSet } = getDocumentRequestContext(c)
    const now = Math.floor(Date.now() / 1000)
    const { rootId } = c.req.param()

    // No tenant filter here: the effective tenant depends on the row's type (global types live in
    // the shared pool, G5). Resolve the type, then enforce ownership against the effective tenant.
    const row = await db.prepare(
      `SELECT * FROM documents
       WHERE root_id = ? AND is_published = 1 AND deleted_at IS NULL
         AND (scheduled_at IS NULL OR scheduled_at <= ?)
         AND (expires_at IS NULL OR expires_at > ?) LIMIT 1`,
    ).bind(rootId, now, now).first() as any

    if (!row) return c.json({ error: 'Not found' }, 404)

    const docType = await new DocumentTypeRegistry(db).findById(row.type_id)
    const effTenant = effectiveTenantForType(tenantId, docType?.settings)
    if (row.tenant_id !== effTenant) return c.json({ error: 'Not found' }, 404) // isolation guard
    if (!(await aclAllowsRead(db, effTenant, principalSet, row, docType))) {
      return c.json({ error: 'Not found' }, 404)
    }

    return c.json({
      id: row.id, rootId: row.root_id, typeId: row.type_id,
      title: row.title, slug: row.slug, path: row.path, locale: row.locale,
      publishedAt: row.published_at, updatedAt: row.updated_at,
      data: JSON.parse(row.data ?? '{}'),
    })
  } catch (error) {
    console.error('Error getting document by root:', error)
    return c.json({ error: 'Failed to get document' }, 500)
  }
})

// ─── Get published document by ID ────────────────────────────────────────────
apiDocumentsRoutes.get('/:id', async (c) => {
  try {
    const db = c.env.DB
    const { tenantId, principalSet } = getDocumentRequestContext(c)
    const now = Math.floor(Date.now() / 1000)
    const { id } = c.req.param()

    const row = await db.prepare(
      `SELECT * FROM documents
       WHERE id = ? AND is_published = 1 AND deleted_at IS NULL
         AND (scheduled_at IS NULL OR scheduled_at <= ?)
         AND (expires_at IS NULL OR expires_at > ?) LIMIT 1`,
    ).bind(id, now, now).first() as any

    if (!row) return c.json({ error: 'Not found' }, 404)

    const docType = await new DocumentTypeRegistry(db).findById(row.type_id)
    const effTenant = effectiveTenantForType(tenantId, docType?.settings)
    if (row.tenant_id !== effTenant) return c.json({ error: 'Not found' }, 404) // isolation guard
    if (!(await aclAllowsRead(db, effTenant, principalSet, row, docType))) {
      return c.json({ error: 'Not found' }, 404)
    }

    return c.json({
      id: row.id, rootId: row.root_id, typeId: row.type_id,
      title: row.title, slug: row.slug, path: row.path, locale: row.locale,
      publishedAt: row.published_at, updatedAt: row.updated_at,
      data: JSON.parse(row.data ?? '{}'),
    })
  } catch (error) {
    console.error('Error getting document:', error)
    return c.json({ error: 'Failed to get document' }, 500)
  }
})

export { apiDocumentsRoutes }
export default apiDocumentsRoutes
