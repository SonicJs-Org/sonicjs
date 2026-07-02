/**
 * Read executors for per-type document tools (`list_*`, `get_*`).
 *
 * Every read flows through the tenant-scoped DocumentRepository chokepoint (R4) and
 * is filtered per document by `isAllowed` against the caller's principal set — the
 * same path the public `/api/documents` route uses. The MCP layer never bypasses
 * document ACL. Write executors live in ./mutations.ts (Phase 2).
 */

import type { D1Database } from '@cloudflare/workers-types'
import { DocumentRepository } from '../../../../services/document-repository'
import { DocumentTypeRegistry } from '../../../../services/document-type-registry'
import { effectiveTenantForType } from '../../../../services/document-request-context'
import type { Document, PrincipalRef } from '../../../../schemas/document'
import { McpToolError } from '../jsonrpc'

export interface McpReadCtx {
  db: D1Database
  /** Request tenant (before per-type global-pool resolution). */
  tenantId: string
  principalSet: PrincipalRef[]
  listLimit: number
  redactFields: string[]
}

/** Strip redacted fields from a document's data payload. Used on both read output
 *  (shapeDocument) and write input (mutations) so a redacted field can't be written. */
export function redact(data: Record<string, unknown>, fields: string[]): Record<string, unknown> {
  if (!fields.length) return data
  const out = { ...data }
  for (const f of fields) delete out[f]
  return out
}

export function shapeDocument(doc: Document, redactFields: string[]) {
  return {
    id: doc.id,
    rootId: doc.rootId,
    typeId: doc.typeId,
    title: doc.title,
    slug: doc.slug,
    status: doc.status,
    isPublished: doc.isPublished,
    publishedAt: doc.publishedAt,
    updatedAt: doc.updatedAt,
    data: redact(doc.data, redactFields),
  }
}

/**
 * Resolve a type + its effective-tenant repository, or throw a tool error for an
 * unknown/inactive type. Shared by list + get.
 */
async function resolveType(ctx: McpReadCtx, typeId: string) {
  const docType = await new DocumentTypeRegistry(ctx.db).findById(typeId)
  if (!docType || !docType.isActive) throw new McpToolError(`Unknown document type: ${typeId}`)
  const effTenant = effectiveTenantForType(ctx.tenantId, docType.settings)
  const repo = new DocumentRepository(ctx.db, effTenant)
  return { docType, repo }
}

export async function execList(
  ctx: McpReadCtx,
  typeId: string,
  args: { status?: string; limit?: number },
): Promise<ReturnType<typeof shapeDocument>[]> {
  const { docType, repo } = await resolveType(ctx, typeId)
  const status = args.status === 'draft' ? 'draft' : 'published'
  const limit = Math.min(Math.max(1, args.limit ?? ctx.listLimit), ctx.listLimit)
  const now = Math.floor(Date.now() / 1000)

  const docs = await repo.list({
    typeId,
    status,
    timeWindow: status === 'published',
    now,
    limit,
  })

  // Per-document ACL — a published-but-restricted doc is hidden (D5). ACL filtering
  // happens post-fetch, so the returned count can be < limit even when more readable
  // docs exist beyond it; restricted rows consume slots. Same tradeoff as /api/documents.
  const allowed = await Promise.all(
    docs.map((d) => repo.isAllowed(ctx.principalSet, d.rootId, 'read', docType.settings)),
  )
  return docs.filter((_, i) => allowed[i]).map((d) => shapeDocument(d, ctx.redactFields))
}

export async function execGet(
  ctx: McpReadCtx,
  typeId: string,
  args: { id?: string; slug?: string },
): Promise<ReturnType<typeof shapeDocument>> {
  const { docType, repo } = await resolveType(ctx, typeId)

  let doc: Document | null = null
  if (args.id) {
    // Accept either a version id or a root id: try the exact-id lookup first, then
    // fall back to the published / current-draft row of that root.
    doc = (await repo.getById(args.id))
      ?? (await repo.getPublished(args.id))
      ?? (await repo.getCurrentDraft(args.id))
  } else if (args.slug) {
    doc = await repo.getBySlug(typeId, args.slug)
  } else {
    throw new McpToolError('get requires an "id" or "slug" argument')
  }

  if (!doc || doc.typeId !== typeId) throw new McpToolError('Document not found')

  const ok = await repo.isAllowed(ctx.principalSet, doc.rootId, 'read', docType.settings)
  if (!ok) throw new McpToolError('Document not found') // do not leak existence of restricted docs

  return shapeDocument(doc, ctx.redactFields)
}
