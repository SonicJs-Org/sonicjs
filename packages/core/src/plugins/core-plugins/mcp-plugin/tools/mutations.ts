/**
 * Write executors for per-type document tools (`create_/update_/publish_/delete_`).
 *
 * Keyed by root id (the stable document identity), unlike the admin routes which key
 * publish/delete by a specific version-row id. Each op:
 *   1. resolves the type + effective tenant (global types → shared pool, G5),
 *   2. gates on `isAllowed` for the matching permission — create uses a base-grant
 *      check with an empty root id, mutations check the concrete root,
 *   3. writes through DocumentsService (raw prepare/bind/batch — R1), never inline SQL.
 *
 * The MCP layer adds no privilege: a caller can only do what their API key's owning
 * user could do through the admin/API.
 */

import type { D1Database } from '@cloudflare/workers-types'
import { DocumentsService } from '../../../../services/documents'
import { DocumentRepository } from '../../../../services/document-repository'
import { DocumentTypeRegistry } from '../../../../services/document-type-registry'
import { effectiveTenantForType } from '../../../../services/document-request-context'
import { createDocumentSchema, updateDocumentSchema } from '../../../../schemas/document'
import type { DocumentType, Permission, PrincipalRef } from '../../../../schemas/document'
import { getCollectionRegistry } from '../../../../services/collection-registry'
import { McpToolError } from '../jsonrpc'
import { shapeDocument } from './documents'

export interface McpWriteCtx {
  db: D1Database
  /** Request tenant (before per-type global-pool resolution). */
  tenantId: string
  principalSet: PrincipalRef[]
  /** Owning user of the API key — recorded as author + create-owner. */
  userId: string
  redactFields: string[]
}

interface WriteScope {
  docType: DocumentType
  effTenant: string
  repo: DocumentRepository
  svc: DocumentsService
}

async function resolveWriteScope(ctx: McpWriteCtx, typeId: string): Promise<WriteScope> {
  const docType = await new DocumentTypeRegistry(ctx.db).findById(typeId)
  if (!docType || !docType.isActive) throw new McpToolError(`Unknown document type: ${typeId}`)
  const effTenant = effectiveTenantForType(ctx.tenantId, docType.settings)
  const repo = new DocumentRepository(ctx.db, effTenant)
  const svc = new DocumentsService(ctx.db, {
    queryableFields: docType.queryableFields ?? [],
    typeSchemaVersion: docType.schemaVersion,
    maxVersionsPerRoot: docType.settings?.maxVersionsPerRoot,
    tenantId: effTenant,
    versioning: docType.settings?.versioning ?? false,
  })
  return { docType, effTenant, repo, svc }
}

async function assertAllowed(scope: WriteScope, ctx: McpWriteCtx, rootId: string, permission: Permission): Promise<void> {
  const ok = await scope.repo.isAllowed(ctx.principalSet, rootId, permission, scope.docType.settings ?? {})
  if (!ok) throw new McpToolError(`Permission denied: cannot ${permission} ${scope.docType.id}`)
}

/**
 * For `user` type fields that are absent from `data`, inject the caller's userId.
 * Covers the common case where a collection has a required `author` (or similar)
 * field that the LLM has no way to know — it should default to the API key owner.
 */
function applyUserFieldDefaults(
  data: Record<string, unknown>,
  typeId: string,
  userId: string,
): Record<string, unknown> {
  const col = getCollectionRegistry().getByName(typeId)
  if (!col?.schema?.properties) return data
  const props = col.schema.properties as Record<string, { type?: string }>
  const patched = { ...data }
  for (const [name, field] of Object.entries(props)) {
    if (field.type === 'user' && !patched[name]) patched[name] = userId
  }
  return patched
}

export async function execCreate(
  ctx: McpWriteCtx,
  typeId: string,
  args: { title?: string; slug?: string; data?: Record<string, unknown>; publish?: boolean },
) {
  const scope = await resolveWriteScope(ctx, typeId)
  // Base-grant check (no root yet): can this principal create this type?
  await assertAllowed(scope, ctx, '', 'create')

  const data = applyUserFieldDefaults(args.data ?? {}, typeId, ctx.userId)

  const input = createDocumentSchema.parse({
    typeId,
    tenantId: scope.effTenant,
    title: args.title ?? null,
    slug: args.slug ?? null,
    data,
    ownerId: ctx.userId,
    publishOnCreate: Boolean(args.publish),
  })
  const doc = await scope.svc.create(input, ctx.userId)
  return shapeDocument(doc, ctx.redactFields)
}

export async function execUpdate(
  ctx: McpWriteCtx,
  typeId: string,
  args: { id?: string; title?: string; slug?: string; data?: Record<string, unknown> },
) {
  if (!args.id) throw new McpToolError('update requires an "id" (root id)')
  const scope = await resolveWriteScope(ctx, typeId)

  // The document must exist as this type with a current draft to amend.
  const current = await scope.repo.getCurrentDraft(args.id)
  if (!current || current.typeId !== typeId) throw new McpToolError('Document not found')

  await assertAllowed(scope, ctx, args.id, 'update')

  // saveDraft merges data ({ ...prev, ...input.data }), so a partial payload is safe.
  const patch = updateDocumentSchema.parse({
    ...(args.title !== undefined ? { title: args.title } : {}),
    ...(args.slug !== undefined ? { slug: args.slug } : {}),
    ...(args.data !== undefined ? { data: args.data } : {}),
  })
  const doc = await scope.svc.saveDraft(args.id, patch, ctx.userId)
  return shapeDocument(doc, ctx.redactFields)
}

export async function execPublish(ctx: McpWriteCtx, typeId: string, args: { id?: string }) {
  if (!args.id) throw new McpToolError('publish requires an "id" (root id)')
  const scope = await resolveWriteScope(ctx, typeId)

  // Publish the latest draft of the root.
  const current = await scope.repo.getCurrentDraft(args.id)
  if (!current || current.typeId !== typeId) throw new McpToolError('Document not found')

  await assertAllowed(scope, ctx, args.id, 'publish')

  const doc = await scope.svc.publish(current.id, ctx.userId)
  return shapeDocument(doc, ctx.redactFields)
}

export async function execDelete(ctx: McpWriteCtx, typeId: string, args: { id?: string }) {
  if (!args.id) throw new McpToolError('delete requires an "id" (root id)')
  const scope = await resolveWriteScope(ctx, typeId)

  const current = (await scope.repo.getCurrentDraft(args.id)) ?? (await scope.repo.getPublished(args.id))
  if (!current || current.typeId !== typeId) throw new McpToolError('Document not found')

  await assertAllowed(scope, ctx, args.id, 'delete')

  if (scope.docType.settings?.pii) {
    // PII types hard-erase every version + derived data + permissions.
    await scope.svc.erase(args.id, scope.effTenant)
    return { rootId: args.id, deleted: true, erased: true }
  }

  // Non-PII: soft-delete the live rows of the root (published + current draft, which may coincide).
  const ids = new Set<string>()
  const draft = await scope.repo.getCurrentDraft(args.id)
  if (draft) ids.add(draft.id)
  const published = await scope.repo.getPublished(args.id)
  if (published) ids.add(published.id)
  for (const id of ids) await scope.svc.softDelete(id)

  return { rootId: args.id, deleted: true, erased: false }
}
