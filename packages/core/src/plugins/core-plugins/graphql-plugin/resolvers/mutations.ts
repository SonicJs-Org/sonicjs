import { DocumentRepository } from '../../../../services/document-repository'
import { DocumentTypeRegistry } from '../../../../services/document-type-registry'
import { DocumentsService } from '../../../../services/documents'
import { createDocumentSchema } from '../../../../schemas/document'
import type { GraphqlResolverContext } from './context'
import type { Document } from '../../../../schemas/document'

class GraphQLForbiddenError extends Error {
  constructor(message = 'Forbidden') {
    super(message)
    this.name = 'GraphQLForbiddenError'
  }
}

async function requireWritePermission(
  repo: DocumentRepository,
  doc: Pick<Document, 'rootId' | 'typeId'>,
  permission: 'create' | 'update' | 'delete' | 'publish' | 'manage',
  ctx: GraphqlResolverContext,
): Promise<void> {
  // Base grants live on the document type. Passing no settings leaves isAllowed with only
  // per-document ACL rows to go on, which denies every write — including an admin's.
  const docType = await new DocumentTypeRegistry(ctx.db).findById(doc.typeId)
  const allowed = await repo.isAllowed(ctx.principalSet, doc.rootId, permission, docType?.settings ?? {})
  if (!allowed) throw new GraphQLForbiddenError(`Not allowed to ${permission} document ${doc.rootId}`)
}

interface CreateArgs {
  typeId: string
  title?: string
  slug?: string
  data: Record<string, unknown>
  publishOnCreate?: boolean
}

export async function resolveCreateDocument(args: CreateArgs, ctx: GraphqlResolverContext): Promise<Document> {
  if (!ctx.userId) throw new GraphQLForbiddenError('Authentication required to create documents')

  const svc = new DocumentsService(ctx.db, { tenantId: ctx.tenantId })
  const input = createDocumentSchema.parse({
    typeId: args.typeId,
    tenantId: ctx.tenantId,
    title: args.title ?? null,
    slug: args.slug ?? null,
    data: args.data,
    publishOnCreate: args.publishOnCreate ?? false,
  })
  return svc.create(input, ctx.userId ?? undefined)
}

interface UpdateArgs {
  id: string
  title?: string
  slug?: string
  data?: Record<string, unknown>
}

export async function resolveUpdateDocument(args: UpdateArgs, ctx: GraphqlResolverContext): Promise<Document> {
  if (!ctx.userId) throw new GraphQLForbiddenError('Authentication required to update documents')

  const repo = new DocumentRepository(ctx.db, ctx.tenantId)
  const existing = await repo.getById(args.id)
  if (!existing) throw new Error(`Document not found: ${args.id}`)

  await requireWritePermission(repo, existing, 'update', ctx)

  const svc = new DocumentsService(ctx.db, { tenantId: ctx.tenantId })
  return svc.saveDraft(
    existing.rootId,
    {
      title: args.title ?? existing.title,
      slug: args.slug ?? existing.slug,
      data: args.data ?? existing.data,
    },
    ctx.userId,
  )
}

export async function resolvePublishDocument(args: { id: string }, ctx: GraphqlResolverContext): Promise<Document> {
  if (!ctx.userId) throw new GraphQLForbiddenError('Authentication required to publish documents')

  const repo = new DocumentRepository(ctx.db, ctx.tenantId)
  const existing = await repo.getById(args.id)
  if (!existing) throw new Error(`Document not found: ${args.id}`)

  await requireWritePermission(repo, existing, 'publish', ctx)

  const svc = new DocumentsService(ctx.db, { tenantId: ctx.tenantId })
  return svc.publish(args.id, ctx.userId)
}

export async function resolveUnpublishDocument(args: { id: string }, ctx: GraphqlResolverContext): Promise<Document> {
  if (!ctx.userId) throw new GraphQLForbiddenError('Authentication required to unpublish documents')

  const repo = new DocumentRepository(ctx.db, ctx.tenantId)
  const existing = await repo.getById(args.id)
  if (!existing) throw new Error(`Document not found: ${args.id}`)

  await requireWritePermission(repo, existing, 'publish', ctx)

  const svc = new DocumentsService(ctx.db, { tenantId: ctx.tenantId })
  return svc.unpublish(args.id)
}

export async function resolveDeleteDocument(args: { id: string }, ctx: GraphqlResolverContext): Promise<boolean> {
  if (!ctx.userId) throw new GraphQLForbiddenError('Authentication required to delete documents')

  const repo = new DocumentRepository(ctx.db, ctx.tenantId)
  const existing = await repo.getById(args.id)
  if (!existing) throw new Error(`Document not found: ${args.id}`)

  await requireWritePermission(repo, existing, 'delete', ctx)

  const svc = new DocumentsService(ctx.db, { tenantId: ctx.tenantId })
  await svc.softDelete(args.id)
  return true
}
