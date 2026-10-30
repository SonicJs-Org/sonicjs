import { DocumentRepository } from '../../../../services/document-repository'
import type { ListStatus } from '../../../../services/document-repository'
import type { GraphqlResolverContext } from './context'
import type { Document } from '../../../../schemas/document'

interface DocumentsArgs {
  typeId?: string
  status?: string
  limit?: number
  cursor?: string
  locale?: string
  sortDir?: string
}

interface DocumentPage {
  items: Document[]
  cursor: string | null
}

export async function resolveDocuments(args: DocumentsArgs, ctx: GraphqlResolverContext): Promise<DocumentPage> {
  const repo = new DocumentRepository(ctx.db, ctx.tenantId)

  const status: ListStatus = (args.status === 'draft' || args.status === 'all')
    ? args.status
    : 'published'

  const limit = Math.min(Math.max(args.limit ?? 50, 1), 200)

  let cursorUpdatedAt: number | undefined
  let cursorId: string | undefined
  if (args.cursor) {
    try {
      const parsed = JSON.parse(Buffer.from(args.cursor, 'base64').toString('utf8'))
      cursorUpdatedAt = parsed.updatedAt
      cursorId = parsed.id
    } catch {
      // ignore malformed cursor
    }
  }

  const sortDir = args.sortDir === 'ASC' ? 'ASC' : 'DESC'

  const items = await repo.list({
    typeId: args.typeId,
    status,
    locale: args.locale,
    limit,
    cursorUpdatedAt,
    cursorId,
    sortDir,
    timeWindow: status === 'published',
  })

  let nextCursor: string | null = null
  if (items.length === limit) {
    const last = items[items.length - 1]!
    nextCursor = Buffer.from(JSON.stringify({ updatedAt: last.updatedAt, id: last.id })).toString('base64')
  }

  return { items, cursor: nextCursor }
}

export async function resolveDocument(
  args: { id: string },
  ctx: GraphqlResolverContext,
): Promise<Document | null> {
  const repo = new DocumentRepository(ctx.db, ctx.tenantId)
  return repo.getById(args.id)
}
