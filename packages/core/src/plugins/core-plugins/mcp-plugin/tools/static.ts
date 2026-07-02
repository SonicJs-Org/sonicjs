/**
 * Executors for the always-present static tools.
 *
 * `list_collections` reports the collections exposed over MCP and their access
 * flags — metadata only, no document contents, so no ACL filtering is required
 * (the flags themselves are non-sensitive config). Per-document reads still gate
 * through isAllowed in ./documents.ts.
 */

import type { ResolvedMcpType } from '../config'
import type { McpReadCtx } from './documents'
import { DocumentTypeRegistry } from '../../../../services/document-type-registry'

export interface CollectionSummary {
  typeId: string
  displayName: string
  read: boolean
  write: boolean
}

export async function execListCollections(
  ctx: McpReadCtx,
  types: ResolvedMcpType[],
): Promise<CollectionSummary[]> {
  const registry = new DocumentTypeRegistry(ctx.db)
  const out: CollectionSummary[] = []
  for (const t of types) {
    // Skip a configured type whose document type isn't registered/active yet.
    const docType = await registry.findById(t.typeId)
    if (!docType || !docType.isActive) continue
    out.push({ typeId: t.typeId, displayName: t.displayName, read: t.read, write: t.write })
  }
  return out
}
