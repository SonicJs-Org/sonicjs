/**
 * Executors for the always-present static tools.
 *
 * `list_collections` reports the collections exposed over MCP and their access
 * flags — metadata only, no document contents, so no ACL filtering is required
 * (the flags themselves are non-sensitive config). Per-document reads still gate
 * through isAllowed in ./documents.ts.
 */

import type { ResolvedMcpType } from '../config'

export interface CollectionSummary {
  typeId: string
  displayName: string
  read: boolean
  write: boolean
}

/**
 * `types` comes from `resolveMcpConfig` which already filters against
 * `CollectionRegistry.listActive()` — every entry is guaranteed active.
 * No per-type DB round-trip needed.
 */
export function execListCollections(types: ResolvedMcpType[]): CollectionSummary[] {
  return types.map((t) => ({ typeId: t.typeId, displayName: t.displayName, read: t.read, write: t.write }))
}
