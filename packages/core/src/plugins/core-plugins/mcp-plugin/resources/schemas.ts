/**
 * MCP resources — readable `sonicjs://` URIs.
 *
 * v1 exposes collection metadata + per-collection JSON Schema. Document-list
 * resources (`.../documents`) are deferred; agents use the `list_*` tools, which
 * enforce ACL per document. These resource payloads are non-sensitive (schema
 * shape + access flags), so they mirror what `list_collections` already returns.
 */

import type { ResolvedMcpConfig } from '../config'
import type { CollectionRecord } from '../../../../services/collection-registry'
import { collectionToJsonSchema } from '../schema/field-to-jsonschema'
import { McpToolError } from '../jsonrpc'

export interface ResourceListEntry {
  uri: string
  name: string
  mimeType: string
}

export interface ResourceContents {
  uri: string
  mimeType: string
  text: string
}

export function buildResourceList(cfg: ResolvedMcpConfig): ResourceListEntry[] {
  const out: ResourceListEntry[] = [
    { uri: 'sonicjs://collections', name: 'All collections', mimeType: 'application/json' },
  ]
  for (const t of cfg.types) {
    out.push({
      uri: `sonicjs://collections/${t.typeId}/schema`,
      name: `${t.displayName} schema`,
      mimeType: 'application/json',
    })
  }
  return out
}

const SCHEMA_URI = /^sonicjs:\/\/collections\/([^/]+)\/schema$/

export function readResource(
  uri: string,
  cfg: ResolvedMcpConfig,
  collections: Map<string, CollectionRecord>,
): ResourceContents {
  if (uri === 'sonicjs://collections') {
    const list = cfg.types.map((t) => ({
      typeId: t.typeId,
      displayName: t.displayName,
      read: t.read,
      write: t.write,
    }))
    return { uri, mimeType: 'application/json', text: JSON.stringify(list, null, 2) }
  }

  const m = uri.match(SCHEMA_URI)
  if (m) {
    const typeId = m[1]!
    const exposed = cfg.types.find((t) => t.typeId === typeId)
    const col = collections.get(typeId)
    if (!exposed || !col) throw new McpToolError(`Unknown collection: ${typeId}`)
    const schema = collectionToJsonSchema(col.schema, { redactFields: cfg.redactFields })
    return { uri, mimeType: 'application/json', text: JSON.stringify(schema, null, 2) }
  }

  throw new McpToolError(`Unknown resource URI: ${uri}`)
}
