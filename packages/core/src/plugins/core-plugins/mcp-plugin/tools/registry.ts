/**
 * Build the MCP tool list from resolved config + the live collection registry.
 *
 * Static tools (`list_collections`, and `search_content` once enabled) are always
 * present. Per exposed collection, read tools (`list_/get_`) and — when
 * `includeWrite` and the type allows it — write tools (`create_/update_/publish_/
 * delete_`) are generated. `inputSchema` for write tools comes from the collection's
 * JSON Schema with system fields stripped.
 *
 * `op` is the internal routing discriminator the request handler switches on; it is
 * not sent to the client (only name/description/inputSchema are).
 */

import type { ResolvedMcpConfig } from '../config'
import type { CollectionRecord } from '../../../../services/collection-registry'
import { collectionToJsonSchema, type JsonSchemaNode } from '../schema/field-to-jsonschema'

export type McpToolOp =
  | 'list'
  | 'get'
  | 'create'
  | 'update'
  | 'publish'
  | 'delete'
  | 'list_collections'
  | 'search_content'

export interface McpToolDescriptor {
  name: string
  description: string
  inputSchema: JsonSchemaNode
  op: McpToolOp
  typeId?: string
}

export interface BuildToolsOptions {
  /** Emit create/update/publish/delete tools (Phase 2). */
  includeWrite?: boolean
  /** Emit the cross-type search_content tool (Phase 4). */
  includeSearch?: boolean
}

/**
 * Which tool phases are live. Single source of truth — both the JSON-RPC endpoint
 * and the admin dashboard read this so the advertised tool list can't drift from
 * what the endpoint actually serves. search_content → Phase 4.
 */
export const PHASE_FLAGS: BuildToolsOptions = { includeWrite: true, includeSearch: false }

const EMPTY_OBJECT_SCHEMA: JsonSchemaNode = { type: 'object', properties: {} }

export function buildToolRegistry(
  cfg: ResolvedMcpConfig,
  collections: Map<string, CollectionRecord>,
  opts: BuildToolsOptions = {},
): McpToolDescriptor[] {
  const tools: McpToolDescriptor[] = []

  // ── Static ────────────────────────────────────────────────────────────────
  tools.push({
    name: 'list_collections',
    description: 'List every content collection exposed over MCP, with its read/write access.',
    inputSchema: EMPTY_OBJECT_SCHEMA,
    op: 'list_collections',
  })

  if (opts.includeSearch) {
    tools.push({
      name: 'search_content',
      description: 'Search content across exposed collections by title or slug.',
      inputSchema: {
        type: 'object',
        properties: { query: { type: 'string', description: 'Text matched against document title and slug.' } },
        required: ['query'],
      },
      op: 'search_content',
    })
  }

  // ── Per exposed collection ──────────────────────────────────────────────────
  for (const t of cfg.types) {
    const col = collections.get(t.typeId)
    const writeSchema = col
      ? collectionToJsonSchema(col.schema, { forWrite: true, redactFields: cfg.redactFields })
      : EMPTY_OBJECT_SCHEMA

    if (t.read) {
      tools.push({
        name: `list_${t.typeId}`,
        description: `List ${t.displayName} documents.`,
        inputSchema: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              enum: ['published', 'draft'],
              description: 'Lifecycle to list. Defaults to published.',
            },
            limit: { type: 'number', description: `Max documents to return (capped at ${cfg.listLimit}).` },
          },
        },
        op: 'list',
        typeId: t.typeId,
      })
      tools.push({
        name: `get_${t.typeId}`,
        description: `Get one ${t.displayName} document by id or slug.`,
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Document id or root id.' },
            slug: { type: 'string', description: 'Document slug (alternative to id).' },
          },
        },
        op: 'get',
        typeId: t.typeId,
      })
    }

    if (opts.includeWrite && t.write) {
      tools.push({
        name: `create_${t.typeId}`,
        description: `Create a ${t.displayName} document.`,
        inputSchema: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            slug: { type: 'string' },
            data: writeSchema,
            publish: { type: 'boolean', description: 'Publish immediately. Defaults to false (draft).' },
          },
        },
        op: 'create',
        typeId: t.typeId,
      })
      tools.push({
        name: `update_${t.typeId}`,
        description: `Update a ${t.displayName} document (saves a new draft).`,
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Root id of the document to update.' },
            title: { type: 'string' },
            slug: { type: 'string' },
            data: writeSchema,
          },
          required: ['id'],
        },
        op: 'update',
        typeId: t.typeId,
      })
      tools.push({
        name: `publish_${t.typeId}`,
        description: `Publish a ${t.displayName} document.`,
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string', description: 'Root id of the document to publish.' } },
          required: ['id'],
        },
        op: 'publish',
        typeId: t.typeId,
      })
      tools.push({
        name: `delete_${t.typeId}`,
        description: `Delete a ${t.displayName} document.`,
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string', description: 'Root id of the document to delete.' } },
          required: ['id'],
        },
        op: 'delete',
        typeId: t.typeId,
      })
    }
  }

  return tools
}
