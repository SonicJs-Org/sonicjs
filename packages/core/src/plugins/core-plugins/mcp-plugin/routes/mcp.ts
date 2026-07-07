/**
 * MCP JSON-RPC endpoint — POST /mcp.
 *
 * Mounted at top-level /mcp (not /api/mcp) so it clears the /api/:collection
 * catch-all in app.ts. Auth is delegated: the app-wide apiKeyAuthMiddleware
 * (app.ts) resolves `Authorization: Bearer sk_…` to `c.get('user')` before this
 * runs. We only check that a user was resolved, then derive the ACL principal set
 * via the shared getDocumentRequestContext coupling point — so MCP callers get
 * exactly the permissions of the key's owning user, gated per document by isAllowed.
 *
 * v1 supports: initialize, tools/list, tools/call, resources/list, resources/read.
 * Write tools + search_content are gated off here until Phases 2 / 4.
 */

import { Hono } from 'hono'
import type { Bindings, Variables } from '../../../../app'
import { getDocumentRequestContext } from '../../../../services/document-request-context'
import { getCollectionRegistry } from '../../../../services/collection-registry'
import { resolveMcpConfig, type McpConfigInput } from '../config'
import { buildToolRegistry, PHASE_FLAGS } from '../tools/registry'
import { execList, execGet, type McpReadCtx } from '../tools/documents'
import { execCreate, execUpdate, execPublish, execDelete, type McpWriteCtx } from '../tools/mutations'
import { execListCollections } from '../tools/static'
import { buildResourceList, readResource } from '../resources/schemas'
import { parseJsonRpc, rpcResult, rpcError, JSON_RPC, McpToolError } from '../jsonrpc'

const SERVER_INFO = { name: 'sonicjs-mcp', version: '1.0.0' } as const
// MCP protocol revision this server speaks (request/response subset).
const PROTOCOL_VERSION = '2024-11-05'

export function createMcpRoutes(options: McpConfigInput = {}) {
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  app.post('/', async (c) => {
    // Decode body.
    let body: unknown
    try {
      body = await c.req.json()
    } catch {
      return c.json(rpcError(null, JSON_RPC.PARSE_ERROR, 'Invalid JSON'))
    }

    // Validate JSON-RPC envelope.
    const parsed = parseJsonRpc(body)
    if ('error' in parsed) {
      const id = (body && typeof body === 'object' ? (body as any).id ?? null : null)
      return c.json(rpcError(id, parsed.error.code, parsed.error.message))
    }
    const { id, method, params } = parsed

    // Auth (delegated to the global api-key middleware).
    const user = c.get('user')
    if (!user) {
      return c.json(
        rpcError(id, JSON_RPC.UNAUTHORIZED, 'Unauthorized: provide a valid API key via Authorization: Bearer sk_...'),
      )
    }

    const { tenantId, principalSet, userId } = getDocumentRequestContext(c)
    const registry = getCollectionRegistry()
    const active = registry.listActive()
    const collections = new Map(active.map((col) => [col.name, col]))
    const cfg = resolveMcpConfig(options, active)
    const tools = buildToolRegistry(cfg, collections, PHASE_FLAGS)

    try {
      switch (method) {
        case 'initialize':
          return c.json(
            rpcResult(id, {
              protocolVersion: PROTOCOL_VERSION,
              serverInfo: SERVER_INFO,
              capabilities: { tools: {}, resources: {} },
            }),
          )

        case 'tools/list':
          return c.json(
            rpcResult(id, {
              tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
            }),
          )

        case 'tools/call': {
          const name = typeof params.name === 'string' ? params.name : ''
          const args = (params.arguments && typeof params.arguments === 'object'
            ? params.arguments
            : {}) as Record<string, unknown>
          const tool = tools.find((t) => t.name === name)
          if (!tool) return c.json(rpcError(id, JSON_RPC.METHOD_NOT_FOUND, `Unknown tool: ${name}`))

          const readCtx: McpReadCtx = {
            db: c.env.DB,
            tenantId,
            principalSet,
            listLimit: cfg.listLimit,
            redactFields: cfg.redactFields,
          }
          const writeCtx: McpWriteCtx = {
            db: c.env.DB,
            tenantId,
            principalSet,
            userId: userId ?? '',
            redactFields: cfg.redactFields,
          }

          try {
            let result: unknown
            switch (tool.op) {
              case 'list_collections':
                result = execListCollections(cfg.types)
                break
              case 'list':
                result = await execList(readCtx, tool.typeId!, args as { status?: string; limit?: number })
                break
              case 'get':
                result = await execGet(readCtx, tool.typeId!, args as { id?: string; slug?: string })
                break
              case 'create':
                result = await execCreate(writeCtx, tool.typeId!, args as any)
                break
              case 'update':
                result = await execUpdate(writeCtx, tool.typeId!, args as any)
                break
              case 'publish':
                result = await execPublish(writeCtx, tool.typeId!, args as { id?: string })
                break
              case 'delete':
                result = await execDelete(writeCtx, tool.typeId!, args as { id?: string })
                break
              default:
                return c.json(rpcError(id, JSON_RPC.METHOD_NOT_FOUND, `Tool not available: ${name}`))
            }
            return c.json(rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }))
          } catch (e) {
            // Tool-level failure → MCP isError content (not a transport error).
            if (e instanceof McpToolError) {
              return c.json(rpcResult(id, { content: [{ type: 'text', text: e.message }], isError: true }))
            }
            throw e
          }
        }

        case 'resources/list':
          return c.json(rpcResult(id, { resources: buildResourceList(cfg) }))

        case 'resources/read': {
          const uri = typeof params.uri === 'string' ? params.uri : ''
          if (!uri) return c.json(rpcError(id, JSON_RPC.INVALID_PARAMS, 'resources/read requires a "uri" param'))
          try {
            const contents = readResource(uri, cfg, collections)
            return c.json(rpcResult(id, { contents: [contents] }))
          } catch (e) {
            if (e instanceof McpToolError) return c.json(rpcError(id, JSON_RPC.INVALID_PARAMS, e.message))
            throw e
          }
        }

        default:
          return c.json(rpcError(id, JSON_RPC.METHOD_NOT_FOUND, `Method not found: ${method}`))
      }
    } catch (e) {
      console.error('[mcp] handler error:', e)
      return c.json(rpcError(id, JSON_RPC.INTERNAL_ERROR, 'Internal error'))
    }
  })

  return app
}
