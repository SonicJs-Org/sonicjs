/**
 * Minimal JSON-RPC 2.0 helpers for the MCP endpoint.
 *
 * The Model Context Protocol is JSON-RPC 2.0. v1 implements the request/response
 * half over a single POST — no batching, no SSE. These helpers parse an incoming
 * envelope and build spec-compliant result / error responses. Kept dependency-free
 * so the plugin adds nothing to the Workers bundle.
 */

/** Standard JSON-RPC error codes + one custom code for auth failures. */
export const JSON_RPC = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  /** Custom: no valid API key on the request. */
  UNAUTHORIZED: -32001,
} as const

export type JsonRpcId = string | number | null

export interface JsonRpcRequest {
  jsonrpc: '2.0'
  id: JsonRpcId
  method: string
  params: Record<string, unknown>
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0'
  id: JsonRpcId
  result: unknown
}

export interface JsonRpcFailure {
  jsonrpc: '2.0'
  id: JsonRpcId
  error: { code: number; message: string; data?: unknown }
}

/**
 * A tool-level failure (bad arguments, unknown document, ACL denial). The route
 * surfaces these to the client as an MCP tool error (`isError: true` content for
 * tools/call, or a JSON-RPC error envelope elsewhere) rather than a 500.
 */
export class McpToolError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'McpToolError'
  }
}

export function rpcResult(id: JsonRpcId, result: unknown): JsonRpcSuccess {
  return { jsonrpc: '2.0', id: id ?? null, result }
}

export function rpcError(id: JsonRpcId, code: number, message: string, data?: unknown): JsonRpcFailure {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } }
}

/**
 * Validate the shape of a decoded request body. Returns a normalized request or a
 * `{ error }` describing the first violation. Does not throw.
 */
export function parseJsonRpc(body: unknown): JsonRpcRequest | { error: { code: number; message: string } } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { error: { code: JSON_RPC.INVALID_REQUEST, message: 'Request must be a JSON object' } }
  }
  const b = body as Record<string, unknown>
  if (b.jsonrpc !== '2.0') {
    return { error: { code: JSON_RPC.INVALID_REQUEST, message: 'jsonrpc must be "2.0"' } }
  }
  if (typeof b.method !== 'string' || b.method.length === 0) {
    return { error: { code: JSON_RPC.INVALID_REQUEST, message: 'method must be a non-empty string' } }
  }
  const id = (b.id === undefined ? null : b.id) as JsonRpcId
  const params = (b.params && typeof b.params === 'object' && !Array.isArray(b.params))
    ? (b.params as Record<string, unknown>)
    : {}
  return { jsonrpc: '2.0', id, method: b.method, params }
}
