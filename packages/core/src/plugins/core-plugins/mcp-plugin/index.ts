/**
 * MCP Server Plugin — exposes SonicJS content as Model Context Protocol tools.
 *
 * Opt-in: add `mcpPlugin({...})` to the app's `plugins.register` array to activate.
 * When absent, zero routes are mounted. Authentication is delegated entirely to the
 * API Keys plugin — callers present `Authorization: Bearer sk_…` (minted at
 * /admin/plugins/api-keys), which the app-wide apiKeyAuthMiddleware resolves to a
 * user before the MCP endpoint runs. Every read/write then flows through the normal
 * document ACL for that user; MCP adds no privilege.
 *
 * Endpoint (Phase 1): POST /api/mcp — JSON-RPC 2.0 (initialize, tools/list,
 * tools/call, resources/list, resources/read). Admin UI + menu land in Phase 3.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { createMcpRoutes } from './routes/mcp'
import { createMcpAdminRoutes } from './admin/routes'
import type { McpConfigInput } from './config'

const MCP_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>`

/** Build an MCP plugin instance bound to the given config. */
export function mcpPlugin(options: McpConfigInput = {}) {
  return definePlugin({
    id: 'mcp',
    version: '1.0.0',
    name: 'MCP Server',
    description: 'Exposes SonicJS content as Model Context Protocol tools for AI agents (Claude Code, Cursor, …).',
    sonicjsVersionRange: '^3.0.0',
    author: { name: 'SonicJS Team' },

    register(app) {
      // Mount at /mcp (not /api/mcp) — avoids the /api/:collection catch-all in
      // app.ts which is registered before user plugin routes.
      app.route('/mcp', createMcpRoutes(options) as any)
      app.route('/admin/mcp', createMcpAdminRoutes(options) as any)
    },

    menu: [{ label: 'MCP Server', path: '/admin/mcp', icon: MCP_ICON, order: 87 }],
  })
}

/** Alias matching the repo's `createXPlugin` convention. */
export function createMcpPlugin(options?: McpConfigInput) {
  return mcpPlugin(options)
}

export type { McpConfigInput, McpConfig, ResolvedMcpConfig } from './config'
export { resolveMcpConfig, mcpConfigSchema } from './config'
export { buildToolRegistry } from './tools/registry'
export { collectionToJsonSchema, fieldToJsonSchema } from './schema/field-to-jsonschema'
export { createMcpRoutes } from './routes/mcp'

export default mcpPlugin
