import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
import { getCollectionRegistry } from '../../../../services/collection-registry'
import { resolveMcpConfig, type McpConfigInput } from '../config'
import { buildToolRegistry } from '../tools/registry'
import { renderMcpDashboardPage } from './templates'
import type { Bindings, Variables } from '../../../../app'

// Phase flags mirrored from routes/mcp.ts — must stay in sync.
const PHASE_FLAGS = { includeWrite: true, includeSearch: false }

export function createMcpAdminRoutes(options: McpConfigInput = {}) {
  const routes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  routes.use('*', requireAuth())
  routes.use('*', async (c, next) => {
    const user = c.get('user')
    if (user?.role !== 'admin') return c.json({ error: 'Access denied' }, 403)
    return next()
  })

  routes.get('/', async (c) => {
    const url = new URL(c.req.url)
    const endpointUrl = `${url.protocol}//${url.host}/mcp`

    const registry = getCollectionRegistry()
    const active = registry.listActive()
    const collections = new Map(active.map((col) => [col.name, col]))
    const cfg = resolveMcpConfig(options, active)
    const tools = buildToolRegistry(cfg, collections, PHASE_FLAGS)

    const user = c.get('user')!
    return c.html(
      renderMcpDashboardPage({
        endpointUrl,
        types: cfg.types,
        tools,
        user: { name: user.email, email: user.email, role: user.role },
        version: c.get('appVersion'),
        dynamicMenuItems: c.get('pluginMenuItems'),
      }),
    )
  })

  return routes
}
