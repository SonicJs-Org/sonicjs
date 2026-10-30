/**
 * Redirect Management Plugin — document-model backed.
 */

import { definePlugin } from '../sdk/define-plugin'
import manifest from './manifest.json'
import { createRedirectAdminRoutes } from './routes/admin'
import { createRedirectApiRoutes } from './routes/api'
import { REDIRECT_QUERYABLE_FIELDS } from './services/redirect'
import { DocumentTypeRegistry } from '../../services/document-type-registry'
import type { D1Database } from '@cloudflare/workers-types'
import { z } from 'zod'
import { createRedirectMiddleware } from './middleware/redirect'

// Re-exports
export { createRedirectMiddleware, invalidateRedirectCache, warmRedirectCache } from './middleware/redirect'
export { createRedirectAdminRoutes } from './routes/admin'
export { createRedirectApiRoutes } from './routes/api'

export const redirectPlugin = definePlugin({
  id: manifest.id,
  version: manifest.version,
  name: manifest.name,
  description: manifest.description,
  sonicjsVersionRange: '^3.0.0',
  author: { name: manifest.author },

  register(app) {
    app.use('*', createRedirectMiddleware() as any)
    app.route('/admin/redirects', createRedirectAdminRoutes() as any)
    app.route('/api/redirects', createRedirectApiRoutes() as any)
  },

  menu: [
    { label: 'Redirects', path: '/admin/redirects', icon: 'bolt', order: 85, permissions: ['admin', 'redirect.manage'] },
  ],

  async onBoot(ctx) {
    const db = ctx.env?.DB as D1Database | undefined
    if (!db) return

    const registry = new DocumentTypeRegistry(db)
    await registry.register({
      id: 'redirect',
      name: 'redirect',
      displayName: 'Redirect',
      description: 'URL redirect rules managed by the redirect-management plugin.',
      schema: z.record(z.string(), z.unknown()),
      source: 'system',
      queryableFields: REDIRECT_QUERYABLE_FIELDS,
      settings: {
        baseGrants: { public: [], authenticated: [], admin: ['read', 'create', 'update', 'delete'] },
        maxVersionsPerRoot: 1,
      },
    })
  },

  install: async () => console.log('Redirect Management plugin installed (document-model backed)'),
  activate: async () => console.log('Redirect Management plugin activated'),
  deactivate: async () => console.log('Redirect Management plugin deactivated'),
  uninstall: async () => console.log('Redirect Management plugin uninstalled'),
})

export function createRedirectPlugin() {
  return redirectPlugin
}

export default redirectPlugin
