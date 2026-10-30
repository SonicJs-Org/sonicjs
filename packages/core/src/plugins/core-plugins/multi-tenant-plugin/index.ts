/**
 * Multi-Tenant Plugin — Payload-shaped port.
 *
 * Tenant management UI + activation hooks that bust the per-isolate resolver
 * cache. PluginService writes call invalidateTenantCache() directly; the
 * lifecycle callbacks here cover direct activate/deactivate paths.
 */

import { definePlugin } from '../../sdk/define-plugin'
import manifest from './manifest.json'
import { createTenantAdminRoutes } from './routes/admin'
import { createJoinRoutes } from './routes/join'
import { invalidateTenantCache } from '../../../middleware/tenant'

const TENANT_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"/></svg>`

export const multiTenantPlugin = definePlugin({
  id: manifest.id,
  version: '1.0.0',
  name: manifest.name,
  description: manifest.description,
  sonicjsVersionRange: '^3.0.0',
  author: { name: manifest.author },

  register(app) {
    app.route('/admin/tenants', createTenantAdminRoutes() as any)
    // Public invitation join routes — NO auth middleware (unauthenticated invitees).
    app.route('/join/invite', createJoinRoutes() as any)
  },

  menu: [
    { label: 'Tenants', path: '/admin/tenants', icon: TENANT_ICON, order: 80 },
  ],

  activate: async () => {
    invalidateTenantCache()
    console.info('✅ Multi-Tenant plugin activated')
  },
  deactivate: async () => {
    invalidateTenantCache()
    console.info('❌ Multi-Tenant plugin deactivated')
  },
})

export function createMultiTenantPlugin() {
  return multiTenantPlugin
}

export { TenantService } from './services/tenant-service'
export default multiTenantPlugin
