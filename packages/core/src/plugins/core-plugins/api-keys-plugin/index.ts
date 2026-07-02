/**
 * API Keys Plugin — programmatic access tokens for headless REST access.
 *
 * Split, by necessity, across plugin + core:
 *   - Plugin owns: the management surface — admin page + JSON API
 *     (/admin/plugins/api-keys), settings (max keys per user, default expiry),
 *     and the sidebar entry. Plus the ApiKeyService + the resolve middleware.
 *   - Core owns: where the resolve middleware sits in the app-wide auth chain
 *     (app.ts wires `apiKeyAuthMiddleware()` after the Better Auth session
 *     middleware), and the `api_key` document type registration in the
 *     document-type seed (so the q_apikey_* columns exist at boot). This mirrors
 *     how the security-audit plugin's middleware + `security_event` type are
 *     core-wired while the plugin owns its UX.
 *
 * The resolve middleware is always-on for the compiled core build (see
 * middleware/api-key-auth.ts for why it isn't gated on a DB active-flag).
 */

import { definePlugin } from '../../sdk/define-plugin'
import { apiKeysAdminRoutes } from './routes/admin'

const KEY_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>`

export const apiKeysPlugin = definePlugin({
  id: 'api-keys',
  version: '1.0.0-beta.1',
  name: 'API Keys',
  description: 'Programmatic API access keys for headless / server-to-server REST access.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team' },

  register(app) {
    app.route('/admin/plugins/api-keys', apiKeysAdminRoutes as any)
  },

  menu: [
    { label: 'API Keys', path: '/admin/plugins/api-keys', icon: KEY_ICON, order: 86 },
  ],

  configSchema: {
    maxKeysPerUser: {
      type: 'number',
      label: 'Max keys per user',
      description: 'Hard cap on active keys a single user may hold.',
      default: 50,
    },
    defaultExpiryDays: {
      type: 'number',
      label: 'Default expiry (days)',
      description: 'Lifetime applied to new keys when no explicit expiry is given. 0 = never expires.',
      default: 0,
    },
  },

  activate: async () => console.log('[ApiKeys] Plugin activated'),
  deactivate: async () => console.log('[ApiKeys] Plugin deactivated'),
})

export function createApiKeysPlugin() {
  return apiKeysPlugin
}

export {
  ApiKeyService,
  API_KEY_QUERYABLE,
  generateApiKeySecret,
  hashApiKey,
} from './services/api-key-service'
export type {
  CreatedApiKey,
  ApiKeySummary,
  ResolvedApiKeyUser,
} from './services/api-key-service'
export { apiKeyAuthMiddleware } from './middleware/api-key-auth'
export { apiKeysAdminRoutes } from './routes/admin'
export type { ApiKeysSettings } from './types'
export default apiKeysPlugin
