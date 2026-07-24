/**
 * API Documentation Plugin
 *
 * Adds an interactive API reference to the admin panel:
 *   - an auto-discovered endpoint catalog (reuses the core route-metadata
 *     service — `buildRouteList(getAppInstance())`, the same machinery that
 *     already backs `/admin/api-reference`);
 *   - a Scalar API explorer;
 *   - a live OpenAPI 3.0 spec generated from the running route table.
 *
 * Read-only. All routes live under `/admin/plugins/api-docs`, so they inherit
 * the global admin gate (`requireAuth` + `requireRbac('portal','access')`);
 * the sub-app additionally asserts auth + a deactivate→404 gate for
 * defense-in-depth (see routes/admin.ts).
 */

import { definePlugin } from '../../sdk/define-plugin'
import { apiDocsAdminRoutes } from './routes/admin'

// Heroicons "book-open" (matches the manifest adminMenu icon).
const API_DOCS_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>`

export const apiDocsPlugin = definePlugin({
  id: 'api-docs',
  version: '1.0.0-beta.1',
  name: 'API Documentation',
  description:
    'Interactive API reference — endpoint catalog, Scalar explorer, and a live OpenAPI 3.0 spec generated from the running route table.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team' },

  register(app) {
    app.route('/admin/plugins/api-docs', apiDocsAdminRoutes)
  },

  menu: [
    { label: 'API Reference', path: '/admin/plugins/api-docs', icon: API_DOCS_ICON, order: 90 },
  ],

  activate: async () => console.log('[ApiDocs] Plugin activated'),
  deactivate: async () => console.log('[ApiDocs] Plugin deactivated'),
})

export function createApiDocsPlugin() {
  return apiDocsPlugin
}

export { apiDocsAdminRoutes } from './routes/admin'
export default apiDocsPlugin
