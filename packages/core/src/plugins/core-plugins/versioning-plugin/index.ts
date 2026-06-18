/**
 * Versioning Plugin
 *
 * Provides a history viewer and restore UI for document types that opt in via
 * `settings.versioning: true` in their code-defined document type registration.
 *
 * Routes (all under /admin/versioning, covered by the global admin auth guard):
 *   GET  /admin/versioning/:rootId                       — version history panel (HTML fragment)
 *   POST /admin/versioning/:rootId/restore/:versionNumber — restore an older version as new draft
 */

import { definePlugin } from '../../sdk/define-plugin'
import routes from './routes'

export const versioningPlugin = definePlugin({
  id: 'versioning',
  version: '1.0.0',
  name: 'Versioning',
  description: 'View and restore content version history for types with versioning enabled.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/admin/versioning', routes)
  },
})

export function createVersioningPlugin() {
  return versioningPlugin
}
