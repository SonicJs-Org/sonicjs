/**
 * Database Tools Plugin — Payload-shaped port.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { DatabaseToolsService } from './services/database-service'

export const databaseToolsPlugin = definePlugin({
  id: 'database-tools',
  version: '1.0.0',
  name: 'Database Tools',
  description: 'Database management tools including truncate, backup, and validation.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS', email: 'admin@sonicjs.com' },

  // Admin route mounted by app.ts at /admin/database-tools — no register fn needed
  // here since the page lives at the existing createDatabaseToolsAdminRoutes() call.

  menu: [
    { label: 'Database Tools', path: '/admin/database-tools', icon: 'cog', order: 60, permissions: ['admin'] },
  ],
})

export function createDatabaseToolsPlugin() {
  return databaseToolsPlugin
}

export { DatabaseToolsService } from './services/database-service'
