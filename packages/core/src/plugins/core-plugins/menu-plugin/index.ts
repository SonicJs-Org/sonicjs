import { definePlugin } from '../../sdk'
import { DocumentTypeRegistry } from '../../../services/document-type-registry'
import { SYSTEM_MENU_ITEMS } from './services/menu-defaults'
import { upsertSystemItem, listMenuItems } from './services/menu-repository'
import { reconcileMenuFromPlugins } from './services/menu-reconcile'
import { adminMenuRoutes } from './routes/admin-menu'
import { menuMiddleware } from '../../../middleware/menu'
import { renderMenuSettingsContent } from './templates/admin-menu-list.template'
import { z } from 'zod'
import type { D1Database } from '@cloudflare/workers-types'

export const menuPlugin = definePlugin({
  id: 'menu',
  version: '1.0.0',
  name: 'Menu Manager',
  description: 'Admin sidebar navigation manager.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    // Mount sidebar replacement middleware only when this plugin is active
    app.use('/admin/*', menuMiddleware())
    app.route('/admin/menu', adminMenuRoutes as any)
  },

  async onBoot(ctx) {
    const env = (ctx.env ?? {}) as Record<string, unknown>
    const db = env.DB as D1Database | undefined
    if (!db) return

    try {
      // 1. Register menu_item document type
      const typeRegistry = new DocumentTypeRegistry(db)
      await typeRegistry.register({
        id: 'menu_item',
        name: 'menu_item',
        displayName: 'Menu Item',
        description: 'Admin sidebar navigation item',
        schema: z.object({}),
        pluginId: 'menu',
        source: 'plugin',
        queryableFields: [
          { name: 'parent', path: '$.parent', kind: 'scalar', type: 'text', column: 'q_menu_parent' },
          { name: 'visible', path: '$.visible', kind: 'scalar', type: 'boolean', column: 'q_menu_visible' },
          { name: 'source', path: '$.source', kind: 'scalar', type: 'text', column: 'q_menu_source' },
          { name: 'pluginId', path: '$.pluginId', kind: 'scalar', type: 'text', column: 'q_menu_plugin_id' },
        ],
        settings: {
          baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] },
          internal: true,
        },
      })

      // 2. Seed system menu items (insert-only, idempotent)
      for (const item of SYSTEM_MENU_ITEMS) {
        await upsertSystemItem(db, item.id, {
          label: item.label,
          url: item.url,
          icon: item.icon,
          target: item.target,
          isExternal: item.isExternal,
          visible: item.visible,
          parent: item.parent,
          source: item.source,
          pluginId: item.pluginId,
          permissions: [...item.permissions],
          lockedFields: [...item.lockedFields],
        }, item.sortOrder)
      }

      // 3. Reconcile plugin-contributed menu items
      await reconcileMenuFromPlugins(db)
    } catch {
      // DB might not be ready (pre-migration) — skip silently
    }
  },

  settingsTabContent: {
    async loadData(db: any) {
      const items = await listMenuItems(db)
      return { items }
    },
    render({ data }) {
      const items = data?.items ?? []
      return renderMenuSettingsContent(items)
    },
  },
})

export function createMenuPlugin() {
  return menuPlugin
}
