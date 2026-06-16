import type { D1Database } from '@cloudflare/workers-types'
import { invalidateTenantCache } from '../middleware/tenant'

export interface PluginData {
  id: string
  name: string
  display_name: string
  description: string
  version: string
  author: string
  category: string
  icon: string
  status: 'active' | 'inactive' | 'error'
  is_core: boolean
  settings?: any
  permissions?: string[]
  dependencies?: string[]
  download_count: number
  rating: number
  installed_at: number
  activated_at?: number
  last_updated: number
  error_message?: string
}

export interface PluginStats {
  total: number
  active: number
  inactive: number
  errors: number
  uninstalled: number
}

const TENANT = 'default'
const TYPE_ID = 'plugin'

export class PluginService {
  constructor(private db: D1Database) {}

  async getAllPlugins(): Promise<PluginData[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM documents
      WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
      ORDER BY json_extract(data, '$.isCore') DESC, title ASC
    `).bind(TYPE_ID, TENANT).all()
    return (results || []).map(mapDocumentToPlugin)
  }

  async getPlugin(pluginId: string): Promise<PluginData | null> {
    const row = await this.db.prepare(`
      SELECT * FROM documents
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(pluginId, TYPE_ID, TENANT).first()
    if (!row) return null
    return mapDocumentToPlugin(row)
  }

  async getPluginByName(name: string): Promise<PluginData | null> {
    return this.getPlugin(name)
  }

  async getPluginStats(): Promise<PluginStats> {
    const stats = await this.db.prepare(`
      SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN q_plugin_status = 'active' THEN 1 END) as active,
        COUNT(CASE WHEN q_plugin_status = 'inactive' THEN 1 END) as inactive,
        COUNT(CASE WHEN q_plugin_status = 'error' THEN 1 END) as errors
      FROM documents
      WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(TYPE_ID, TENANT).first() as any
    return {
      total: stats?.total || 0,
      active: stats?.active || 0,
      inactive: stats?.inactive || 0,
      errors: stats?.errors || 0,
      uninstalled: 0,
    }
  }

  async installPlugin(pluginData: Partial<PluginData>): Promise<PluginData> {
    const slug = pluginData.id || pluginData.name || `plugin-${Date.now()}`
    const docId = crypto.randomUUID()
    const now = Math.floor(Date.now() / 1000)
    const data = JSON.stringify({
      name: slug,
      displayName: pluginData.display_name || 'Unnamed Plugin',
      description: pluginData.description || '',
      version: pluginData.version || '1.0.0',
      author: pluginData.author || 'Unknown',
      category: pluginData.category || 'utilities',
      icon: pluginData.icon || '🔌',
      status: 'active',
      isCore: pluginData.is_core || false,
      settings: pluginData.settings || {},
      permissions: pluginData.permissions || [],
      dependencies: pluginData.dependencies || [],
      downloadCount: pluginData.download_count || 0,
      rating: pluginData.rating || 0,
    })
    // R5: 17 columns / 9 ? / 8 literals — verified
    await this.db.prepare(`
      INSERT INTO documents (
        id, root_id, type_id, version_number, is_current_draft, is_published, status,
        parent_root_id, slug, title, tenant_id, locale, translation_group_id,
        data, metadata, created_at, updated_at
      ) VALUES (
        ?, ?, ?, 1, 1, 1, 'published',
        '', ?, ?, ?, 'default', '',
        ?, '{}', ?, ?
      )
    `).bind(
      docId, docId, TYPE_ID,
      slug, pluginData.display_name || 'Unnamed Plugin', TENANT,
      data, now, now
    ).run()

    await this.logActivity(slug, 'installed', null, { version: pluginData.version })
    await this.logActivity(slug, 'activated', null)
    const installed = await this.getPlugin(slug)
    if (!installed) throw new Error('Failed to install plugin')
    return installed
  }

  /**
   * Ensure a definePlugin-registered plugin exists in the DB with active status.
   * No-op if already present. Used by admin routes to auto-register SDK plugins
   * that have never been explicitly installed.
   */
  async ensurePlugin(id: string, data: {
    displayName?: string
    description?: string
    author?: string
    version?: string
  }): Promise<PluginData> {
    const existing = await this.getPlugin(id)
    if (existing) return existing
    return this.installPlugin({
      id,
      name: id,
      display_name: data.displayName || id,
      description: data.description || '',
      author: data.author || '',
      version: data.version || '1.0.0',
    })
  }

  async uninstallPlugin(pluginId: string): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    if (plugin.is_core) throw new Error('Cannot uninstall core plugins')
    if (plugin.status === 'active') await this.deactivatePlugin(pluginId)
    const now = Math.floor(Date.now() / 1000)
    await this.db.prepare(`
      UPDATE documents
      SET deleted_at = ?, updated_at = ?, is_current_draft = 0, is_published = 0
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1
    `).bind(now, now, pluginId, TYPE_ID, TENANT).run()
    await this.logActivity(pluginId, 'uninstalled', null, { name: plugin.name })
  }

  async activatePlugin(pluginId: string): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    if (plugin.dependencies && plugin.dependencies.length > 0) {
      await this.checkDependencies(plugin.dependencies)
    }
    const now = Math.floor(Date.now() / 1000)
    await this.db.prepare(`
      UPDATE documents
      SET data = json_set(data, '$.status', 'active', '$.activatedAt', ?, '$.errorMessage', null),
          updated_at = ?
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(now, now, pluginId, TYPE_ID, TENANT).run()
    // Sync status into the plugins table so isPluginActive() sees the change immediately.
    await this.db.prepare(`UPDATE plugins SET status = 'active' WHERE id = ?`).bind(pluginId).run().catch(() => {})
    // Plugin activation state feeds the tenant resolver cache (the multi-tenant plugin short-circuits
    // to single-tenant while inactive). The UI toggle does not run plugin lifecycle callbacks, so bust
    // the cache here. Cheap no-op for every other plugin.
    invalidateTenantCache()
    await this.logActivity(pluginId, 'activated', null)
  }

  async deactivatePlugin(pluginId: string): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    await this.checkDependents(plugin.name)
    const now = Math.floor(Date.now() / 1000)
    await this.db.prepare(`
      UPDATE documents
      SET data = json_set(data, '$.status', 'inactive', '$.activatedAt', null),
          updated_at = ?
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(now, pluginId, TYPE_ID, TENANT).run()
    // Sync status into the plugins table so isPluginActive() sees the change immediately.
    await this.db.prepare(`UPDATE plugins SET status = 'inactive' WHERE id = ?`).bind(pluginId).run().catch(() => {})
    invalidateTenantCache()
    await this.logActivity(pluginId, 'deactivated', null)
  }

  async updatePluginSettings(pluginId: string, settings: any): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    const now = Math.floor(Date.now() / 1000)
    await this.db.prepare(`
      UPDATE documents
      SET data = json_set(data, '$.settings', json(?)), updated_at = ?
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(JSON.stringify(settings), now, pluginId, TYPE_ID, TENANT).run()
    // Multi-tenant resolver settings (header name, subdomain config) live in plugin settings.
    invalidateTenantCache()
    await this.logActivity(pluginId, 'settings_updated', null)
  }

  async updatePluginVersion(pluginId: string, patch: { version: string; description: string; permissions: string[]; settings: any }): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    await this.db.prepare(`
      UPDATE documents
      SET data = json_set(data,
            '$.version', ?,
            '$.description', ?,
            '$.permissions', json(?),
            '$.settings', json(?)
          ),
          updated_at = ?
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(
      patch.version, patch.description,
      JSON.stringify(patch.permissions), JSON.stringify(patch.settings || {}),
      now, pluginId, TYPE_ID, TENANT
    ).run()
  }

  async setPluginError(pluginId: string, error: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    await this.db.prepare(`
      UPDATE documents
      SET data = json_set(data, '$.status', 'error', '$.errorMessage', ?),
          updated_at = ?
      WHERE slug = ? AND type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
    `).bind(error, now, pluginId, TYPE_ID, TENANT).run()
    await this.logActivity(pluginId, 'error', null, { error })
  }

  async getPluginActivity(pluginId: string, limit: number = 10): Promise<any[]> {
    try {
      const { results } = await this.db.prepare(`
        SELECT id, data, created_at FROM documents
        WHERE type_id = 'plugin_activity'
          AND tenant_id = ?
          AND is_current_draft = 1
          AND deleted_at IS NULL
          AND json_extract(data, '$.pluginId') = ?
        ORDER BY created_at DESC
        LIMIT ?
      `).bind(TENANT, pluginId, limit).all()
      return (results || []).map((row: any) => {
        const d = typeof row.data === 'string' ? JSON.parse(row.data) : (row.data || {})
        return {
          id: row.id,
          action: d.action,
          userId: d.userId || null,
          details: d.details || null,
          timestamp: row.created_at,
        }
      })
    } catch {
      return []
    }
  }

  async registerHook(pluginId: string, hookName: string, handlerName: string, priority: number = 10): Promise<void> {
    const id = `hook-${Date.now()}`
    await this.db.prepare(`
      INSERT INTO plugin_hooks (id, plugin_id, hook_name, handler_name, priority)
      VALUES (?, ?, ?, ?, ?)
    `).bind(id, pluginId, hookName, handlerName, priority).run()
  }

  async registerRoute(pluginId: string, path: string, method: string, handlerName: string, middleware?: any[]): Promise<void> {
    const id = `route-${Date.now()}`
    await this.db.prepare(`
      INSERT INTO plugin_routes (id, plugin_id, path, method, handler_name, middleware)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(id, pluginId, path, method, handlerName, JSON.stringify(middleware || [])).run()
  }

  async getPluginHooks(pluginId: string): Promise<any[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM plugin_hooks WHERE plugin_id = ? AND is_active = TRUE ORDER BY priority ASC
    `).bind(pluginId).all()
    return results || []
  }

  async getPluginRoutes(pluginId: string): Promise<any[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM plugin_routes WHERE plugin_id = ? AND is_active = TRUE
    `).bind(pluginId).all()
    return results || []
  }

  private async checkDependencies(dependencies: string[]): Promise<void> {
    for (const dep of dependencies) {
      const plugin = await this.getPluginByName(dep)
      if (!plugin || plugin.status !== 'active') {
        throw new Error(`Required dependency '${dep}' is not active`)
      }
    }
  }

  private async checkDependents(pluginName: string): Promise<void> {
    const { results } = await this.db.prepare(`
      SELECT slug, title FROM documents
      WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
        AND q_plugin_status = 'active'
        AND json_extract(data, '$.dependencies') LIKE ?
    `).bind(TYPE_ID, TENANT, `%"${pluginName}"%`).all()
    if (results && results.length > 0) {
      const names = results.map((p: any) => p.title || p.slug).join(', ')
      throw new Error(`Cannot deactivate. The following plugins depend on this one: ${names}`)
    }
  }

  private async logActivity(pluginId: string, action: string, userId: string | null, details?: any): Promise<void> {
    try {
      const docId = crypto.randomUUID()
      const now = Math.floor(Date.now() / 1000)
      // R5: 17 columns, 7 ? binds (docId×2, slug, title, data, now×2), 10 literals — verified
      const data = JSON.stringify({ pluginId, action, userId, details: details || null })
      await this.db.prepare(`
        INSERT INTO documents (
          id, root_id, type_id, version_number, is_current_draft, is_published, status,
          parent_root_id, slug, title, tenant_id, locale, translation_group_id,
          data, metadata, created_at, updated_at
        ) VALUES (
          ?, ?, 'plugin_activity', 1, 1, 1, 'published',
          '', ?, ?, 'default', 'default', '',
          ?, '{}', ?, ?
        )
      `).bind(docId, docId, docId, action, data, now, now).run()
    } catch {
      // Activity logging is best-effort; don't fail the main operation
    }
  }
}

function mapDocumentToPlugin(row: any): PluginData {
  const data = typeof row.data === 'string' ? JSON.parse(row.data) : (row.data || {})
  return {
    id: row.slug || data.name || row.root_id,
    name: data.name || row.slug || '',
    display_name: data.displayName || row.title || '',
    description: data.description || '',
    version: data.version || '1.0.0',
    author: data.author || 'Unknown',
    category: data.category || 'utilities',
    icon: data.icon || '🔌',
    status: data.status || 'inactive',
    is_core: data.isCore === true || data.isCore === 1,
    settings: data.settings,
    permissions: data.permissions,
    dependencies: data.dependencies,
    download_count: data.downloadCount || 0,
    rating: data.rating || 0,
    installed_at: row.created_at,
    activated_at: data.activatedAt || undefined,
    last_updated: row.updated_at,
    error_message: data.errorMessage || undefined,
  }
}
