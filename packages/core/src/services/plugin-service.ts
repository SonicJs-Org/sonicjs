import type { D1Database } from '@cloudflare/workers-types'
import { z } from 'zod'
// Note: PLUGIN_REGISTRY and CORE_PLUGIN_IDS are project-specific
// They should be passed as parameters to the service in the consuming application
// import { PLUGIN_REGISTRY, CORE_PLUGIN_IDS } from '../plugins/plugin-registry'

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }
export type JsonObject = { [key: string]: JsonValue }
export type PluginSettings = Record<string, unknown>

export interface PluginActivityEntry {
  id: string
  action: string
  userId: string | null
  details: JsonValue | null
  timestamp: number
}

export interface PluginHookRecord {
  id: string
  plugin_id: string
  hook_name: string
  handler_name: string
  priority: number
  is_active: boolean
}

export interface PluginRouteRecord {
  id: string
  plugin_id: string
  path: string
  method: string
  handler_name: string
  middleware: JsonValue[]
  is_active: boolean
}

const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() => z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
  z.array(jsonValueSchema),
  z.record(z.string(), jsonValueSchema)
]))

const pluginSettingsSchema: z.ZodType<PluginSettings> = z.record(z.string(), z.unknown())
const pluginStatusSchema = z.enum(['active', 'inactive', 'error'])
const sqliteBooleanSchema = z.union([z.boolean(), z.number()])

const pluginRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  display_name: z.string(),
  description: z.string(),
  version: z.string(),
  author: z.string(),
  category: z.string(),
  icon: z.string(),
  status: pluginStatusSchema,
  is_core: sqliteBooleanSchema,
  settings: z.string().nullable().optional(),
  permissions: z.string().nullable().optional(),
  dependencies: z.string().nullable().optional(),
  download_count: z.coerce.number().optional().default(0),
  rating: z.coerce.number().optional().default(0),
  installed_at: z.coerce.number(),
  activated_at: z.coerce.number().nullable().optional(),
  last_updated: z.coerce.number(),
  error_message: z.string().nullable().optional(),
}).passthrough()

const pluginStatsRowSchema = z.object({
  total: z.coerce.number().optional().default(0),
  active: z.coerce.number().optional().default(0),
  inactive: z.coerce.number().optional().default(0),
  errors: z.coerce.number().optional().default(0)
}).passthrough()

const pluginActivityRowSchema = z.object({
  id: z.string(),
  action: z.string(),
  user_id: z.string().nullable().optional(),
  details: z.string().nullable().optional(),
  timestamp: z.coerce.number()
}).passthrough()

const pluginHookRowSchema = z.object({
  id: z.string(),
  plugin_id: z.string(),
  hook_name: z.string(),
  handler_name: z.string(),
  priority: z.coerce.number().optional().default(10),
  is_active: sqliteBooleanSchema.optional().default(true)
}).passthrough()

const pluginRouteRowSchema = z.object({
  id: z.string(),
  plugin_id: z.string(),
  path: z.string(),
  method: z.string(),
  handler_name: z.string(),
  middleware: z.string().nullable().optional(),
  is_active: sqliteBooleanSchema.optional().default(true)
}).passthrough()

function toBoolean(value: boolean | number): boolean {
  return value === true || value === 1
}

function parseJsonColumn<T>(value: string | null | undefined, schema: z.ZodType<T>, columnName: string): T | undefined {
  if (value == null) {
    return undefined
  }

  let parsed: unknown

  try {
    parsed = JSON.parse(value) as unknown
  } catch (error) {
    throw new Error(`Invalid ${columnName}: ${(error as Error).message}`)
  }

  const result = schema.safeParse(parsed)
  if (!result.success) {
    throw new Error(`Invalid ${columnName}: ${result.error.issues.map(issue => issue.message).join(', ')}`)
  }

  return result.data
}

function parseJsonColumnOrNull<T>(value: string | null | undefined, schema: z.ZodType<T>, columnName: string): T | null {
  if (value == null) {
    return null
  }

  const parsed = parseJsonColumn(value, schema, columnName)
  return parsed ?? null
}

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
  settings?: PluginSettings
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

export class PluginService {
  constructor(private db: D1Database) {}

  async getAllPlugins(): Promise<PluginData[]> {
    // Ensure all plugins from registry exist in database (auto-install if missing)
    await this.ensureAllPluginsExist()

    const stmt = this.db.prepare(`
      SELECT * FROM plugins
      ORDER BY is_core DESC, display_name ASC
    `)

    const { results } = await stmt.all()
    return (results || []).map((row) => this.mapPluginFromDb(row))
  }

  /**
   * Ensure all plugins from the registry exist in the database
   * Auto-installs any newly detected plugins with inactive status
   *
   * Note: This method should be overridden or configured with a plugin registry
   * in the consuming application
   */
  private async ensureAllPluginsExist(): Promise<void> {
    // This functionality requires a project-specific PLUGIN_REGISTRY
    // In the consuming application, you should pass the registry to this service
    console.log('[PluginService] ensureAllPluginsExist - requires PLUGIN_REGISTRY configuration')
  }

  async getPlugin(pluginId: string): Promise<PluginData | null> {
    const stmt = this.db.prepare('SELECT * FROM plugins WHERE id = ?')
    const plugin = await stmt.bind(pluginId).first()
    
    if (!plugin) return null
    return this.mapPluginFromDb(plugin)
  }

  async getPluginByName(name: string): Promise<PluginData | null> {
    const stmt = this.db.prepare('SELECT * FROM plugins WHERE name = ?')
    const plugin = await stmt.bind(name).first()
    
    if (!plugin) return null
    return this.mapPluginFromDb(plugin)
  }

  async getPluginStats(): Promise<PluginStats> {
    const stmt = this.db.prepare(`
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
        COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive,
        COUNT(CASE WHEN status = 'error' THEN 1 END) as errors
      FROM plugins
    `)
    
    const stats = pluginStatsRowSchema.parse(await stmt.first() ?? {})
    return {
      total: stats.total,
      active: stats.active,
      inactive: stats.inactive,
      errors: stats.errors,
      uninstalled: 0
    }
  }

  async installPlugin(pluginData: Partial<PluginData>): Promise<PluginData> {
    const id = pluginData.id || `plugin-${Date.now()}`
    const now = Math.floor(Date.now() / 1000)
    
    const stmt = this.db.prepare(`
      INSERT INTO plugins (
        id, name, display_name, description, version, author, category, icon,
        status, is_core, settings, permissions, dependencies, download_count, 
        rating, installed_at, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    
    await stmt.bind(
      id,
      pluginData.name || id,
      pluginData.display_name || 'Unnamed Plugin',
      pluginData.description || '',
      pluginData.version || '1.0.0',
      pluginData.author || 'Unknown',
      pluginData.category || 'utilities',
      pluginData.icon || '🔌',
      'inactive',
      pluginData.is_core || false,
      JSON.stringify(pluginData.settings || {}),
      JSON.stringify(pluginData.permissions || []),
      JSON.stringify(pluginData.dependencies || []),
      pluginData.download_count || 0,
      pluginData.rating || 0,
      now,
      now
    ).run()
    
    // Log the installation
    await this.logActivity(id, 'installed', null, { version: pluginData.version ?? null })
    
    const installed = await this.getPlugin(id)
    if (!installed) throw new Error('Failed to install plugin')
    
    return installed
  }

  async uninstallPlugin(pluginId: string): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    if (plugin.is_core) throw new Error('Cannot uninstall core plugins')
    
    // First deactivate if active
    if (plugin.status === 'active') {
      await this.deactivatePlugin(pluginId)
    }
    
    // Delete the plugin
    const stmt = this.db.prepare('DELETE FROM plugins WHERE id = ?')
    await stmt.bind(pluginId).run()
    
    // Log the uninstallation
    await this.logActivity(pluginId, 'uninstalled', null, { name: plugin.name })
  }

  async activatePlugin(pluginId: string): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    
    // Check dependencies
    if (plugin.dependencies && plugin.dependencies.length > 0) {
      await this.checkDependencies(plugin.dependencies)
    }
    
    const now = Math.floor(Date.now() / 1000)
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET status = 'active', activated_at = ?, error_message = NULL 
      WHERE id = ?
    `)
    
    await stmt.bind(now, pluginId).run()
    
    // Log the activation
    await this.logActivity(pluginId, 'activated', null)
  }

  async deactivatePlugin(pluginId: string): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    
    // Check if other plugins depend on this one
    await this.checkDependents(plugin.name)
    
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET status = 'inactive', activated_at = NULL 
      WHERE id = ?
    `)
    
    await stmt.bind(pluginId).run()
    
    // Log the deactivation
    await this.logActivity(pluginId, 'deactivated', null)
  }

  async updatePluginSettings<T extends object>(pluginId: string, settings: T): Promise<void> {
    const plugin = await this.getPlugin(pluginId)
    if (!plugin) throw new Error('Plugin not found')
    
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET settings = ?, updated_at = unixepoch() 
      WHERE id = ?
    `)
    
    await stmt.bind(JSON.stringify(settings), pluginId).run()
    
    // Log the settings update
    await this.logActivity(pluginId, 'settings_updated', null)
  }

  async setPluginError(pluginId: string, error: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET status = 'error', error_message = ? 
      WHERE id = ?
    `)
    
    await stmt.bind(error, pluginId).run()
    
    // Log the error
    await this.logActivity(pluginId, 'error', null, { error })
  }

  async getPluginActivity(pluginId: string, limit: number = 10): Promise<PluginActivityEntry[]> {
    const stmt = this.db.prepare(`
      SELECT * FROM plugin_activity_log 
      WHERE plugin_id = ? 
      ORDER BY timestamp DESC 
      LIMIT ?
    `)
    
    const { results } = await stmt.bind(pluginId, limit).all()
    return (results || []).map((row) => {
      const activity = pluginActivityRowSchema.parse(row)

      return {
        id: activity.id,
        action: activity.action,
        userId: activity.user_id ?? null,
        details: parseJsonColumnOrNull(activity.details, jsonValueSchema, 'plugin_activity_log.details'),
        timestamp: activity.timestamp
      }
    })
  }

  async registerHook(pluginId: string, hookName: string, handlerName: string, priority: number = 10): Promise<void> {
    const id = `hook-${Date.now()}`
    const stmt = this.db.prepare(`
      INSERT INTO plugin_hooks (id, plugin_id, hook_name, handler_name, priority)
      VALUES (?, ?, ?, ?, ?)
    `)
    
    await stmt.bind(id, pluginId, hookName, handlerName, priority).run()
  }

  async registerRoute(pluginId: string, path: string, method: string, handlerName: string, middleware?: JsonValue[]): Promise<void> {
    const id = `route-${Date.now()}`
    const stmt = this.db.prepare(`
      INSERT INTO plugin_routes (id, plugin_id, path, method, handler_name, middleware)
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    
    await stmt.bind(
      id, 
      pluginId, 
      path, 
      method, 
      handlerName, 
      JSON.stringify(middleware || [])
    ).run()
  }

  async getPluginHooks(pluginId: string): Promise<PluginHookRecord[]> {
    const stmt = this.db.prepare(`
      SELECT * FROM plugin_hooks 
      WHERE plugin_id = ? AND is_active = TRUE
      ORDER BY priority ASC
    `)
    
    const { results } = await stmt.bind(pluginId).all()
    return (results || []).map((row) => {
      const hook = pluginHookRowSchema.parse(row)

      return {
        id: hook.id,
        plugin_id: hook.plugin_id,
        hook_name: hook.hook_name,
        handler_name: hook.handler_name,
        priority: hook.priority,
        is_active: toBoolean(hook.is_active)
      }
    })
  }

  async getPluginRoutes(pluginId: string): Promise<PluginRouteRecord[]> {
    const stmt = this.db.prepare(`
      SELECT * FROM plugin_routes 
      WHERE plugin_id = ? AND is_active = TRUE
    `)
    
    const { results } = await stmt.bind(pluginId).all()
    return (results || []).map((row) => {
      const route = pluginRouteRowSchema.parse(row)

      return {
        id: route.id,
        plugin_id: route.plugin_id,
        path: route.path,
        method: route.method,
        handler_name: route.handler_name,
        middleware: parseJsonColumn(route.middleware, z.array(jsonValueSchema), 'plugin_routes.middleware') ?? [],
        is_active: toBoolean(route.is_active)
      }
    })
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
    const stmt = this.db.prepare(`
      SELECT id, display_name FROM plugins 
      WHERE status = 'active' 
      AND dependencies LIKE ?
    `)
    
    const { results } = await stmt.bind(`%"${pluginName}"%`).all()
    if (results && results.length > 0) {
      const names = results
        .map((plugin) => z.object({ display_name: z.string() }).parse(plugin).display_name)
        .join(', ')
      throw new Error(`Cannot deactivate. The following plugins depend on this one: ${names}`)
    }
  }

  private async logActivity(pluginId: string, action: string, userId: string | null, details?: JsonValue): Promise<void> {
    const id = `activity-${Date.now()}`
    const stmt = this.db.prepare(`
      INSERT INTO plugin_activity_log (id, plugin_id, action, user_id, details)
      VALUES (?, ?, ?, ?, ?)
    `)
    
    await stmt.bind(
      id,
      pluginId,
      action,
      userId,
      details === undefined ? null : JSON.stringify(details)
    ).run()
  }

  private mapPluginFromDb(row: unknown): PluginData {
    const plugin = pluginRowSchema.parse(row)

    return {
      id: plugin.id,
      name: plugin.name,
      display_name: plugin.display_name,
      description: plugin.description,
      version: plugin.version,
      author: plugin.author,
      category: plugin.category,
      icon: plugin.icon,
      status: plugin.status,
      is_core: toBoolean(plugin.is_core),
      settings: parseJsonColumn(plugin.settings, pluginSettingsSchema, 'plugins.settings'),
      permissions: parseJsonColumn(plugin.permissions, z.array(z.string()), 'plugins.permissions'),
      dependencies: parseJsonColumn(plugin.dependencies, z.array(z.string()), 'plugins.dependencies'),
      download_count: plugin.download_count,
      rating: plugin.rating,
      installed_at: plugin.installed_at,
      activated_at: plugin.activated_at ?? undefined,
      last_updated: plugin.last_updated,
      error_message: plugin.error_message ?? undefined
    }
  }
}
