import { Hono } from 'hono'
import { requireAuth } from '../middleware'
import { renderPluginsListPage, PluginsListPageData, Plugin } from '../templates/pages/admin-plugins-list.template'
import { renderPluginSettingsPage, PluginSettingsPageData } from '../templates/pages/admin-plugin-settings.template'
import { SettingsService } from '../services/settings'
import { PluginService } from '../services'
import { PLUGIN_REGISTRY, findPluginByCodeName } from '../plugins/manifest-registry'
import type { Bindings, Variables } from '../app'

const adminPluginRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminPluginRoutes.use('*', requireAuth())

// Build available plugins list from the auto-generated registry.
// To add a new plugin to this list, create a manifest.json in the plugin directory
// and run: node packages/scripts/generate-plugin-registry.mjs
const AVAILABLE_PLUGINS = Object.values(PLUGIN_REGISTRY).map(p => ({
  id: p.id,
  name: p.codeName,
  display_name: p.displayName,
  description: p.description,
  version: p.version,
  author: p.author,
  category: p.category,
  icon: p.iconEmoji,
  permissions: p.permissions,
  dependencies: p.dependencies,
  is_core: p.is_core
}))

// Plugin list page
adminPluginRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB

    // Temporarily skip permission check for admin users
    // TODO: Fix permission system
    if (user?.role !== 'admin') {
      return c.text('Access denied', 403)
    }

    const pluginService = new PluginService(db)

    // Get all installed plugins with error handling
    let installedPlugins: any[] = []
    let stats = { total: 0, active: 0, inactive: 0, errors: 0, uninstalled: 0 }

    try {
      installedPlugins = await pluginService.getAllPlugins()
      stats = await pluginService.getPluginStats()
    } catch (error) {
      console.error('Error loading plugins:', error)
      // Continue with empty data
    }

    // Get list of installed plugin IDs
    const installedPluginIds = new Set(installedPlugins.map(p => p.id))

    // Find uninstalled plugins
    const uninstalledPlugins = AVAILABLE_PLUGINS.filter(p => !installedPluginIds.has(p.id))

    // Map installed plugins to template format
    const templatePlugins: Plugin[] = installedPlugins.map(p => ({
      id: p.id,
      name: p.name,
      displayName: p.display_name,
      description: p.description,
      version: p.version,
      author: p.author,
      status: p.status,
      category: p.category,
      icon: p.icon,
      downloadCount: p.download_count,
      rating: p.rating,
      lastUpdated: formatLastUpdated(p.last_updated),
      dependencies: p.dependencies,
      permissions: p.permissions,
      isCore: p.is_core
    }))

    // Add uninstalled plugins to the list
    const uninstalledTemplatePlugins: Plugin[] = uninstalledPlugins.map(p => ({
      id: p.id,
      name: p.name,
      displayName: p.display_name,
      description: p.description,
      version: p.version,
      author: p.author,
      status: 'uninstalled' as const,
      category: p.category,
      icon: p.icon,
      downloadCount: 0,
      rating: 0,
      lastUpdated: 'Not installed',
      dependencies: p.dependencies,
      permissions: p.permissions,
      isCore: p.is_core
    }))

    // Combine installed and uninstalled plugins
    const allPlugins = [...templatePlugins, ...uninstalledTemplatePlugins]

    // Update stats with uninstalled count
    stats.uninstalled = uninstalledPlugins.length
    stats.total = installedPlugins.length + uninstalledPlugins.length

    const pageData: PluginsListPageData = {
      plugins: allPlugins,
      stats,
      user: {
        name: user?.email || 'User',
        email: user?.email || '',
        role: user?.role || 'user'
      },
      version: c.get('appVersion')
    }

    return c.html(renderPluginsListPage(pageData))
  } catch (error) {
    console.error('Error loading plugins page:', error)
    return c.text('Internal server error', 500)
  }
})

// Get plugin settings page
adminPluginRoutes.get('/:id', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const pluginId = c.req.param('id')

    // Check authorization first
    if (user?.role !== 'admin') {
      return c.redirect('/admin/plugins')
    }

    const pluginService = new PluginService(db)
    const plugin = await pluginService.getPlugin(pluginId)

    if (!plugin) {
      return c.text('Plugin not found', 404)
    }

    // Get activity log
    const activity = await pluginService.getPluginActivity(pluginId, 20)

    // Load additional context for plugins with custom settings components
    let enrichedSettings = plugin.settings || {}

    // For OTP Login plugin, add site name and email config status
    if (pluginId === 'otp-login') {
      // Get site name from general settings via SettingsService
      const settingsService = new SettingsService(db)
      const generalSettings = await settingsService.getGeneralSettings()
      const siteName = generalSettings.siteName || 'SonicJS'

      // Check if email plugin is configured
      const emailPlugin = await db.prepare(`
        SELECT settings FROM plugins WHERE id = 'email'
      `).first() as { settings: string | null } | null

      let emailConfigured = false
      if (emailPlugin?.settings) {
        try {
          const emailSettings = JSON.parse(emailPlugin.settings)
          emailConfigured = !!(emailSettings.apiKey && emailSettings.fromEmail && emailSettings.fromName)
        } catch (e) { /* ignore */ }
      }

      enrichedSettings = {
        ...enrichedSettings,
        siteName,
        _emailConfigured: emailConfigured
      }
    }

    // Map plugin data to template format
    const templatePlugin = {
      id: plugin.id,
      name: plugin.name,
      displayName: plugin.display_name,
      description: plugin.description,
      version: plugin.version,
      author: plugin.author,
      status: plugin.status,
      category: plugin.category,
      icon: plugin.icon,
      downloadCount: plugin.download_count,
      rating: plugin.rating,
      lastUpdated: formatLastUpdated(plugin.last_updated),
      dependencies: plugin.dependencies,
      permissions: plugin.permissions,
      isCore: plugin.is_core,
      settings: enrichedSettings
    }

    // Map activity data
    const templateActivity = (activity || []).map(item => ({
      id: item.id,
      action: item.action,
      message: formatPluginActivityMessage(item),
      timestamp: item.timestamp,
      user: item.userId || undefined
    }))

    const pageData: PluginSettingsPageData = {
      plugin: templatePlugin,
      activity: templateActivity,
      user: {
        name: user?.email || 'User',
        email: user?.email || '',
        role: user?.role || 'user'
      }
    }

    return c.html(renderPluginSettingsPage(pageData))
  } catch (error) {
    console.error('Error getting plugin settings page:', error)
    return c.text('Internal server error', 500)
  }
})

// Activate plugin
adminPluginRoutes.post('/:id/activate', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const pluginId = c.req.param('id')

    // Temporarily skip permission check for admin users
    if (user?.role !== 'admin') {
      return c.json({ error: 'Access denied' }, 403)
    }

    const pluginService = new PluginService(db)
    await pluginService.activatePlugin(pluginId)

    return c.json({ success: true })
  } catch (error) {
    console.error('Error activating plugin:', error)
    const message = error instanceof Error ? error.message : 'Failed to activate plugin'
    return c.json({ error: message }, 400)
  }
})

// Deactivate plugin
adminPluginRoutes.post('/:id/deactivate', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const pluginId = c.req.param('id')

    // Temporarily skip permission check for admin users
    if (user?.role !== 'admin') {
      return c.json({ error: 'Access denied' }, 403)
    }

    const pluginService = new PluginService(db)
    await pluginService.deactivatePlugin(pluginId)

    return c.json({ success: true })
  } catch (error) {
    console.error('Error deactivating plugin:', error)
    const message = error instanceof Error ? error.message : 'Failed to deactivate plugin'
    return c.json({ error: message }, 400)
  }
})

// Generic install handler - uses the auto-generated plugin registry.
// No per-plugin switch/case needed. Adding a manifest.json is enough.
adminPluginRoutes.post('/install', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB

    // Temporarily skip permission check for admin users
    if (user?.role !== 'admin') {
      return c.json({ error: 'Access denied' }, 403)
    }

    const body = await c.req.json()
    const pluginService = new PluginService(db)

    // Look up plugin in registry by codeName (what the frontend sends as body.name)
    // or by id
    const registryEntry = findPluginByCodeName(body.name)
      || PLUGIN_REGISTRY[body.name]
      || PLUGIN_REGISTRY[body.id]

    if (!registryEntry) {
      return c.json({ error: 'Plugin not found in registry' }, 404)
    }

    const plugin = await pluginService.installPlugin({
      id: registryEntry.id,
      name: registryEntry.codeName,
      display_name: registryEntry.displayName,
      description: registryEntry.description,
      version: registryEntry.version,
      author: registryEntry.author,
      category: registryEntry.category,
      icon: registryEntry.iconEmoji,
      permissions: registryEntry.permissions,
      dependencies: registryEntry.dependencies,
      is_core: registryEntry.is_core,
      settings: registryEntry.defaultSettings,
    })

    return c.json({ success: true, plugin })
  } catch (error) {
    console.error('Error installing plugin:', error)
    const message = error instanceof Error ? error.message : 'Failed to install plugin'
    return c.json({ error: message }, 400)
  }
})

// Uninstall plugin
adminPluginRoutes.post('/:id/uninstall', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const pluginId = c.req.param('id')

    // Temporarily skip permission check for admin users
    if (user?.role !== 'admin') {
      return c.json({ error: 'Access denied' }, 403)
    }

    const pluginService = new PluginService(db)
    await pluginService.uninstallPlugin(pluginId)

    return c.json({ success: true })
  } catch (error) {
    console.error('Error uninstalling plugin:', error)
    const message = error instanceof Error ? error.message : 'Failed to uninstall plugin'
    return c.json({ error: message }, 400)
  }
})

// Update plugin settings
adminPluginRoutes.post('/:id/settings', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const pluginId = c.req.param('id')

    // Temporarily skip permission check for admin users
    if (user?.role !== 'admin') {
      return c.json({ error: 'Access denied' }, 403)
    }

    const settings = await c.req.json()

    const pluginService = new PluginService(db)
    await pluginService.updatePluginSettings(pluginId, settings)

    // Clear auth validation cache if updating core-auth plugin
    if (pluginId === 'core-auth') {
      try {
        const cacheKv = c.env.CACHE_KV
        if (cacheKv) {
          await cacheKv.delete('auth:settings')
          await cacheKv.delete('auth:registration-enabled')
          console.log('[AuthSettings] Cache cleared after updating authentication settings')
        }
      } catch (cacheError) {
        console.error('[AuthSettings] Failed to clear cache:', cacheError)
      }
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Error updating plugin settings:', error)
    const message = error instanceof Error ? error.message : 'Failed to update settings'
    return c.json({ error: message }, 400)
  }
})

// Helper function to format last updated time
function formatLastUpdated(timestamp: number): string {
  const now = Date.now() / 1000
  const diff = now - timestamp

  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`
  if (diff < 604800) return `${Math.floor(diff / 86400)} days ago`
  if (diff < 2592000) return `${Math.floor(diff / 604800)} weeks ago`
  return `${Math.floor(diff / 2592000)} months ago`
}

function formatPluginActivityMessage(item: { action: string; details: unknown }): string {
  if (item.details && typeof item.details === 'object' && !Array.isArray(item.details)) {
    const message = (item.details as Record<string, unknown>).message
    if (typeof message === 'string' && message.length > 0) {
      return message
    }
  }

  return item.action.replace(/_/g, ' ')
}

export { adminPluginRoutes }
