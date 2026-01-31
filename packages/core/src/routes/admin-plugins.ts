import { Hono } from 'hono'
import { requireAuth } from '../middleware'
import { renderPluginsListPage, PluginsListPageData, Plugin } from '../templates/pages/admin-plugins-list.template'
import { renderPluginSettingsPage, PluginSettingsPageData } from '../templates/pages/admin-plugin-settings.template'
import { PluginService } from '../services'
// TODO: authValidationService not yet migrated - commented out temporarily
// import { authValidationService } from '../services/auth-validation'
import type { Bindings, Variables } from '../app'

const adminPluginRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminPluginRoutes.use('*', requireAuth())

// Available plugins registry - plugins that can be installed
const AVAILABLE_PLUGINS = [
  {
    id: 'third-party-faq',
    name: 'faq-plugin',
    display_name: 'FAQ System',
    description: 'Frequently Asked Questions management system with categories, search, and custom styling',
    version: '2.0.0',
    author: 'Community Developer',
    category: 'content',
    icon: '❓',
    permissions: ['manage:faqs'],
    dependencies: [],
    is_core: false
  },
  {
    id: 'demo-login-prefill',
    name: 'demo-login-plugin',
    display_name: 'Demo Login Prefill',
    description: 'Prefills login form with demo credentials (admin@sonicjs.com/sonicjs!) for easy site demonstration',
    version: '1.0.0-beta.1',
    author: 'SonicJS',
    category: 'demo',
    icon: '🎯',
    permissions: [],
    dependencies: [],
    is_core: false
  },
  {
    id: 'database-tools',
    name: 'database-tools',
    display_name: 'Database Tools',
    description: 'Database management tools including truncate, backup, and validation',
    version: '1.0.0-beta.1',
    author: 'SonicJS Team',
    category: 'system',
    icon: '🗄️',
    permissions: ['manage:database', 'admin'],
    dependencies: [],
    is_core: false
  },
  {
    id: 'seed-data',
    name: 'seed-data',
    display_name: 'Seed Data',
    description: 'Generate realistic example users and content for testing and development',
    version: '1.0.0-beta.1',
    author: 'SonicJS Team',
    category: 'development',
    icon: '🌱',
    permissions: ['admin'],
    dependencies: [],
    is_core: false
  },
  {
    id: 'quill-editor',
    name: 'quill-editor',
    display_name: 'Quill Rich Text Editor',
    description: 'Quill WYSIWYG editor integration for rich text editing. Lightweight, modern editor with customizable toolbars and dark mode support.',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'editor',
    icon: '✍️',
    permissions: [],
    dependencies: [],
    is_core: true
  },
  {
    id: 'tinymce-plugin',
    name: 'tinymce-plugin',
    display_name: 'TinyMCE Rich Text Editor',
    description: 'Powerful WYSIWYG rich text editor for content creation. Provides a full-featured editor with formatting, media embedding, and customizable toolbars for richtext fields.',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'editor',
    icon: '📝',
    permissions: [],
    dependencies: [],
    is_core: false
  },
  {
    id: 'easy-mdx',
    name: 'easy-mdx',
    display_name: 'EasyMDE Markdown Editor',
    description: 'Lightweight markdown editor with live preview. Provides a simple and efficient editor with markdown support for richtext fields.',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'editor',
    icon: '📝',
    permissions: [],
    dependencies: [],
    is_core: false
  },
  {
    id: 'turnstile',
    name: 'turnstile-plugin',
    display_name: 'Cloudflare Turnstile',
    description: 'CAPTCHA-free bot protection for forms using Cloudflare Turnstile. Provides seamless spam prevention with configurable modes, themes, and pre-clearance options.',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'security',
    icon: '🛡️',
    permissions: [],
    dependencies: [],
    is_core: true
  },
  {
    id: 'ai-search',
    name: 'ai-search-plugin',
    display_name: 'AI Search',
    description: 'Advanced search with Cloudflare AI Search. Full-text search, semantic search, and advanced filtering across all content collections.',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'search',
    icon: '🔍',
    permissions: [],
    dependencies: [],
    is_core: true
  }
]

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

    // Skip plugins that have their own custom settings pages (not using component system)
    const pluginsWithCustomPages = ['ai-search']
    if (pluginsWithCustomPages.includes(pluginId)) {
      // Let the plugin's own route handle this
      return c.text('', 404) // Return 404 so Hono continues to next route
    }

    // Check authorization
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
    const enrichedSettings = plugin.settings || {}

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
      message: item.message,
      timestamp: item.timestamp,
      user: item.user_email
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

// Install plugin
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
    
    // Handle FAQ plugin installation
    if (body.name === 'faq-plugin') {
      const faqPlugin = await pluginService.installPlugin({
        id: 'third-party-faq',
        name: 'faq-plugin',
        display_name: 'FAQ System',
        description: 'Frequently Asked Questions management system with categories, search, and custom styling',
        version: '2.0.0',
        author: 'Community Developer',
        category: 'content',
        icon: '❓',
        permissions: ['manage:faqs'],
        dependencies: [],
        settings: {
          enableSearch: true,
          enableCategories: true,
          questionsPerPage: 10
        }
      })

      return c.json({ success: true, plugin: faqPlugin })
    }

    // Handle Demo Login plugin installation
    if (body.name === 'demo-login-plugin') {
      const demoPlugin = await pluginService.installPlugin({
        id: 'demo-login-prefill',
        name: 'demo-login-plugin',
        display_name: 'Demo Login Prefill',
        description: 'Prefills login form with demo credentials (admin@sonicjs.com/sonicjs!) for easy site demonstration',
        version: '1.0.0-beta.1',
        author: 'SonicJS',
        category: 'demo',
        icon: '🎯',
        permissions: [],
        dependencies: [],
        settings: {
          enableNotice: true,
          demoEmail: 'admin@sonicjs.com',
          demoPassword: 'sonicjs!'
        }
      })

      return c.json({ success: true, plugin: demoPlugin })
    }

    // Handle core Authentication System plugin installation
    if (body.name === 'core-auth') {
      const authPlugin = await pluginService.installPlugin({
        id: 'core-auth',
        name: 'core-auth',
        display_name: 'Authentication System',
        description: 'Core authentication and user management system',
        version: '1.0.0-beta.1',
        author: 'SonicJS Team',
        category: 'security',
        icon: '🔐',
        permissions: ['manage:users', 'manage:roles', 'manage:permissions'],
        dependencies: [],
        is_core: true,
        settings: {}
      })

      return c.json({ success: true, plugin: authPlugin })
    }

    // Handle core Media Manager plugin installation
    if (body.name === 'core-media') {
      const mediaPlugin = await pluginService.installPlugin({
        id: 'core-media',
        name: 'core-media',
        display_name: 'Media Manager',
        description: 'Core media upload and management system',
        version: '1.0.0-beta.1',
        author: 'SonicJS Team',
        category: 'media',
        icon: '📸',
        permissions: ['manage:media', 'upload:files'],
        dependencies: [],
        is_core: true,
        settings: {}
      })

      return c.json({ success: true, plugin: mediaPlugin })
    }

    // Handle core Workflow Engine plugin installation
    if (body.name === 'core-workflow') {
      const workflowPlugin = await pluginService.installPlugin({
        id: 'core-workflow',
        name: 'core-workflow',
        display_name: 'Workflow Engine',
        description: 'Content workflow and approval system',
        version: '1.0.0-beta.1',
        author: 'SonicJS Team',
        category: 'content',
        icon: '🔄',
        permissions: ['manage:workflows', 'approve:content'],
        dependencies: [],
        is_core: true,
        settings: {}
      })

      return c.json({ success: true, plugin: workflowPlugin })
    }

    // Handle Database Tools plugin installation
    if (body.name === 'database-tools') {
      const databaseToolsPlugin = await pluginService.installPlugin({
        id: 'database-tools',
        name: 'database-tools',
        display_name: 'Database Tools',
        description: 'Database management tools including truncate, backup, and validation',
        version: '1.0.0-beta.1',
        author: 'SonicJS Team',
        category: 'system',
        icon: '🗄️',
        permissions: ['manage:database', 'admin'],
        dependencies: [],
        is_core: false,
        settings: {
          enableTruncate: true,
          enableBackup: true,
          enableValidation: true,
          requireConfirmation: true
        }
      })

      return c.json({ success: true, plugin: databaseToolsPlugin })
    }

    // Handle Seed Data plugin installation
    if (body.name === 'seed-data') {
      const seedDataPlugin = await pluginService.installPlugin({
        id: 'seed-data',
        name: 'seed-data',
        display_name: 'Seed Data',
        description: 'Generate realistic example users and content for testing and development',
        version: '1.0.0-beta.1',
        author: 'SonicJS Team',
        category: 'development',
        icon: '🌱',
        permissions: ['admin'],
        dependencies: [],
        is_core: false,
        settings: {
          userCount: 20,
          contentCount: 200,
          defaultPassword: 'password123'
        }
      })

      return c.json({ success: true, plugin: seedDataPlugin })
    }

    // Handle Quill Editor plugin installation
    if (body.name === 'quill-editor') {
      const quillPlugin = await pluginService.installPlugin({
        id: 'quill-editor',
        name: 'quill-editor',
        display_name: 'Quill Rich Text Editor',
        description: 'Quill WYSIWYG editor integration for rich text editing. Lightweight, modern editor with customizable toolbars and dark mode support.',
        version: '1.0.0',
        author: 'SonicJS Team',
        category: 'editor',
        icon: '✍️',
        permissions: [],
        dependencies: [],
        is_core: true,
        settings: {
          version: '2.0.2',
          defaultHeight: 300,
          defaultToolbar: 'full',
          theme: 'snow'
        }
      })

      return c.json({ success: true, plugin: quillPlugin })
    }

    // Handle TinyMCE plugin installation
    if (body.name === 'tinymce-plugin') {
      const tinymcePlugin = await pluginService.installPlugin({
        id: 'tinymce-plugin',
        name: 'tinymce-plugin',
        display_name: 'TinyMCE Rich Text Editor',
        description: 'Powerful WYSIWYG rich text editor for content creation. Provides a full-featured editor with formatting, media embedding, and customizable toolbars for richtext fields.',
        version: '1.0.0',
        author: 'SonicJS Team',
        category: 'editor',
        icon: '📝',
        permissions: [],
        dependencies: [],
        is_core: false,
        settings: {
          apiKey: 'no-api-key',
          defaultHeight: 300,
          defaultToolbar: 'full',
          skin: 'oxide-dark'
        }
      })

      return c.json({ success: true, plugin: tinymcePlugin })
    }

    // Handle Easy MDX plugin installation
    if (body.name === 'easy-mdx') {
      const easyMdxPlugin = await pluginService.installPlugin({
        id: 'easy-mdx',
        name: 'easy-mdx',
        display_name: 'EasyMDE Markdown Editor',
        description: 'Lightweight markdown editor with live preview. Provides a simple and efficient editor with markdown support for richtext fields.',
        version: '1.0.0',
        author: 'SonicJS Team',
        category: 'editor',
        icon: '📝',
        permissions: [],
        dependencies: [],
        is_core: false,
        settings: {
          defaultHeight: 400,
          theme: 'dark',
          toolbar: 'full',
          placeholder: 'Start writing your content...'
        }
      })

      return c.json({ success: true, plugin: easyMdxPlugin })
    }

    // Handle AI Search plugin installation
    if (body.name === 'ai-search-plugin' || body.name === 'ai-search') {
      const defaultSettings = {
        enabled: true,
        ai_mode_enabled: true,
        selected_collections: [],
        dismissed_collections: [],
        autocomplete_enabled: true,
        cache_duration: 1,
        results_limit: 20,
        index_media: false,
      }

      const aiSearchPlugin = await pluginService.installPlugin({
        id: 'ai-search',
        name: 'ai-search-plugin',
        display_name: 'AI Search',
        description: 'Advanced search with Cloudflare AI Search. Full-text search, semantic search, and advanced filtering across all content collections.',
        version: '1.0.0',
        author: 'SonicJS Team',
        category: 'search',
        icon: '🔍',
        permissions: [],
        dependencies: [],
        is_core: true,
        settings: defaultSettings
      })

      return c.json({ success: true, plugin: aiSearchPlugin })
    }

    // Handle Turnstile plugin installation
    if (body.name === 'turnstile-plugin') {
      const turnstilePlugin = await pluginService.installPlugin({
        id: 'turnstile',
        name: 'turnstile-plugin',
        display_name: 'Cloudflare Turnstile',
        description: 'CAPTCHA-free bot protection for forms using Cloudflare Turnstile. Provides seamless spam prevention with configurable modes, themes, and pre-clearance options.',
        version: '1.0.0',
        author: 'SonicJS Team',
        category: 'security',
        icon: '🛡️',
        permissions: [],
        dependencies: [],
        is_core: true,
        settings: {
          siteKey: '',
          secretKey: '',
          theme: 'auto',
          size: 'normal',
          mode: 'managed',
          appearance: 'always',
          preClearanceEnabled: false,
          preClearanceLevel: 'managed',
          enabled: false
        }
      })

      return c.json({ success: true, plugin: turnstilePlugin })
    }

    return c.json({ error: 'Plugin not found in registry' }, 404)
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

    // TODO: Clear auth validation cache if updating core-auth plugin
    // Commented out until authValidationService is migrated
    // if (pluginId === 'core-auth') {
    //   authValidationService.clearCache()
    //   console.log('[AuthSettings] Cache cleared after updating authentication settings')
    // }

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

export { adminPluginRoutes }
