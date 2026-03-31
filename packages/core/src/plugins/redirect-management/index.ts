import { PluginBuilder } from '../sdk/plugin-builder'
import type { Plugin, PluginContext } from '../types'
import manifest from './manifest.json'
import { RedirectService } from './services/redirect'
import { createRedirectAdminRoutes } from './routes/admin'
import { createRedirectApiRoutes } from './routes/api'

// Export middleware for direct mounting in app
export { createRedirectMiddleware, invalidateRedirectCache, warmRedirectCache } from './middleware/redirect'

// Export admin routes for mounting
export { createRedirectAdminRoutes } from './routes/admin'

// Export API routes for mounting
export { createRedirectApiRoutes } from './routes/api'

export function createRedirectPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: manifest.id,
    version: manifest.version,
    description: manifest.description
  })

  builder.metadata({
    author: { name: manifest.author },
    license: manifest.license,
    compatibility: '^2.0.0'
  })

  // Admin routes
  builder.addRoute('/admin/redirects', createRedirectAdminRoutes(), {
    description: 'Redirect management admin routes',
    requiresAuth: true,
    priority: 100
  })

  // API routes
  builder.addRoute('/api/redirects', createRedirectApiRoutes(), {
    description: 'Redirect management REST API',
    requiresAuth: false,  // API handles its own auth via Bearer tokens
    priority: 100
  })

  // Add admin page
  builder.addAdminPage(
    '/redirect-management/settings',
    'Redirect Management Settings',
    'RedirectManagementSettings',
    {
      description: 'Configure redirect settings and manage URL redirects',
      icon: 'arrow-right',
      permissions: ['admin', 'redirect.manage']
    }
  )

  // Add menu item
  builder.addMenuItem('Redirects', '/admin/redirects', {
    icon: 'arrow-right',
    order: 85,
    permissions: ['admin', 'redirect.manage']
  })

  // Register service
  let redirectService: RedirectService | null = null

  builder.addService('redirectService', {
    implementation: RedirectService,
    description: 'Redirect management service for lifecycle and settings',
    singleton: true
  })

  // Lifecycle
  builder.lifecycle({
    install: async (context: PluginContext) => {
      redirectService = new RedirectService(context.db)
      await redirectService.install()
      console.log('Redirect Management plugin installed successfully')
    },
    activate: async (context: PluginContext) => {
      redirectService = new RedirectService(context.db)
      await redirectService.activate()
      console.log('Redirect Management plugin activated')
    },
    deactivate: async (context: PluginContext) => {
      if (redirectService) {
        await redirectService.deactivate()
        redirectService = null
      }
      console.log('Redirect Management plugin deactivated')
    },
    uninstall: async (context: PluginContext) => {
      if (redirectService) {
        await redirectService.uninstall()
        redirectService = null
      }
      console.log('Redirect Management plugin uninstalled')
    },
    configure: async (config: any) => {
      if (redirectService) {
        await redirectService.saveSettings(config)
      }
      console.log('Redirect Management plugin configured', config)
    }
  })

  return builder.build()
}

export default createRedirectPlugin()
