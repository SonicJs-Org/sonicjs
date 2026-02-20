/**
 * Main Application Factory
 *
 * Creates a configured SonicJS application with all core functionality
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'
import {
  apiRoutes,
  apiMediaRoutes,
  apiSystemRoutes,
  adminApiRoutes,
  authRoutes,
  testCleanupRoutes,
  adminContentRoutes,
  adminUsersRoutes,
  adminMediaRoutes,
  adminPluginRoutes,
  adminLogsRoutes,
  adminDashboardRoutes,
  adminCollectionsRoutes,
  adminSettingsRoutes,
  adminFormsRoutes,
  publicFormsRoutes,
  adminApiReferenceRoutes
} from './routes'
import { getCoreVersion } from './utils/version'
import { bootstrapMiddleware } from './middleware/bootstrap'
import { metricsMiddleware } from './middleware/metrics'
import { csrfProtection } from './middleware/csrf'
import { securityHeadersMiddleware } from './middleware/security-headers'
import { createDatabaseToolsAdminRoutes } from './plugins/core-plugins/database-tools-plugin/admin-routes'
import { createSeedDataAdminRoutes } from './plugins/core-plugins/seed-data-plugin/admin-routes'
import { emailPlugin } from './plugins/core-plugins/email-plugin'
import { otpLoginPlugin } from './plugins/core-plugins/otp-login-plugin'
import { aiSearchPlugin } from './plugins/core-plugins/ai-search-plugin'
import { createMagicLinkAuthPlugin } from './plugins/available/magic-link-auth'
import cachePlugin from './plugins/cache'
import { faviconSvg } from './assets/favicon'

// ============================================================================
// Type Definitions
// ============================================================================

export interface Bindings {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  ASSETS: Fetcher
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  IMAGES_ACCOUNT_ID?: string
  IMAGES_API_TOKEN?: string
  ENVIRONMENT?: string
  BUCKET_NAME?: string
  GOOGLE_MAPS_API_KEY?: string
}

export interface Variables {
  user?: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
  requestId?: string
  startTime?: number
  appVersion?: string
  csrfToken?: string
}

export interface SonicJSConfig {
  // Collections configuration
  collections?: {
    directory?: string
    autoSync?: boolean
  }

  // Plugins configuration
  plugins?: {
    directory?: string
    autoLoad?: boolean
    disableAll?: boolean  // Disable all plugins including core plugins
  }

  // Custom routes
  routes?: Array<{
    path: string
    handler: Hono
  }>

  // Custom middleware
  middleware?: {
    beforeAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>
    afterAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>
  }

  // App metadata
  version?: string
  name?: string
}

export type SonicJSApp = Hono<{ Bindings: Bindings; Variables: Variables }>

// ============================================================================
// Application Factory
// ============================================================================

/**
 * Create a SonicJS application with core functionality
 *
 * @param config - Application configuration
 * @returns Configured Hono application
 *
 * @example
 * ```typescript
 * import { createSonicJSApp } from '@sonicjs-cms/core'
 *
 * const app = createSonicJSApp({
 *   collections: {
 *     directory: './src/collections',
 *     autoSync: true
 *   },
 *   plugins: {
 *     directory: './src/plugins',
 *     autoLoad: true
 *   }
 * })
 *
 * export default app
 * ```
 */
export function createSonicJSApp(config: SonicJSConfig = {}): SonicJSApp {
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  // Set app metadata
  const appVersion = config.version || getCoreVersion()
  const appName = config.name || 'SonicJS AI'

  // App version middleware
  app.use('*', async (c, next) => {
    c.set('appVersion', appVersion)
    await next()
  })

  // Metrics middleware - track all requests for real-time analytics
  app.use('*', metricsMiddleware())

  // Bootstrap middleware - runs migrations, syncs collections, and initializes plugins
  app.use('*', bootstrapMiddleware(config))

  // Custom middleware - before auth
  if (config.middleware?.beforeAuth) {
    for (const middleware of config.middleware.beforeAuth) {
      app.use('*', middleware)
    }
  }

  // Logging middleware
  app.use('*', async (_c, next) => {
    // Logging logic here
    await next()
  })

  // Security middleware
  app.use('*', securityHeadersMiddleware())

  // CSRF protection middleware
  app.use('*', csrfProtection())

  // Custom middleware - after auth
  if (config.middleware?.afterAuth) {
    for (const middleware of config.middleware.afterAuth) {
      app.use('*', middleware)
    }
  }

  // Core routes
  // Routes are being imported incrementally from routes/*
  // Each route is tested and migrated one-by-one
  app.route('/api', apiRoutes)
  app.route('/api/media', apiMediaRoutes)
  app.route('/api/system', apiSystemRoutes)
  app.route('/admin/api', adminApiRoutes)
  app.route('/admin/dashboard', adminDashboardRoutes)
  app.route('/admin/collections', adminCollectionsRoutes)
  app.route('/admin/forms', adminFormsRoutes)
  app.route('/admin/settings', adminSettingsRoutes)
  app.route('/forms', publicFormsRoutes)
  app.route('/api/forms', publicFormsRoutes) // API endpoint for form submissions
  app.route('/admin/api-reference', adminApiReferenceRoutes)
  app.route('/admin/database-tools', createDatabaseToolsAdminRoutes())
  app.route('/admin/seed-data', createSeedDataAdminRoutes())
  app.route('/admin/content', adminContentRoutes)
  app.route('/admin/media', adminMediaRoutes)
  // Plugin routes - AI Search (MUST be registered BEFORE admin/plugins to avoid route conflict)
  // Register AI Search routes first so they take precedence over the generic /:id handler
  if (aiSearchPlugin.routes && aiSearchPlugin.routes.length > 0) {
    for (const route of aiSearchPlugin.routes) {
      app.route(route.path, route.handler)
    }
  }

  // Plugin routes - Cache (dashboard and management API)
  // Fixes GitHub Issue #461: Cache routes were not registered
  app.route('/admin/cache', cachePlugin.getRoutes())

  // Plugin routes - OTP Login (MUST be registered BEFORE admin/plugins to avoid route conflict)
  // Register OTP Login routes first so they take precedence over the generic /:id handler
  if (otpLoginPlugin.routes && otpLoginPlugin.routes.length > 0) {
    for (const route of otpLoginPlugin.routes) {
      app.route(route.path, route.handler as any)
    }
  }

  app.route('/admin/plugins', adminPluginRoutes)
  app.route('/admin/logs', adminLogsRoutes)
  app.route('/admin', adminUsersRoutes)
  app.route('/auth', authRoutes)

  // Test cleanup routes (only for development/test environments)
  app.route('/', testCleanupRoutes)

  // Plugin routes - Email
  if (emailPlugin.routes && emailPlugin.routes.length > 0) {
    for (const route of emailPlugin.routes) {
      app.route(route.path, route.handler as any)
    }
  }

  // Plugin routes - Magic Link Auth (passwordless authentication via email links)
  const magicLinkPlugin = createMagicLinkAuthPlugin()
  if (magicLinkPlugin.routes && magicLinkPlugin.routes.length > 0) {
    for (const route of magicLinkPlugin.routes) {
      app.route(route.path, route.handler as any)
    }
  }

  // Serve favicon
  app.get('/favicon.svg', (c) => {
    return new Response(faviconSvg, {
      headers: {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'public, max-age=31536000'
      }
    })
  })

  // Serve files from R2 storage (public file access)
  app.get('/files/*', async (c) => {
    try {
      // Extract the path from the URL pathname (everything after /files/)
      const url = new URL(c.req.url)
      const pathname = url.pathname

      // Remove the /files/ prefix to get the R2 object key
      const objectKey = pathname.replace(/^\/files\//, '')

      if (!objectKey) {
        return c.notFound()
      }

      // Get file from R2
      const object = await c.env.MEDIA_BUCKET.get(objectKey)

      if (!object) {
        return c.notFound()
      }

      // Set appropriate headers
      const headers = new Headers()
      object.httpMetadata?.contentType && headers.set('Content-Type', object.httpMetadata.contentType)
      object.httpMetadata?.contentDisposition && headers.set('Content-Disposition', object.httpMetadata.contentDisposition)
      headers.set('Cache-Control', 'public, max-age=31536000') // 1 year cache
      headers.set('Access-Control-Allow-Origin', '*') // Allow CORS for media files
      headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
      headers.set('Access-Control-Allow-Headers', 'Content-Type')

      return new Response(object.body as any, {
        headers
      })
    } catch (error) {
      console.error('Error serving file:', error)
      return c.notFound()
    }
  })

  // Custom routes - User-defined routes
  if (config.routes) {
    for (const route of config.routes) {
      app.route(route.path, route.handler)
    }
  }

  // Root redirect to login
  app.get('/', (c) => {
    return c.redirect('/auth/login')
  })

  // Health check
  app.get('/health', (c) => {
    return c.json({
      name: appName,
      version: appVersion,
      status: 'running',
      timestamp: new Date().toISOString()
    })
  })

  // 404 handler
  app.notFound((c) => {
    return c.json({ error: 'Not Found', status: 404 }, 404)
  })

  // Error handler
  app.onError((err, c) => {
    console.error(err)
    return c.json({ error: 'Internal Server Error', status: 500 }, 500)
  })

  return app
}

/**
 * Setup core middleware (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
export function setupCoreMiddleware(_app: SonicJSApp): void {
  console.warn('setupCoreMiddleware is deprecated. Use createSonicJSApp() instead.')
  // Backward compatibility implementation
}

/**
 * Setup core routes (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
export function setupCoreRoutes(_app: SonicJSApp): void {
  console.warn('setupCoreRoutes is deprecated. Use createSonicJSApp() instead.')
  // Backward compatibility implementation
}
