/**
 * My SonicJS Application
 *
 * Entry point for your SonicJS headless CMS application
 */

import { Hono } from 'hono'
import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import custom collections
import blogPostsCollection from './collections/blog-posts.collection'
import pageBlocksCollection from './collections/page-blocks.collection'
import contactMessagesCollection from './collections/contact-messages.collection'

// Import plugins (manual mounting until auto-loading is implemented)
import contactFormPlugin from './plugins/contact-form/index'
import redirectManagementPlugin from './plugins/redirect-management/index'
import { createRedirectMiddleware } from './plugins/redirect-management/middleware/redirect'
import { createRedirectAdminRoutes } from './plugins/redirect-management/routes/admin'

// Register all custom collections
registerCollections([
  blogPostsCollection,
  pageBlocksCollection,
  contactMessagesCollection
])

// Application configuration
const config: SonicJSConfig = {
  collections: {
    autoSync: true
  },
  plugins: {
    directory: './src/plugins',
    autoLoad: false,  // Set to true to auto-load custom plugins
    disableAll: false,  // Enable plugins
    enabled: ['email', 'contact-form', 'redirect-management']  // Enable specific plugins
  }
}

// Create the core application
const coreApp = createSonicJSApp(config)

// Create main app and mount plugin routes manually
// (Plugin auto-mounting not yet implemented in core)
const app = new Hono()

// Mount redirect middleware early (intercepts before routing)
app.use('*', createRedirectMiddleware())

// Mount plugin routes
if (contactFormPlugin.routes) {
  for (const route of contactFormPlugin.routes) {
    app.route(route.path, route.handler)
  }
}

// Mount redirect management admin routes
const redirectAdminRoutes = createRedirectAdminRoutes()
app.route('/admin/redirects', redirectAdminRoutes)

// Mount core app last (catch-all)
app.route('/', coreApp)

export default app
