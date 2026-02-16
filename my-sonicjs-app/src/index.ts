/**
 * My SonicJS Application
 *
 * Entry point for your SonicJS headless CMS application
 */

import { Hono } from 'hono'
import { createSonicJSApp, registerCollections, ExperimentService } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import custom collections
import blogPostsCollection from './collections/blog-posts.collection'
import pageBlocksCollection from './collections/page-blocks.collection'
import contactMessagesCollection from './collections/contact-messages.collection'

// Import plugins (manual mounting until auto-loading is implemented)
import contactFormPlugin from './plugins/contact-form/index'

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
    enabled: ['email', 'contact-form']  // Enable specific plugins
  }
}

// Create the core application
const coreApp = createSonicJSApp(config)

// Create main app and mount plugin routes manually
// (Plugin auto-mounting not yet implemented in core)
const app = new Hono()

// Mount plugin routes
if (contactFormPlugin.routes) {
  for (const route of contactFormPlugin.routes) {
    app.route(route.path, route.handler)
  }
}

// Mount core app last (catch-all)
app.route('/', coreApp)

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: any, ctx: ExecutionContext) {
    const expService = new ExperimentService(env.DB, env.CACHE_KV, env.SEARCH_EXPERIMENTS)
    const active = await expService.getActiveExperiment()
    if (active) {
      const result = await expService.evaluateExperiment(active.id)
      if (result?.auto_completed) {
        console.log('[Cron] Experiment ' + active.id + ' auto-completed: winner=' + result.winner)
      }
    }
  }
}
