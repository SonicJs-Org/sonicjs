/**
 * My SonicJS Application
 *
 * Entry point for your SonicJS headless CMS application.
 * Exports both `fetch` (HTTP) and `scheduled` (cron) so the Worker handles both
 * cold-start paths. The `boot` function from `createSonicJSApp` ensures a
 * cron-first cold isolate still gets the hook bus wired before dispatching.
 */

import { createSonicJSApp, registerCollections, createScheduledHandler, getHookSystem } from '@sonicjs-cms/core'
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
    register: [contactFormPlugin],
    disableAll: false,
  }
}

// Create the core application (includes boot() for cron cold-start wiring)
const app = createSonicJSApp(config)

// Export both HTTP fetch and the cron scheduled handler.
// The scheduled handler calls app.boot(env) before dispatching so a
// cron-first cold isolate gets the same plugin wiring as an HTTP request.
export default {
  fetch: app.fetch,
  scheduled: createScheduledHandler({
    // Pass the same plugins the HTTP app uses so cron handlers see the same state.
    plugins: () => config.plugins?.register ?? [],
    getHooks: getHookSystem,
    boot: app.boot,
  }),
}
