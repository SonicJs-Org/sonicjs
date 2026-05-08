/**
 * My SonicJS Application
 *
 * Entry point for your SonicJS headless CMS application
 */

import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import your collection configurations
// Add new collections here after creating them in src/collections/
import blogPostsCollection from './collections/blog-posts.collection'

// Import your plugins (each is the default export from PluginBuilder.build())
// Add new plugins here after creating them in src/plugins/
// import myPlugin from './plugins/my-plugin'

// Register collections BEFORE creating the app
// This ensures they are synced to the database on startup
registerCollections([
  blogPostsCollection,
  // Add more collections here as you create them
])

// Application configuration
const config: SonicJSConfig = {
  collections: {
    autoSync: true
  },
  plugins: {
    register: [
      // myPlugin,
    ]
  }
}

// Create and export the application
export default createSonicJSApp(config)
