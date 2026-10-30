/**
 * My SonicJS Application
 *
 * Entry point for your SonicJS headless CMS application.
 * The example plugin is included to demonstrate how plugins work —
 * feel free to remove it or use it as a starting point for your own.
 */

import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import your collection configurations
// Add new collections here after creating them in src/collections/
import blogPostsCollection from './collections/blog-posts.collection'

// Example plugin — demonstrates routes, admin UI, collections, hooks, and settings.
// Remove this import (and the register entry below) when you no longer need it.
import { examplePlugin } from './plugins/example'
import { moodsCollection } from './plugins/example/collections/moods.collection'

// Register collections BEFORE creating the app.
registerCollections([
  blogPostsCollection,
  moodsCollection,
  // Add more collections here as you create them
])

// Application configuration
const config: SonicJSConfig = {
  plugins: {
    register: [
      examplePlugin,
      // Add your own plugins here
    ],
  },
}

// Create and export the application
export default createSonicJSApp(config)
