/**
 * My SonicJS Application
 *
 * Entry point for your SonicJS headless CMS application
 */

import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import custom collections
import blogPostsCollection from './collections/blog-posts.collection'
import pageBlocksCollection from './collections/page-blocks.collection'
import contactMessagesCollection from './collections/contact-messages.collection'

// Import custom plugins
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
    register: [contactFormPlugin]
  }
}

export default createSonicJSApp(config)
