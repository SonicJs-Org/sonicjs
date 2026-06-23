/**
 * SonicJS Stats Collector
 *
 * Self-hosted telemetry collection using SonicJS
 * Tracks anonymous installation metrics
 */

import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import collections
import installsCollection from './collections/installs.collection'
import eventsCollection from './collections/events.collection'

// Import plugins
import { statsDashboardPlugin } from './plugins/stats-dashboard'

// Register collections
registerCollections([
  installsCollection,
  eventsCollection,
])

// Application configuration
const config: SonicJSConfig = {
  collections: {
    autoSync: true
  },
  plugins: {
    autoLoad: false,
    register: [statsDashboardPlugin],
  }
}

// Create and export the application
export default createSonicJSApp(config)
