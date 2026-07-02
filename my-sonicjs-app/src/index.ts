/**
 * My SonicJS Application — v3 greenfield
 *
 * Exports both `fetch` (HTTP) and `scheduled` (cron) so the Worker handles both
 * cold-start paths. app.boot() ensures a cron-first cold isolate still gets the
 * hook bus wired before dispatching.
 */

import type { SonicJSConfig } from '@sonicjs-cms/core';
import {
  collectCronSchedules,
  createScheduledHandler,
  createSonicJSApp,
  emailReconciliationPlugin,
  getHookSystem,
  mcpPlugin,
  redirectPlugin,
  registerCollections,
} from '@sonicjs-cms/core';
import { examplePlugin } from './plugins/example';
import { moodsCollection } from './plugins/example/collections/moods.collection';

// User profile model — uncomment defineUserProfile() in this file to add custom fields
import './user-profile.model';

// Import code-defined collections
import { siteSettingsCollection } from '@sonicjs-cms/core';
import blogPostsCollection from './collections/blog-posts.collection';
import e2eTestCollection from './collections/e2e-test.collection';

// Register collections so they appear in admin UI
registerCollections([siteSettingsCollection, blogPostsCollection, e2eTestCollection, moodsCollection]);

const config: SonicJSConfig = {
  plugins: {
    // Add plugins to this array to activate them. Each plugin's register()
    // runs synchronously at startup; onBoot() runs async on first request.
    register: [redirectPlugin, examplePlugin, mcpPlugin()],
    disableAll: false,
  },
};

// Create the core application (includes boot() for cron cold-start wiring)
const app = createSonicJSApp(config);

// All plugins that declare crons, for the scheduled handler.
// Core crons (emailReconciliationPlugin) are wired automatically by createSonicJSApp.
const allCronPlugins = [emailReconciliationPlugin, ...(config.plugins?.register ?? [])];

// Log declared schedules at startup so wrangler.toml can be kept in sync.
const schedules = collectCronSchedules(allCronPlugins);
if (schedules.length > 0) {
  console.log('[cron] Declared schedules:', schedules.join(', '));
}

export default {
  fetch: app.fetch,
  scheduled: createScheduledHandler({
    plugins: allCronPlugins,
    getHooks: getHookSystem,
    boot: app.boot,
  }),
};
