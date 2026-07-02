/**
 * SonicJS Demo App — demo.sonicjs.com
 *
 * Public demo site. Always runs the latest `main` (built from the workspace core)
 * and resets its data on every promotion + every 2 hours (see demoSeedPlugin).
 *
 * Phase 1: workspace scaffold — boots core, exports fetch + scheduled.
 * Phases 2/3 wire demo collections, the demo-login prefill plugin, and the
 * demo-seed (reseed route + 2h cron) plugin.
 */

import type { SonicJSConfig } from '@sonicjs-cms/core';
import {
  collectCronSchedules,
  createScheduledHandler,
  createSonicJSApp,
  emailReconciliationPlugin,
  getHookSystem,
  registerCollections,
} from '@sonicjs-cms/core';

// Code-defined demo collections.
import blogPostsCollection from './collections/blog-posts.collection';
import pagesCollection from './collections/pages.collection';
import testimonialsCollection from './collections/testimonials.collection';
import faqsCollection from './collections/faqs.collection';

// Demo plugins.
import { demoLoginPlugin } from './plugins/demo-login';
import { demoSeedPlugin } from './plugins/demo-seed';

// Register collections so they appear in the admin UI and auto-register a
// document_type at bootstrap.
registerCollections([
  blogPostsCollection,
  pagesCollection,
  testimonialsCollection,
  faqsCollection,
]);

// definePlugin() returns DefinedPlugin; SonicJSConfig.plugins.register is typed
// Plugin[]. The two diverge only in route element typing — a known core type-def
// gap (my-sonicjs-app hits the same mismatch). DefinedPlugin satisfies the
// runtime contract, so cast here to keep this app's type-check clean.
const demoPlugins = [demoLoginPlugin, demoSeedPlugin] as unknown as NonNullable<NonNullable<SonicJSConfig['plugins']>['register']>;

const config: SonicJSConfig = {
  plugins: {
    register: demoPlugins,
    disableAll: false,
  },
};

const app = createSonicJSApp(config);

// All plugins that declare crons, for the scheduled handler.
// Core crons (emailReconciliationPlugin) are wired automatically by createSonicJSApp.
const allCronPlugins = [emailReconciliationPlugin, ...(config.plugins?.register ?? [])];

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
