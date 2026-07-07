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
  SONICJS_VERSION,
  collectCronSchedules,
  createScheduledHandler,
  createSonicJSApp,
  emailReconciliationPlugin,
  getHookSystem,
  mediaPlugin,
  registerCollections,
  renderLoginPage,
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
const demoPlugins = [mediaPlugin, demoLoginPlugin, demoSeedPlugin] as unknown as NonNullable<NonNullable<SonicJSConfig['plugins']>['register']>;

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

// Browser cache TTL (max-age) and edge/shared cache TTL (s-maxage). s-maxage
// bounds how long Cloudflare's edge serves a stale copy after a login-template
// deploy — Cloudflare honors s-maxage for edge retention independent of the
// zone's Browser-Cache-TTL override — so no manual cache purge is needed on
// deploy. High enough that misses stay rare; low enough that a template change
// propagates within ~10 min.
const LOGIN_BROWSER_TTL = 300; // 5 min (browser)
const LOGIN_EDGE_TTL = 600; // 10 min (Cloudflare edge)

// Pre-render the login form ONCE per isolate. The no-query login page is fully
// static for the demo: `demoLoginActive` is always true (the demo-login plugin
// is re-asserted active on every reseed) and `version` is a build-time constant.
// Rendering here — instead of letting the request flow through the Hono app —
// bypasses bootstrap (8+ cold D1 queries), plugin wiring, the Better Auth
// session lookup, and the handler's own demo-login D1 query. That serial chain
// is what makes the cold first load ~10s; a static string return is ~0ms.
//
// SECURITY (reviewed): this constant is built from renderLoginPage alone, so it
// can NEVER carry a Set-Cookie header. We must never feed app.fetch's live
// response into the cache — an authenticated admin hitting /auth/login can make
// Better Auth emit `Set-Cookie: session_token`, and caching that under a shared,
// URL-keyed entry with `Cache-Control: public` is a cross-user session-replay
// hazard. Only this cookie-free static constant is ever cached/served here.
const LOGIN_HTML = renderLoginPage({ version: SONICJS_VERSION }, true);

/** Immutable headers for the static login response — public-cacheable, no cookies. */
function loginHeaders(): Headers {
  const h = new Headers();
  h.set('Content-Type', 'text/html; charset=UTF-8');
  h.set('Cache-Control', `public, max-age=${LOGIN_BROWSER_TTL}, s-maxage=${LOGIN_EDGE_TTL}`);
  h.set('X-Content-Type-Options', 'nosniff');
  return h;
}

/**
 * Worker entry. Short-circuits GET/HEAD /auth/login (no query string) with a
 * static, edge-cacheable login form — no D1, no bootstrap, no Set-Cookie.
 * Every other request (including ?error=/?message=/?redirect= login variants,
 * which need dynamic content) flows through the full SonicJS app.
 */
async function fetch(
  request: Request,
  env: Record<string, unknown>,
  ctx: ExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  const isStaticLogin =
    (request.method === 'GET' || request.method === 'HEAD') &&
    url.pathname === '/auth/login' &&
    url.search === '';

  if (!isStaticLogin) return app.fetch(request, env, ctx);

  // Edge cache: serve a previously-stored copy without re-rendering. Safe to
  // share across all visitors — the entry is the cookie-free static form.
  // The cache key is version-scoped (`__v`) so a new deploy uses a fresh key and
  // never serves a stale login template; old entries age out via max-age. This
  // synthetic URL is only ever a cache key, never a real route.
  const cache = caches.default;
  const cacheKey = new Request(
    `${url.origin}/auth/login?__v=${encodeURIComponent(SONICJS_VERSION)}`,
    { method: 'GET' },
  );
  const cached = await cache.match(cacheKey);
  if (cached) {
    return request.method === 'HEAD'
      ? new Response(null, { status: cached.status, headers: cached.headers })
      : cached;
  }

  const stored = new Response(LOGIN_HTML, { status: 200, headers: loginHeaders() });
  ctx.waitUntil(cache.put(cacheKey, stored.clone()));

  return request.method === 'HEAD'
    ? new Response(null, { status: 200, headers: loginHeaders() })
    : stored;
}

export default {
  fetch,
  scheduled: createScheduledHandler({
    plugins: allCronPlugins,
    getHooks: getHookSystem,
    boot: app.boot,
  }),
};
