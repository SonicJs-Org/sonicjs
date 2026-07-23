/**
 * API Docs — admin routes (/admin/plugins/api-docs)
 *
 * P1 scaffold: the page shell + the security gates. The Endpoints and
 * Interactive tabs (and the generated OpenAPI spec route) land in P2/P3.
 */
import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
// Imported from its defining module rather than the middleware barrel, for
// symmetry with invalidatePluginStatusCache — its cache companion, which the
// barrel does NOT re-export. In a production bundle this resolves to the same
// module singleton as the barrel export, so it's purely a sourcing choice; it
// also keeps the status cache and its invalidator coherent under the test
// runner's module resolution.
import { isPluginActive } from '../../../../middleware/plugin-middleware'
import { buildRouteList, getAppInstance } from '../../../../services'
import { getCoreVersion } from '../../../../utils/version'
import type { Bindings, Variables } from '../../../../app'
import { renderApiDocsPage } from '../components/api-docs-page'
import { buildApiDocsOpenApiSpec } from '../services/openapi-builder'

/** Plugin id — must match manifest.json `id` and the plugins table slug. */
export const API_DOCS_PLUGIN_ID = 'api-docs'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Defense-in-depth: `/admin/*` is already globally gated by requireAuth +
// requireRbac('portal','access'), but assert auth locally so the sub-app is
// safe even if remounted, and so the intent is explicit at the plugin boundary.
adminRoutes.use('*', requireAuth())

// Deactivate→404 gate.
//
// SonicJS mounts plugin routes unconditionally and only hides the sidebar entry
// when a plugin is deactivated (middleware/plugin-menu.ts) — the routes stay
// reachable by direct URL. So we gate here explicitly, returning 404 (not 403)
// to match the v3 "deactivated plugin looks absent" intent.
//
// Use the BOOLEAN isPluginActive(db, id) — NOT requireActivePlugin(), which
// throws and the global onError turns into a 500.
//
// Caveat: isPluginActive caches plugin status per-isolate with no TTL, and
// cache invalidation only clears the isolate that performed the toggle. So this
// gate is best-effort across warm isolates — a toggle takes effect on new
// isolates immediately and on a warm one when it recycles. Acceptable for a
// read-only docs surface.
adminRoutes.use('*', async (c, next) => {
  if (!(await isPluginActive(c.env.DB, API_DOCS_PLUGIN_ID))) {
    return c.notFound()
  }
  return next()
})

adminRoutes.get('/', (c) => {
  const user = c.get('user')
  const endpoints = buildRouteList(getAppInstance())
  return c.html(
    renderApiDocsPage({
      endpoints,
      user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
      version: c.get('appVersion'),
      dynamicMenuItems: c.get('pluginMenuItems'),
    }),
  )
})

/**
 * GET /admin/plugins/api-docs/openapi.json
 *
 * The live OpenAPI 3.0 spec, auto-generated from the running route table. Mounted
 * on THIS sub-app deliberately, so it inherits the requireAuth + deactivate→404
 * gates above (and the global /admin/* RBAC gate) — the spec enumerates the full
 * admin surface, so it must never be reachable unauthenticated (cf. the core
 * `GET /api` auth-gating decision). It also feeds the Interactive (Scalar) tab.
 */
adminRoutes.get('/openapi.json', (c) => {
  const url = new URL(c.req.url)
  const serverUrl = `${url.protocol}//${url.host}`
  const routes = buildRouteList(getAppInstance())
  const spec = buildApiDocsOpenApiSpec(routes, serverUrl, getCoreVersion())
  return c.json(spec)
})

export { adminRoutes as apiDocsAdminRoutes }
