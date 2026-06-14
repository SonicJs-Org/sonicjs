/**
 * Main Application Factory
 *
 * Creates a configured SonicJS application with all core functionality
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'
import {
  apiRoutes,
  apiMediaRoutes,
  apiSystemRoutes,
  adminApiRoutes,
  authRoutes,
  testCleanupRoutes,
  adminContentRoutes,
  adminUsersRoutes,
  adminMediaRoutes,
  adminPluginRoutes,
  adminLogsRoutes,
  adminCollectionsRoutes,
  adminSettingsRoutes,
  adminApiReferenceRoutes,
  apiDocumentsRoutes,
  adminDocumentsRoutes,
  adminTestimonialsRoutes
} from './routes'
import { getCoreVersion } from './utils/version'
import { bootstrapMiddleware } from './middleware/bootstrap'
import { metricsMiddleware } from './middleware/metrics'
import { csrfProtection } from './middleware/csrf'
import { securityHeadersMiddleware } from './middleware/security-headers'
import { createDatabaseToolsAdminRoutes } from './plugins/core-plugins/database-tools-plugin/admin-routes'
import { createSeedDataAdminRoutes } from './plugins/core-plugins/seed-data-plugin/admin-routes'
import { emailPlugin } from './plugins/core-plugins/email-plugin'
import { emailReconciliationPlugin } from './plugins/core-plugins/email-reconciliation'
import { otpLoginPlugin } from './plugins/core-plugins/otp-login-plugin'
import { oauthProvidersPlugin } from './plugins/core-plugins/oauth-providers'
import { userProfilesPlugin } from './plugins/core-plugins/user-profiles'
import { aiSearchPlugin } from './plugins/core-plugins/ai-search-plugin'
import { securityAuditPlugin } from './plugins/core-plugins/security-audit-plugin'
import { securityAuditMiddleware } from './plugins/core-plugins/security-audit-plugin'
import { stripePlugin } from './plugins/core-plugins/stripe-plugin'
import { testimonialsPlugin } from './plugins/core-plugins/testimonials'
import { formsPlugin } from './plugins/core-plugins/forms-plugin'
import { requireAuth, requireRole, requireRbac } from './middleware/auth'
import { createAuth } from './auth/config'
import { adminRbacRoutes } from './routes/admin-rbac'
import { pluginMenuMiddleware } from './middleware/plugin-menu'
import { analyticsPlugin } from './plugins/core-plugins/analytics'
import { eventsApiRoutes } from './plugins/core-plugins/analytics/routes/api'
import { globalVariablesPlugin } from './plugins/core-plugins/global-variables-plugin'
import { shortcodesPlugin } from './plugins/core-plugins/shortcodes-plugin'
import { helloWorldPlugin } from './plugins/core-plugins/hello-world-plugin'
import { multiTenantPlugin } from './plugins/core-plugins/multi-tenant-plugin'
import { lexicalEditorPlugin } from './plugins/core-plugins/lexical-editor'
import { tenantMiddleware } from './middleware/tenant'
import { createMagicLinkAuthPlugin } from './plugins/available/magic-link-auth'
import cachePlugin from './plugins/cache'
import type { Plugin } from './plugins/types'
import { registerPluginRoutes } from './plugins/mount'
import { HookSystemImpl } from './plugins/hook-system'
import { setHookSystem } from './plugins/hooks/hook-system-singleton'
import { createPluginWirer } from './plugins/wire'
import { EmailService } from './services/email/email-service'
import { resolveEmailProvider, type BuiltInProviderName } from './services/email/resolve-provider'
import { loadDbEmailSettings, dbSettingsFrom } from './services/email/db-settings'
import { setEmailService, getEmailService, hasEmailService } from './services/email/email-service-singleton'
import type { EmailProvider } from './services/email/types'
import { faviconSvg } from './assets/favicon'
import { setAppInstance } from './services/route-metadata'
import { setPluginMenu } from './services/plugin-menu-singleton'
import { setPluginDefinitions } from './services/plugin-definition-registry'

// ============================================================================
// Type Definitions
// ============================================================================

export interface Bindings {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  ASSETS: Fetcher
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  IMAGES_ACCOUNT_ID?: string
  IMAGES_API_TOKEN?: string
  ENVIRONMENT?: string
  CORS_ORIGINS?: string
  JWT_SECRET?: string
  JWT_EXPIRES_IN?: string
  JWT_REFRESH_GRACE_SECONDS?: string
  BUCKET_NAME?: string
  GOOGLE_MAPS_API_KEY?: string
  BETTER_AUTH_SECRET?: string
  BETTER_AUTH_URL?: string
  GITHUB_CLIENT_ID?: string
  GITHUB_CLIENT_SECRET?: string
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
}

export interface Variables {
  user?: {
    userId: string
    email: string
    role: string
    isSuperAdmin?: boolean
    exp: number
    iat: number
  }
  session?: { id: string; userId: string; token: string; expiresAt: number; createdAt: number; updatedAt: number }
  rbacPerms?: string[]
  requestId?: string
  startTime?: number
  appVersion?: string
  csrfToken?: string
  pluginMenuItems?: Array<{ label: string; path: string; icon: string }>
  /**
   * The plugin hook system attached to the request. Set by bootstrapMiddleware
   * BEFORE any heavy bootstrap work runs, so anything that emits a hook during
   * bootstrap (cron cold starts, RBAC seed, document-type registration) sees a
   * live bus instead of a no-op.
   */
  hookSystem?: import('./plugins/hooks/typed-hooks').HookSystemLike
  /** Tenant slug resolved per request by tenantMiddleware ('default' when single-tenant). */
  tenantId?: string
  /** The authed user's role IN the resolved tenant (per-tenant RBAC); global role for 'default'. */
  tenantRole?: string
}

export interface SonicJSConfig {
  // Collections configuration
  collections?: {
    directory?: string
    autoSync?: boolean
  }

  // Plugins configuration
  plugins?: {
    /**
     * @deprecated No-op. Cloudflare Workers has no runtime filesystem, so a
     * plugin directory cannot be scanned at runtime. Pass plugins explicitly via
     * `register` instead.
     */
    directory?: string
    /**
     * @deprecated No-op. Filesystem autoload is not supported on Workers. Pass
     * plugins explicitly via `register` instead.
     */
    autoLoad?: boolean
    /**
     * User-supplied plugins to mount. Each plugin's declarative `routes[]` and/or
     * synchronous `register(app)` hook is mounted into the app, before the
     * `/admin` catch-all so plugin admin pages are not shadowed.
     *
     * @example
     * createSonicJSApp({ plugins: { register: [contactFormPlugin] } })
     */
    register?: Plugin[]
    /**
     * Disable ALL plugins — core AND user. When true, no plugin routes are
     * mounted and plugin bootstrap (DB seeding) is skipped. Use this to run a
     * bare core app.
     */
    disableAll?: boolean
  }

  /**
   * Email configuration. Controls the app-wide EmailService that backs password
   * reset, magic-link, OTP, and any plugin that declares `email:send`.
   *
   * Bring your own provider, name a built-in, or let env auto-detect:
   * - `provider`: a custom `EmailProvider` instance (highest precedence).
   * - `providerName`: `'resend' | 'sendgrid' | 'console'`, credentialed from env.
   * - neither: auto-detect from env (RESEND_API_KEY, then SENDGRID_API_KEY),
   *   falling back to the console provider (logs instead of delivering).
   */
  email?: {
    provider?: EmailProvider
    providerName?: BuiltInProviderName
    /** Default from-address. Falls back to env DEFAULT_FROM_EMAIL, then a placeholder. */
    from?: string
  }

  // Custom routes
  routes?: Array<{
    path: string
    handler: Hono
  }>

  // Custom middleware
  middleware?: {
    beforeAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>
    afterAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>
  }

  // Better Auth extension hook. Allows app-level customization of the BA
  // instance (social providers, 2FA, org, etc.) without forking core config.
  auth?: { extendBetterAuth?: import('./auth/config').ExtendBetterAuth }

  // App metadata
  version?: string
  name?: string
}

/**
 * A function that boots the plugin infrastructure from env bindings.
 *
 * Runs email init + plugin wiring, both promise-memoized so calling it multiple
 * times per isolate is a no-op. Pass it to `createScheduledHandler` as the
 * `boot` option so cron-first cold isolates wire up before dispatching.
 */
export type BootIsolateFn = (env: Record<string, unknown>) => Promise<void>

/**
 * The app returned by {@link createSonicJSApp}. Extends the Hono app with a
 * `boot` function that wires plugins from env bindings, suitable for use in a
 * Worker `scheduled()` handler.
 */
export type SonicJSApp = Hono<{ Bindings: Bindings; Variables: Variables }> & {
  /** Boot the plugin infrastructure from Cloudflare env bindings (once-guarded). */
  readonly boot: BootIsolateFn
}

// ============================================================================
// Application Factory
// ============================================================================

/**
 * Create a SonicJS application with core functionality
 *
 * @param config - Application configuration
 * @returns Configured Hono application
 *
 * @example
 * ```typescript
 * import { createSonicJSApp } from '@sonicjs-cms/core'
 *
 * const app = createSonicJSApp({
 *   collections: {
 *     directory: './src/collections',
 *     autoSync: true
 *   },
 *   plugins: {
 *     directory: './src/plugins',
 *     autoLoad: true
 *   }
 * })
 *
 * export default app
 * ```
 */
export function createSonicJSApp(config: SonicJSConfig = {}): SonicJSApp {
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  // Set app metadata
  const appVersion = config.version || getCoreVersion()
  const appName = config.name || 'SonicJS AI'

  // ── Plugin hook system (two-phase boot) ───────────────────────────────────
  // Create the app's hook system and publish it as the process singleton so
  // env-independent callers (e.g. cron handlers) can reach it. Route mounting is
  // synchronous (below); hook subscriptions + plugin onBoot run lazily on the
  // first request via wireRegisteredPlugins (see plugins/wire.ts).
  const hookSystem = new HookSystemImpl()
  setHookSystem(hookSystem)

  // Core plugins, split by where their routes mount relative to the /admin
  // catch-all. Defined once and reused for both mounting and wiring so the two
  // never drift.
  // Not annotated as Plugin[]: the core plugins are typed against the built
  // `dist` declarations, which TS treats as a distinct identity from the `src`
  // Plugin. Both consumers (registerPluginRoutes, createPluginWirer) accept a
  // structural subset, so inference is the right call here.
  const magicLinkPlugin = createMagicLinkAuthPlugin()
  const corePluginsBeforeCatchAll = [
    securityAuditPlugin,
    aiSearchPlugin,
    oauthProvidersPlugin,
    userProfilesPlugin,
    otpLoginPlugin,
    analyticsPlugin,
    stripePlugin,
    // Previously declared via PluginBuilder.addRoute() but never mounted in
    // app.ts, so their routes 404'd in production. Fixes #758.
    globalVariablesPlugin,
    shortcodesPlugin,
    helloWorldPlugin,
    multiTenantPlugin,
    lexicalEditorPlugin,
  ]
  const corePluginsAfterCatchAll = [emailPlugin, magicLinkPlugin, emailReconciliationPlugin]

  // Lazy, once-guarded plugin wiring (the async half of two-phase boot). The
  // first request subscribes every plugin's hooks and runs their onBoot; later
  // requests await the same cached pass. Errors are isolated so wiring can never
  // break a request.
  const wirePlugins = createPluginWirer(
    () => [...corePluginsBeforeCatchAll, ...corePluginsAfterCatchAll, ...(config.plugins?.register ?? [])],
    // The capability-gated `ctx.cap.email` resolves to the app EmailService, which
    // is initialized (below) just before wiring on the first request.
    () => ({
      hooks: hookSystem,
      env: firstRequestEnv,
      providers: { email: () => getEmailService() },
    })
  )
  let firstRequestEnv: Record<string, unknown> | undefined

  // Initialize the app-wide EmailService from config + env on first request (env
  // bindings — provider keys, DB for email_log — are only available per-request).
  // Idempotent: built once per worker.
  // Provider precedence: explicit config > named built-in > env keys > admin-UI
  // DB settings (Resend, the historical configuration path) > console fallback.
  const initEmailService = async (env: Record<string, unknown> = {}) => {
    if (hasEmailService()) return
    let provider: EmailProvider
    let defaultFrom = config.email?.from
    let defaultReplyTo: string | undefined

    if (
      config.email?.provider ||
      config.email?.providerName ||
      env.RESEND_API_KEY ||
      env.SENDGRID_API_KEY
    ) {
      provider = resolveEmailProvider({
        provider: config.email?.provider,
        providerName: config.email?.providerName,
        env,
      })
    } else {
      // No config/env provider — fall back to admin-UI email settings if present.
      const dbSettings = await loadDbEmailSettings(env.DB as never)
      if (dbSettings?.apiKey) {
        // Route the admin-UI key through resolveEmailProvider (consistent provider
        // selection + degrade-to-console safety) instead of hardcoding Resend.
        provider = resolveEmailProvider({
          providerName: 'resend',
          env: { ...env, RESEND_API_KEY: dbSettings.apiKey },
        })
        defaultFrom = defaultFrom || dbSettingsFrom(dbSettings)
        defaultReplyTo = dbSettings.replyTo
      } else {
        provider = resolveEmailProvider({ env }) // → console fallback, with its warning
      }
    }

    defaultFrom = defaultFrom || (env.DEFAULT_FROM_EMAIL as string | undefined) || 'noreply@sonicjs.local'
    setEmailService(new EmailService({ provider, defaultFrom, defaultReplyTo, db: env.DB as never }))
  }

  // App version middleware
  app.use('*', async (c, next) => {
    c.set('appVersion', appVersion)
    await next()
  })

  // Metrics middleware - track all requests for real-time analytics
  app.use('*', metricsMiddleware())

  // Bootstrap middleware - runs migrations, syncs collections, and initializes plugins
  app.use('*', bootstrapMiddleware(config))

  // bootIsolate — extracted from the wiring middleware so it can be called from
  // both HTTP requests AND cron-first cold isolates (scheduled() handlers) that
  // never receive an HTTP request. Idempotent: initEmailService + wirePlugins are
  // both once-guarded per isolate.
  const boot: BootIsolateFn = async (env: Record<string, unknown>) => {
    if (config.plugins?.disableAll) return
    firstRequestEnv = env
    try {
      await initEmailService(env)
    } catch (err) {
      console.error('[email] init failed:', err)
    }
    try {
      await wirePlugins()
    } catch (err) {
      console.error('[plugins] wiring failed:', err)
    }
  }

  // Plugin wiring middleware - calls boot() on the first request so it runs after
  // bootstrap. Subsequent requests return the cached once-guard result instantly.
  app.use('*', async (c, next) => {
    await boot(c.env as unknown as Record<string, unknown>)
    return next()
  })

  // Custom middleware - before auth
  if (config.middleware?.beforeAuth) {
    for (const middleware of config.middleware.beforeAuth) {
      app.use('*', middleware)
    }
  }

  // Logging middleware
  app.use('*', async (_c, next) => {
    // Logging logic here
    await next()
  })

  // Security middleware
  app.use('*', securityHeadersMiddleware())

  // CSRF protection middleware
  app.use('*', csrfProtection())

  // Better Auth session middleware: populate c.set('user') (and 'session') from
  // the Better Auth session so existing requireAuth/requireRole and every
  // c.get('user') consumer keep working unchanged.
  app.use('*', async (c, next) => {
    try {
      const reqUrl = new URL(c.req.url)
      const requestBaseURL = `${reqUrl.protocol}//${reqUrl.host}`
      const auth = createAuth(c.env, config.auth?.extendBetterAuth, requestBaseURL)
      const session = await auth.api.getSession({ headers: c.req.raw.headers })
      if (session?.user) {
        const u = session.user as { id: string; email: string; role?: string; isSuperAdmin?: boolean }
        const s = session.session as {
          id: string; userId: string; token: string
          expiresAt: number | Date; createdAt: number | Date; updatedAt: number | Date
        }
        const ms = (v: number | Date) => (typeof v === 'number' ? v : new Date(v).getTime())
        c.set('user', {
          userId: u.id,
          email: u.email,
          role: u.role ?? 'viewer',
          isSuperAdmin: u.isSuperAdmin === true,
          exp: ms(s.expiresAt),
          iat: ms(s.createdAt),
        })
        c.set('session', {
          id: s.id,
          userId: s.userId,
          token: s.token,
          expiresAt: ms(s.expiresAt),
          createdAt: ms(s.createdAt),
          updatedAt: ms(s.updatedAt),
        })
      }
    } catch {
      // Not signed in / no valid session — leave c.get('user') undefined.
    }
    await next()
  })

  // Custom middleware - after auth
  if (config.middleware?.afterAuth) {
    for (const middleware of config.middleware.afterAuth) {
      app.use('*', middleware)
    }
  }

  // Tenant resolution: sets c.get('tenantId') for every request (API + admin). Short-circuits to
  // 'default' while the multi-tenant plugin is inactive, so single-tenant behavior is unchanged.
  // Runs after auth (admin switcher cookie) and before route handlers read the request context.
  app.use('*', tenantMiddleware())

  // Admin panel access control: require authentication and dynamic RBAC portal
  // access. Legacy `users.role` no longer decides who can enter /admin/*.
  app.use('/admin/*', requireAuth())
  app.use('/admin/*', requireRbac('portal', 'access'))

  // Plugin dynamic menu items for admin sidebar
  app.use('/admin/*', pluginMenuMiddleware())

  // RBAC-aware admin shell. Computes the signed-in user's effective permission
  // set once, then (1) redirects the dashboard landing to the first section the
  // user can actually reach when they lack `dashboard:read`, and (2) strips nav
  // items the user can't access from the rendered HTML *server-side* (via the
  // <!--nav:perm--> markers in the layout) so nothing inaccessible reaches the
  // browser. Routes remain independently gated by requireRbac.
  const NAV_LANDING: Array<{ path: string; perm: string }> = [
    { path: '/admin/content', perm: 'content:read' },
    { path: '/admin/media', perm: 'media:read' },
    { path: '/admin/collections', perm: 'content:read' },
    { path: '/admin/forms', perm: 'content:read' },
    { path: '/admin/users', perm: 'users:manage' },
    { path: '/admin/plugins', perm: 'plugins:manage' },
    { path: '/admin/settings', perm: 'settings:manage' },
    { path: '/admin/rbac', perm: 'rbac:manage' },
  ]
  app.use('/admin/*', async (c, next) => {
    const user = c.get('user') as { userId?: string } | undefined
    if (!user?.userId) return next()

    let perms: string[] = []
    try {
      const { RbacService } = await import('./services/rbac')
      perms = await new RbacService(c.env.DB, c.env.CACHE_KV).permissionsForUser(user.userId)
    } catch {
      return next() // fail open to the route's own requireRbac gate
    }

    // Cache for requireRbac fast-path — avoids a DB hit per middleware call.
    c.set('rbacPerms', perms)

    // Dashboard landing: if the user can't view the dashboard, send them to the
    // first section they do have access to (instead of an empty/forbidden page).
    const path = new URL(c.req.url).pathname
    if (
      (path === '/admin' || path === '/admin/' || path === '/admin/dashboard') &&
      !perms.includes('dashboard:read')
    ) {
      const dest = NAV_LANDING.find((n) => perms.includes(n.perm))
      if (dest) return c.redirect(dest.path)
      return c.redirect('/auth/login?error=Your account has no accessible sections')
    }

    await next()

    // Strip nav items the user lacks, server-side.
    try {
      const contentType = c.res.headers.get('content-type') || ''
      if (!contentType.includes('text/html')) return
      const body = await c.res.text()
      const filtered = body.includes('<!--nav:')
        ? body.replace(
            /<!--nav:([^>]+?)-->([\s\S]*?)<!--\/nav-->/g,
            (_m, perm: string, inner: string) => (perms.includes(perm) ? inner : '')
          )
        : body
      const headers = new Headers(c.res.headers)
      headers.delete('content-length')
      c.res = new Response(filtered, { status: c.res.status, headers })
    } catch {
      /* leave response as-is on any failure */
    }
  })

  // Core routes
  // Routes are being imported incrementally from routes/*
  // Each route is tested and migrated one-by-one
  // Dedicated /api sub-routers MUST be registered before the bare `/api` router,
  // whose `/:collection` wildcard otherwise shadows them (e.g. GET /api/documents
  // matched `/:collection`='documents' → 404 "Collection not found").
  app.route('/api/media', apiMediaRoutes)
  app.route('/api/system', apiSystemRoutes)
  app.route('/api/documents', apiDocumentsRoutes)
  app.route('/api', apiRoutes)
  app.route('/admin/documents', adminDocumentsRoutes)
  // Testimonials admin (document-backed). The plugin adds the sidebar item to /admin/testimonials,
  // but the HTML router itself must be mounted here like the other core admin routers — it was missing,
  // so the Testimonials page and "add testimonial" form (hx-post /admin/testimonials) 404'd.
  app.route('/admin/testimonials', adminTestimonialsRoutes)
  // Testimonials PUBLIC API (/api/testimonials). After the definePlugin port,
  // the plugin uses register(app) instead of routes[]; call registerPluginRoutes
  // so the API routes are actually mounted.
  registerPluginRoutes(app, [testimonialsPlugin as any], { source: 'core' })

  // Forms (admin builder, public rendering, API submission). Same as above —
  // routes[] was replaced with register(app) in the definePlugin port.
  registerPluginRoutes(app, [formsPlugin as any], { source: 'core' })

  app.route('/admin/api', adminApiRoutes)
  app.route('/admin/collections', adminCollectionsRoutes)
  app.route('/admin/settings', adminSettingsRoutes)
  app.route('/admin/api-reference', adminApiReferenceRoutes)
  app.route('/admin/database-tools', createDatabaseToolsAdminRoutes())
  app.route('/admin/seed-data', createSeedDataAdminRoutes())
  app.route('/admin/content', adminContentRoutes)
  app.route('/admin/media', adminMediaRoutes)
  // Security audit middleware - logs auth events (login, register, logout)
  app.use('/auth/*', securityAuditMiddleware())

  // ── Plugin routes (before the /admin catch-all) ───────────────────────────
  // All plugin route mounting flows through registerPluginRoutes() (see
  // plugins/mount.ts), which mounts each plugin's declarative routes[] and/or
  // synchronous register(app) hook. These MUST be mounted before the bare
  // `/admin` catch-all so plugin-owned `/admin/<x>` pages are not shadowed.
  //
  // `disableAll` turns off every plugin — core AND user — for a bare core app.
  if (!config.plugins?.disableAll) {
    registerPluginRoutes(app, corePluginsBeforeCatchAll, { source: 'core' })

    // Plugin routes - Cache (dashboard and management API)
    // Fixes GitHub Issue #461: Cache routes were not registered
    app.route('/admin/cache', cachePlugin.getRoutes())

    // User-supplied plugins. Mounted here — before the catch-all — so consumers
    // never have to edit core or hand-mount routes (#829, #621, #758).
    if (config.plugins?.register && config.plugins.register.length > 0) {
      registerPluginRoutes(app, config.plugins.register, { source: 'user' })
    }
  }

  // Public event tracking API — POST /api/events (open), GET /api/events (admin)
  app.route('/api/events', eventsApiRoutes)

  app.route('/admin/plugins', adminPluginRoutes)
  app.route('/admin/logs', adminLogsRoutes)
  app.route('/admin/rbac', adminRbacRoutes)
  app.route('/admin', adminUsersRoutes)
  app.route('/auth', authRoutes)

  // Better Auth handler — serves /auth/sign-in/*, /auth/sign-up/*, /auth/sign-out,
  // /auth/get-session, /auth/callback/* etc. Registered AFTER authRoutes so the
  // page-render routes (GET /auth/login, /auth/register) take precedence; only
  // Better Auth's own API paths fall through to this catch-all.
  app.on(['GET', 'POST'], '/auth/*', (c) => {
    const reqUrl = new URL(c.req.url)
    const requestBaseURL = `${reqUrl.protocol}//${reqUrl.host}`
    const auth = createAuth(c.env, config.auth?.extendBetterAuth, requestBaseURL)
    return auth.handler(c.req.raw)
  })

  // Test cleanup routes (only for development/test environments)
  app.route('/', testCleanupRoutes)

  // Plugin routes mounted AFTER the /admin catch-all.
  // Email (/admin/plugins/email) and magic-link auth routes were historically
  // registered here; position preserved to keep route-match precedence identical.
  if (!config.plugins?.disableAll) {
    registerPluginRoutes(app, corePluginsAfterCatchAll, { source: 'core' })
  }

  // Wire the menu singleton + definition registry so the catalyst sidebar and
  // /admin/plugins/:id/configure work for plugins that declared menu[] and
  // configSchema via definePlugin.  We do this once after ALL routes are mounted
  // so the singletons reflect the full set of plugins the app will serve.
  if (!config.plugins?.disableAll) {
    const allMountedPlugins: any[] = [
      ...corePluginsBeforeCatchAll,
      testimonialsPlugin,
      formsPlugin,
      ...corePluginsAfterCatchAll,
      ...(config.plugins?.register ?? []),
    ]
    setPluginMenu(allMountedPlugins.flatMap((p) => (p.menu ?? [])))
    setPluginDefinitions(allMountedPlugins)
  }

  // Serve favicon
  app.get('/favicon.svg', (c) => {
    return new Response(faviconSvg, {
      headers: {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'public, max-age=31536000'
      }
    })
  })

  // Serve files from R2 storage (public file access)
  app.get('/files/*', async (c) => {
    try {
      // Extract the path from the URL pathname (everything after /files/)
      const url = new URL(c.req.url)
      const pathname = url.pathname

      // Remove the /files/ prefix to get the R2 object key
      const objectKey = pathname.replace(/^\/files\//, '')

      if (!objectKey) {
        return c.notFound()
      }

      // Get file from R2
      const object = await c.env.MEDIA_BUCKET.get(objectKey)

      if (!object) {
        return c.notFound()
      }

      // Set appropriate headers
      const headers = new Headers()
      object.httpMetadata?.contentType && headers.set('Content-Type', object.httpMetadata.contentType)
      object.httpMetadata?.contentDisposition && headers.set('Content-Disposition', object.httpMetadata.contentDisposition)
      headers.set('Cache-Control', 'public, max-age=31536000') // 1 year cache
      headers.set('Access-Control-Allow-Origin', '*') // Allow CORS for media files
      headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
      headers.set('Access-Control-Allow-Headers', 'Content-Type')

      return new Response(object.body as any, {
        headers
      })
    } catch (error) {
      console.error('Error serving file:', error)
      return c.notFound()
    }
  })

  // Custom routes - User-defined routes
  if (config.routes) {
    for (const route of config.routes) {
      app.route(route.path, route.handler)
    }
  }

  // Root redirect to login
  app.get('/', (c) => {
    return c.redirect('/auth/login')
  })

  // Health check
  app.get('/health', (c) => {
    return c.json({
      name: appName,
      version: appVersion,
      status: 'running',
      timestamp: new Date().toISOString()
    })
  })

  // Store app instance for route introspection (API reference auto-discovery)
  setAppInstance(app)

  // 404 handler
  app.notFound((c) => {
    return c.json({ error: 'Not Found', status: 404 }, 404)
  })

  // Error handler
  app.onError((err, c) => {
    console.error(err)
    return c.json({ error: 'Internal Server Error', status: 500 }, 500)
  })

  // Attach boot to the app object so Worker entries can pass it to
  // createScheduledHandler without having to recreate the boot logic.
  return Object.assign(app, { boot }) as SonicJSApp
}

/**
 * Setup core middleware (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
export function setupCoreMiddleware(_app: SonicJSApp): void {
  console.warn('setupCoreMiddleware is deprecated. Use createSonicJSApp() instead.')
  // Backward compatibility implementation
}

/**
 * Setup core routes (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
export function setupCoreRoutes(_app: SonicJSApp): void {
  console.warn('setupCoreRoutes is deprecated. Use createSonicJSApp() instead.')
  // Backward compatibility implementation
}
