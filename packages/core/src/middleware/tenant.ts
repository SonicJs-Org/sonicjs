/**
 * Tenant resolution middleware (multi-tenant plugin runtime).
 *
 * Sets `c.set('tenantId', ...)` for every request. While the multi-tenant plugin is inactive this
 * short-circuits to 'default', making behavior identical to single-tenant SonicJS. When active,
 * the tenant is resolved (first match wins) from:
 *
 *   1. the configured tenant header (API clients, default `X-Tenant-Id`)
 *   2. the `sonicjs-tenant` cookie (admin tenant switcher)
 *   3. an exact host -> tenant domain mapping (`q_tenant_domain`)
 *   4. a subdomain of the configured root domain (`acme.example.com` -> 'acme'), when enabled
 *   5. fallback: 'default'
 *
 * Every candidate is validated against the tenant registry (must exist AND be active); invalid
 * candidates fall through to the next source. Resolution state (plugin status + settings + tenant
 * map) is cached per isolate with a short TTL and invalidated by tenant/plugin writes in the same
 * isolate — so an /admin request naming a tenant this isolate's registry does not hold re-reads the
 * registry once rather than falling through to 'default' (see tenantMiddleware).
 *
 * `getDocumentRequestContext()` reads the resolved value — the document layer chokepoint stays the
 * single place tenant scope enters queries (R3).
 */
import type { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import { escapeHtml } from '../utils/sanitize'

export const TENANT_COOKIE = 'sonicjs-tenant'
export const TENANT_SWITCHER_MARKER = '<!-- TENANT_SWITCHER -->'
export const MULTI_TENANT_PLUGIN_ID = 'multi-tenant'

const CACHE_TTL_MS = 30_000

export interface TenantResolutionSettings {
  headerName: string
  subdomainResolution: boolean
  rootDomain: string
}

interface TenantCacheEntry {
  pluginActive: boolean
  settings: TenantResolutionSettings
  /** slug -> { name, status } for all live tenant records. */
  tenants: Map<string, { name: string; status: string }>
  /** lowercased exact domain -> slug */
  domains: Map<string, string>
  fetchedAt: number
}

const DEFAULT_SETTINGS: TenantResolutionSettings = {
  headerName: 'X-Tenant-Id',
  subdomainResolution: false,
  rootDomain: '',
}

let cache: TenantCacheEntry | null = null

/** Busts the per-isolate resolution cache. Called by tenant writes and plugin lifecycle changes. */
export function invalidateTenantCache(): void {
  cache = null
}

/**
 * Reads the plugin's activation flag and resolution settings. `null` means the DB could not be
 * read at all (first boot, unmigrated) and the caller should fall back to single-tenant.
 */
async function loadPluginState(
  db: any
): Promise<{ pluginActive: boolean; settings: TenantResolutionSettings } | null> {
  try {
    const pluginRow = await db.prepare(
      `SELECT data FROM documents
       WHERE type_id = 'plugin' AND tenant_id = 'default' AND slug = ?
         AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
    ).bind(MULTI_TENANT_PLUGIN_ID).first() as { data?: string } | null

    if (!pluginRow) return { pluginActive: false, settings: DEFAULT_SETTINGS }

    try {
      const data = typeof pluginRow.data === 'string' ? JSON.parse(pluginRow.data) : (pluginRow.data ?? {})
      const s = data.settings ?? {}
      return {
        pluginActive: true,
        settings: {
          headerName: typeof s.headerName === 'string' && s.headerName.trim() !== '' ? s.headerName.trim() : DEFAULT_SETTINGS.headerName,
          subdomainResolution: s.subdomainResolution === true,
          rootDomain: typeof s.rootDomain === 'string' ? s.rootDomain.trim().toLowerCase() : '',
        },
      }
    } catch {
      return { pluginActive: true, settings: DEFAULT_SETTINGS }
    }
  } catch {
    return null
  }
}

/**
 * @param refreshPluginStatus re-read the plugin row even on a cache hit.
 *
 * Both the TTL cache and `invalidateTenantCache()` are per-isolate, but a Worker runs many
 * isolates — so toggling the plugin only takes effect immediately on whichever isolate served
 * the toggle. Measured against a preview deployment immediately after activation: the Tenants
 * nav link (pluginMenuMiddleware, uncached) rendered on 10/10 admin requests while the tenant
 * switcher rendered on 5/10. The same page disagreed with itself, and the isolates still
 * reporting the plugin inactive were also ignoring the tenant header, cookie and domain map,
 * silently serving every request as 'default' for up to the full 30s TTL.
 *
 * Admin requests therefore pay one extra indexed single-row lookup to stay coherent — the same
 * per-request query pluginMenuMiddleware already issues on every /admin page. Public and API
 * traffic keeps the cached fast path, where nobody is watching a toggle they just clicked and
 * 30s of eventual consistency is the documented behavior.
 */
async function loadTenantState(db: any, refreshPluginStatus = false): Promise<TenantCacheEntry> {
  const now = Date.now()
  const cached = cache && now - cache.fetchedAt < CACHE_TTL_MS ? cache : null

  if (cached) {
    if (!refreshPluginStatus) return cached

    const plugin = await loadPluginState(db)
    if (!plugin) return cached
    // Only an activation flip needs the heavier reload; otherwise keep the cached tenant
    // registry and take the (possibly just-edited) settings from the row we already read.
    if (plugin.pluginActive === cached.pluginActive) {
      return plugin.pluginActive ? { ...cached, settings: plugin.settings } : cached
    }
    invalidateTenantCache()
  }

  let pluginActive = false
  let settings = DEFAULT_SETTINGS
  const tenants = new Map<string, { name: string; status: string }>()
  const domains = new Map<string, string>()

  try {
    const plugin = await loadPluginState(db)
    if (!plugin) throw new Error('tenant state unreadable')

    if (plugin.pluginActive) {
      pluginActive = true
      settings = plugin.settings

      const { results } = await db.prepare(
        `SELECT slug, name, status, domain FROM auth_tenant`
      ).all()
      for (const row of (results ?? []) as any[]) {
        const status = row.status === 'inactive' ? 'inactive' : 'active'
        tenants.set(row.slug, { name: row.name || row.slug, status })
        if (row.domain && status === 'active') {
          domains.set(String(row.domain).toLowerCase(), row.slug)
        }
      }
      // The default tenant always resolves, even before its registry row is materialized.
      if (!tenants.has('default')) tenants.set('default', { name: 'Default', status: 'active' })
    }
  } catch {
    // DB not migrated/seeded yet (first boot): behave as single-tenant.
    pluginActive = false
  }

  cache = { pluginActive, settings, tenants, domains, fetchedAt: now }
  return cache
}

function isActiveTenant(state: TenantCacheEntry, slug: string | undefined | null): slug is string {
  if (!slug) return false
  const entry = state.tenants.get(slug)
  return !!entry && entry.status === 'active'
}

/**
 * Pure resolution, exported for tests. Returns the tenant slug for a request snapshot.
 *
 * When `opts.enforceMembership` is set (authed requests), every non-'default' candidate must also be
 * in `opts.memberSlugs` — an authed user can only resolve into tenants they belong to. Anonymous
 * requests (public API / content serving) pass `enforceMembership: false` so domain/header routing
 * to public content is unaffected. 'default' is always allowed.
 */
export function resolveTenantSlug(
  state: Pick<TenantCacheEntry, 'pluginActive' | 'settings' | 'tenants' | 'domains'>,
  req: { header: string | undefined; cookie: string | undefined; host: string | undefined },
  opts?: { memberSlugs?: Set<string>; enforceMembership?: boolean }
): string {
  if (!state.pluginActive) return 'default'
  const full = state as TenantCacheEntry
  const enforce = opts?.enforceMembership === true
  const member = (slug: string): boolean =>
    !enforce || slug === 'default' || (opts?.memberSlugs?.has(slug) ?? false)
  const accept = (slug: string | undefined | null): slug is string =>
    isActiveTenant(full, slug) && member(slug)

  const header = req.header?.trim().toLowerCase()
  if (accept(header)) return header

  const cookie = req.cookie?.trim().toLowerCase()
  if (accept(cookie)) return cookie

  const host = req.host?.split(':')[0]?.toLowerCase() ?? ''
  if (host) {
    const bySlug = state.domains.get(host)
    if (accept(bySlug)) return bySlug

    const { subdomainResolution, rootDomain } = state.settings
    if (subdomainResolution && rootDomain && host.endsWith(`.${rootDomain}`)) {
      const sub = host.slice(0, -(rootDomain.length + 1))
      if (sub && !sub.includes('.') && accept(sub)) return sub
    }
  }

  return 'default'
}

/** slug -> the user's role in that tenant (excludes always-open 'default'). Empty on error/anon. */
async function loadMemberRoles(db: any, userId: string): Promise<Map<string, string>> {
  try {
    const { results } = await db.prepare(`
      SELECT t.slug, m.role FROM auth_tenant_member m
      JOIN auth_tenant t ON t.id = m.tenant_id
      WHERE m.user_id = ?
    `).bind(userId).all()
    return new Map((results ?? []).map((r: any) => [r.slug as string, (r.role as string) || 'viewer']))
  } catch {
    return new Map()
  }
}

export function tenantMiddleware() {
  return async (c: Context<any>, next: Next) => {
    const db = (c as any).env?.DB
    if (!db) {
      c.set('tenantId', 'default')
      return next()
    }

    // /admin is where someone may have just flipped the plugin toggle and is looking at the
    // result, so admin requests re-read the activation flag instead of trusting the per-isolate
    // cache. See loadTenantState().
    const path = new URL(c.req.url).pathname
    const isAdmin = path.startsWith('/admin')
    let state = await loadTenantState(db, isAdmin)

    // A tenant created on another isolate is absent from this isolate's cached registry, and
    // resolveTenantSlug() rejects any candidate it cannot find there. So for up to the full 30s TTL
    // the cookie the switcher just set silently resolves to 'default': the admin clicks Switch, the
    // redirect lands on an isolate that has never heard of the tenant they created a moment ago, and
    // the row comes back still offering to switch. That is CI run 39582792718's 70-multi-tenant
    // failure, and it is invisible locally because `wrangler dev` runs one isolate, where the
    // create's own invalidateTenantCache() is always the cache the next read hits.
    //
    // Both candidates are free to read, so when one names a tenant this isolate does not know,
    // re-read the registry once before giving up on it. Admin-only, for the same reason
    // loadTenantState() re-reads the activation flag only there: /admin is where someone is watching
    // the result of a write they just made, and gating on the path keeps public and API traffic from
    // being able to force a registry reload with a junk header.
    if (isAdmin && state.pluginActive) {
      const candidates = [
        c.req.header(state.settings.headerName)?.trim().toLowerCase(),
        getCookie(c, TENANT_COOKIE)?.trim().toLowerCase(),
      ]
      if (candidates.some((slug) => slug && !state.tenants.has(slug))) {
        invalidateTenantCache()
        state = await loadTenantState(db)
      }
    }

    // Membership gate: for authed requests, resolution is restricted to the user's tenants. Anon
    // requests (public API / content) skip enforcement so public routing is unchanged. Platform
    // super-admins bypass the gate entirely (access every tenant).
    const user = c.get('user') as { userId?: string; role?: string; isSuperAdmin?: boolean } | undefined
    let memberSlugs: Set<string> | undefined
    let memberRoles: Map<string, string> | undefined
    const enforceMembership = !!(user?.userId && state.pluginActive && !user.isSuperAdmin)
    if (user?.userId && state.pluginActive && !user.isSuperAdmin) {
      memberRoles = await loadMemberRoles(db, user.userId)
      memberSlugs = new Set(memberRoles.keys())
    }

    const tenantId = resolveTenantSlug(
      state,
      {
        header: c.req.header(state.settings.headerName),
        cookie: getCookie(c, TENANT_COOKIE),
        host: c.req.header('host'),
      },
      { memberSlugs, enforceMembership }
    )
    c.set('tenantId', tenantId)

    // Per-tenant RBAC: the role principal fed to the document ACL is the user's role IN the resolved
    // tenant. For the 'default' tenant or a super-admin, the global role applies (single-tenant
    // behavior). For a resolved non-default tenant the gate guarantees membership, so the map has it.
    if (user?.userId) {
      const role =
        tenantId === 'default' || user.isSuperAdmin
          ? user.role
          : memberRoles?.get(tenantId) ?? user.role
      c.set('tenantRole', role)
    }

    await next()

    // Inject the admin tenant switcher at the layout marker (same post-response pattern as
    // pluginMenuMiddleware). Inactive plugin → marker collapses to nothing via the else branch
    // only when the marker is present; non-admin/non-HTML responses are untouched.
    if (!path.startsWith('/admin')) return
    if (!c.res.headers.get('content-type')?.includes('text/html')) return

    const status = c.res.status
    const headers = new Headers(c.res.headers)
    const html = await c.res.text()
    if (html.includes(TENANT_SWITCHER_MARKER)) {
      const replacement = state.pluginActive
        ? renderTenantSwitcher(state, tenantId, enforceMembership ? memberSlugs : undefined)
        : ''
      c.res = new Response(html.split(TENANT_SWITCHER_MARKER).join(replacement), { status, headers })
    } else {
      // Body was consumed by .text(); must rebuild the Response either way.
      c.res = new Response(html, { status, headers })
    }
  }
}

function renderTenantSwitcher(state: TenantCacheEntry, currentTenantId: string, memberSlugs?: Set<string>): string {
  const active = [...state.tenants.entries()]
    .filter(([slug, t]) => t.status === 'active' && (!memberSlugs || slug === 'default' || memberSlugs.has(slug)))
    .sort(([a], [b]) => (a === 'default' ? -1 : b === 'default' ? 1 : a.localeCompare(b)))

  const options = active
    .map(([slug, t]) =>
      `<option value="${escapeHtml(slug)}" ${slug === currentTenantId ? 'selected' : ''}>${escapeHtml(t.name)}</option>`
    )
    .join('')

  return `
    <div class="border-b border-zinc-950/5 px-4 py-3 dark:border-white/5" data-tenant-switcher>
      <label for="tenant-switcher-select" class="mb-1 flex items-center gap-1.5 text-xs/5 font-medium text-zinc-500 dark:text-zinc-400">
        <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"/></svg>
        Tenant
      </label>
      <form method="POST" action="/admin/tenants/switch" data-tenant-switcher-form>
        <select
          id="tenant-switcher-select"
          name="tenant"
          onchange="this.form.requestSubmit ? this.form.requestSubmit() : this.form.submit()"
          class="w-full rounded-lg border border-zinc-950/10 bg-white px-2 py-1.5 text-sm/5 text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white"
        >${options}</select>
        <input type="hidden" name="redirect" value="" data-tenant-switcher-redirect>
      </form>
      <script>
        (function () {
          var r = document.querySelector('[data-tenant-switcher-redirect]');
          if (r) r.value = window.location.pathname + window.location.search;
        })();
      </script>
    </div>`
}
