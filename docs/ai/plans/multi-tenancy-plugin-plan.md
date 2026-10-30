# Multi-Tenancy Plugin Plan (v3, document model)

> Status: in progress
> Branch: `lane711/v3-multi-tenant-plugin` → PR base `v3`
> Supersedes: `docs/ai/MULTI_TENANCY_PLAN.md` (v2-era, pre-document-model — proposed `tenant_id` ALTERs that the document model already ships)

## 1. Goal

Ship multi-tenancy as a **plugin** that is **off by default**. A developer activates it on the
admin Plugins page; once active, document reads/writes are scoped to a per-request tenant, admins
get a Tenants CRUD page plus a tenant switcher in the sidebar, and the public/content APIs resolve
tenants from a header or subdomain. Deactivating the plugin returns the system to exactly today's
single-tenant behavior (everything under the `'default'` tenant).

No new tables. No new migrations. The document model already carries `tenant_id` on all four
document tables with tenant-leading indexes (`0002_documents.sql:53,76-106,111,129,148`) — this
plugin is about **threading a real tenant id** through the existing plumbing and giving it a UI.

## 2. Research summary — how Payload and Strapi do it

### Payload CMS (`@payloadcms/plugin-multi-tenant`, first-party)

Shared database / shared schema. The plugin is a config transform:

- A `tenants` collection holds tenant records (name, slug, domain — developer-defined).
- Every opted-in collection gets a hidden, indexed `tenant` relationship field injected.
- All access functions are wrapped: results are AND-combined with
  `{ tenant: { in: userTenantIDs } }`. `userHasAccessToAllTenants(user)` short-circuits for
  super-admins.
- **Cookie-driven admin context**: a `payload-tenant` cookie is the single source of truth for the
  admin's selected tenant. A `TenantSelector` component in the nav sets it; the injected tenant
  field's `defaultValue` reads it, so new documents are auto-assigned to the selected tenant.
- `baseFilter` scopes admin list views *and* relationship queries to the cookie tenant.
- Domain-based resolution is **not** in the plugin — the official example wires an `afterLogin`
  hook matching `request.host` to `tenant.domain`, setting the same cookie.
- Tenant deletion cascades cleanup across enabled collections (opt-out).
- Server-side stamping: the tenant is never trusted from the request body.

### Strapi CMS (no official support — deliberate)

Strapi's official stance is one instance per tenant; the 1,000+-vote feature request has sat at
"Candidate" since ~2020. The archived community plugin (anetaj/strapi-plugin-multi-tenant) hooked
Koa **routes**, which Strapi itself acknowledges was the wrong layer: any forgotten route is
silently unprotected (fail-open), and the admin panel bypasses route middleware entirely. Modern
hand-rolled Strapi 5 tenancy uses **Document Service middleware** — one chokepoint below
controllers that covers REST, GraphQL, and admin operations.

### Lessons applied here

1. **Filter at the data-service layer, not the route layer** (Strapi's hard lesson). SonicJS
   already has the chokepoints: `DocumentRepository` (constructor-bound `tenantId`, every query
   binds it) and `DocumentsService`. We thread tenant into those, not into per-route guards.
2. **Cookie-driven admin tenant selection** (Payload's pattern): `sonicjs-tenant` cookie + sidebar
   switcher; new admin writes stamp the selected tenant server-side.
3. **Off-by-default, opt-in activation** — and when inactive, resolution short-circuits to
   `'default'` so behavior is byte-identical to today.
4. **Tenant as a first-class record** — a `tenant` document type, exactly like the existing
   document-backed `plugin` type (no new table).
5. **Decide the global/scoped split explicitly** (Strapi's biggest documented pain): see §4.
6. **Logical, not physical isolation** — shared D1 database, row-level scoping. Stated honestly,
   covered by tests asserting cross-tenant reads/writes fail on every path we scope.

## 3. Current state (verified on this branch)

- `documents.tenant_id TEXT NOT NULL DEFAULT 'default'`; `document_references` /
  `document_facets` / `document_permissions` each carry denormalized `tenant_id NOT NULL`
  (projection copies it: `document-projection.ts:64,80`). `document_types` is **global** (no
  tenant column) — the type/collection registry is shared across tenants, same as Payload sharing
  one config.
- `DocumentRepository(db, tenantId)` — positional, required; every query binds it.
- `DocumentsService(db, { tenantId })` — defaults `'default'`; **but `create()` uses
  `input.tenantId`, not `this.tenantId`** (`documents.ts:112`) — a service built for tenant A can
  insert into tenant B. Must be unified.
- `services/document-request-context.ts:24-28` is the **designated** single per-request tenant
  derivation point ("Future: derive from subdomain/header/session here (this is the one place)") —
  but only `api-documents.ts` and the `admin-documents.ts` ACL helper use it. Everything else
  hardcodes `'default'` (~30 sites: three per-file `const TENANT`, constructor defaults, a zod
  default, inline SQL literals).
- Plugin state is **document-backed** (`type_id='plugin'`, slug = plugin id,
  `q_plugin_status` generated column) via `PluginService`; install → `'inactive'`,
  activate/deactivate = admin Plugins page toggle → `POST /admin/plugins/:id/activate|deactivate`.
  Only `core-auth` auto-installs. **A plugin therefore ships OFF by default for free.**
- Routes mount statically at app construction; deactivation does NOT unmount routes — plugins
  self-gate (pattern: security-audit middleware). Our admin routes must self-gate on plugin status.
- True global per-request middleware exists only in core (`app.ts`), not as a plugin surface —
  the tenant-resolution middleware is a small **core** addition, exactly like the existing
  `pluginMenuMiddleware` precedent.
- Sidebar menu items come from `manifest.json#adminMenu` via the **auto-generated**
  `manifest-registry.ts` (`node packages/scripts/generate-plugin-registry.mjs`), and only render
  while the plugin document is `active` (`plugin-menu.ts:83`).
- Legacy `plugins` *table* does not exist on this branch (no DDL) — all new code must use
  `PluginService` / documents (several old plugins still mis-query the table; do not copy them).
- E2E: Playwright config at `tests/playwright.config.ts` (NOT root — pass `--config`), wrangler
  dev :8787, `loginAsAdmin` via Better Auth API (`admin@sonicjs.com` / `sonicjs!`), DB cleaned by
  pattern via `/test-cleanup` only at suite start/end → use `Date.now()`-suffixed fixtures.
  Next free spec number: **70**. Unit tests: `cd packages/core && npx vitest run <path>`
  (root `npm test` is a stub). Real-DB harness: `__tests__/utils/d1-sqlite.ts`.

## 4. Global vs tenant-scoped (explicit decision)

| Surface | Scope | Rationale |
|---|---|---|
| Content documents (all user collections), `/admin/content`, `/api/content`, `/api/documents`, `/admin/documents` | **Tenant** | The point of the feature |
| Testimonials (doc-backed plugin content) | **Tenant** | Plugin content follows content rules |
| Media documents (`media_asset`) | **Tenant** | Payload/Strapi both flag unscoped media as a top pain point |
| Tenant registry itself (`tenant` docs) | Global (stored under `'default'`) | Tenants are platform metadata, like Payload's `tenants` collection |
| Plugin registry (`plugin` docs), site settings, RBAC docs, email log | Global | Platform configuration; per-tenant plugin/settings is a future phase |
| Better Auth users/sessions | Global | BA tables have no tenant column; BA `organization` plugin is disabled in core. Per-user tenant membership = future phase (documented non-goal) |
| `document_types` / collections | Global | Schema registry is shared, same as Payload's collection config |

**Non-goals (v1)**: per-user tenant membership / per-tenant RBAC, per-tenant plugin activation,
per-tenant theming/branding, custom-domain SSL management, data migration of existing documents
between tenants, per-tenant storage quotas. Each is listed in §10 as future work.

## 5. Architecture

### 5.1 Tenant record = `tenant` document type (no new table)

Registered in `document-types-seed.ts` next to the `plugin` type (always present, harmless when
plugin inactive — zero rows):

```
id: 'tenant', source: 'system',
settings: { internal: true, maxVersionsPerRoot: 1,
            baseGrants: { admin: ['read','create','update','delete','manage'] } },
queryableFields: [
  { name: 'status', kind: 'scalar', type: 'text', column: 'q_tenant_status' },
  { name: 'domain', kind: 'scalar', type: 'text', column: 'q_tenant_domain' },
]
```

Document shape: `slug` = tenant slug (URL-safe id, unique via `idx_documents_unique_slug`),
`data = { name, slug, domain?, status: 'active'|'inactive', notes?, createdBy }`. Rows live under
`tenant_id='default'` (platform-global registry). The `'default'` tenant itself gets a row
(`ensureDefaultTenant()`, idempotent, undeletable in UI + service).

### 5.2 TenantService (modeled on `PluginService`)

`packages/core/src/plugins/core-plugins/multi-tenant-plugin/services/tenant-service.ts`

Raw `prepare/bind/batch` (R1), tenant registry CRUD:
- `listTenants()` — q_-column-backed list (slug, name, domain, status, doc timestamps)
- `getTenantBySlug(slug)` / `getTenantByDomain(host)` (exact match on `q_tenant_domain`)
- `createTenant({ name, slug, domain?, notes? })` — slug validation `^[a-z0-9][a-z0-9-]{1,62}$`,
  reserved slugs (`default` allowed only via ensure, `www`, `admin`, `api`), unique slug + domain
- `updateTenant(slug, patch)` / `setStatus(slug, status)`
- `deleteTenant(slug)` — refuses `'default'`; refuses when tenant still owns documents
  (count `documents WHERE tenant_id = ?`) unless `force` — v1 UI exposes only the safe path
  (Payload cascades; we fail-closed and tell the admin what blocks deletion)
- `countDocumentsForTenant(slug)` — for the list page + delete guard
- writes call `invalidateTenantCache()`

### 5.3 Tenant resolution (per-request, fail-closed to `'default'`)

`services/tenant-resolver.ts` (plugin dir) + `packages/core/src/middleware/tenant.ts` (core, the
one legitimate core middleware addition — same precedent as `pluginMenuMiddleware`):

```
tenantMiddleware(): app.use('*', ...) registered in app.ts right after the session middleware
  1. if multi-tenant plugin not active (cached check, 30s TTL per isolate,
     busted by activate/deactivate + settings save) → c.set('tenantId', 'default')
  2. else resolve, first match wins:
     a. X-Tenant-Id header  (API clients; validated against active tenant slugs)
     b. sonicjs-tenant cookie (admin switcher; validated; stale/unknown → cleared semantics, fall through)
     c. Host subdomain (only when settings.subdomainResolution && settings.rootDomain set:
        `acme.example.com` → slug `acme`), else exact q_tenant_domain match on full host
     d. 'default'
  3. c.set('tenantId', resolved)
```

Validation = slug exists AND `q_tenant_status='active'`; resolver caches the slug→status map per
isolate (TTL 30s). Unknown/invalid identifiers fall through to `'default'` — they never grant
access to another tenant's rows, and `'default'` is what an unconfigured caller could already see
(documented honestly; same deference Payload's baseFilter makes to access control).

`getDocumentRequestContext` then changes exactly one line (its designed purpose):

```ts
const tenantId = (c.get('tenantId') as string | undefined) ?? 'default'
```

### 5.4 Literal-`'default'` sweep (the threading work)

Tenant-scoped surfaces switch from literals to `getDocumentRequestContext(c).tenantId`:

| File | Sites |
|---|---|
| `routes/admin-content.ts` | `makeDocService` (:413/:417), `getDocService` (:2147), create inputs :1179/:1595/:2175, list/raw queries :477/:539/:1766/:1780/:1830, erase :2281 |
| `routes/api-content-crud.ts` | :70, :103-104, :182, :207/:211/:215, :258, :281/:285 |
| `routes/admin-documents.ts` | :76, :125, :165, :178, :227/:234, :279-:372 |
| `routes/admin-testimonials.ts` | `getService` :61, create :153 |
| `plugins/core-plugins/testimonials/index.ts` | :27, :119 |
| `services/media-documents.ts` + `routes/admin-media.ts` | ctor default stays; route construction sites pass ctx tenant (:753, :877) |
| `services/documents.ts` | **unify**: `create()` uses `input.tenantId ?? this.tenantId` |

Stay `'default'` (global, per §4): `settings.ts`, `rbac.ts`, `plugin-service.ts`,
`plugin-menu.ts`, `middleware/auth.ts` site-settings reads, `email-service.ts` log writes,
`user-profiles`, `email-reconciliation`, `admin-api.ts` (collections/platform endpoints),
`test-cleanup.ts` (extended to also purge `Test %`-titled docs in *all* tenants + `e2e-*` tenants).

### 5.5 Plugin packaging

`packages/core/src/plugins/core-plugins/multi-tenant-plugin/`

- `manifest.json` — id `multi-tenant`, category `utilities`, `is_core: false`,
  `adminMenu: { label: 'Tenants', path: '/admin/tenants', order: 80 }`,
  `defaultSettings: { headerName: 'X-Tenant-Id', subdomainResolution: false, rootDomain: '' }`
  (generic settings form renders these automatically — text/text/boolean)
- `index.ts` — `PluginBuilder`: `addRoute('/admin/tenants', adminRoutes, { requiresAuth: true })`,
  menu item, lifecycle activate/deactivate → `invalidateTenantCache()`
- `services/tenant-service.ts`, `services/tenant-resolver.ts`
- `routes/admin.ts` — self-gated on plugin active (inactive → notice page linking to
  `/admin/plugins`), admin-role required (requireAuth + role check, matching admin-plugins.ts)
- `templates/tenants-list.template.ts`, `templates/tenant-form.template.ts` — catalyst layout
  (NOT v2), patterns from testimonials list + plugins list

Registration plumbing: export from `core-plugins/index.ts`, append to `CORE_PLUGIN_IDS`, add to
`corePluginsBeforeCatchAll` in `app.ts`, run `node packages/scripts/generate-plugin-registry.mjs`.

Off by default: NOT in `BOOTSTRAP_PLUGIN_IDS` → shows `uninstalled` on the Plugins page; admin
clicks Install (→ `inactive`) then the toggle (→ `active`). Generic plugin-page machinery —
no new UI needed for the toggle itself.

### 5.6 Admin UI

**Tenants page (`/admin/tenants`)** — list: name, slug, domain, status badge, document count,
current-tenant indicator, "Switch" action; header buttons "New Tenant". Form: name, slug
(auto-suggested from name, immutable on edit), domain, status select, notes. Delete via
confirm dialog; blocked for `default` and non-empty tenants with explanatory toast.
HTMX/form patterns copied from testimonials; `escapeHtml` on all user-controlled output (R8).

**Tenant switcher (sidebar, all admin pages)** — Payload's selector, SonicJS mechanics:
marker `<!-- TENANT_SWITCHER -->` added to `admin-layout-catalyst.template.ts` sidebar footer
(above user dropdown); core `tenantSwitcherMiddleware` (same file as tenant middleware) injects a
dropdown when the plugin is active: current tenant name + active-tenant list + "Manage tenants"
link. Selection = plain form `POST /admin/tenants/switch` (slug) → sets `sonicjs-tenant` cookie
(httpOnly, sameSite=Lax, path=/, 1y) → redirect back (`Referer` fallback `/admin`). Layout
auto-injects CSRF into plain form posts. When plugin inactive → marker replaced with ''.

**Plugin settings page** — generic `renderSettingsFields` auto-form from `defaultSettings`;
settings save POST already exists (`/admin/plugins/:id/settings`); `updatePluginSettings` write
path also busts the resolver cache (status+settings cached together).

### 5.7 Request flows (after activation)

```
Admin: cookie sonicjs-tenant=acme
  → tenantMiddleware sets c.tenantId='acme'
  → /admin/content list → getDocumentRequestContext → DocumentRepository(db,'acme')
  → only acme rows; create stamps tenant_id='acme'

API client: X-Tenant-Id: acme → same chokepoint → /api/content scoped to acme

Public visitor: acme.example.com (subdomainResolution on)
  → host match → published reads scoped to acme

Plugin inactive: every request → 'default' → today's behavior, byte-identical
```

## 6. Implementation order

1. **Core seed + context** — `tenant` doc type in `document-types-seed.ts`;
   `document-request-context.ts` reads `c.get('tenantId')`; `DocumentsService.create()`
   tenant unification.
2. **Plugin skeleton** — manifest, index, registry regen, app.ts wiring; visible on Plugins page,
   installs, toggles.
3. **TenantService + resolver + core tenant middleware** (with activation cache).
4. **Admin routes + templates** (CRUD + switch endpoint + self-gating).
5. **Switcher injection** (layout marker + middleware).
6. **Literal sweep** (§5.4) — content/media/testimonial routes through request context.
7. **Unit/integration tests** (real-SQLite harness, R10): tenant-service CRUD + guards;
   resolver precedence/validation/cache; isolation integration (create under A, invisible under
   B through real route handlers); regression: plugin inactive → all existing flows on 'default'.
8. **E2E `tests/e2e/70-multi-tenant.spec.ts`**: plugin uninstalled by default → install +
   activate via Plugins page UI → Tenants nav appears → create tenant → switch → create content
   under tenant → verify isolation both directions → switch back → deactivate → single-tenant
   behavior restored. Fixtures `Date.now()`-suffixed; cleanup via test-cleanup extension.
9. **Verify + ship**: `npm run type-check`, vitest suites, e2e spec 70 (+ smoke), commit, PR
   to `v3`.

## 7. Test matrix

| Layer | File | Asserts |
|---|---|---|
| Unit (real SQLite) | `__tests__/services/tenant-service.sqlite.test.ts` | CRUD, slug/domain uniqueness, reserved slugs, default-tenant ensure/undeletable, delete blocked while documents exist, q_ generated cols populated |
| Unit (real SQLite) | `__tests__/services/tenant-resolver.sqlite.test.ts` | header > cookie > subdomain > default precedence; inactive plugin → default; unknown/inactive tenant falls through; cache TTL + invalidation |
| Integration | `__tests__/routes/admin-tenants.integration.test.ts` | route CRUD, self-gating when inactive, switch sets cookie, default-tenant delete 400 |
| Integration | `__tests__/routes/tenant-isolation.integration.test.ts` | content created with tenant A context invisible to tenant B via `/admin/content` + `/api/content` + `/api/documents`; writes stamp resolved tenant (body-supplied tenant ignored) |
| E2E | `tests/e2e/70-multi-tenant.spec.ts` | full §6.8 flow through real UI |

## 8. Security notes

- Tenant id always resolved server-side (header/cookie/host validated against the registry) and
  bound by `DocumentRepository`/`DocumentsService` — never trusted from a request body (Payload &
  Strapi lesson; closes the existing `create(input.tenantId)` gap).
- Logical isolation on shared D1 (row scoping), not physical isolation — stated in docs.
- Switch endpoint: admin-role + CSRF (global) + active-tenant validation.
- All template output through `escapeHtml` (R8). Zod validation at route boundary.
- id/root_id-keyed lookups stay safe via globally-unique nanoids; mutation paths still go through
  tenant-scoped repository/ACL (`denyIfNotAllowed` keeps the request-context tenant).

## 9. Risks

| Risk | Mitigation |
|---|---|
| Missed `'default'` literal leaks cross-tenant data | Sweep is enumerated (§5.4) from a verified call-site census; isolation tests cover every scoped route family; final `grep -n "'default'"` audit vs §4 table |
| Resolver DB hit per request | Isolate cache (30s TTL) on plugin status + tenant map; inactive short-circuit is one cached check |
| Stale activation cache after toggle | Same-isolate invalidation on activate/deactivate/settings; 30s worst case cross-isolate (admin UI reads status from DB, unaffected) |
| Existing e2e suite breaks (admin flows now tenant-aware) | Plugin inactive in default DB → all existing specs run on `'default'` path unchanged; spec 70 deactivates at the end |
| `q_*` column budget (100/table) | +2 columns (`q_tenant_status`, `q_tenant_domain`) via existing self-heal path; no migration |
| Hono router lock / route mounting | Declarative `addRoute` before `/admin` catch-all via existing `registerPluginRoutes` position |

## 10. Future work (explicit non-goals now)

Per-user tenant membership (Better Auth `organization` plugin is the natural hook once enabled),
per-tenant RBAC roles, per-tenant plugin activation + settings, per-tenant theming, custom-domain
management UI, tenant data export/import + cross-tenant migration tooling, per-tenant quotas,
tenant-scoped media R2 prefixes, cascade delete option (Payload-style `cleanupAfterTenantDelete`).

## 11. Review

**Shipped.** Multi-tenancy is a working, off-by-default plugin on the document model.

What landed:
- `tenant` document type (no new tables) + `q_tenant_status`/`q_tenant_domain` generated columns
  (self-healed via `ensureScalarSchema` on registration; confirmed created on real-app bootstrap).
- `middleware/tenant.ts`: per-request resolution (header > cookie > exact domain > subdomain >
  default), per-isolate cache busted by tenant/plugin writes, and the sidebar switcher injection at
  a layout marker. `getDocumentRequestContext` reads the resolved tenant (the one chokepoint).
- `DocumentsService.create()` unified to stamp the service/request tenant, never the request body.
- Plugin package (`multi-tenant-plugin`): `TenantService`, admin Tenants CRUD + switch endpoint
  (self-gated), list/form templates, registered in `app.ts` + core-plugins, registry regenerated.
- Literal-`'default'` sweep across content (admin + api), documents, testimonials, media, and the
  admin reference picker. Globals (settings, RBAC, plugin/user-profile/email, type registry) stay
  platform-wide; the collection-delete guard now counts across all tenants (collections are global).
- `PluginService` activate/deactivate/settings writes bust the resolver cache.

Tests:
- 23 plugin unit tests (TenantService CRUD/guards/generated columns, resolver precedence, real-DB
  cross-tenant isolation) — green.
- E2E `tests/e2e/70-multi-tenant.spec.ts` (6 tests) — green against the real app on wrangler dev:
  off-by-default → activate via Plugins page → Tenants nav + switcher appear → create tenant via UI
  → cross-tenant document isolation (created doc stamped + visible to its tenant, invisible to
  default) → switch updates the current badge → deactivate restores single-tenant.
- Fixed a pre-existing harness bug (`createTestD1` deleted from a non-existent `collections` table,
  which had been erroring every real-SQLite test on `v3`).

Deviations from plan:
- Isolation E2E uses `blog_post` (a seeded, app-registered type) rather than `testimonial`
  (plugin-owned, not in the core bootstrap seed) — same chokepoints exercised.
- Nav-link assertion checks DOM presence, not visibility: plugin menu items live inside the
  collapsed Plugins accordion. The tenant switcher renders twice (responsive desktop + mobile
  sidebar), asserted with `.first()`.

Deferred (per §10): per-user tenant membership / per-tenant RBAC, per-tenant plugin activation and
settings, theming, custom-domain management, cross-tenant data migration tooling, quotas.
