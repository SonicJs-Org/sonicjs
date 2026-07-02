# SonicJS Plugin SDK v4 — Author Guide

Plugin SDK v4 adopts a Payload-shaped identity pattern: one function (`definePlugin`), one mounting call (`registerPlugins`), no fluent builder.

---

## 1. Plugin anatomy

Every plugin is a plain object created by `definePlugin`. TypeScript narrows the shape based on what you declare.

```ts
import { definePlugin } from '@sonicjs-cms/core'

export const myPlugin = definePlugin({
  // ── required ───────────────────────────────────────────────
  id: 'my-plugin',           // kebab-case, unique across app
  version: '1.0.0',          // semver
  name: 'My Plugin',

  // ── optional identity ──────────────────────────────────────
  description: 'What this plugin does.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'ACME Corp', email: 'dev@acme.io' },

  // ── sync route mounting (MUST be sync, see §3) ─────────────
  register(app) {
    app.route('/admin/my-plugin', myAdminRoutes)
    app.route('/api/my-plugin', myApiRoutes)
  },

  // ── async wire phase (env-dependent) ───────────────────────
  async onBoot(ctx) {
    // ctx.env.DB, ctx.env.KV, ctx.cap.email, etc.
  },

  // ── declarative admin sidebar entry ────────────────────────
  menu: [
    { label: 'My Plugin', path: '/admin/my-plugin', icon: 'bolt', order: 50 },
  ],

  // ── schema-driven settings form ────────────────────────────
  configSchema: {
    apiKey: { type: 'string', variant: 'sensitive', label: 'API Key' },
    webhookUrl: { type: 'string', variant: 'url', label: 'Webhook URL' },
  },

  // ── lifecycle hooks ────────────────────────────────────────
  install:   async (ctx) => { /* create tables, seed data */ },
  uninstall: async (ctx) => { /* drop tables */ },
  activate:  async (ctx) => { /* start background work */ },
  deactivate: async (ctx) => { /* stop background work */ },
})
```

---

## 2. Capability vocabulary

Capabilities gate access to platform services. Declare them in the `capabilities` array; `ctx.cap.*` is narrowed to only the declared capabilities.

| Capability string | `ctx.cap.*` field     | What it provides                      |
|-------------------|-----------------------|---------------------------------------|
| `email:send`      | `ctx.cap.email`       | `EmailService` (send transactional)   |
| `db:read`         | `ctx.cap.db`          | `D1Database` read access              |
| `db:write`        | `ctx.cap.db`          | `D1Database` write access             |
| `kv:read`         | `ctx.cap.kv`          | `KVNamespace` read                    |
| `kv:write`        | `ctx.cap.kv`          | `KVNamespace` write                   |
| `r2:read`         | `ctx.cap.r2`          | `R2Bucket` read                       |
| `r2:write`        | `ctx.cap.r2`          | `R2Bucket` write                      |

```ts
export const myPlugin = definePlugin({
  id: 'my-plugin',
  version: '1.0.0',
  name: 'My Plugin',
  capabilities: ['email:send', 'db:write'] as const,

  async onBoot(ctx) {
    // ctx.cap.email is EmailService — TS guarantees it
    // ctx.cap.db is D1Database — TS guarantees it
    await ctx.cap.email.send({ to: 'admin@example.com', subject: 'Boot', html: '<p>up</p>' })
  },
})
```

Accessing `ctx.cap.X` without declaring `'X:...'` in `capabilities` throws `SonicCapabilityError` at runtime (and TypeScript errors at compile time with `as const`).

---

## 3. Lifecycle: sync vs async

Hono's SmartRouter locks after the first request. Routes **must** mount synchronously at app construction — never `await` inside `register`.

```
App construction (sync):
  registerPlugins(app, plugins, host)
    │
    ├─ validate (semver, unique ids)
    ├─ topo-sort by `requires`
    ├─ MOUNT PASS — plugin.register(app) ← SYNC, no await
    ├─ setPluginMenu(all menu entries)
    └─ setPluginDefinitions(all plugins)

First request (async):
  registry.boot(env)
    │
    └─ WIRE PASS — plugin.onBoot(ctx) ← async OK
         ├─ subscribe hooks
         ├─ init services (DB, email, etc.)
         └─ one-shot, cached for all subsequent requests
```

If `register` returns a `Promise`, `registerPlugins` throws `RegisterPluginsError('register_returned_promise')` at startup — fail-fast, not at first request.

---

## 4. Typed hooks

Hooks declared in `hooks: { ... }` are validated at startup. The type system narrows the handler signature per event.

```ts
export const myPlugin = definePlugin({
  id: 'my-plugin',
  version: '1.0.0',
  name: 'My Plugin',

  hooks: {
    'content:read': async (event, ctx) => {
      // event.content typed to ContentReadEvent
      return { ...event.content, title: event.content.title.toUpperCase() }
    },
    'user:login': async (event, ctx) => {
      // event.user typed to UserLoginEvent
      console.log('login', event.user.email)
    },
  },
})
```

For hooks not yet in the typed catalog, subscribe via the raw bus in `onBoot`:

```ts
async onBoot(ctx) {
  const hooks = (ctx.raw as any)?.hooks
  hooks?.register('some:legacy-event', async (event: any) => { ... })
},
```

---

## 5. Schema-driven settings

Declare `configSchema` on your plugin and a settings form is auto-generated at `/admin/plugins/:id/configure`. No HTML, no route handler needed.

```ts
export const myPlugin = definePlugin({
  id: 'my-plugin',
  version: '1.0.0',
  name: 'My Plugin',

  configSchema: {
    apiKey: {
      type: 'string',
      variant: 'sensitive',   // renders as <input type="password">
      label: 'API Key',
      required: true,
    },
    fromEmail: {
      type: 'string',
      variant: 'email',
      label: 'From Email',
      required: true,
    },
    retryCount: {
      type: 'number',
      label: 'Retry Count',
      default: 3,
      min: 0,
      max: 10,
    },
    enableWebhooks: {
      type: 'boolean',
      label: 'Enable Webhooks',
      default: false,
    },
    provider: {
      type: 'select',
      label: 'Provider',
      options: ['resend', 'sendgrid', 'postmark'],
      default: 'resend',
    },
  },
})
```

**Field types:**

| `type`      | `variant` options                           | Renders as                    |
|-------------|---------------------------------------------|-------------------------------|
| `string`    | `text` (default), `email`, `url`, `password`, `sensitive` | `<input type="...">` |
| `number`    | —                                           | `<input type="number">`       |
| `boolean`   | —                                           | `<input type="checkbox">`     |
| `select`    | —                                           | `<select>`                    |

Access saved settings in `onBoot` via `pluginService.getPlugin(id)?.settings`.

---

## 6. Declarative admin sidebar menu

The catalyst sidebar reads menu entries from the module singleton populated by `app.ts` at startup. Declare entries in `menu`:

```ts
menu: [
  {
    label: 'My Plugin',
    path: '/admin/my-plugin',
    icon: 'bolt',          // name from MENU_ICON_MAP, or raw <svg...> string
    order: 50,             // ASC, default 100
    permissions: ['admin', 'my-plugin:view'],  // any match = visible
  },
],
```

**Available icon names:** `puzzle-piece`, `envelope`, `cog`, `chart`, `sparkles`, `bolt`, `document`, `lock`, `photo`.

For a custom icon, pass raw SVG as the `icon` string:

```ts
icon: '<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">...</svg>',
```

**Permission semantics:** `admin` users see all items regardless of permissions. Other roles must have at least one of the listed permission slugs.

---

## 7. Cron (scheduled work)

Declare scheduled jobs alongside the plugin definition. The host `scheduled()` handler dispatches by schedule.

```ts
export const myPlugin = definePlugin({
  id: 'my-plugin',
  version: '1.0.0',
  name: 'My Plugin',
  capabilities: ['db:write'] as const,

  crons: [
    { schedule: '0 * * * *', name: 'hourly-sync' },
  ],

  async onCronTick(event, ctx) {
    if (event.scheduledTime && event.cron === '0 * * * *') {
      await ctx.cap.db.prepare('DELETE FROM cache WHERE expires_at < ?').bind(Date.now()).run()
    }
  },
})
```

After adding a new schedule, run:
```bash
cd packages/core && npm run generate:triggers
```
This updates `wrangler.toml` `[triggers]` automatically.

---

## 8. Sync vs async quick-reference

| Phase         | When              | Allowed operations                     |
|---------------|-------------------|----------------------------------------|
| `register`    | App construction  | `app.route()`, `app.use()` — sync only |
| `onBoot`      | First request     | DB queries, KV, external APIs — async  |
| `onCronTick`  | Scheduled event   | Anything env-dependent — async         |
| `install`     | Admin action      | DB schema changes, seed data — async   |
| `activate`    | Admin action      | Start background work — async          |
| `deactivate`  | Admin action      | Stop background work — async           |
| `uninstall`   | Admin action      | Drop tables, clean up — async          |

---

## 9. Testing harness

**Unit tests** (`__tests__/**/*.test.ts`) — fast, mock-free:

```ts
import { helloWorldPlugin, isDefinedPlugin } from '@sonicjs-cms/core'

test('isDefinedPlugin returns true', () => {
  expect(isDefinedPlugin(helloWorldPlugin)).toBe(true)
})

test('menu entries are present', () => {
  expect(helloWorldPlugin.menu?.length).toBeGreaterThan(0)
  expect(helloWorldPlugin.menu?.[0].path).toBe('/admin/hello-world')
})
```

**Integration tests** (`__tests__/**/*.integration.test.ts`) — real SQLite via D1 shim:

```ts
import { createD1Database } from '../src/__tests__/utils/d1-sqlite'

test('configure save round-trip', async () => {
  const db = await createD1Database()
  // run migrations...
  // call pluginService.updatePluginSettings(id, values)
  // call pluginService.getPlugin(id) and assert .settings
})
```

**E2E tests** (`tests/e2e/`) — Playwright against running Wrangler:

```ts
test('configure form renders', async ({ page }) => {
  await loginAsAdmin(page)
  await page.goto('/admin/plugins/hello-world/configure')
  await expect(page.locator('input[name="greeting"]')).toBeVisible()
})
```

Run:
```bash
npm run e2e                                              # full suite
npx playwright test tests/e2e/77-schema-driven-settings.spec.ts --headed
```

---

## 10. Common patterns & migration from PluginBuilder

### Pattern: routes that need env (DB/KV)

```ts
register(app) {
  // Mount the router synchronously.
  // Handler closures capture `c.env` per-request — no need to pass env here.
  app.route('/api/my-plugin', new Hono().get('/', async (c) => {
    const db = c.env.DB
    const rows = await db.prepare('SELECT * FROM my_table').all()
    return c.json(rows)
  }))
},
```

### Pattern: factory function for large route sets

```ts
function buildMyApi(): Hono {
  const api = new Hono()
  api.get('/', handler)
  api.post('/', handler)
  return api
}

export const myPlugin = definePlugin({
  id: 'my-plugin', version: '1.0.0', name: 'My Plugin',
  register(app) {
    app.route('/api/my-plugin', buildMyApi() as any)
  },
})
```

### Migration from PluginBuilder

| PluginBuilder (v3)                          | definePlugin (v4)                            |
|---------------------------------------------|----------------------------------------------|
| `new PluginBuilder(manifest)`               | `definePlugin({ id, version, name, ... })`   |
| `.addRoute(path, handler)`                  | `register(app) { app.route(path, handler) }` |
| `.addMenuItem({ label, path })`             | `menu: [{ label, path, icon, order }]`       |
| `.addSettings(schema)`                      | `configSchema: { field: { type, label } }`   |
| `.onInstall(fn)` / `.onActivate(fn)`        | `install: fn` / `activate: fn`               |
| `.onBoot(fn)`                               | `async onBoot(ctx) { ... }`                  |
| `.build()`                                  | _(nothing — `definePlugin` returns the plugin directly)_ |

There is no `PluginBuilder`, `PluginHelpers`, or `.build()` in v4. Every plugin is a plain object.

---

## Using built-in plugins

Several plugins ship with `@sonicjs-cms/core` and are importable directly:

```ts
import {
  helloWorldPlugin,
  redirectPlugin,
  emailReconciliationPlugin,
} from '@sonicjs-cms/core'
```

Register them in your Worker entry (`my-sonicjs-app/src/index.ts`):

```ts
import { createSonicJSApp, helloWorldPlugin } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

const config: SonicJSConfig = {
  plugins: {
    register: [helloWorldPlugin],
  },
}

const app = createSonicJSApp(config)
export default { fetch: app.fetch }
```

Then visit `/admin/hello-world` to confirm it loaded, or `/admin/plugins/hello-world/configure` to adjust its settings.

> **Do not** use a relative path like `'./plugins/hello-world-plugin'` — the plugin lives inside the core package and is not on the filesystem of your Worker app.

---

## See also

- `packages/core/src/plugins/sdk/define-plugin.ts` — full TypeScript source + JSDoc
- `packages/core/src/plugins/sdk/config-schema.ts` — field types and renderer
- `packages/core/src/services/plugin-menu-singleton.ts` — menu filtering + icon map
- `packages/core/src/plugins/core-plugins/hello-world-plugin/index.ts` — reference implementation
- `packages/core/src/plugins/core-plugins/email-plugin/index.ts` — configSchema with 4 typed fields
- `docs/plugins/hello-world-from-scratch.md` — step-by-step tutorial: build your own Hello World plugin with configurable name

---

## Credits

Plugin SDK v4 was designed with reference to the [mmcintosh/sonicjs-infowall-merge](https://github.com/mmcintosh/sonicjs-infowall-merge) fork maintained by **MarkMac** (`mmcintosh@infowall.com`). Three concepts in particular originated in that work:

| Concept | Infowall source commit |
|---------|----------------------|
| Declarative `menu: [...]` on plugins → admin sidebar | `6a30846c` (PR-1) |
| `configSchema` → auto-rendered settings form | `bef0e7ea` + `902a0d1e` (PR-2a / PR-2b) |
| Attach `hookSystem` to request before heavy bootstrap work | `60c0846f` (bootstrap-fix PR) |

SonicJS v4 SDK re-implements these ideas from scratch with a different internal architecture (`definePlugin` identity model vs. infowall's manifest-registry approach), but the design direction — and the bootstrap-hookSystem fix specifically — derives directly from that fork.
