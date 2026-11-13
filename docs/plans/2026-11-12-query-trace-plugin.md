# Query Trace Plugin (Admin Performance Panel): Implementation Plan

> **For Hermes:** Delegate to a Sonnet subagent, task-by-task (subagent-driven-development). Plan only — no code has been written.
> **Rev 2:** Delivered as a plugin, so it can be turned on and off per installation from Admin → Plugins.

**Goal:** Ship a `query-trace` core plugin. When it is active, every `/admin/*` HTML page gets a collapsible "Performance Trace" panel at the bottom. The panel lists every D1 query, KV op, and cache lookup in the request, slowest first, with enough context to see where admin pages can get faster: cached or not, rows read vs returned, duplicates, which middleware ran it, network vs SQL time, and a waterfall. When the plugin is inactive there is no panel, no recording, and no headers. The bindings are still wrapped in passthrough proxies so singletons stay traceable (§1). That has a **bounded** overhead, not zero; the budget and how it's measured are in §6 risk 4.

**Architecture:**
- **Plugin** (`plugins/core-plugins/query-trace-plugin/`) owns everything feature-specific:
  - manifest + settings schema
  - analysis heuristics
  - panel template
  - the trace middleware
  - a small "enable for me" admin page
- **Core** gets plugin-agnostic primitives in `utils/request-trace/`. All of them are passthrough no-ops when no trace is active:
  - `getCurrentTrace()`, a request-scoped store on top of AsyncLocalStorage
  - `traceSpan(name, mw)`, a span wrapper
  - the D1/KV binding proxies, plus `wrapTraceBindings(env)`
  - SQL/key redaction helpers

  The binding proxies live in core, not the plugin, because core's `boot()` (HTTP *and* cron-first `scheduled()` paths) must apply them before it seeds singletons.
- The core cache plugin reports hit/miss events through `getCurrentTrace()`, so it never imports the query-trace plugin.
- **Mounting:** core mounts the plugin's middleware in `app.ts` as the first middleware. This is the established pattern (security-audit, tenant, 2FA). The middleware short-circuits unless the plugin is active.
  - Why not in `register()`: `app.ts:655-661` documents that middleware added from a plugin's `register()` silently doesn't run for admin routes mounted before it.

**Tech stack:** Hono 4.13, the `definePlugin` SDK + `configSchema`, D1/KV bindings, AsyncLocalStorage, server-rendered templates, Tailwind CDN (already in both admin layouts), Vitest, Playwright.

**Repo:** `SonicJs-Org/sonicjs`, base `origin/main` (`0f30977a6` at time of writing).
**Branch / worktree (required):** `lane711/query-trace-plugin` in its own worktree. Don't touch `/Users/lane/Dev/refs/sonicjs` directly; it has uncommitted changes.

---

## 1. Context from code inspection

| Fact | Where | Implication |
|---|---|---|
| Plugin activation lives in the `documents` table (`type_id='plugin'`, `data.status`). `isPluginActive()` caches it per isolate and `PluginService.activate/deactivate` invalidates that cache **only in the same isolate** | `middleware/plugin-middleware.ts:11-47`, `services/plugin-service.ts:200-237` | Use our own 30 s TTL cache that reads status + settings in one query, so other isolates pick up a toggle within 30 s. Invalidate in-isolate from `PluginService` too. |
| Plugin settings: `PluginService.updatePluginSettings()` writes `data.settings`. There's no generic invalidation, only per-plugin special cases (tenant, 2FA) | `services/plugin-service.ts:241-265` | Add a `query-trace` invalidation line there, same pattern. |
| `definePlugin({ id, version, configSchema, register, menu, activate, deactivate })`. `configSchema` auto-renders the settings form (string/number/boolean/select) | `plugins/sdk/define-plugin.ts:136-225`, `plugins/sdk/config-schema.ts` | Settings UI for free on the plugin's configure page. |
| Manifest registry is generated from every `manifest.json` (`npm run plugins:generate`). `defaultActive` controls greenfield auto-activation | `plugins/manifest-registry.ts`, `packages/scripts/generate-plugin-registry.mjs` | New plugin = folder + `manifest.json` + regenerate. `defaultActive: false`. |
| Core plugins with routes go in `corePluginsBeforeCatchAll` | `app.ts:307-330`, mounted at `app.ts:723` | Add `queryTracePlugin` there for its `/admin/plugins/query-trace` page. |
| Existing core-mounted plugin middleware that short-circuits when inactive: `securityAuditMiddleware`, `tenantMiddleware`, `enforceTwoFactorEnrolment` | `app.ts:578,662,713` | Same pattern for `queryTraceMiddleware()`. |
| `c.env.DB` is used directly in **354** places (raw D1 + Drizzle via `drizzle(env.DB)`) | `packages/core/src/**` | Wrap the **binding** with a proxy and don't touch call sites. Drizzle's D1 driver goes through `prepare/bind/all/raw/run/first/batch`, so it's covered. |
| `c.env` is a writable field on the Hono Context | `node_modules/hono/dist/context.js:28` | Per-request `c.env = { ...c.env, DB: traced }` without mutating the shared isolate env. |
| `boot(env)` seeds `firstRequestEnv`, `EmailService`, and plugin hook closures. It is called from the HTTP wiring middleware **and** directly from a Worker's `scheduled()` handler on cron-first cold isolates, where no HTTP middleware ever runs | `app.ts:417-440`, `BootIsolateFn` (`app.ts:244-253`) | `boot()` itself must call `wrapTraceBindings(env)` before seeding anything. Otherwise a cron-first isolate pins raw bindings. |
| Singletons capture env on the first request (`firstRequestEnv`, `EmailService({db})`, `setGlobalKVNamespace`) | `app.ts:401,423`, `middleware/bootstrap.ts:466` | Proxies must **not** hold a trace. They look it up through ALS on each call and are cached per raw binding in a WeakMap. **The proxies must also be installed on every request, before bootstrap, whatever the plugin state or path.** Otherwise an earlier untraced request (plugin inactive, or a non-admin path) seeds those singletons with *raw* bindings, and their later D1/KV calls bypass tracing. A passthrough proxy with no active trace costs one ALS lookup per call and records nothing (see Task 10). |
| Better Auth already loads ALS via `import(/* webpackIgnore */ 'node:async_hooks')` with a `globalThis.AsyncLocalStorage` fallback | `packages/core/node_modules/@better-auth/core/dist/async_hooks/index.mjs` | Copy that exact pattern. No new hard dependency; the starter and sample app ship `nodejs_compat`. |
| Cache plugin tiers: memory → KV → miss | `plugins/cache/services/cache.ts` `get` ~L185, `getWithSource` ~L229, `set` ~L288, `getMany` | Memory hits never touch KV, so instrument here for the "cached?" column. |
| The nav-strip middleware already rewrites admin HTML bodies | `app.ts:606-649` | Copy the pattern, but note the pitfall: Hono's `c.res` setter copies the old headers, **including `content-length`**, onto the new Response (`context.js:111-125`). Set `c.res = undefined` before assigning. (The nav-strip likely has this latent bug. Flag it in the PR, don't fix it here.) |
| Middleware order: appVersion (L405) → metrics → bootstrap → boot/wire → … → `requireAuth` → `requireRbac` → pluginMenu → menu → RBAC perms (L606) → 2FA → routes | `app.ts:405-670` | Mount the trace middleware **before** appVersion so bootstrap and auth queries are captured. |
| Both admin layouts: Tailwind CDN, `<html class="dark">`, HTMX 2.0.3. No CSP `script-src` | `templates/layouts/*`, `middleware/security-headers.ts` | Tailwind classes work in injected HTML, and a small inline script is allowed. |
| `escapeHtml` exists | `utils/sanitize.ts` | Use it for SQL, keys, and caller strings. |
| Real-SQLite D1 test harness | `__tests__/utils/d1-sqlite.ts` | Use it for proxy tests against real SQL. |
| Latest e2e spec: `126-…` | `tests/e2e/` | New spec: `127-query-trace-plugin.spec.ts`. |

---

## 2. Feature spec

### 2.1 On/off per installation (plugin lifecycle)
- **Off by default = available but not installed.** The plugin is listed in the registry (`is_core: false`, `defaultActive: false`) and shows under Admin → Plugins as available. It has no `documents` row, which `state.ts` treats as inactive.
  - It must **not** go through `PluginBootstrapService`: that only auto-installs `is_core` / `defaultActive` plugins, and it force-activates every bootstrapped plugin that's inactive (`services/plugin-bootstrap.ts:121-131`).
- **On** = an admin clicks **Install** (the existing install handler creates the row as active) or **Activate**.
- **Off again** = **Deactivate** (row status `inactive`) or **Uninstall** (row removed).
- Each installation has its own D1, so on/off is per installation automatically.
- **Inactive / not installed** → after wrapping the bindings in passthrough proxies (see 1. and Task 10), `queryTraceMiddleware` returns `next()` following one cached in-memory check, refreshed from D1 at most every 30 s per isolate. No recording, no ALS load, no body rewrite, no headers.
- **Active** → behavior is driven by the plugin settings (`configSchema`):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `visibility` | select `opt-in` / `all-admins` | `opt-in` | `opt-in`: only admins who turned it on for themselves see it (cookie). `all-admins`: every admin sees it on every page |
| `warnQueryMs` | number | 25 | Amber threshold |
| `slowQueryMs` | number | 100 | Red threshold + "slow query" finding |
| `captureCallers` | boolean | true | Capture the stack-frame caller per query |
| `serverTimingHeader` | boolean | true | Emit a `Server-Timing` header on traced responses |
| `maxEntries` | number (100–5000) | 1000 | Per-request cap |

- **Opt-in toggle:** `?trace=1` / `?trace=0` on any admin URL sets or clears the cookie `sjs_trace=1` (path `/admin`, HttpOnly, SameSite=Lax, Secure on https, 7 days), then redirects to the same URL without the param. The plugin page `/admin/plugins/query-trace` also has "Enable for me / Disable for me" buttons and shows the current state.
- A trace is **collected** when: the plugin is active, the path is `/admin` or starts with `/admin/`, and (`visibility=all-admins` or the cookie is present).
- The `Server-Timing` header and the panel are both emitted only when the request ends with `c.get('user')?.role === 'admin'`. The panel additionally requires that the response is `text/html` and non-redirect, the body has `</body>`, and the request is **not** an `HX-Request`.
- **ALS unavailable** (no `nodejs_compat`): the plugin activates but logs one warning, and the plugin page shows a yellow notice "Tracing unavailable: enable nodejs_compat".

### 2.2 Recorded per entry (`TraceEntry`)
| Field | Source | Why |
|---|---|---|
| `seq` | counter | Execution order |
| `kind` | `d1 \| kv \| cache` | Type column |
| `op` | D1: `SELECT/INSERT/UPDATE/DELETE/PRAGMA/OTHER` + method (`all/first/run/raw/batch/exec`). KV: `get/getWithMetadata/put/delete/list`. Cache: `get/getWithSource/set` (`getMany`/`setMany` show up as their per-key `get`/`set` events) | |
| `label` | **Redacted** at record time; the raw text is never stored. **SQL:** collapsed whitespace, then every string literal (`'…'`), numeric literal, and blob literal (`X'…'`) replaced with `?`, case preserved, ≤2,000 chars. **KV/cache keys:** `redactKey()` splits on `:`, `/`, `\|` and keeps a segment **only** if it is in the explicit allowlist `KNOWN_KEY_SEGMENTS`. The allowlist is built from the namespaces in `CACHE_CONFIGS` (`services/cache.ts:134`) plus the fixed key prefixes actually used in core: grep `CACHE_KV.get(`/`put(` and the cache `namespace`s, e.g. `settings`, `rbac`, `perms`, `plugin`, `collections`, `content`, `menu`, `session`, `ratelimit`. Every other segment is redacted whatever its spelling: `<uuid>`, `<email>`, `<n>` (all digits), otherwise `<redacted:LEN>`. The panel and Copy JSON only ever see the redacted label | SQL literals and keys can carry tokens, emails, and user/session IDs |
| `fingerprint` | SQL with literals/params → `?`, `IN (?, ?, …)` → `IN (?…)`, lowercased | Groups duplicates and N+1 patterns |
| `tables` | regex on `FROM/JOIN/INTO/UPDATE` | |
| `params` | **masked**: `string(36)`, `number`, `null`, `bool` | Session tokens and hashes get bound |
| *(private)* `identityKey` | salted per-request hash of `fingerprint` + the **raw** bound values (FNV-1a over `JSON.stringify(values)`). Kept in a `Map<seq, string>` on `RequestTrace` that is **never** rendered or exported; `toJSON()` excludes it | Lets "identical repeat" compare actual values without exposing them |
| `startMs` / `durationMs` | `performance.now()` relative to trace start, wall time around the awaited call. **Batch members:** see `parentSeq` | Waterfall + default sort |
| `parentSeq` | set on statements recorded from a `batch()` call; points at the batch's parent entry. The parent (`op: 'batch'`, `label: 'batch(N)'`) holds the one shared wall time. Each member gets `durationMs = meta.duration ?? 0` (its own server time), never the shared wall time | Stops a 10-statement batch from showing the batch time ten times |
| `costMs` | derived: `durationMs` for standalone entries and batch members, **excluded** for batch parents in per-statement aggregations | The single field every per-statement aggregation uses (see 2.5 note) |
| `d1DurationMs` | `meta.duration` | **wall − d1 = network/RPC overhead.** A large gap means latency is the cost: batch or cache. A small gap means SQL is slow: index |
| `rowsReturned` | `results.length` / first = 1·0 / writes = `meta.changes` | |
| `rowsRead` / `rowsWritten` | `meta.rows_read` / `meta.rows_written` | Read much greater than returned → missing index |
| `servedBy` | `meta.served_by_region`, `meta.served_by_primary` | Read-replica visibility |
| `cache` | D1 `null` ("not cached"). KV get `hit/miss`. Cache `hit:memory/hit:kv/miss` | The "Cached" column |
| `span` | top of the span stack (`bootstrap`, `requireAuth`, `requireRbac`, `menu`, …, `handler`) | Which layer issued it |
| `caller` | first stack frame outside `request-trace`, `query-trace-plugin`, and `node_modules` → `fn file:line` | Where to fix it |
| `error` | message if it threw | |

### 2.3 Spans
`traceSpan(name, mw)` (core util) wraps a middleware. It records `startMs`, `durationMs`, and `selfMs` (time excluding downstream `next()`), and pushes and pops the name on the trace's span stack around the middleware's own code. Queries outside every span are labelled `handler`. Spans to wrap in `app.ts`: `bootstrap`, `boot`, `csrf`, `apiKeyAuth`, `jwtAuth`, `tenant`, `requireAuth`, `requireRbac`, `pluginMenu`, `menu`, `rbacPerms+navStrip`, `enforce2FA`.

### 2.4 Panel UI (`<details id="sjs-trace-panel">`, collapsed, appended before `</body>`)
**Summary:** `⚡ Trace · 412 ms server · 37 D1 (31 unique) · DB 288 ms Σ · 6 dupes · cache 4 hit / 3 miss · KV 2 · slowest 92 ms`. The badge is green under 150 ms, amber under 500 ms, red above.

**Expanded:**
1. **Opportunities:** findings from 2.5, ordered by severity, then impact ms.
2. **Queries & cache ops**, **sorted by duration desc by default**. Columns:
   - `ms` (colored by the thresholds)
   - `D1 ms`, `Type`, `Op`
   - `Query / key` (click to expand full SQL + masked params + caller)
   - `Tables`
   - `Rows ret/read/written`
   - `Cached`, `×dupes`, `Span`
   - `Start` + waterfall bar (% of total)

   Headers sort client-side with a ~20-line inline script.
3. **Grouped by fingerprint:** count, total, avg, max, total rows_read. Sorted by total ms desc.
4. **Spans:** name, start, total, self, # queries, DB ms. Sorted by self desc.
5. **Footer:**
   - `Copy JSON` (full trace, to paste into an agent session)
   - `Hide for me` (`?trace=0`, only in opt-in mode)
   - "cold isolate" note when bootstrap ran its slow path
   - dropped-entry count
   - link to the plugin settings

Trace JSON is embedded in `<script type="application/json" id="sjs-trace-data">` with `<` escaped as `\u003c`.

### 2.5 Findings (`analyze.ts`, pure)
| Rule | Trigger | Message |
|---|---|---|
| N+1 / repeated fingerprint | ≥3× same fingerprint | "`select … from users where id = ?` ran 12× (148 ms). Batch with `IN (…)` or memoize per request." |
| Identical repeat | same private `identityKey` (fingerprint + raw bound values) ≥2×. Masked params are **not** used: distinct IDs all mask to `string(36)`/`number` | "Identical query repeated 4×. Cache it in request context." |
| Missing index suspect | `rowsRead ≥ 1000` and `rowsRead/max(rowsReturned,1) ≥ 20` | "Read 18,400 rows to return 20. Check the index on `<tables>`." |
| Slow query | `costMs ≥ slowQueryMs` (statements), or a batch parent's `durationMs ≥ slowQueryMs` reported as "slow batch" | "Slow query (230 ms)." / "Slow batch of 10 (230 ms)." |
| Latency-bound | ≥5 D1 calls with `(wall−d1)/wall > 0.8` | "Network overhead is X% of DB time. Batch with `db.batch()` or cache." |
| Serial chain | ≥3 consecutive non-overlapping D1 calls in the same span | "4 sequential queries in `handler` (60 ms). `Promise.all`/`batch` if independent." (hint) |
| Cache miss → DB | cache `miss` followed by D1 in the same span | "Cache miss on `settings:general` → 3 queries. Check TTL/warming." |
| Write on GET | `rowsWritten > 0` on GET | "GET wrote N rows (`<tables>`)." |
| Middleware-heavy | non-handler span self time > 50% of total | "Middleware is 63% of server time; top: `requireRbac` 120 ms." |
| Cold bootstrap | `bootstrap` span > 200 ms | "Cold-start bootstrap (840 ms). Isolate warm-up, not page cost." |

**Which field each aggregation uses:**
- **DB Σ (summary + `Server-Timing db`):** sum of `durationMs` over *top-level* D1 entries, i.e. standalone statements plus batch parents. Batch members are excluded, so the shared wall time counts once.
- **Query counts (`N D1`, unique, dupes):** statements only. Batch members count, batch parents don't.
- **Default table sort:** top-level entries by `durationMs` desc. Batch members render indented under their parent.
- **Fingerprint groups, N+1, identical repeat, slow query:** `costMs` over statements.
- **Latency-bound:** top-level entries only (`durationMs` vs `d1DurationMs`, where a parent's `d1DurationMs` is the sum of its members).

### 2.6 `Server-Timing` (traced responses for **admin users only**, including HTMX partials, when the setting is on)
`total;dur=412, db;dur=288;desc="37 q", cache;desc="4 hit/3 miss", mw;dur=130`. This shows up in DevTools → Network → Timing.

---

## 3. Files

**Create: core primitives (plugin-agnostic, no-op when idle)**
- `packages/core/src/utils/request-trace/trace-context.ts`:
  - `RequestTrace`, `TraceEntry`, `SpanRecord` types/class
  - `loadAsyncLocalStorage()` (Better-Auth-style dynamic import, memoized)
  - `runWithTrace`, `getCurrentTrace`
- `packages/core/src/utils/request-trace/trace-span.ts`: `traceSpan(name, mw)`
- `packages/core/src/utils/request-trace/sql-fingerprint.ts`: `fingerprintSql`, `redactSql`, `redactKey`, `KNOWN_KEY_SEGMENTS`, `identityKey`, `sqlOp`, `extractTables`, `maskParams`
- `packages/core/src/utils/request-trace/traced-d1.ts`: `getTracedD1(raw)`
- `packages/core/src/utils/request-trace/traced-kv.ts`: `getTracedKV(raw)`
- `packages/core/src/utils/request-trace/wrap-bindings.ts`: `wrapTraceBindings(env)` returns `{ ...env, DB: getTracedD1(env.DB), CACHE_KV: getTracedKV(env.CACHE_KV) }`. It is **idempotent**: proxies are recognised by their `RAW` symbol and returned as-is, so wrapping twice (HTTP middleware, then `boot()`) can't double-wrap.
- `packages/core/src/utils/request-trace/index.ts`

**Create: plugin `packages/core/src/plugins/core-plugins/query-trace-plugin/`**
- `manifest.json`
- `index.ts`: `definePlugin` with `configSchema`, `register` (routes), activate/deactivate, exports
- `constants.ts`: `QUERY_TRACE_PLUGIN_ID = 'query-trace'`, cookie name
- `state.ts`: `getQueryTraceState(db)` (30 s TTL cache of `{active, settings}`), `invalidateQueryTraceState()`
- `services/analyze.ts`: `analyze`, `summarize`, `findOpportunities`, `groupByFingerprint`, `serverTimingValue`
- `components/trace-panel.ts`: `renderTracePanel(trace, analysis, settings)`
- `middleware/query-trace-middleware.ts`: `queryTraceMiddleware()`
- `routes/admin.ts`: `GET /admin/plugins/query-trace` (status, ALS availability, per-user enable/disable, link to settings) and `POST /admin/plugins/query-trace/me` (toggle cookie; CSRF via existing middleware)

**Tests**
- `packages/core/src/__tests__/utils/request-trace/{trace-context,trace-span}.test.ts`
- `packages/core/src/__tests__/utils/request-trace/{sql-fingerprint,traced-d1,traced-kv,wrap-bindings}.test.ts` + `traced-proxy.bench.ts` (`vitest bench`, not a CI gate)
- `packages/core/src/__tests__/plugins/query-trace/{analyze,state,trace-panel,middleware,routes}.test.ts`. Check where existing plugin tests live (`__tests__/plugins/` vs a `tests/` folder in the plugin dir) and follow the majority.
- `tests/e2e/127-query-trace-plugin.spec.ts`

**Modify**
- `packages/core/src/app.ts`:
  - import and mount `queryTraceMiddleware()` **before** the appVersion middleware (L405)
  - wrap the spans from 2.3 with `traceSpan`
  - add `queryTracePlugin` to `corePluginsBeforeCatchAll`
- `packages/core/src/plugins/cache/services/cache.ts`: `getCurrentTrace()?.record(...)` in `get`, `getWithSource`, `set`. **Not** in `getMany`/`setMany`: they loop over `get`/`set` (`cache.ts:456-479`), so per-key events are already recorded once.
- `packages/core/src/services/plugin-service.ts`: call `invalidateQueryTraceState()` when the id is `'query-trace'` in **every** state-changing path. Mirror the 2FA special case:
  - `installPlugin`, both the new-install branch and the re-install branch (`plugin-service.ts:~83-135`, next to the existing `invalidatePluginStatusCache(slug)`). Install sets status `active` without going through `activatePlugin`.
  - `uninstallPlugin` (explicitly, even though an active uninstall also goes through `deactivatePlugin`)
  - `activatePlugin`
  - `deactivatePlugin`
  - `updatePluginSettings`
- `packages/core/src/plugins/core-plugins/index.ts`: export `queryTracePlugin`, `createQueryTracePlugin`. Add `'query-trace'` to `CORE_PLUGIN_IDS`.
- `packages/core/src/plugins/manifest-registry.ts`: **regenerated** by `npm run plugins:generate`, not hand-edited
- `packages/core/src/index.ts`: export `traceSpan` and `getCurrentTrace` so third-party plugins can add spans and cache events
- Plugin docs (`docs/` or `www/`; match where existing plugin docs live)

---

## 4. Tasks (TDD, commit after each)

### Task 0: Worktree
```bash
cd /Users/lane/Dev/refs/sonicjs && git fetch origin
git worktree add ../sonicjs-query-trace -b lane711/query-trace-plugin origin/main
cd ../sonicjs-query-trace && npm install && npm run workspace
```

### Task 1: Core `trace-context.ts` + `trace-span.ts`
```ts
// trace-context.ts
export type CacheOutcome = 'hit' | 'miss' | 'hit:memory' | 'hit:kv' | null
export interface TraceEntry { seq:number; kind:'d1'|'kv'|'cache'; op:string; label:string; fingerprint:string;
  tables:string[]; params:string[]; startMs:number; durationMs:number; d1DurationMs?:number;
  rowsReturned?:number; rowsRead?:number; rowsWritten?:number; servedBy?:string; cache:CacheOutcome;
  span:string; caller?:string; error?:string }
export interface SpanRecord { name:string; startMs:number; durationMs:number; selfMs:number }
export class RequestTrace {
  readonly t0 = performance.now(); entries: TraceEntry[] = []; spans: SpanRecord[] = []
  spanStack: string[] = []; dropped = 0; closed = false
  constructor(readonly method: string, readonly path: string, readonly maxEntries = 1000,
              readonly captureCallers = true) {}
  now() { return performance.now() - this.t0 }
  currentSpan() { return this.spanStack[this.spanStack.length - 1] ?? 'handler' }
  record(e: Omit<TraceEntry, 'seq' | 'span'>) {
    if (this.closed) return
    if (this.entries.length >= this.maxEntries) { this.dropped++; return }
    this.entries.push({ ...e, seq: this.entries.length + 1, span: this.currentSpan() })
  }
}
type ALS<T> = { run<R>(s: T, fn: () => R): R; getStore(): T | undefined }
let alsPromise: Promise<ALS<RequestTrace> | null> | null = null
let als: ALS<RequestTrace> | null = null
/** Better-Auth pattern: dynamic import so builds without nodejs_compat still bundle. */
export function loadAsyncLocalStorage(): Promise<ALS<RequestTrace> | null> {
  alsPromise ??= import(/* @vite-ignore */ /* webpackIgnore: true */ 'node:async_hooks')
    .then((m: any) => m.AsyncLocalStorage)
    .catch(() => (globalThis as any).AsyncLocalStorage ?? null)
    .then((C: any) => (als = C ? new C() : null))
  return alsPromise
}
export const runWithTrace = <R>(t: RequestTrace, fn: () => R): R => (als ? als.run(t, fn) : fn())
export function getCurrentTrace(): RequestTrace | undefined {
  const t = als?.getStore(); return t && !t.closed ? t : undefined
}
```
- `traceSpan`: if there's no current trace, `return mw(c, next)` (zero cost). Otherwise push the name, run `mw` with a wrapped `next` that pops while downstream runs and re-pushes after, then record the span.
- Tests:
  - ALS isolation across interleaved concurrent `runWithTrace` calls
  - `closed` stops recording
  - `getCurrentTrace()` is undefined outside a run
  - `maxEntries` → `dropped`
  - `traceSpan` attributes entries recorded inside middleware vs downstream correctly, and computes `selfMs`

### Task 2: Plugin skeleton + manifest + registry
- `manifest.json`: `id: "query-trace"`, `name: "Query Trace"`, description "Per-request D1/KV/cache tracing panel for admin performance tuning.", `category` (use an existing value from other manifests, e.g. `developer` or `utilities`), `iconEmoji: "⚡"`, `is_core: false`, `defaultActive: false`, `dependencies: []`, `permissions: {}`, and `defaultSettings` per 2.1. Check other manifests to see whether `adminMenu` is required. If a sidebar entry would be noise, omit it and rely on the Plugins page.
- `index.ts`: `definePlugin({ id: 'query-trace', version: '1.0.0', name: 'Query Trace', configSchema: {...2.1}, register(app){ app.route('/admin/plugins/query-trace', queryTraceAdminRoutes) }, activate, deactivate })`.
- Do **not** add it to any bootstrap list (see 2.1: bootstrap force-activates). On a fresh install it must show as available-but-not-installed.
- Run `npm run plugins:generate` and commit the regenerated `manifest-registry.ts`.
- Add it to `core-plugins/index.ts` exports + `CORE_PLUGIN_IDS`, and to `corePluginsBeforeCatchAll` in `app.ts`.
- Tests:
  - the plugin appears in `PLUGIN_REGISTRY`, and `configSchema` defaults equal the manifest's `defaultSettings`
  - on a fresh DB, `PluginBootstrapService` does not install it
  - `getQueryTraceState()` reports inactive
  - install via `PluginService.installPlugin` → active
  - `deactivatePlugin` → inactive

### Task 3: `state.ts`
One query against the **raw** (unwrapped) DB, before tracing starts:
```sql
SELECT json_extract(data,'$.status') AS status, json_extract(data,'$.settings') AS settings
FROM documents WHERE slug = 'query-trace' AND type_id = 'plugin' AND tenant_id = 'default'
  AND is_current_draft = 1 AND deleted_at IS NULL
```
- Cache `{active, settings: applySchemaDefaults(...), fetchedAt}` per isolate for 30 s. On a DB error, treat it as inactive (first boot, unmigrated).
- Wire `invalidateQueryTraceState()` into `PluginService` on install (new + re-install), uninstall, activate, deactivate, and settings update.
- Tests:
  - inactive when there's no row
  - active + merged defaults
  - TTL respected
  - invalidation forces a re-read
  - **stale-after-install regression:** prime the cache as inactive (no row) → `installPlugin` → the next `getQueryTraceState()` is active **without** waiting for the TTL. Same check for re-install after uninstall, and for uninstall → inactive.
  - a DB error gives inactive

### Task 4: core `utils/request-trace/sql-fingerprint.ts`
Tests first:
- literals → `?`
- `IN (?, ?, ?)` → `in (?…)`
- whitespace collapse
- `sqlOp`, where `WITH` maps to SELECT
- `extractTables` handles quoted/backticked names and joins, and dedupes
- `maskParams(['abc', 5, null, true])` → `['string(3)','number','null','bool']`
- `redactSql("SELECT * FROM t WHERE token = 'abc123' AND n = 5 AND b = X'00ff'")` → `SELECT * FROM t WHERE token = ? AND n = ? AND b = ?`. Escaped quotes (`'it''s'`) are handled.
- `redactKey` examples:
  - `settings:general` → `settings:general`
  - `rbac:perms:3f2b…-uuid` → `rbac:perms:<uuid>`
  - `session:abcdef0123456789abcdef` → `session:<redacted:22>` (the segment is letter-led and would match a shape regex, but it's not in the allowlist)
  - `session:secretToken` → `session:<redacted:11>`
  - `user:jane@x.com` → `user:<email>`
  - `page:42` → `page:<n>`
- `identityKey(fp, ['a'])` ≠ `identityKey(fp, ['b'])`; same values → same key; different trace salt → different key
- Allowlist test: every `KNOWN_KEY_SEGMENTS` entry exists as a literal key prefix or namespace in `packages/core/src`. This guards against the list drifting into keeping arbitrary words.

### Task 5: core `utils/request-trace/traced-d1.ts` + `wrap-bindings.ts`
- `getTracedD1(raw)`: one proxy per raw binding (WeakMap). Falsy → passthrough. Every call checks `getCurrentTrace()`; if there is none, call straight through with no timing.
- `prepare(sql)` → wrapper. `bind(...args)` → new wrapper carrying sql + args. `all/first/run/raw` time the call, record, and return the **unchanged** result. Errors are recorded and rethrown. `first(col)` and `raw({columnNames})` keep their semantics.
- **`batch(stmts)` must unwrap** each wrapper to the real `D1PreparedStatement` (hidden `RAW` symbol) before calling `raw.batch`, because workerd type-checks batch members. Record **one parent entry** (`op: 'batch'`, `label: 'batch(N)'`, the shared wall `durationMs`, `d1DurationMs` = Σ member `meta.duration`). Record **one member entry per statement** with `parentSeq` set, `durationMs = d1DurationMs = meta.duration ?? 0`, and per-result rows. Members never get the shared wall time.
- `exec` is recorded. `dump`/unknown pass through via the Proxy `get` trap. `withSession(...)` → `getTracedD1(raw.withSession(...))`.
- The label goes through `redactSql` and `identityKey` is computed from the raw args **before** they are discarded. Raw SQL and raw args are never stored on the entry.
- Caller only when `trace.captureCallers`: `new Error().stack`, skipping frames that contain `request-trace`, `query-trace-plugin`, or `node_modules`.
- Tests (d1-sqlite harness + a mock D1 that returns `meta`):
  - `drizzle(getTracedD1(db))` select/insert inside `runWithTrace` → correct op, tables, and rows
  - `batch` with wrappers succeeds
  - a 10-statement batch gives 1 parent + 10 members, and member `durationMs` ≠ the parent wall time
  - DB Σ counts the parent once
  - labels contain no literals (`WHERE email = 'x@y.com'` → `WHERE email = ?`)
  - no trace → no records and an identical result
  - errors are recorded and rethrown
  - `wrapTraceBindings` is idempotent: wrapping twice returns the same proxies, and a proxied `batch` still unwraps to the raw statements
  - `getTracedD1(proxy) === proxy`

### Task 6: core `utils/request-trace/traced-kv.ts`
Same WeakMap pattern. Keys go through `redactKey`. `get`/`getWithMetadata` record `cache: hit|miss`. `put`/`delete`/`list` are recorded without a cache outcome. Tests mirror Task 5.

### Task 7: Cache plugin instrumentation
In `plugins/cache/services/cache.ts`, `get`, `getWithSource`, and `set` call `getCurrentTrace()?.record({ kind:'cache', … })`. `getMany`/`setMany` record **nothing themselves**: they delegate to `get`/`set` per key, so recording there too would double-count lookups and inflate the dupe analysis. Each records with the `redactKey`-ed key, outcome, and duration. Export `redactKey` from `utils/request-trace` so the cache plugin doesn't import the query-trace plugin. This imports from `utils/request-trace` only. Extend `plugins/cache/tests/cache.test.ts`: inside `runWithTrace` it records memory hit, KV hit, and miss. `getMany(['a','b','c'])` records **exactly 3** cache entries, not 4. Outside a trace it records nothing.

### Task 8: `analyze.ts`
Pure functions for 2.5 + `summarize()` + `groupByFingerprint()` + `serverTimingValue()`. Thresholds come from settings. One fixture test per rule, plus ordering by severity and impact.

### Task 9: `trace-panel.ts`
`renderTracePanel(trace, analysis, settings): string` per 2.4. Tailwind zinc palette, dark-first. `data-testid`s: `trace-summary`, `trace-queries`, `trace-opportunities`, `trace-spans`, `trace-copy-json`. Tests:
- `<script>` in SQL is escaped (`escapeHtml` from `utils/sanitize`)
- rows are sorted by duration desc
- empty state
- dropped count
- `Hide for me` link only in opt-in mode

### Task 10: `queryTraceMiddleware()`
```ts
export const queryTraceMiddleware = (): MiddlewareHandler => async (c, next) => {
  const rawDb = c.env.DB
  // 1. ALWAYS install passthrough proxies (every path, plugin active or not), before bootstrap,
  //    so singletons seeded by ANY request (EmailService, cache plugin KV, firstRequestEnv) hold
  //    proxies, not raw bindings. With no active trace a proxy call = one ALS lookup, no recording.
  c.env = wrapTraceBindings(c.env) as typeof c.env           // core util, idempotent; boot() applies it too (cron path)
  const url = new URL(c.req.url)
  const p = url.pathname
  if (p !== '/admin' && !p.startsWith('/admin/')) return next()   // not '/administrator', '/admin-foo'
  const state = await getQueryTraceState(rawDb)             // 30s TTL, raw DB (never traced)
  if (!state.active) return next()
  const t = url.searchParams.get('trace')
  if (t === '1' || t === '0') { /* set/delete cookie; url.searchParams.delete('trace'); return c.redirect(url.pathname + url.search) */ }
  const optedIn = getCookie(c, QUERY_TRACE_COOKIE) === '1'
  if (state.settings.visibility !== 'all-admins' && !optedIn) return next()
  if (!(await loadAsyncLocalStorage())) return next()      // warned once in loader
  const trace = new RequestTrace(c.req.method, url.pathname, state.settings.maxEntries, state.settings.captureCallers)
  await runWithTrace(trace, () => next())
  trace.closed = true
  const user = c.get('user') as { role?: string } | undefined
  if (user?.role !== 'admin') return                         // no header, no panel for non-admins / anonymous
  const analysis = analyze(trace, state.settings)
  if (state.settings.serverTimingHeader) c.header('Server-Timing', serverTimingValue(analysis))
  const ct = c.res.headers.get('content-type') ?? ''
  const s = c.res.status
  if (!ct.includes('text/html') || (s >= 300 && s < 400) || c.req.header('HX-Request')) return
  const body = await c.res.text()
  const i = body.lastIndexOf('</body>')
  const out = i === -1 ? body : body.slice(0, i) + renderTracePanel(trace, analysis, state.settings) + body.slice(i)
  const headers = new Headers(c.res.headers); headers.delete('content-length')
  c.res = undefined as any                                   // avoid Hono re-copying content-length
  c.res = new Response(out, { status: s, headers })
}
```
- Note: a `?trace=` toggle from a non-admin sets a cookie that does nothing, which is harmless. The panel still requires the admin role.
- Tests (`app.request()` on a minimal Hono app with mock DB/KV and a stubbed state + user):
  - plugin inactive → response untouched, no header. `c.env.DB` **is** a passthrough proxy and records nothing.
  - **singleton regression:** request 1 (plugin inactive) has a stub module-level service capture `c.env.DB` / `c.env.CACHE_KV`. Request 2 (active + opted-in admin) calls that captured service, and its D1/KV calls appear in request 2's trace.
  - `/administrator` and `/admin-foo` → not traced. `/admin` and `/admin/x` → traced.
  - `all-admins` + anonymous or non-admin request → **no `Server-Timing` header** and no panel
  - active + opt-in + no cookie → untouched
  - active + cookie + admin + HTML → panel + `Server-Timing` + no stale `content-length`
  - `all-admins` without cookie → panel
  - non-admin → no panel and no header
  - admin `HX-Request` → header only
  - JSON → untouched
  - redirect → untouched
  - `?trace=1` → `Set-Cookie` + 302 to the clean URL
  - two concurrent requests → each panel lists only its own queries
  - ALS unavailable → passthrough

### Task 11: Plugin admin page (`routes/admin.ts`)
`GET /admin/plugins/query-trace`, rendered with `wrapAdminPage` from `core-plugins/_shared/admin-template.ts`. Shows:
- active state and current visibility mode
- ALS availability
- an "Enable for me" / "Disable for me" form posting to `/admin/plugins/query-trace/me`
- a link to the plugin settings page. Check which route the Plugins page uses for `configSchema` settings (`/admin/plugins/:id` vs `/:id/configure`) and link to that.

Gate it the same way other plugin admin pages are gated (admin role or `plugins:manage`). Route tests.

### Task 12: Wire `app.ts`
0. In `boot()` (`app.ts:420`), when `!config.plugins?.disableAll`, replace `env` with `wrapTraceBindings(env)` **before** `firstRequestEnv = env`, `initEmailService(env)`, and `wirePlugins()`. This covers cron-first isolates where `scheduled()` calls `boot(env)` without any HTTP middleware. On the HTTP path `c.env` is already wrapped, so the call is a no-op (idempotent).
   - **Cron-first regression test:** call `app.boot(rawEnv)` as a `scheduled()` handler would, with no HTTP request first. Then make an opted-in admin request whose handler calls a service seeded by `boot` (e.g. `getEmailService()`'s DB / a plugin hook's captured env). Those D1/KV calls appear in the trace.
1. `if (!config.plugins?.disableAll) app.use('*', queryTraceMiddleware())` **immediately before** the appVersion middleware (L405). Under `disableAll` it isn't mounted at all: no proxies, no tracing, no response rewrite. That matches how `app.ts:721-722` gates plugin routes. Test: a `disableAll` app never wraps bindings and never adds the panel or header, even when a `query-trace` row is active.
2. Wrap the existing middleware with `traceSpan(...)` per 2.3, **behavior otherwise identical**. Example: `app.use('*', traceSpan('bootstrap', bootstrapMiddleware(...)))`, `app.use('/admin/*', traceSpan('requireAuth', requireAuth()))`.
3. `npm run type-check && npm test`. The full suite must stay green (main pipeline touched).

### Task 13: E2E `tests/e2e/127-query-trace-plugin.spec.ts`
Use the existing login and plugin helpers in `tests/e2e/utils` (look for how other specs activate plugins). Restore plugin state in `afterAll` so other specs aren't affected.
1. Fresh install (default) → Admin → Plugins lists Query Trace as available, not installed. `/admin/dashboard?trace=1` → no `#sjs-trace-panel`, no `Server-Timing`.
2. Install it from Admin → Plugins (that makes it active) → visit `/admin/dashboard` without the cookie → no panel (opt-in default).
3. `/admin/dashboard?trace=1` → redirected to the clean URL. The panel exists and is collapsed, and the summary matches `/\d+ ms server/` and `/\d+ D1/`.
4. Expand it → the queries table has ≥1 row, row[0] ms ≥ row[1] ms, and the Cached column has a value matching `not cached|hit|miss`.
5. `/admin/content` and `/admin/users` → the panel persists, and the response has a `Server-Timing` header.
6. Settings → `visibility = all-admins` → clear the cookie → the panel shows without opt-in. Reset to `opt-in`.
7. `?trace=0` → the panel is gone. Deactivate the plugin → `?trace=1` has no effect. `afterAll`: uninstall to restore the fresh-install state.
8. Anonymous request to `/admin/dashboard` while active + `all-admins` → no `Server-Timing` header.

`npm run e2e` must pass in full (Lane's rule: never merge unless **all** checks including e2e pass).

### Task 14: Docs
Plugin doc page:
- activation, settings, and the opt-in flow
- every column and finding explained, with "how to act on it"
- the `nodejs_compat` note
- the Workers timer note: `performance.now()` advances only across I/O, so pure-CPU template time reads ~0. DB/KV timings are accurate.
- not captured: outbound `fetch`, R2
- security: admin-only, masked params, opt-in cookie

### Task 15: PR
Push and open a PR to `main` with screenshots (dashboard + content list, panel expanded) plus the plugin settings page. Monitor CI and report back (standing rule). **Don't merge**: Lane reviews, and merges and releases only happen after 8 PM PT.

---

## 5. Phase 2 (separate PRs, optional)
- **HTMX partial traces:** append a `<template hx-swap-oob="beforeend:#sjs-trace-htmx">` row to traced `HX-Request` responses, giving the panel a "Partial requests" list. Deferred because of the `<tr>`-fragment swap edge cases. `Server-Timing` already covers partials in DevTools.
- **EXPLAIN QUERY PLAN** button per SELECT row → `POST /admin/plugins/query-trace/explain`:
  - admin + CSRF
  - SELECT-only
  - SQL + params passed as an HMAC-signed token, so arbitrary SQL can't be submitted
  - shows `SCAN` vs `SEARCH USING INDEX` inline
- **History:** per-route summaries (p50/p95 DB ms, query count) in KV or a plugin table, with a "slowest admin pages" view on the plugin page.
- Outbound `fetch` and R2 (`MEDIA_BUCKET`) tracing.
- A per-tenant toggle for multi-tenant installs.

## 6. Risks / open questions
1. **Visibility default:** `opt-in` (cookie) vs `all-admins`. The plan defaults to opt-in so activating it in prod doesn't surprise other admins. Switchable in settings.
2. **Cross-isolate lag:** activate, deactivate, and settings changes propagate to other isolates within ≤30 s (TTL). Acceptable for a dev tool.
3. **ALS:** loaded the same way Better Auth does it. Without `nodejs_compat`, it's a graceful no-op with a notice.
4. **Core touch points and overhead budget.** These are kept minimal and passthrough when idle. The claim is a **bounded overhead target**, not "no overhead": `getCurrentTrace()` (one property read), `traceSpan` (one check), one cache-service call per op, and one middleware.
   - Inactive overhead per request: an env spread + two WeakMap lookups. Per DB/KV call: one Proxy hop + one ALS lookup, and while ALS has never been loaded that's a null check.
   - Admin requests add one in-memory state read (plus one D1 read per isolate per 30 s).
   - Proxies are always on (unless `disableAll`) so that the full E2E suite exercises them on every run.
   - **Budget:** inactive-path overhead ≤ **2 µs per D1/KV call** and ≤ **20 µs per request** for the env spread, both measured in Node with `traced-proxy.bench.ts` (raw mock D1 vs proxied mock D1, 100k `prepare().bind().first()` calls). Real D1 round-trips are milliseconds, so this is well under 0.1% of a query.
   - Paste the bench numbers into the implementation PR. If the budget is blown, fall back to wrapping only after the plugin has been active once in the isolate, and accept that singletons seeded earlier are documented as untraced.
5. **Masked params:** values are never shown. A `showParamValues` setting could come later for local dev.
6. **Possible nav-strip `content-length` bug** (`app.ts:637-645`). Note it in the PR and fix separately.

## 7. Done criteria
- [ ] `Query Trace` appears in Admin → Plugins as available (not installed) on a fresh install. Install or activate turns it on; deactivate or uninstall turns it off, per installation. Settings are editable.
- [ ] Inactive: zero behavior change. Bindings are passthrough proxies that record nothing, and there's no panel or header. Under `disableAll` the middleware isn't mounted.
- [ ] Labels, keys, and exported JSON contain no SQL literals, raw key identifiers, or bound values. Identical-repeat detection uses only the private per-request key.
- [ ] Batch wall time is counted once. Singleton-held bindings are traced.
- [ ] Active: the panel is at the bottom of every full admin page for eligible admins, collapsed, slowest first.
- [ ] Every D1 query (raw + Drizzle, including `batch`), KV op, and cache lookup is listed with cached status, D1 vs wall time, rows, dupes, span, and caller. Opportunities, fingerprint groups, spans, Copy JSON, and `Server-Timing` are all present.
- [ ] Non-admins and anonymous requests never get the panel or the `Server-Timing` header. Only `/admin` and `/admin/*` are traced.
- [ ] `npm run type-check`, `npm test`, `npm run e2e` green in CI. PR open and not merged.
