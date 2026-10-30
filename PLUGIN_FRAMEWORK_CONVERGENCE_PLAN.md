# Plugin Framework Convergence & Production-Readiness Plan

> Canonical, decisive plan to converge Mark's Infowall fork and the shipped SonicJS v3
> plugin framework into ONE production-ready, future-proof base. Grounded in the
> adversarially-verified dimension comparisons and the actual SonicJS source on this
> branch (`lane711/plugin-system-define`, PRs #841/#842/#844 already merged).
>
> **Verification posture (read first):** every load-bearing claim about *SonicJS* is
> cited to live source on this branch (`packages/core/src/...`) and re-verified. Claims
> about *Infowall* are grounded in Mark's **actual source, which IS available read-only**
> at `/Users/lane/Dev/refs/infowall-ai-main` — a sibling SonicJS fork with the same
> monorepo shape (it is simply not part of THIS repo's build). The relevant SDK lives at
> `infowall-ai-main/packages/core/src/plugins/sdk/{define-plugin,capabilities,events,register-plugins,types}.ts`
> and `.../services/{cron-registry,email-service-singleton,hook-system-singleton}.ts`.
> Two crux dimensions were re-verified directly against that source: the hook-event
> catalog (`sdk/events.ts` — a discriminated union keyed by a `type` field, with
> `auth:*`/`cron:tick` fully typed and `content:*`/`app:*`/`request:*` carrying a
> permissive index signature) and the capability vocabulary (`sdk/capabilities.ts` —
> `storage:*`, `hooks.content-{read,write}:register`, plus a real `normalizeCapability()`
> + `CAPABILITY_RENAMES` mechanism). The "port from Infowall" tasks below are written as
> **self-contained specs** (signature / inputs / outputs / test) so they're buildable on
> their own — AND each can be cross-checked against the cited Infowall file.
>
> *(An earlier synthesis pass wrongly reported Infowall as "out-of-tree/unopenable"; that
> was a tooling artifact — it searched inside this workspace instead of the absolute path.
> Corrected throughout. The Infowall internals cited here came from agents that did read
> the real source.)*
>
> Code referenced (verified live): `packages/core/src/plugins/{mount,wire,cron,capabilities}.ts`,
> `plugins/hooks/{catalog,typed-hooks}.ts`, `plugins/sdk/define-plugin.ts`,
> `plugins/plugin-validator.ts`, `services/email/`, `migrations/037_email_log.sql`,
> `app.ts` (222–330), `my-sonicjs-app/src/index.ts`, `packages/core/tsconfig.json`.

---

## 0. The Infowall reference is available — specs are self-contained, cross-check encouraged

Mark's Infowall fork is readable at `/Users/lane/Dev/refs/infowall-ai-main` (read-only; not built by this repo). So "match Infowall's behavior" **is a verifiable acceptance criterion** — open the cited file and diff the behavior. No phase is gated on availability. Two practices keep it clean:

- **Every "port" task below is a self-contained spec** (signature, inputs, outputs, error posture, named test) — buildable with zero Infowall access. The Infowall citation is verifiable provenance, not a dependency. This is deliberate: the canonical contract should be defined by the spec + tests in *this* repo, not by whatever a sibling checkout happens to contain at a given commit.
- **Optional convenience: vendor a snapshot.** So reviewers needn't have the sibling checkout, copy the ~10 Infowall SDK files (`plugins/sdk/*`, `services/{cron-registry,email-service-singleton,hook-system-singleton}.ts`, the email reference) into `reference/infowall/` (committed, not built). Nice-to-have, not a precondition.

**Decision:** build to the specs in §2/§3 (they are complete on their own); reviewers cross-check each port against `/Users/lane/Dev/refs/infowall-ai-main`. The single thing that genuinely needs Mark's sign-off before Phase 5d is the **convergence *direction*** (§7 OQ1), not reference availability.

---

## 1. Executive Summary

### Where each fork leads (SonicJS verified against this branch; Infowall against `/Users/lane/Dev/refs/infowall-ai-main`)

| Dimension | Leader | One-line reason |
|---|---|---|
| Authoring API | **mixed** | Infowall: const-generic `Caps` narrows `ctx` at compile time + a real plugin migrated. SonicJS: transform-factory with strict-sync `register`, transform-capable handlers, lifecycle hooks. |
| Registration / two-phase boot | **mixed** | SonicJS: promise-memoized once-guard (concurrency-safe, `wire.ts:124-131`), per-plugin error isolation. Infowall: topo-sort + cycle detection + REJECT validation (SonicJS `dependencies` is inert in the v3 path). |
| Hook system & dispatch | **Infowall** | Identical `HookSystemImpl` bus; Infowall has real production dispatch sites, SonicJS has **ZERO** outside tests — its typed catalog is inert. |
| Capabilities & security | **Infowall** | 3 enforcement layers + type narrowing. SonicJS: 1 runtime layer + warn-only validation, **no hook-subscription gate** (`wire.ts:84-85`). **But the canonical capability *vocabulary* already lives in SonicJS** (`capabilities.ts:21-32`) — see §2.4 / §3.2. |
| Cron / scheduled | **Infowall** | Infowall fires end-to-end + live reconciliation. SonicJS cron is **inert** (`createScheduledHandler` exists at `cron.ts:168` but is never wired into a Worker entry). |
| Singleton services | **SonicJS** | Generic `createServiceSingleton<T>` + promise-memoized guard (no race). Infowall: hand-written near-duplicates + boolean-after-await race + a warmup-fetch hack. |
| Email reference impl | **mixed** | SonicJS: provider-agnostic `EmailProvider` (Resend/SendGrid/Console) + safe degrade + `email_log` that **already** carries the status spine. Infowall: CF-binding-locked but has the live reconciler. |
| Testing & DX | **mixed** | SonicJS: type-level `__typeChecks`, cron-dispatch glue tested, once-guard concurrency tested. Infowall: blessed `mock-factories.ts`, real-route dispatch tests, a migrated reference plugin. |
| Code structure / type identity | **mixed** | SonicJS: structural contracts bridge the `src`/`dist` dual-`Plugin` identity (but erode types to `any`) + commits `dist/`. Infowall: single `SonicPlugin<Caps>`, gitignored `dist`. |
| Production-readiness / future-proofing | **mixed** | Infowall: REJECT posture, live cron+reconciliation. SonicJS: error isolation, `db:<table>` ownership, provider-agnostic email, concurrency-safe guard. |

### The convergence thesis

**SonicJS is the base of record; we port Infowall's enforcement, dispatch, and ordering into it.**

1. **SonicJS already shipped** (#841/#842/#844) and is the live codebase here. Infowall is the reference to harvest from, not rebase onto.
2. **SonicJS owns the better *substrate*** — promise-memoized once-guard, per-plugin error isolation, generic singleton factory, provider-agnostic email, `db:<table>` ownership, the augmentable-interface catalog, strict-sync `register` typing, **and the already-converged capability vocabulary**.
3. **Infowall owns the better *rigor*** — it actually *fires* hooks, *enforces* capabilities at the hook-subscription layer, *orders* by dependency with cycle detection, and *runs* cron+reconciliation end-to-end.

### What the long pole actually is (corrected)

The original plan called "contract alignment" the headline and lumped the capability vocabulary in with it. **That is half wrong.** The capability *vocabulary* is **already converged on the SonicJS side**: `FIXED_CAPABILITIES` (`capabilities.ts:21-32`) already ships `media:read/write`, `http:fetch`, `cron:register`, `admin:menu`, `hooks.auth:subscribe`, `hooks.content:subscribe`, plus the `db:<table>` pattern. There is **no `storage:*` in SonicJS to rename**. So the capability work is small: a one-directional **Infowall→canonical rename map** + flipping **warn→reject**.

The real long pole is three things, all on the SonicJS side:

1. **Hook catalog + real dispatch** — zero production dispatch sites; the catalog is inert (§2.3, §3.3).
2. **Cron + wire-phase reachability from `scheduled()`** — not just email-init; the **entire wire phase is HTTP-gated** and never runs in the scheduled path (§2.5, §2.6).
3. **Capability *enforcement* at the hook-subscription boundary** — the confirmed security regression (§2.4).

Contract alignment still goes first (do it in #844 so nothing is built against shapes that change), but it is the **hook catalog/payloads**, not the capability vocab, that carries the weight.

---

## 2. Per-Dimension Decisions

Each decision is final and grounded in verified SonicJS source. "Port" = bring Infowall's mechanism into the named SonicJS files, implemented to the self-contained spec below and cross-checked against the cited Infowall file at `/Users/lane/Dev/refs/infowall-ai-main`.

### 2.1 Authoring API → **Keep SonicJS's transforming `definePlugin`; ADD const-generic `Caps` and a declarative `hooks` map**

**Winner: merge, SonicJS shape wins.** `definePlugin(input): DefinedPlugin` (`sdk/define-plugin.ts:166`) is the base — it throws on missing `id`/`version`, enriches `onBoot`/`onCronTick` with a typed+gated context, carries lifecycle hooks (`install/uninstall/activate/deactivate`), and emits `__sonicV3`. Keep all of it.

**Port (self-contained spec; cross-checkable against `infowall-ai-main/.../sdk/define-plugin.ts`):**
- **Const-generic capability narrowing.** Re-type as `definePlugin<const Caps extends readonly Capability[]>(input: DefinePluginInput<Caps>): DefinedPlugin<Caps>` so `ctx.cap.email` resolves to `EmailService | never` instead of today's `unknown` (`capabilities.ts:109-113`). Pure DX shift-left; no runtime change. Keep SonicJS's runtime lazy getters underneath as defense-in-depth.
  - *Test:* `@ts-expect-error` when reading `ctx.cap.email` without `'email:send'` in `Caps`; positive case resolves to `EmailService`.
- **Declarative `hooks` field on `DefinePluginInput`.** Add `hooks?: { [E in HookEventName]?: TypedHookHandler<E> }`. The runtime **already** supports declarative `hooks[]` via `WirablePlugin.hooks` + `wireRegisteredPlugins` Phase A (`wire.ts:75-91`); this is surfacing a typed field and threading it into the existing array, not a new engine. Effort: LOW. Keep imperative `ctx.hooks.on()` in `onBoot` as the dynamic-subscription escape hatch.

**Keep SonicJS-strictly-better:** `register?: (app: Hono) => void` typed strictly synchronous (`define-plugin.ts:88`); the strict-sync guard (`PluginRegisterMustBeSyncError`) is correct. Keep transform-capable handlers (`TypedHookHandler` returns `HookPayload<E> | void`, void-coalesced at `typed-hooks.ts:79`) — pub/sub-only handlers cannot gate/mutate writes.

### 2.2 Registration & two-phase boot → **Keep SonicJS's structure; PORT topo-sort + cycle detection; ADD opt-in strict mode**

**Winner: merge, SonicJS structure wins.** Keep the `mount.ts` (sync construction) / `wire.ts` (async lazy) split, per-plugin error isolation (`result.skipped`, `result.errors`, "wiring never throws"), and the strict-sync `register` guard (`mount.ts:63`).

**Take SonicJS's promise-memoized once-guard wholesale** (`createPluginWirer` caches the in-flight promise, `wire.ts:124-131`). This is the correct fix for Infowall's boolean-set-after-await race. **Do NOT regress to a boolean guard.**

**Port — dependency ordering (self-contained spec):**
- Add `topoSort(plugins)`: DFS with a `visiting`-Set for cycle detection, returning a dependency-first ordering, throwing `PluginDependencyCycleError` (new, exported) on a cycle. Operate on the **structural** `MountablePlugin`/`WirablePlugin` contracts so it stays cast-free. Signature: `topoSort(plugins: ReadonlyArray<{ id: string; dependencies?: string[] }>): typeof plugins`.
- Make `DefinedPlugin.dependencies` actually drive ordering. Today it is **inert** — neither `mount.ts` nor `wire.ts` reads it (verified: `magic-link-auth`'s `dependencies: ['email']` is convention-only). Wire `topoSort` into both mount order and wire order.
  - *Test:* `[B(deps:[A]), A]` wires `A` before `B`; `[A(deps:[B]), B(deps:[A])]` throws `PluginDependencyCycleError`; a missing dependency id is a strict-mode reject / prod warn.

**Add opt-in strict mode (dev/CI):** a `strict` flag surfacing `capability_missing` / unknown-capability / cycle / bad-semver as throws at registration, with resilient per-plugin capture as the production default. Posture is a deliberate, configurable decision — never an accident of which code was copied.

### 2.3 Hook system & event catalog → **Keep `HookSystemImpl`; KEEP SonicJS's typed catalog; PORT real dispatch sites (highest-value action)**

**Winner: Infowall on dispatch reality; SonicJS on typing.** The bus (`HookSystemImpl`) is the convergence anchor; no work there.

**Keep SonicJS's catalog representation:** `interface HookEventPayloads` (`catalog.ts:54-67`) + the `satisfies`-guarded `HOOK_EVENT_NAMES` runtime list (`catalog.ts:85-95`) + declaration-merging extensibility. Strictly better-typed than Infowall's `{type, [key]:unknown}`.

**THE decisive action — instrument real dispatch sites.** Verified: SonicJS's v3 hook surface is **inert** — zero `dispatch`/`execute` of any `content:*`/`auth:*` catalog event outside tests; production auth/email call `getEmailService().send()` directly. A v3 plugin subscribing to `content:create` or `auth:registration:completed` **never fires today.** Port (additively):
- **Auth** (fire-and-forget via `executionCtx.waitUntil`): `auth:registration:completed`, `auth:password-reset:requested`, `auth:password-reset:completed` in `routes/auth.ts`; `auth:magic-link:consumed`, `auth:otp:verified` in their plugin routes.
- **Content** (before/after split): in the content service / `api-content-crud` write paths.

Add dispatch sites as a **thin additive layer alongside** the existing working direct sends (lower risk than ripping out direct calls), then migrate consumers to events.

**⚠ This is a breaking change to the *shipped* catalog, not greenfield.** `catalog.ts` already ships `content:create/update/delete/read/publish/save` (no before/after), and `wire-integration.test.ts:62` **dispatches `content:create`** and asserts a subscriber fires. Renaming to `content:after:create` + dropping `content:save` breaks that shipped catalog and its passing test. Therefore (see §3.3):
- Treat the rename as a **breaking catalog change with a one-release alias window** (`content:create` aliases `content:after:create`, emitting a deprecation warn on subscribe).
- Update `wire-integration.test.ts` expectations **in the same change**, and rewrite it to drive a **real route** rather than a manual `dispatch` (so it certifies the production flow, not just the bus).

**Transform contract: KEEP SonicJS's mutate-and-return.** Required for before-hooks to gate/mutate writes; already tested.

### 2.4 Capabilities & security → **Keep SonicJS's already-canonical vocab + `db:<table>` + lazy getters; PORT hook-subscription enforcement + type narrowing (the real gap)**

**Winner: Infowall on enforcement; SonicJS owns the vocabulary AND the base.** Correcting the original plan: SonicJS's runtime lazy gated getters (`createCapabilityContext`, `capabilities.ts:127-158`), its `db:<table>` ownership, **and its capability names** (`FIXED_CAPABILITIES`, `capabilities.ts:21-32`) all stay. The vocabulary is **not** a future merge target — it already is the canonical set.

**Port the enforcement (SonicJS's confirmed security regression):**
1. **Hook-subscription gating — the one true security gap.** `wire.ts:84-85` registers every declared hook with **no capability check**; `hooks.auth:subscribe`/`hooks.content:subscribe` gate nothing. Build a `HOOK_CAPABILITY_MAP: Record<HookEventName, Capability>` mapping each (now-unified) event name to its required cap, and reject-on-miss in `wire.ts` Phase A. **Caveat (verified):** SonicJS subscribes by arbitrary `hook.name` string with no closed-catalog check at the wire boundary, so closing the gap requires the unified event names from §3.3 to land first; the map keys off `HookEventName`, not free strings.
   - *Test:* a plugin declaring `hooks.content:subscribe`-less but subscribing `content:after:create` is rejected with `SonicCapabilityError`; declaring the cap allows it.
2. **Validation → throw (strict).** Upgrade `definePlugin`'s warn-only unknown-capability check (`define-plugin.ts:172-178`, "These will gate nothing") to a hard fail in strict mode. `validateCapabilities` already returns the unknown set (`capabilities.ts:84-86`); only the caller's disposition changes.
3. **Type-level narrowing** per §2.1.

**Reconcile `SonicCapabilityError` — and version it as breaking.** Current shape (`capabilities.ts:52-63`) is `{ capability, plugin }`. Adding `accessedApi` and applying it both sides is a **breaking change to an exported error** (anyone catching/inspecting it). Ship the new shape `{ capability, plugin, accessedApi? }` with `accessedApi` **optional** so existing consumers don't break, document it in the changelog as a shape change, and keep the existing fields' names unchanged.

**Shared immaturity (track, don't per-fork):** only `email` is operationally wired; `media`/`cache`/`http`/`cron` providers are unwired; `db:`/`media:`/`admin:menu`/`hooks.*` gate nothing at runtime beyond subscription; ambient `c.env` is ungated; read/write granularity is cosmetic (`:read` still grants `.put`). Follow-ups, not blockers.

**Drop or define `request:intercept` (was kept blindly).** SonicJS has **no middleware-plugin mechanism** — plugins mount routes (`mount.ts`) and `register(app)` synchronously; there is no capability-gated middleware-insertion surface. Keeping `request:intercept` would gate nothing, repeating the exact anti-pattern this plan condemns. **Decision: DROP `request:intercept` from the canonical vocabulary** until a real middleware-insertion surface exists; reintroduce it together with that surface (tracked in §5.4 Phase 2).

### 2.5 Cron → **Keep registry-free direct-dispatch; WIRE the entry; make the wire phase reachable from `scheduled()`; enforce `cron:register`; per-provider reconciliation**

**Winner: Infowall on liveness; SonicJS's model is cleaner.** Keep `dispatchCronTick` over the plugin LIST (`cron.ts:111-136`) and `createScheduledHandler` (`cron.ts:168`) — no `CronRegistry`, no cold-isolate empty-registry, no warmup fetch. **Do NOT add `cron:tick` to the typed catalog.**

**Cron action #1 — wire the Worker entry.** Verified inert: `my-sonicjs-app/src/index.ts:56` is `export default app` (plain Hono, no `scheduled:`); no `[triggers]` in `wrangler.toml`; no plugin declares `crons[]`.
- `createSonicJSApp` must **expose the resolved plugin list** (today private: `corePluginsBeforeCatchAll` + `corePluginsAfterCatchAll` + `config.plugins.register`, `app.ts:233-253`).
- The reference app hand-assembles its outer Hono (`index.ts:44-54`, `app.route('/', coreApp)`), so the export `{ fetch: app.fetch, scheduled: ... }` goes on **that** entry.

**Cron action #2 — make the wire phase reachable from `scheduled()` (the bigger, previously-missed gap).** Verified: `wirePlugins()` runs **only** inside `app.use('*')` (`app.ts:314`) and `initEmailService` runs there too (`app.ts:319`). The scheduled path has no `c.env`, no middleware chain — so in a **cron-first cold isolate, plugin wiring never runs, `onBoot` never ran, and `getHooks()` returns an empty bus.** A plugin whose `onCronTick` dispatches a hook fires into a void, and `getEmailService()` throws-before-get. Fix:
- **Extract `initEmailService` and the wire trigger out of the `createSonicJSApp` closure into exported, env-only functions** — this is a real refactor, not a one-liner (both are currently closures at `app.ts:269` and `app.ts:252`, neither exported, neither reachable from `cron.ts`). Target API:
  - `export async function bootIsolate(env, { hooks, plugins, config }): Promise<void>` that runs the once-guarded wire pass + `initEmailService(env)` (and bootstrap/migrations if the cron path needs DB).
- `createScheduledHandler` calls `bootIsolate(env, …)` **before** `dispatchCronTick`, sharing the same promise-memoized once-guard the HTTP path uses, so a warm isolate is a no-op and a cron-first isolate is correctly initialized.
  - *Test:* a fresh isolate whose first event is `scheduled()` has a populated hook bus and a reachable `getEmailService()`; the HTTP path remains a no-op second time.

**`[triggers]` is deploy-time static — `collectCronSchedules()` is an OFFLINE codegen step, not runtime.** Verified constraint: Cloudflare `wrangler.toml` `[triggers] crons` cannot be generated from runtime state on Workers. So:
- Ship `collectCronSchedules()` as a **sync command** that reads the app config offline and **writes `wrangler.toml`** `[triggers]` (codegen), with a CI check that the committed `[triggers]` matches the configured plugins' `crons[]`. The plan does **not** pretend triggers can be dynamic.

**Enforce `cron:register`** at `definePlugin`/registration — reject a `crons[]`/`onCronTick` declaration when `cron:register` is absent. **Add 5-field cron-expression validation** at declaration time (both forks silently no-op on malformed schedules). **Do NOT** inherit Infowall's unconditional legacy-workload firing (no `event.cron` guard).

**Reconciliation is net-new and per-provider.** Infowall's reconciler is CF-GraphQL-specific and does NOT port to Resend/SendGrid. Add optional `reconcile(rows)` on `EmailProvider` + a core `email-reconciliation` cron (via `crons[]`+`onCronTick`) to populate `delivery_state` (`migration 037`, always null today).

### 2.6 Singleton services → **Keep the generic factory; SOLVE cron-first-isolate reachability via the extracted boot fn; close DI #561 as won't-fix**

**Winner: SonicJS.** Adopt `createServiceSingleton<T>(label)` as the shared base for ALL singletons (throw-before-get + idempotent-last-write-wins + reset, test-proven), retiring Infowall's two hand-written files.

**Solve cron-first-isolate reachability** — see §2.5's `bootIsolate` extraction. The original "have `createScheduledHandler` call `initEmailService(env)`" is **infeasible as written**: `initEmailService` is a closure inside `createSonicJSApp` (`app.ts:269`), not exported, not reachable from the standalone `createScheduledHandler` factory (`cron.ts:168`). The fix is the extraction refactor in §2.5, and it must also run the **wire pass**, not just email init.

**Close DI #561 as "won't fix — superseded by the env-independent factory."** The env-independent access requirement (cron runs outside any request) is inherent to Cloudflare's per-request-binding model; the generic factory makes it a clean, testable seam. Keeping the factory while leaving #561 "delete singletons" open is contradictory dead work.

**Tighten SonicJS's `initEmailService`** to share the wiring promise rather than relying on the benign `hasEmailService()` double-run window (`app.ts:270`).

### 2.7 Email reference impl → **Keep the provider-agnostic core; ADD CF as a 4th provider; the status spine ALREADY exists; fix the DB-settings bypass**

**Winner: mixed, SonicJS transport model wins.** Keep `EmailProvider { name; isConfigured(); send(NormalizedEmailMessage) }` with Resend/SendGrid/Console + safe degrade-to-Console (`resolve-provider.ts:73-81`). Add a **fourth `CloudflareEmailProvider`** (CF `send_email` binding) so CF is one transport among many.

**Correction: the two-column status spine is ALREADY in SonicJS.** Verified `037_email_log.sql` already has `status`, `delivery_state`, `delivery_synced_at`, `failed_at_send`, `flow`, `provider`, `provider_id`. So "port the spine" is **already done**. The genuinely missing columns are only `user_id`, `context_type`/`context_id`, `tenant_id`, and partial indexes (§3.4). Do **not** re-derive existing columns.

**Fix the SonicJS DB-settings bypass:** `app.ts:289` hardcodes `new ResendProvider(...)` instead of routing through `resolveEmailProvider`, so the admin-UI path is Resend-locked and skips the degrade-to-Console safety. Route through `resolveEmailProvider` and apply `DbEmailSettings.replyTo` as a default (dropped today).

**Package SonicJS email as a `definePlugin()` plugin** to prove the v3 authoring story. Today the registered `emailPlugin` is still the legacy `PluginBuilder` admin-UI plugin whose `/test` calls `fetch('https://api.resend.com/emails')` directly.

**Keep both leak-closures** (they converge on outcome): SonicJS closes #574 via direct-call (`auth.ts`, never returns the link). Once auth events fire (§2.3), password-reset email can move to the event path without reopening the leak.

### 2.8 Testing & DX → **Union the suites; ADD a shared mock harness; close the two correctness gaps; concrete catalog-coverage gate**

**Winner: mixed.** Each fork's tested layer is the other's blind spot.
- **SonicJS contributes:** cron-dispatch glue, type-level `__typeChecks()` with `@ts-expect-error`, once-guard concurrency (`Promise.all` → `bootCount===1`), provider/degrade tests.
- **Infowall contributes:** real-route dispatch tests that exercise a **live emitter**, and the blessed `mock-factories.ts` (`makeMockD1Database`/`makeMockKVNamespace`/`makeMockHonoContext`/`makeMockEmailService`/`makeMockHookSystem`).

**Build a single published author-facing mock harness** (port `mock-factories.ts` into SonicJS `__tests__/utils/`). 5+ inline hook-system fakes already exist; without one harness, third-party authors have no importable test primitive.

**Close the two correctness gaps, both test-gated:**
- (a) Add production dispatch sites (§2.3) so the green wire/typed-hooks tests stop certifying a dead API. **Rewrite `wire-integration.test.ts` to drive a real route**, not a manual `dispatch` — today (`:62`) it dispatches the event itself, certifying the bus, not the production flow (false confidence on Risk #2).
- (b) The once-guard fix is already SonicJS's.

**Make the catalog-coverage rule a concrete, named deliverable** (it's cheap and prevents the exact "inert but green" regression): a test `no-event-without-dispatch-site.test.ts` that, for every name in `HOOK_EVENT_NAMES`, asserts a matching `dispatch('<name>'` source occurrence exists outside `__tests__`. Specify it now; don't leave it a vague checkbox.

**Add ONE v3-SDK e2e** and make `my-sonicjs-app` dogfood `plugins.register` + a `scheduled` handler — it currently bypasses the framework (`autoLoad:false`, hand-loops `contactFormPlugin.routes`, wraps `coreApp`; verified `index.ts:40-54`).

### 2.9 Code structure & type identity → **Stop committing `dist/`; fix the self-import identity at BOTH compile-time and runtime**

**Winner: mixed.** SonicJS's structural contracts (`MountablePlugin`/`WirablePlugin`/`CronablePlugin`/`HookSystemLike`) bridge the `src`/`dist` dual-`Plugin` identity but erode types to `any` (`mount.ts:53`, `typed-hooks.ts:25-27`).

**Fix the root cause — do these together:**
1. **Stop committing `dist/`.** Gitignore `packages/*/dist/`. The committed `dist` + dirty tree (40 D / 24 M / 40 untracked) is actively misleading.
2. **Fix the identity split at BOTH halves (the original plan fixed only the compile-time half).** Core plugins self-import `import { Plugin } from '@sonicjs-cms/core'`, resolving via the `node_modules` symlink to `package.json` `types: ./dist/index.d.ts` while runtime modules live in `src`.
   - **Compile-time:** add to `packages/core/tsconfig.json` `paths` (which already maps `@sonicjs-cms/templates`, verified `:12-15`) → `"@sonicjs-cms/core": ["./src/index.ts"]`, `"@sonicjs-cms/core/*": ["./src/*"]`. **Risk flagged:** the barrel `src/index.ts` could self-resolve `@sonicjs-cms/core` back to itself; verify no import cycle through the barrel (prefer mapping the deep `src/*` paths and converting the handful of core-plugin self-imports to relative `../../` imports, which sidesteps the barrel entirely — Infowall imports `definePlugin` via relative `../../sdk`).
   - **Runtime (the missing half):** path-mapping only affects *typecheck*; the runtime still loads `dist` via the symlink and is **stale if not rebuilt**. Add a `prebuild`/watch guarantee **and** a test that imports through the package entry and asserts `Plugin` identity at runtime. Gitignoring `dist` + path-mapping alone dissolves only the compile-time half.
   - *Test:* `instanceof`/structural identity check importing the same symbol via the package entry and via `src` resolve to one identity; a CI step fails if `dist` is older than `src`.

**Then tighten the contracts.** Once the identity split is gone the structural contracts become optional; keep them (cast-free user plugins) but tighten `any`/`unknown` toward typed `Hono<{ Bindings; Variables }>` signatures.

### 2.10 Production-readiness & future-proofing → **Sequence: vocabulary/payloads → real dispatch → enforcement → cron/reconciliation+DB reflection → schema reconciliation**

The one net-new item beyond prior dimensions: **reflect v3 registration into the DB `plugins` table** (best-effort, non-fatal) so the admin view (`admin-plugins.ts`) stops drifting from the actually-wired `config.plugins.register` list.

---

## 3. Contract Alignment (HIGHEST PRIORITY — but it's the HOOK CATALOG, not the cap vocab)

Until this lands, **every plugin is fork-specific and we do not advertise cross-compatibility.** Two artifacts; note the asymmetry corrected from the original plan.

### 3.1 The portability problem (verified)

- **Capabilities — mostly already converged.** SonicJS's `FIXED_CAPABILITIES` already IS the canonical set. The only work is a one-directional **Infowall→canonical rename map** + flipping warn→reject. This is **not** the long pole.
- **Hook events — the real long pole.** Names differ, payload *shapes* are internally inconsistent even within SonicJS (see below), and dispatch *reality* differs (Infowall fires; SonicJS fires nothing). This carries the weight.

### 3.2 CAPABILITY vocabulary — Infowall ADOPTS SonicJS's existing vocab (rescoped)

**Decision: SonicJS's shipped vocabulary IS canonical. Add a one-directional `CAPABILITY_RENAMES` (Infowall→canonical) + flip the unknown-capability posture from warn to reject.** No SonicJS rename is needed — there is no `storage:*` here.

| Canonical (already in SonicJS) | Infowall spelling (migrates via rename map) | Note |
|---|---|---|
| `email:send` | `email:send` | identical |
| `cache:read` / `cache:write` | same | identical |
| `media:read` / `media:write` | `storage:read` / `storage:write` | **canonical already SonicJS**; rename Infowall in |
| `http:fetch` | *(none)* | SonicJS-only; gate egress |
| `db:<table>` | *(none)* | SonicJS-only; keep `/^db:[a-zA-Z_][a-zA-Z0-9_]*$/` |
| `admin:menu` | *(none)* | SonicJS-only |
| `cron:register` | `hooks.cron:register` | cron is a direct method, not a subscription |
| `hooks.auth:subscribe` | `hooks.auth:register` | `:subscribe` matches pub/sub |
| `hooks.content:subscribe` | `hooks.content-write:register` + `hooks.content-read:register` | one cap; before/after granularity lives in the event |
| `hooks.email:subscribe` *(add when email events ship)* | `hooks.email-events:register` | follows the `hooks.<family>:subscribe` rule |
| ~~`request:intercept`~~ | `request:intercept` | **DROPPED** (§2.4) — no middleware surface to gate |

**`CAPABILITY_RENAMES` seed (one-directional, Infowall→canonical):** `storage:read→media:read`, `storage:write→media:write`, `hooks.cron:register→cron:register`, `hooks.auth:register→hooks.auth:subscribe`, `hooks.content-write:register→hooks.content:subscribe`, `hooks.content-read:register→hooks.content:subscribe`, `hooks.email-events:register→hooks.email:subscribe`. **Suffix rule:** `hooks.<family>:subscribe` for subscription caps; `<service>:<verb>` for service caps.

**Enforcement:** unknown cap → **hard reject** (strict) / **loud warn** (prod), never silent. Implement in `validateCapabilities` callers + the `HOOK_CAPABILITY_MAP` (§2.4). The `media:read`/`media:write`/`http:fetch`/`cron:register`/`admin:menu`/`hooks.auth:subscribe`/`hooks.content:subscribe` rows are **"already canonical, no SonicJS change."**

### 3.3 HOOK-EVENT catalog (canonical) — breaking change with an alias window

**Decision: SonicJS's augmentable `interface HookEventPayloads` + `satisfies`-guarded runtime list, RE-KEYED to before/after content + a SINGLE unified actor shape, pruned to events with a real dispatch site.** This is a **breaking change to the shipped catalog** (`content:create`→`content:after:create`, drop `content:save`), shipped with a one-release alias window and updated tests (§2.3).

**FIX the actor-shape inconsistency (verified internal bug).** Today the shapes disagree *within SonicJS*:
- content payload: `user?: { userId: string; email; role }` (flat, `catalog.ts:25`) — uses **`userId`**.
- auth payloads: `user: { id: string; email; role }` (`catalog.ts:29-31`) — uses **`id`**.

A plugin author reading `user.id` on content or `user.userId` on auth gets `undefined`. **Decision: ONE canonical actor shape across all events — `user?: { id: string; email: string; role?: string }` (use `id`, not `userId`).** Re-key the content payload from `userId`→`id` as part of #844a; this is itself a breaking field rename and rides the same alias/deprecation window.

| Concept | Canonical | Was (SonicJS) |
|---|---|---|
| Pre-create (gate/transform) | **`content:before:create`** | *(none)* |
| Post-create | **`content:after:create`** | `content:create` (alias 1 release) |
| Pre/Post-update | **`content:before:update`** / **`content:after:update`** | `content:update` (alias) |
| Pre/Post-delete | **`content:before:delete`** / **`content:after:delete`** | `content:delete` (alias) |
| Read | **`content:read`** | `content:read` |
| Publish | **`content:after:publish`** | `content:publish` (alias) |
| Save | **DROP** | `content:save` (deprecate; covered by create/update) |
| Registration done | **`auth:registration:completed`** | same |
| PW reset requested | **`auth:password-reset:requested`** `{ user:{id,email}, resetToken }` | same |
| PW reset completed | **`auth:password-reset:completed`** | same |
| Magic-link consumed | **`auth:magic-link:consumed`** | *(none)* |
| OTP verified | **`auth:otp:verified`** | *(none)* |

**Payload rule:** unified `user?: { id, email, role? }` everywhere. Content keeps the concrete `ContentEventPayload { collection, id?, data, user? }` (with `user.id`, not `userId`).

**Cron is NOT a catalog event** (§2.5). **Prune the dead** — every catalog event must have a real dispatch site landing in the same change.

### 3.4 `email_log` schema — additive ONLY (most columns already exist)

**Correction (verified against live `037`):** `delivery_state`, `delivery_synced_at`, `failed_at_send`, `flow`, `provider`, `provider_id` are **already present**. The original plan's "add `failed_at_send` (already present)" was self-contradicting. The migration adds **4 columns + partial indexes, nothing else.**

| Concept | In `037` today | Action |
|---|---|---|
| Submit status `status` {pending,sent,failed} | ✅ present | keep |
| `failed_at_send` epoch | ✅ present | **no-op** (was wrongly listed as "add") |
| `delivery_state` / `delivery_synced_at` | ✅ present (null) | populate via per-provider reconcile (§2.5) |
| `flow` / `provider` / `provider_id` | ✅ present | keep |
| `user_id` | ❌ | **ADD** |
| `context_type` / `context_id` | ❌ | **ADD** |
| `tenant_id` | ❌ | **ADD** |
| Partial indexes (status/synced-at hot paths) | ❌ (5 plain indexes exist) | **ADD partial indexes** |

**Migration numbering:** highest today is `037`; `038` is free **now**, but this plan spans phases during which other migrations may land. **Use "the next free number at implementation time," not a hardcoded `038`,** and **add a CI guard for duplicate migration prefixes** (none exists today). Name it `<NN>_email_log_observability.sql`.

**Rollback / forward-only story (D1):** D1 migrations are forward-only on Workers. The 4 new columns are **nullable with no default**, so a half-applied migration leaves existing rows valid (NULLs) and in-flight writes unaffected — `writeLog` stays best-effort and never references the new columns until the migration is confirmed applied (gated by the bootstrap migration runner). No backfill is required; observability of pre-migration rows degrades gracefully to NULL. Document this explicitly in the migration header.

---

## 4. Production-Readiness Checklist

Before third parties build plugins, ALL must be true. Each is test-gated.

### 4.1 Real dispatch sites (hooks fire)
- [ ] `auth:registration:completed`, `auth:password-reset:requested`, `auth:password-reset:completed` dispatched from `routes/auth.ts` via `executionCtx.waitUntil` (never blocks the response).
- [ ] `auth:magic-link:consumed`, `auth:otp:verified` from their plugin routes.
- [ ] `content:before:*` / `content:after:*` / `content:read` from the content write/read paths.
- [ ] **Real-route integration test** (rewritten `wire-integration.test.ts`) drives an actual HTTP route → subscriber fires; it no longer manually `dispatch`es.
- [ ] **Named CI test `no-event-without-dispatch-site.test.ts`**: every `HOOK_EVENT_NAMES` entry has a non-test dispatch site (the concrete remediation for Risk #2).

### 4.2 Error handling & isolation
- [ ] Production default: per-plugin isolation preserved (`mount.ts` skip, `wire.ts` capture, `cron.ts` isolate — never throw).
- [ ] Strict mode (dev/CI): unknown-capability, `capability_missing` on hook subscription, dependency cycle, bad semver all **throw** at registration.
- [ ] `register()` async return is a hard error (already: `PluginRegisterMustBeSyncError`).
- [ ] Only SonicJS's promise-memoized `createPluginWirer` guard is used — no boolean-after-await.

### 4.3 Observability (`email_log` browser)
- [ ] Migration `<NN>_email_log_observability.sql` adds `user_id`, `context_type/id`, `tenant_id` + partial indexes (existing columns untouched); forward-only/NULL-safe documented.
- [ ] CI guard: no duplicate migration prefixes.
- [ ] Admin `email_log` browser shows submit-side `status` + delivery-side `delivery_state`.
- [ ] Per-provider `reconcile()` populates `delivery_state`.
- [ ] `writeLog` stays best-effort (logging failure never fails the send) and never references new columns pre-migration.

### 4.4 Security
- [ ] Hook-subscription gating live (`HOOK_CAPABILITY_MAP` keyed by `HookEventName` + reject) — closes the regression.
- [ ] Unknown caps rejected (strict) / loudly warned (prod) — never silent; `CAPABILITY_RENAMES` applied on load.
- [ ] `SonicCapabilityError` shape `{ capability, plugin, accessedApi? }` (`accessedApi` optional → non-breaking), changelogged.
- [ ] Type narrowing live: `ctx.cap.email` is `EmailService | never`, not `unknown`.
- [ ] `request:intercept` is NOT in the vocabulary until a middleware surface exists.
- [ ] Documented honest boundary: ambient `c.env` and raw Hono `app` are NOT capability-gated.

### 4.5 Cron
- [ ] `scheduled:` handler wired in the reference Worker entry; resolved plugin list exposed from `createSonicJSApp`.
- [ ] **`bootIsolate(env, …)` (extracted from the `createSonicJSApp` closure) runs the once-guarded wire pass + email init BEFORE `dispatchCronTick`** — verified test: cron-first cold isolate has a populated hook bus and reachable `getEmailService()`.
- [ ] `collectCronSchedules()` is an **offline codegen sync command writing `wrangler.toml` `[triggers]`**; CI checks committed triggers match config. (`[triggers]` is acknowledged deploy-time static.)
- [ ] `cron:register` enforced; 5-field expression validated at declaration; no unconditional legacy-workload firing.
- [ ] Cron integration test: fired trigger → `bootIsolate` → `onCronTick` → email/reconcile end-to-end.

### 4.6 DX & reference app
- [ ] `my-sonicjs-app` migrated to `plugins.register` + `definePlugin` + `scheduled` (dogfoods the framework).
- [ ] Shared `mock-factories.ts` published for third-party authors.
- [ ] One v3-SDK e2e: "drop a plugin into `plugins.register` → routes + hooks + cron work."

---

## 5. Future-Proofing

### 5.1 Distribution (npm + build-time registry on Workers)
- Plugins ship as npm packages exporting a `definePlugin(...)` default; consumers import and add to `plugins.register: []`. No filesystem auto-loading (Workers has no runtime `fs`; today's `directory`/`autoLoad` is deprecated and should be removed, not extended).
- **Build-time registry generator:** a script that reads installed plugin packages and emits a static, tree-shakeable `plugin-registry.ts` import map, replacing the legacy manifest-registry the admin reads.
- `definePlugin` output is already npm-portable (`__sonicV3` marker for detection).

### 5.2 Versioning & compatibility
- **Connect the existing semver gate — but reconcile the field-name mismatch first (verified).** `plugin-validator.ts:374/394` runs `semver.satisfies`/`intersects` against the **legacy `Plugin.compatibility`** field, which `DefinePluginInput` does **not** have. So you cannot just "connect the existing gate." Add `sonicjsVersionRange?: string` to `DefinePluginInput`, and either (a) map `sonicjsVersionRange`→the validator's `compatibility` key at the boundary, or (b) generalize the validator to read whichever field is present. Validate at registration against the running core version.
- Add explicit `semver.valid()` reject for the plugin's own `version`.

### 5.3 Marketplace
- The reconciled vocabulary (§3) is the precondition. "Verified plugin" badge requires: caps all known + gated, all subscribed events in the catalog, version-range satisfied, no dependency cycle.
- DB-reflected activation (§2.10) gives the admin UI a single source of truth.

### 5.4 Isolation / sandboxing
- Phase 1 boundary: the curated capability-gated service surface (email/cache/http/media/db). Documented as NOT covering ambient `c.env`/raw `app`.
- Phase 2 (deferred, tracked): method-level read/write enforcement (today `:read` still grants `.put`), egress gating wired to `http:fetch`, a decision on hiding raw `env`, **and a real middleware-insertion surface that finally makes `request:intercept` enforceable** (only then is that cap reintroduced).

### 5.5 The src/dist `Plugin` type-identity problem
- Resolved per §2.9: gitignore `dist/` + self path-mapping (compile-time) **+ a runtime identity test + prebuild/watch guarantee** (runtime). Path-mapping alone dissolves only the compile-time half.

### 5.6 Legacy-adapter retirement
- Both forks still ship `plugins/sdk/plugin-builder.ts`. SonicJS core plugins (`email`, `hello-world`, `workflow`) still author via it.
- Migrate core plugins to `definePlugin` one-by-one (start with `email`, §2.7), keep `PluginBuilder` as a thin shim that internally calls `definePlugin`, then remove it once no core plugin depends on it. Do NOT remove until the migration is complete (`workflow-plugin/index.ts` still uses it).

---

## 6. Phased Roadmap (mapped onto the SonicJS PR stack)

Each phase is test-gated (keep the core suite green + add listed tests) and tsc-clean. Ported behavior is cross-checked against the Infowall reference at `/Users/lane/Dev/refs/infowall-ai-main`. The only cross-team prerequisite before Phase 5d is Mark's sign-off on the convergence **direction** (§7 OQ1) and the contract changes (§3).

### Add to #844 (current branch) — small, high-value finishers
- **#844a — Contract alignment (§3):** land the `CAPABILITY_RENAMES` map (Infowall→canonical; SonicJS vocab unchanged) + flip warn→reject posture; re-key the hook catalog to before/after with a **one-release alias window**, drop `content:save`, **unify the actor shape to `user.id` everywhere** (fixes the `userId`/`id` split), and **update + real-route-ify `wire-integration.test.ts` in the same change.** *Tests: catalog `__typeChecks`, capability validation matrix, rename-map resolution, alias-deprecation warn, actor-shape consistency.*
- **#844b — definePlugin ergonomics:** const-generic `Caps` narrowing + declarative `hooks` field threaded into existing `hooks[]`. *Tests: `ctx.cap.email` is `EmailService|never`; declarative hook fires through wiring.*
- **#844c — Fix the email DB-settings bypass** (route `app.ts:289` through `resolveEmailProvider`, apply `replyTo`). *Tests: admin-UI SendGrid selection + degrade-to-Console.*

### Phase 5d — Hook dispatch + capability enforcement (NEW)
- Instrument real dispatch sites (auth + content) additively (§2.3, §4.1), honoring the alias window.
- Build `HOOK_CAPABILITY_MAP` keyed by `HookEventName` + reject-on-miss in `wire.ts` Phase A (§2.4).
- Upgrade unknown-capability to strict-reject; ship `SonicCapabilityError` with optional `accessedApi` (non-breaking).
- Add the `no-event-without-dispatch-site` CI test.
- *Gate: real-route integration test proving a `definePlugin` subscriber fires; security test proving an undeclared `hooks.auth:subscribe` is rejected.*

### Phase 6 — Ordering + cron liveness + reachability + reconciliation (NEW)
- Port `topoSort` + cycle detection; make `dependencies` drive order; add `PluginDependencyCycleError` (§2.2).
- **Extract `bootIsolate(env, …)` out of the `createSonicJSApp` closure** (wire pass + email init), wire `createScheduledHandler` to call it before dispatch; expose the resolved plugin list; cron-first-isolate reachability test (§2.5/§2.6).
- Wire `scheduled:` into the reference Worker entry; ship `collectCronSchedules()` as an **offline `wrangler.toml` `[triggers]` codegen** + CI parity check; enforce `cron:register`; 5-field validation.
- Add `EmailProvider.reconcile()` + a core `email-reconciliation` cron; migration `<NN>_email_log_observability.sql` (4 cols + partial indexes only); migration-prefix CI guard (§3.4).
- Add `CloudflareEmailProvider`; package email as a `definePlugin` plugin (§2.7).
- *Gate: cron end-to-end integration test (incl. cron-first isolate); dependency-cycle throws; reconciliation populates `delivery_state`.*

### Phase 7 — Structure, distribution, hardening (NEW)
- Gitignore `dist/`; self path-mapping (compile-time) **+ runtime identity test + prebuild/watch guarantee**; verify no barrel self-cycle; tighten structural contracts (§2.9).
- Build-time plugin-registry generator; reconcile `sonicjsVersionRange` vs the validator's `compatibility` field, then connect the semver gate into the v3 path (§5.1–5.2).
- DB activation reflection in `wire.ts`; admin `email_log` browser; published `mock-factories.ts`; v3-SDK e2e; migrate `my-sonicjs-app` to dogfood the framework (§2.8, §2.10).
- Begin legacy `PluginBuilder` retirement (§5.6).
- *Gate: tsc-clean with `dist` untracked; runtime identity test green; e2e green; admin view matches wired list.*

---

## 7. Risks & Open Questions for Mark

### Risks
1. **Breaking the shipped catalog (top risk).** The before/after re-key + `content:save` drop + actor-shape `userId`→`id` rename are breaking changes to a **shipped** catalog and a **passing** test (`wire-integration.test.ts:62`), not greenfield. Requires the one-release alias window + same-change test updates (§2.3/§3.3). *(The earlier draft listed "out-of-tree reference" as the top risk; that was a verification artifact — Infowall IS readable at `/Users/lane/Dev/refs/infowall-ai-main`, so every port has a verifiable reference and nothing is gated on availability.)*
2. **Convergence direction not yet agreed.** This plan assumes SonicJS is base-of-record and Infowall rebases onto it — adopting SonicJS's name-map hook catalog (dropping Infowall's `type`-discriminated `SonicHookEvent`/`SonicHookHandler<T>`) and SonicJS's capability spellings. If Mark wants the reverse (or a different hook-API shape), §2.1/§2.3/§3 change materially. Resolve OQ1 before Phase 5d.
3. **Inert-but-green API.** SonicJS passes its suite while firing zero catalog events. The `no-event-without-dispatch-site` test is the concrete fix.
4. **Cron readiness is doubly overstated.** Cron is inert AND the entire wire phase is HTTP-gated, so cron-first isolates have an empty hook bus and unreachable email — bigger than email-init. `bootIsolate` extraction is a real refactor; `[triggers]` is deploy-time static (offline codegen only).
5. **Reconciliation is non-portable.** Infowall's CF-GraphQL reconciler can't be copied; per-provider `reconcile()` is net-new; `delivery_state` stays null until it lands.
6. **Type-erosion vs strict typing.** Tightening structural contracts may surface latent `any`-masked mismatches; expect a tsc cleanup pass. Runtime identity is fixed separately from compile-time.
7. **Reference-app drift.** `my-sonicjs-app` bypasses the framework; breaking changes won't surface until Phase 7's dogfooding migration.
8. **Cron vs first-request concurrency (NEW).** A cron and a first HTTP request can run in separate isolates against shared D1. Migration/seed idempotency is the only coordinator. **Decision: out of scope for app code — D1's `CREATE TABLE IF NOT EXISTS` + idempotent seeds handle it; the once-guarded `bootIsolate` is per-isolate, not cross-isolate.** Documented, not engineered further.

### Open questions for Mark
1. **Convergence direction (the one decision that gates everything).** This plan assumes **SonicJS is base-of-record** and Infowall rebases onto it: adopt SonicJS's name-map `HookEventPayloads` catalog (and retire Infowall's `type`-discriminated `SonicHookEvent` + `SonicHookHandler<T>` API), adopt SonicJS's capability spellings via a one-directional `CAPABILITY_RENAMES`, and harvest Infowall's enforcement/dispatch/ordering/cron into it. Confirm this direction — or, if you'd rather keep the discriminated-union hook API, say so now, because it reshapes §2.1, §2.3, and §3.3. *(Reference availability is NOT a question — your source at `/Users/lane/Dev/refs/infowall-ai-main` is readable and was used to ground this plan.)*
2. **Content event granularity + alias window:** confirm before/after canonical and a one-release alias for `content:create`→`content:after:create`. Re-key Infowall's content subscribers, or want a rename adapter on your side?
3. **Actor shape:** confirm unifying to `user.id` (drop content's `userId`) across all events.
4. **Capability suffix:** confirm adopting `hooks.<family>:subscribe` + the one-directional `CAPABILITY_RENAMES`, since it flips Infowall's `:register` spelling. (SonicJS vocab is unchanged.)
5. **`storage:` → `media:`:** OK to rename Infowall's `storage:*` to the canonical SonicJS `media:*`?
6. **`request:intercept`:** OK to DROP it until a real middleware-insertion surface exists (it currently gates nothing in SonicJS)?
7. **DI #561:** close as "won't fix — superseded by the env-independent `createServiceSingleton` factory"?
8. **CF Email transport:** `CloudflareEmailProvider` as a first-class core provider, or in your fork's overlay? (CF-specific; most SonicJS users are Resend/SendGrid.)
9. **Reconciliation ownership:** do you contribute `CloudflareEmailProvider.reconcile()`? Ship Resend/SendGrid reconcilers, or leave them no-op (delivery_state null) until those providers expose delivery webhooks?
10. **Transform contract:** confirm SonicJS's mutate-and-return handlers (over void-only pub/sub) as canonical — required for before-hooks to gate/transform writes; changes the handler signature your fork's plugins were written against.
