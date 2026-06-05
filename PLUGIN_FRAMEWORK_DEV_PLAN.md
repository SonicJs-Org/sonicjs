# Plugin Framework — Phased Development Plan

> Execution-ready task breakdown to take the SonicJS v3 plugin framework to **production-ready**
> (Phases 1–3) and **future-proof** (Phase 4). Derived from `PLUGIN_FRAMEWORK_CONVERGENCE_PLAN.md`
> and the locked decisions below. Companion to (not replacement for) that analysis doc.
>
> **Base of record:** SonicJS core on `lane711/plugin-system-define`. Infowall
> (`/Users/lane/Dev/refs/infowall-ai-main`) is a read-only design reference to cross-check ports against.
>
> **Task format:** each task lists **Goal / Files / Change / Tests / Done-when** and a size
> (S ≈ hours, M ≈ 1–2 days, L ≈ 3–5 days). Every task keeps the core suite green + `tsc` + lint clean.

---

## Decisions locked (these are settled — do not relitigate mid-build)

1. **SonicJS core is the single canonical framework.** Infowall is a reference, not a merge target. No two-SDK co-maintenance.
2. **Hook API = name-map** (`interface HookEventPayloads` + `on('name', payload)`). Augmentable via declaration merging (third-party typed events) — this is the future-proofing reason. Reject the discriminated-union shape.
3. **Content events = before/after split** (`content:before:create` + `content:after:create`, …). Adopt from Infowall. Drop `content:save`. Keep `content:read`.
4. **Cron stays OFF the hook catalog** — separate `dispatchCronTick`/`onCronTick`. Cron is a scheduled invocation, not a lifecycle event.
5. **Capability spellings = SonicJS** (`media:*`, `http:fetch`, `db:<table>`, `admin:menu`, `cron:register`, `hooks.<family>:subscribe`). Add a one-directional rename map for Infowall spellings. **Drop `request:intercept`** until a real middleware-insertion surface exists.
6. **Actor shape = `user: { id, email, role? }` everywhere** (fix the `userId`/`id` bug).
7. **Substrate = SonicJS** (promise-memoized once-guard, `createServiceSingleton<T>`, provider-agnostic `EmailProvider`). Retire Infowall's hand-written singletons + boolean-after-await guard.
8. **Posture = resilient-by-default, strict-in-dev/CI.** Production isolates per-plugin errors; a `strict` flag turns unknown-capability / missing-cap / dependency-cycle / bad-semver into throws.

---

## Phase map & cut lines

| Phase | Theme | Ships in | Gate |
|---|---|---|---|
| **1** | Contract alignment (shapes final) | extend PR **#844** | shapes frozen; nothing downstream built against moving targets |
| **2** | Make hooks + capabilities REAL (dispatch + enforcement) | new branch → PR | a plugin can subscribe and actually fire; security gate live |
| **3** | Ordering + cron liveness + reconciliation + observability | new branch → PR | **← PRODUCTION-READY cut line** |
| **4** | Structure, distribution, versioning, hardening | new branch(es) → PR | **← FUTURE-PROOF cut line** |

Phase 1 must land before 2–4 start. Within a phase, tasks marked `∥` can run in parallel.

---

## Phase 1 — Contract Alignment (extend #844)

Lowest-risk, highest-leverage. Freeze the public shapes so nothing later is built against names/payloads that change. All breaking catalog changes ship with a **one-release alias window** (old name still works, emits a deprecation `console.warn` on subscribe).

### T1.1 — Unify the actor shape to `user.id` `[S]`
- **Goal:** kill the live bug where content payloads expose `user.userId` and auth payloads expose `user.id`.
- **Files:** `packages/core/src/plugins/hooks/catalog.ts`.
- **Change:** define one `interface HookActor { id: string; email: string; role?: string }`; use `user?: HookActor` in `ContentEventPayload` and `user: HookActor` in the auth payloads. Re-key content's `userId`→`id`.
- **Tests:** extend the `__typeChecks` block in `typed-hooks.test.ts`; add a runtime assertion that a dispatched event's `user.id` is populated.
- **Done when:** no payload in the catalog uses `userId`; tsc + tests green.

### T1.2 — Re-key the hook catalog to before/after + prune + extend `[M]`
- **Goal:** adopt the before/after model; add the two auth events SonicJS lacks; drop dead events.
- **Files:** `catalog.ts` (`HookEventPayloads`, `HOOK_EVENT_NAMES`), `typed-hooks.ts` (alias resolution), `__tests__/plugins/wire-integration.test.ts`, `typed-hooks.test.ts`.
- **Change:**
  - Add `content:before:{create,update,delete}` (gate/transform) + `content:after:{create,update,delete}` + `content:after:publish`. Keep `content:read`.
  - Add `auth:magic-link:consumed`, `auth:otp:verified`.
  - **Alias map** `LEGACY_EVENT_ALIASES: Record<string, HookEventName>` = `{ 'content:create':'content:after:create', 'content:update':'content:after:update', 'content:delete':'content:after:delete', 'content:publish':'content:after:publish' }`. In `createTypedHooks().on()`, if a legacy name is used, resolve it and `console.warn` a deprecation once.
  - Drop `content:save` (deprecate via alias to `content:after:update` for one release, then remove).
- **Tests:** catalog `__typeChecks` for new names; alias resolution + single deprecation warn; update `wire-integration.test.ts` to the new names (and see T2.7 — it gets rewritten to a real route in Phase 2).
- **Done when:** new catalog is canonical; legacy names still resolve with a warn; tests green.

### T1.3 — Capability rename map + normalization + posture flip `[S]` `∥`
- **Goal:** future-proof capability naming; stop silently ignoring unknown caps.
- **Files:** `packages/core/src/plugins/capabilities.ts`, `plugins/sdk/define-plugin.ts`.
- **Change:**
  - Add `CAPABILITY_RENAMES: Record<string, Capability>` (one-directional, Infowall→canonical): `storage:read→media:read`, `storage:write→media:write`, `hooks.cron:register→cron:register`, `hooks.auth:register→hooks.auth:subscribe`, `hooks.content-read:register→hooks.content:subscribe`, `hooks.content-write:register→hooks.content:subscribe`, `hooks.email-events:register→hooks.email:subscribe`.
  - Add `normalizeCapability(input): Capability | null` (apply renames, then check `isKnownCapability`).
  - Add `hooks.email:subscribe` to `FIXED_CAPABILITIES` (placeholder for when email events ship). **Do not** add `request:intercept`.
  - In `definePlugin`, normalize declared caps on the way in; in **strict** mode, unknown cap → throw; in prod → loud `console.warn` (today it's a soft warn that "gates nothing").
- **Tests:** rename resolution table; unknown cap throws in strict / warns in prod; `media:*` etc. unchanged.
- **Done when:** Infowall-spelled caps normalize to canonical; unknown caps are never silently accepted.

### T1.4 — Const-generic `Caps` narrowing on `definePlugin` `[M]` `∥`
- **Goal:** `ctx.cap.email` resolves to `EmailService | never` at compile time, not `unknown`.
- **Files:** `plugins/sdk/define-plugin.ts`, `plugins/capabilities.ts` (the gated-context type).
- **Change:** `definePlugin<const Caps extends readonly Capability[]>(input: DefinePluginInput<Caps>): DefinedPlugin<Caps>`; type the gated context so each accessor is present only if its capability is in `Caps`. Keep the runtime lazy throwing getters underneath (defense-in-depth).
- **Tests:** `@ts-expect-error` reading `ctx.cap.email` without `'email:send'` in `Caps`; positive case is typed `EmailService`.
- **Done when:** capability typing is shift-left; no runtime change; tsc green.

### T1.5 — Declarative `hooks` field on `DefinePluginInput` `[S]` `∥`
- **Goal:** let authors declare hooks statically, not only imperatively in `onBoot`.
- **Files:** `plugins/sdk/define-plugin.ts`, `plugins/wire.ts` (already subscribes `WirablePlugin.hooks`).
- **Change:** add `hooks?: { [E in HookEventName]?: TypedHookHandler<E> }`; in `definePlugin`, flatten it into the existing `hooks[]` array the wire phase already consumes. Keep `ctx.hooks.on()` in `onBoot` as the dynamic escape hatch.
- **Tests:** a plugin with a declarative `hooks` entry fires through `wireRegisteredPlugins`.
- **Done when:** both declarative and imperative subscription paths work and are tested.

### T1.6 — Fix the email DB-settings bypass `[S]` `∥`
- **Goal:** the admin-UI email path should honor the provider-agnostic resolver + safe degrade, not hardcode Resend.
- **Files:** `packages/core/src/app.ts` (`initEmailService`, ~L289), `services/email/resolve-provider.ts`, `services/email/db-settings.ts`.
- **Change:** route the DB-settings branch through `resolveEmailProvider` (so a misconfigured key degrades to Console, not a broken Resend); apply `DbEmailSettings.replyTo` as a default (dropped today).
- **Tests:** admin-UI SendGrid selection resolves SendGrid; missing key degrades to Console; `replyTo` applied.
- **Done when:** no hardcoded `new ResendProvider(...)` in `app.ts`.

**Phase 1 exit:** catalog + capabilities + authoring shapes are final; legacy names alias with warnings; full suite green; tsc + lint clean. Land in #844.
**Status: ✅ DONE** — commit `7ad63cca1` (T1.6), see Appendix D.

---

## Phase 2 — Make Hooks & Capabilities Real (Phase 5d)

The "stop shipping an inert API" phase. Today a plugin subscribing to anything **never fires**, and `hooks.*:subscribe` **gates nothing**. New branch off #844.

### T2.1 — Dispatch auth events from `routes/auth.ts` `[M]`
- **Goal:** fire `auth:registration:completed`, `auth:password-reset:requested`, `auth:password-reset:completed`.
- **Files:** `packages/core/src/routes/auth.ts`, a small `dispatchHookEvent` helper (new, in `plugins/hooks/`).
- **Change:** add a thin helper `dispatchEvent(c, name, payload)` that resolves the singleton hook system and dispatches **fire-and-forget via `c.executionCtx.waitUntil`** (never blocks the response; never throws into the request). Add dispatch calls at the existing success points **alongside** the current direct `getEmailService().send()` (additive — don't rip out working sends yet).
- **Tests:** real-route integration — POST the reset route, assert a subscribed plugin handler ran with the typed payload.
- **Done when:** the three auth events fire on real requests; response latency unchanged.

### T2.2 — Dispatch magic-link + OTP events `[S]` `∥`
- **Files:** `plugins/available/magic-link-auth/index.ts`, `plugins/core-plugins/otp-login-plugin/index.ts`.
- **Change:** dispatch `auth:magic-link:consumed` on successful verify; `auth:otp:verified` on successful OTP verify (via the same `waitUntil` helper).
- **Tests:** real-route tests for each.

### T2.3 — Dispatch content lifecycle events `[M]`
- **Goal:** fire `content:before:*` (gate/transform) + `content:after:*` + `content:read`.
- **Files:** the content write/read paths — `services/content` and/or `routes/api` content CRUD (locate the canonical write path; grep for the content insert/update/delete).
- **Change:** `before` hooks run **in-band** (can mutate/cancel — handlers return the payload or throw to cancel); `after` hooks run fire-and-forget. Additive alongside existing logic.
- **Tests:** a `before:create` handler that mutates data is reflected in the stored row; an `after:create` handler observes the created row.
- **Done when:** content events fire on real CRUD; the transform contract (mutate-and-return) is tested.

### T2.4 — Hook-subscription capability gate `[M]`
- **Goal:** close the security gap — subscribing to an event requires the matching capability.
- **Files:** `plugins/capabilities.ts` (new `HOOK_CAPABILITY_MAP`), `plugins/wire.ts` (Phase A).
- **Change:** `HOOK_CAPABILITY_MAP: Record<HookEventName, Capability>` (`auth:* → hooks.auth:subscribe`, `content:* → hooks.content:subscribe`, etc.). In `wire.ts` Phase A, before registering a plugin's hook, assert the plugin declared the required cap; reject with `SonicCapabilityError` (strict) / skip + warn (prod). Keys off `HookEventName` (requires Phase 1's unified names).
- **Tests:** a plugin subscribing `content:after:create` without `hooks.content:subscribe` is rejected; with it, allowed.
- **Done when:** no ungated hook subscription is possible.

### T2.5 — Strict unknown-capability + error shape `[S]` `∥`
- **Files:** `plugins/sdk/define-plugin.ts`, `plugins/capabilities.ts`.
- **Change:** unknown declared capability → hard throw in strict mode (uses `validateCapabilities`). Add **optional** `accessedApi?` to `SonicCapabilityError` (non-breaking — existing `{capability, plugin}` fields unchanged); changelog it.
- **Tests:** strict throws; prod warns; error shape carries `accessedApi` when set.

### T2.6 — `no-event-without-dispatch-site` CI test `[S]` `∥`
- **Goal:** prevent regressing to an inert catalog.
- **Files:** `__tests__/plugins/no-event-without-dispatch-site.test.ts` (new).
- **Change:** for every name in `HOOK_EVENT_NAMES`, assert a non-test source occurrence of `dispatch('<name>'` (or the helper) exists. Allowlist any intentionally-not-yet-dispatched event explicitly (none should remain after T2.1–2.3).
- **Done when:** the test fails if someone adds a catalog event without a dispatcher.

### T2.7 — Re-route `wire-integration.test.ts` `[S]` `∥`
- **Change:** rewrite it to drive a **real HTTP route** → subscriber fires, instead of manually calling `dispatch`. Removes false confidence that the bus works while production fires nothing.

**Phase 2 exit:** a `definePlugin` plugin can subscribe to auth/content events and **actually fire**; subscription is capability-gated; CI prevents inert events. New PR stacked on #844.
**Status: ✅ DONE** — commit `ce08884aa`. See Appendix E.

> **Implementation note (cancel semantics):** The underlying `HookSystemImpl.execute` swallows non-CRITICAL errors from handlers (they are logged + chain continues). For in-band before-hooks to hard-cancel a write, the handler must throw `new Error('CRITICAL: ...')`. Full soft-cancel semantics (any throw = cancel) require a hook system upgrade and are tracked for Phase 3.

---

## Phase 3 — Ordering + Cron Liveness + Reconciliation + Observability (Phase 6) → **PRODUCTION-READY**

New branch. This is the phase that makes cron and dependency ordering real and closes observability.

### T3.1 — Dependency topo-sort + cycle detection `[M]`
- **Goal:** make `dependencies` actually drive order (today inert).
- **Files:** `plugins/mount.ts` + `plugins/wire.ts` (or a shared `plugins/topo-sort.ts`), new `PluginDependencyCycleError`.
- **Change:** `topoSort(plugins)`: DFS with a `visiting` Set, returns dependency-first order, throws on cycle. Operate on the structural `{ id/name, dependencies? }` shape (cast-free). Wire into both mount order and wire order. Cross-check against Infowall `register-plugins.ts` `topoSort`.
- **Tests:** `[B(deps:[A]), A]` → A before B; cycle throws; missing dep id → strict reject / prod warn.

### T3.2 — Extract `bootIsolate(env, …)` from the app closure `[L]`
- **Goal:** make the wire phase + email init reachable outside the HTTP middleware (the real blocker for cron).
- **Files:** `packages/core/src/app.ts` (extract `initEmailService` + the wire trigger), new exported `plugins/boot.ts`.
- **Change:** `export async function bootIsolate(env, { hooks, plugins, config }): Promise<void>` that runs the **promise-memoized once-guarded** wire pass + `initEmailService(env)` (+ bootstrap/migrations if the cron path needs DB). The HTTP middleware calls `bootIsolate` instead of its inline closures, sharing the same guard. Expose the resolved plugin list from `createSonicJSApp`.
- **Tests:** a fresh isolate whose first event is `scheduled()` ends up with a populated hook bus and reachable `getEmailService()`; warm isolate = no-op second run.
- **Done when:** boot logic is env-only and shared by HTTP + cron paths.

### T3.3 — Wire `scheduled()` end-to-end `[M]`
- **Files:** `plugins/cron.ts` (`createScheduledHandler`), `my-sonicjs-app/src/index.ts`.
- **Change:** `createScheduledHandler` calls `bootIsolate(env, …)` **before** `dispatchCronTick`. The reference app exports `{ fetch: app.fetch, scheduled: createScheduledHandler(...) }`. Enforce `cron:register` at registration; add 5-field cron-expression validation at declaration (both forks silently no-op on malformed today).
- **Tests:** cron integration — fired trigger → `bootIsolate` → `onCronTick` runs with a live hook bus + reachable email.

### T3.4 — `wrangler.toml [triggers]` offline codegen `[S]` `∥`
- **Goal:** `[triggers]` is deploy-time static on Workers — generate it, don't pretend it's dynamic.
- **Files:** `collectCronSchedules()` (exists in `cron.ts`), a new `scripts/generate-cron-triggers.*`, CI check.
- **Change:** a sync command that reads the app's configured plugins and **writes** `[triggers] crons` into `wrangler.toml`; CI asserts the committed triggers match the configured `crons[]`.

### T3.5 — Per-provider reconciliation + observability migration `[M]`
- **Files:** `services/email/types.ts` (`EmailProvider.reconcile?`), new core `email-reconciliation` cron, `packages/core/migrations/<NN>_email_log_observability.sql`, `db/schema.ts`.
- **Change:** optional `reconcile(rows)` on `EmailProvider`; a core cron (via `crons[]`+`onCronTick`) that populates `delivery_state`/`delivery_synced_at` (CF provider real; Resend/SendGrid no-op until they expose delivery webhooks). Migration adds **only** `user_id`, `context_type`, `context_id`, `tenant_id` + partial indexes (the status/delivery columns already exist in `037`). Use the **next free migration number** at implementation time; add a **CI guard for duplicate migration prefixes**. Columns nullable/no-default (forward-only D1, NULL-safe).
- **Tests:** reconcile populates `delivery_state`; migration applies cleanly; `writeLog` never references new columns pre-migration.

### T3.6 — `CloudflareEmailProvider` + email-as-`definePlugin` `[M]` `∥`
- **Files:** `services/email/providers/cloudflare.ts` (new), `plugins/core-plugins/email-plugin/`.
- **Change:** add CF `send_email` binding provider as a 4th transport. Repackage the email plugin as a `definePlugin()` plugin (declares `email:send`, `db:email_log`, cron for reconciliation) to prove the v3 authoring story — replacing the legacy `PluginBuilder` admin plugin whose `/test` calls `fetch('https://api.resend.com/emails')` directly.

**Phase 3 exit (PRODUCTION-READY):** dependency ordering real; cron fires end-to-end incl. cron-first cold isolates; reconciliation populates delivery state; observability columns + admin-visible. New PR.

---

## Phase 4 — Structure, Distribution, Versioning, Hardening (Phase 7) → **FUTURE-PROOF**

Can overlap Phase 3 partially; T4.1 is independent and high-value.

### T4.1 — Stop committing `dist/`; fix the src/dist `Plugin` identity `[M]`
- **Files:** `.gitignore`, `packages/core/tsconfig.json` (`paths`), the handful of core-plugin self-imports (`import { Plugin } from '@sonicjs-cms/core'`), a runtime identity test, `prebuild` guarantee.
- **Change:** gitignore `packages/*/dist/`; map `@sonicjs-cms/core`/`/*` to `./src` in tsconfig **and** convert core-plugin self-imports to relative `../../` (sidesteps the barrel self-cycle); add a CI step that fails if `dist` is older than `src`; add a test asserting the `Plugin` symbol has one identity via package-entry vs `src`. This dissolves the dual-identity problem that forced the structural `MountablePlugin`/`WirablePlugin` casts.
- **Done when:** `git status` is clean of `dist`; structural contracts can tighten off `any`.

### T4.2 — Build-time plugin-registry generator `[M]`
- **Change:** a script that reads installed plugin packages and emits a static, tree-shakeable registry import map (replaces the legacy manifest-registry the admin reads). Workers has no runtime `fs`, so this is build-time.

### T4.3 — Versioning / semver compat gate `[S]` `∥`
- **Files:** `plugins/sdk/define-plugin.ts` (`DefinePluginInput`), `plugins/plugin-validator.ts`.
- **Change:** add `sonicjsVersionRange?: string`; reconcile with the validator's legacy `compatibility` field; validate at registration against the running core version; `semver.valid()` reject for the plugin's own `version`.

### T4.4 — DB activation reflection + admin `email_log` browser `[M]` `∥`
- **Change:** `wire.ts` best-effort reflects the actually-wired `plugins.register` list into the `plugins` table so the admin view stops drifting. Add an admin `email_log` browser showing submit `status` + delivery `delivery_state`.

### T4.5 — Shared author mock harness `[S]` `∥`
- **Change:** publish `__tests__/utils/mock-factories.ts` (`makeMockD1Database`/`makeMockKVNamespace`/`makeMockHonoContext`/`makeMockEmailService`/`makeMockHookSystem`) so third-party authors have one importable test primitive (port the shape from Infowall; 5+ inline fakes exist today).

### T4.6 — Dogfood + v3-SDK e2e `[M]`
- **Change:** migrate `my-sonicjs-app` to `plugins.register` + a `scheduled` handler (today it bypasses the framework: `autoLoad:false`, hand-loops `contactFormPlugin.routes`, wraps `coreApp`). Add one e2e: "drop a plugin into `plugins.register` → routes + hooks + cron work."

### T4.7 — Retire legacy `PluginBuilder` `[L]`
- **Change:** migrate core plugins to `definePlugin` one-by-one (email first, done in T3.6); make `PluginBuilder` a thin shim that calls `definePlugin`; remove only once no core plugin (`workflow-plugin`, etc.) depends on it.

**Phase 4 exit (FUTURE-PROOF):** clean tree, single type identity, build-time distribution, versioning gate, dogfooded reference app, retiring legacy SDK.

---

## Suggested sequencing & parallelism

- **Sprint 1 (start now):** Phase 1 entirely (T1.1→T1.6; T1.3–T1.6 parallelize after T1.1/T1.2 land the catalog). → extend #844, merge.
- **Sprint 2:** Phase 2 (T2.1–T2.3 dispatch in parallel; T2.4 after Phase 1 names; T2.5–T2.7 parallel). → new PR.
- **Sprint 3:** Phase 3 (T3.2 `bootIsolate` is the critical path; T3.1/T3.4/T3.6 parallel). → **production-ready** PR.
- **Sprint 4+:** Phase 4 (T4.1 first — unblocks type tightening; rest parallel). → future-proof.

**Critical path:** T1.2 (catalog names) → T2.4 (gate keys off names) and T3.2 (`bootIsolate`) → T3.3 (cron). Everything else fans off these.

## Definition of done (every task)
1. Core unit + integration suite green (`npm test --workspace=@sonicjs-cms/core`).
2. `tsc --noEmit` clean; `eslint src/` 0 errors.
3. New behavior has a unit **and** (if user-visible) integration test; breaking catalog/cap changes have alias + deprecation-warn tests.
4. Verified live in `my-sonicjs-app` where it touches a request/cron path.
5. Cross-checked against the Infowall reference for any "port" task.

## Risks carried from the analysis
- **Breaking the shipped catalog** (T1.2): mitigated by the one-release alias window + same-change test updates.
- **`bootIsolate` is a real refactor** (T3.2), not a one-liner — both `initEmailService` and the wire trigger are closures inside `createSonicJSApp` today.
- **Reconciliation is non-portable** (T3.5): Infowall's CF-GraphQL reconciler can't be copied; per-provider `reconcile()` is net-new; `delivery_state` stays null for providers without delivery webhooks.
- **Reference-app drift** (T4.6): breaking changes won't surface in `my-sonicjs-app` until it dogfoods the framework.

---

## Appendix E — Phase 2 Status (ce08884aa)

### What landed

| Task | Files | What |
|---|---|---|
| **T2.1** | `routes/auth.ts`, `plugins/hooks/dispatch-event.ts` | Auth dispatch: `auth:registration:completed` (JSON + form routes), `auth:password-reset:requested` (carries resetToken for custom notification plugins), `auth:password-reset:completed` |
| **T2.2** | `plugins/available/magic-link-auth/index.ts`, `plugins/core-plugins/otp-login-plugin/index.ts` | `auth:magic-link:consumed` on successful verify; `auth:otp:verified` on OTP verify |
| **T2.3** | `routes/api-content-crud.ts` | `content:before:create/update/delete` (in-band, payload mutations flow through to DB write); `content:after:create/update/delete` + `content:after:publish` (fire-and-forget); `content:read` (fire-and-forget) |
| **T2.4** | `plugins/capabilities.ts` (`HOOK_CAPABILITY_MAP`), `plugins/wire.ts` | Wire Phase A now gates declarative hook subscriptions by required capability; v3 plugins gated, old PluginBuilder plugins exempt; non-strict warns, strict records SonicCapabilityError |
| **T2.5** | `plugins/capabilities.ts` | `SonicCapabilityError.accessedApi?: string` — optional, non-breaking |
| **T2.6** | `__tests__/plugins/no-event-without-dispatch-site.test.ts` | CI guard: every HOOK_EVENT_NAMES entry must have a `dispatchHookEvent()` call in source |
| **T2.7** | `__tests__/plugins/wire-integration.test.ts` | Rewired to call `dispatchHookEvent()` (same helper production routes use) instead of manually calling `hooks.dispatch()` |

### Key design decisions
- `dispatchHookEvent(c, event, payload, mode)` takes the Hono context and safely extracts `executionCtx` (it's absent in Node test environments — Hono throws on access).
- Cancel semantics: the underlying `HookSystemImpl` swallows non-CRITICAL errors. Hard-cancel requires `throw new Error('CRITICAL: ...')`. Full soft-cancel is a Phase 3 hook-system upgrade.
- `content:before:*` mutations: the returned payload's `data` map is applied to the DB write, so plugins can add/change fields pre-insert.

### Tests: +14 new (`dispatch-event.test.ts` — 7; `no-event-without-dispatch-site.test.ts` — 1; wire-integration — 2 rewritten + 2 kept). Full core suite **1622 passed, 0 failed**; tsc + lint clean.
