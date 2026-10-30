# Plugin SDK — Payload-Shaped Refactor Plan (v3 Greenfield)

**Status**: APPROVED — ready for implementation.
**Branch base**: `origin/v3`
**Target branch**: `lane711/plugin-sdk-v4-payload-shaped` (create off v3)
**Compatibility**: GREENFIELD — no v2 / no legacy `PluginBuilder` / no `MountablePlugin`/`WirablePlugin` split. Break existing plugin defs freely; we re-port them in P6.
**Reference fork**: `mmcintosh/sonicjs-infowall-merge` (the "infowall" path) — pull SDK shape + PR-1 menu + PR-2a/2b schema settings.
**Goal**: Single canonical `SonicPlugin<Caps>` type, Payload-style DX, schema-driven settings + admin menu, validation centralized in `registerPlugins`.

---

## 0. North-star — what "done" looks like

A plugin author writes one file:

```ts
// my-sonicjs-app/src/plugins/my-feature/index.ts
import { definePlugin } from '@sonicjs-cms/core'
import { z } from 'zod'

export default definePlugin({
  id: 'my-feature',
  version: '1.0.0',
  sonicjsVersionRange: '^3.0.0',
  capabilities: ['email:send', 'hooks.cron:register'] as const,
  requires: ['core-auth'],

  // 1. Schema-driven settings — admin UI auto-rendered at /admin/settings/plugins/my-feature
  configSchema: {
    apiKey:   { type: 'string', label: 'API Key', sensitive: true, required: true },
    region:   { type: 'select', label: 'Region', options: ['us', 'eu'], default: 'us' },
    enabled:  { type: 'boolean', label: 'Enabled', default: true },
  },

  // 2. Declarative admin sidebar entry
  menu: [
    { label: 'My Feature', path: '/admin/my-feature', icon: 'sparkles', order: 50 },
  ],

  // 3. Sync route registration — Hono SmartRouter constraint
  register(app) {
    app.get('/admin/my-feature', (c) => c.html('...'))
    app.post('/api/my-feature/ping', (c) => c.json({ ok: true }))
  },

  // 4. Discriminated-union typed hooks — `event` auto-narrows per key
  hooks: {
    'cron:tick': (event, ctx) => {
      // event: { type: 'cron:tick', schedule, hookFamily, ... }
      // ctx.cap.email narrows to EmailService (declared); ctx.cap.cache is `never`
    },
    'content:after:create': (event, ctx) => {
      // event payload narrowed to ContentCreatePayload
    },
  },

  // 5. Async boot — env-dependent setup
  async onBoot(ctx) {
    const settings = await ctx.settings.load() // typed: { apiKey: string; region: 'us'|'eu'; enabled: boolean }
    if (settings.enabled) ctx.cap.email.send({ ... })
  },

  // 6. Optional cron
  crons: [{ schedule: '*/15 * * * *', hookFamily: 'my-feature-reconcile' }],
  async onCronTick(event, ctx) { ... },
})
```

Plus the app wires:

```ts
// my-sonicjs-app/src/index.ts
import { registerPlugins } from '@sonicjs-cms/core'
import myFeature from './plugins/my-feature'
import coreAuth from '@sonicjs-cms/core/plugins/core-auth'

const app = new Hono()
await registerPlugins(app, [coreAuth, myFeature])
```

`registerPlugins` is the **single chokepoint**: validates everything, topo-sorts by `requires`, runs Strapi-style two-phase boot (`register` for ALL, then `onBoot` for ALL), wires hooks, collects menu, collects crons, returns a typed `PluginsRegistry`.

---

## 1. Background — current vs target

### Current v3 state (DO NOT keep)

| File | Issue |
|---|---|
| `packages/core/src/plugins/sdk/define-plugin.ts` (~15KB) | Dual `MountablePlugin` + `WirablePlugin` interfaces; validation inline; legacy `PluginBuilder` still exported alongside |
| `packages/core/src/plugins/sdk/plugin-builder.ts` | Legacy fluent builder — DELETE |
| `packages/core/src/plugins/mount.ts` | `MountablePlugin` interface — REPLACED by `SonicPlugin.register` (sync) |
| `packages/core/src/plugins/wire.ts` | `WirablePlugin` interface — REPLACED by `SonicPlugin.hooks` + `onBoot` |
| `packages/core/src/plugins/capabilities.ts` | Lives at top level — MOVE under `sdk/` |
| Per-plugin admin route hand-rolling settings forms | REPLACED by schema-driven renderer |
| Per-plugin `addMenuItem(...)` calls | REPLACED by declarative `menu: [...]` |

### Target shape (from infowall — confirmed by API read of `mmcintosh/sonicjs-infowall-merge`)

```
packages/core/src/plugins/
├── sdk/
│   ├── capabilities.ts      # SonicCapability union + KNOWN_CAPABILITIES + CAPABILITY_RENAMES + normalizeCapability
│   ├── events.ts            # SonicHookEvent discriminated union + SONIC_HOOK_EVENT_TYPES
│   ├── types.ts             # SonicPlugin<Caps>, SonicHookHandler<K>, SonicHookContext<Caps>, SonicPluginBootContext, PluginMenuEntry, service shapes
│   ├── define-plugin.ts     # 1.3KB identity factory — preserves Caps tuple type
│   ├── register-plugins.ts  # ~28KB pipeline: validate → topo-sort → register-all → wire-hooks → onBoot-all → reflect-DB
│   ├── config-schema.ts     # NEW (PR-2a): ConfigSchemaField types + parseConfigSchema + renderSchemaFields
│   └── index.ts             # SDK barrel
├── hooks/                   # KEEP — host-side hook system implementation
├── cron.ts                  # KEEP — schedule collection + dispatch (unchanged)
├── topo-sort.ts             # KEEP — used by registerPlugins
├── generate-triggers.ts     # KEEP — wrangler.toml [triggers] codegen
├── hook-system.ts           # KEEP — HookSystemImpl
├── plugin-registry.ts       # KEEP — runtime registry (returned from registerPlugins)
├── plugin-manager.ts        # KEEP — install/activate/deactivate UI ops
├── plugin-validator.ts      # KEEP — manifest validation (separate concern)
├── manifest-registry.ts     # KEEP — generated manifest catalog
└── core-plugins/, available/, cache/, redirect-management/, design/ — KEEP, port to new shape in P6
```

**Deleted in this refactor**: `mount.ts`, `wire.ts`, `sdk/plugin-builder.ts`, `capabilities.ts` (top-level).

---

## 2. Phases — implementation order

Each phase is one PR. Stack on previous. Run `npm run type-check` + `npm test` + relevant E2E before merging each.

| # | Phase | Files added | Files deleted | E2E spec |
|---|---|---|---|---|
| **P1** | SDK shell (types + capabilities + events + define-plugin) | 4 new in `sdk/` | — | — |
| **P2** | `registerPlugins` pipeline + delete mount/wire | `sdk/register-plugins.ts` | `mount.ts`, `wire.ts`, `sdk/plugin-builder.ts`, `capabilities.ts` (move) | `75-register-plugins.spec.ts` |
| **P3** | Bootstrap hookSystem-on-request fix | `middleware/bootstrap.ts` edit | — | — |
| **P4** | Declarative menu surface (PR-1) | `services/plugin-menu-singleton.ts` | — | `76-plugin-menu.spec.ts` |
| **P5** | Schema-driven settings (PR-2a) | `sdk/config-schema.ts` + admin route changes | — | `77-schema-settings.spec.ts` |
| **P6** | Port all core-plugins to `SonicPlugin` shape | edits to 27 plugin `index.ts` files | — | `78-plugin-shape-port.spec.ts` (smoke per plugin) |
| **P7** | Port app entry + remove legacy `plugins.register` API | `my-sonicjs-app/src/index.ts` edits | legacy `register-plugins-api.ts` if present | `79-app-bootstrap.spec.ts` |
| **P8** | Documentation + author guide | `docs/plugins/v4-author-guide.md` | old `docs/plugins/plugin-development-guide.md` | — |

E2E numbering: highest existing on v3 is `tests/e2e/74` → start at **75** (R11 in CLAUDE.md says 68+; current floor is 75).

---

## 3. Phase P1 — SDK shell (no behavior change yet)

**Goal**: Land the new types under `packages/core/src/plugins/sdk/` without removing anything. The engine still uses the old shape; new types exist alongside.

### P1.1 — `sdk/capabilities.ts`

Move from `packages/core/src/plugins/capabilities.ts` to `packages/core/src/plugins/sdk/capabilities.ts`.

```ts
// packages/core/src/plugins/sdk/capabilities.ts
export type SonicCapability =
  // Service capabilities
  | 'email:send'
  | 'storage:read'
  | 'storage:write'
  | 'cache:read'
  | 'cache:write'
  // Hook subscription capabilities
  | 'hooks.auth:register'
  | 'hooks.content-write:register'
  | 'hooks.content-read:register'
  | 'hooks.cron:register'
  | 'hooks.email-events:register'
  // Request-handling capabilities
  | 'request:intercept'

export const KNOWN_CAPABILITIES: ReadonlySet<SonicCapability> = new Set([
  'email:send', 'storage:read', 'storage:write', 'cache:read', 'cache:write',
  'hooks.auth:register', 'hooks.content-write:register', 'hooks.content-read:register',
  'hooks.cron:register', 'hooks.email-events:register', 'request:intercept',
])

export const CAPABILITY_RENAMES = {
  // populate as renames happen — empty for now
} as const satisfies Record<string, SonicCapability>

export function normalizeCapability(input: string): SonicCapability | null {
  const renamed = (CAPABILITY_RENAMES as Record<string, SonicCapability>)[input] ?? input
  return KNOWN_CAPABILITIES.has(renamed as SonicCapability) ? (renamed as SonicCapability) : null
}

export function normalizeCapabilities(
  inputs: readonly string[]
): { capabilities: SonicCapability[]; unknown: string[] } {
  const capabilities: SonicCapability[] = []
  const unknown: string[] = []
  for (const i of inputs) {
    const c = normalizeCapability(i)
    if (c) capabilities.push(c)
    else unknown.push(i)
  }
  return { capabilities, unknown }
}
```

### P1.2 — `sdk/events.ts`

Discriminated union over existing hook events. Mirror what's in `hooks/catalog.ts` but with a `type` field for narrowing.

```ts
// packages/core/src/plugins/sdk/events.ts
import type {
  ContentEventPayload,
  AuthRegistrationCompletedPayload,
  AuthPasswordResetRequestedPayload,
  AuthPasswordResetCompletedPayload,
  AuthMagicLinkConsumedPayload,
  AuthOtpVerifiedPayload,
} from '../hooks/catalog'
import type { CronTickEvent } from '../cron'

export type SonicHookEvent =
  | ({ type: 'content:before:create' } & ContentEventPayload)
  | ({ type: 'content:after:create' } & ContentEventPayload)
  | ({ type: 'content:before:update' } & ContentEventPayload)
  | ({ type: 'content:after:update' } & ContentEventPayload)
  | ({ type: 'content:before:delete' } & ContentEventPayload)
  | ({ type: 'content:after:delete' } & ContentEventPayload)
  | ({ type: 'auth:registration:completed' } & AuthRegistrationCompletedPayload)
  | ({ type: 'auth:password-reset:requested' } & AuthPasswordResetRequestedPayload)
  | ({ type: 'auth:password-reset:completed' } & AuthPasswordResetCompletedPayload)
  | ({ type: 'auth:magic-link:consumed' } & AuthMagicLinkConsumedPayload)
  | ({ type: 'auth:otp:verified' } & AuthOtpVerifiedPayload)
  | ({ type: 'cron:tick' } & CronTickEvent)

export const SONIC_HOOK_EVENT_TYPES = [
  'content:before:create', 'content:after:create',
  'content:before:update', 'content:after:update',
  'content:before:delete', 'content:after:delete',
  'auth:registration:completed', 'auth:password-reset:requested',
  'auth:password-reset:completed', 'auth:magic-link:consumed',
  'auth:otp:verified', 'cron:tick',
] as const satisfies ReadonlyArray<SonicHookEvent['type']>

export function isSonicHookEvent(type: string): type is SonicHookEvent['type'] {
  return (SONIC_HOOK_EVENT_TYPES as readonly string[]).includes(type)
}
```

### P1.3 — `sdk/types.ts`

```ts
// packages/core/src/plugins/sdk/types.ts
import type { Hono } from 'hono'
import type { Bindings, Variables } from '../../app'
import type { SonicCapability } from './capabilities'
import type { SonicHookEvent } from './events'
import type { CronDeclaration, CronTickEvent } from '../cron'
import type { HookSystem } from '../../types/plugin'
import type { ConfigSchemaField } from './config-schema'

// ── Hook handler (narrowed by event-type literal K) ──
export type SonicHookHandler<
  K extends SonicHookEvent['type'] = SonicHookEvent['type'],
  Caps extends readonly SonicCapability[] = readonly SonicCapability[],
> = (
  event: Extract<SonicHookEvent, { type: K }>,
  ctx: SonicHookContext<Caps>,
) => void | Promise<void>

// ── Ctx — capability-narrowed services ──
export interface SonicHookContext<Caps extends readonly SonicCapability[]> {
  cap: CapabilityContext<Caps>
  hooks: HookSystem
  env?: Record<string, unknown>
}

export type CapabilityContext<Caps extends readonly SonicCapability[]> = {
  email: 'email:send' extends Caps[number] ? EmailService : never
  storage: ('storage:read' | 'storage:write') extends Caps[number] ? StorageService : never
  cache: ('cache:read' | 'cache:write') extends Caps[number] ? CacheService : never
}

// ── Service shapes (concrete impls in services/, kept thin here) ──
export interface EmailService {
  send(input: { to: string; subject: string; html: string; from?: string; replyTo?: string }): Promise<{ id: string }>
}
export interface StorageService {
  get(key: string): Promise<ArrayBuffer | null>
  put(key: string, value: ArrayBuffer | string): Promise<void>
}
export interface CacheService {
  get<T>(key: string): Promise<T | null>
  put<T>(key: string, value: T, ttl?: number): Promise<void>
}
export interface CronService {
  declare(decl: CronDeclaration): void
}

// ── Menu entry (PR-1) ──
export interface PluginMenuEntry {
  label: string
  path: string
  icon?: string
  order?: number
  permissions?: string[]
}

// ── Plugin boot context (passed to onBoot) ──
export interface SonicPluginBootContext<Caps extends readonly SonicCapability[]> {
  cap: CapabilityContext<Caps>
  hooks: HookSystem
  env: Record<string, unknown>
  settings: SettingsAccessor // typed by configSchema, see P5
}

export interface SettingsAccessor<T = Record<string, unknown>> {
  load(): Promise<T>
  save(patch: Partial<T>): Promise<void>
}

// ── THE canonical plugin shape ──
export interface SonicPlugin<
  Caps extends readonly SonicCapability[] = readonly SonicCapability[],
> {
  readonly id: string
  readonly version: string
  readonly displayName?: string
  readonly description?: string
  readonly sonicjsVersionRange?: string
  readonly requires?: readonly string[]
  readonly capabilities: Caps

  /**
   * Sync route registration. MUST be synchronous (Hono SmartRouter locks after first
   * request). Returning a Promise → registerPlugins throws `register_returned_promise`.
   */
  readonly register?: (
    app: Hono<{ Bindings: Bindings; Variables: Variables }>,
  ) => void

  /**
   * Declarative hooks — keyed map. Handler `event` param auto-narrows per key.
   * Each subscription requires the matching `hooks.<family>:register` capability.
   */
  readonly hooks?: Readonly<Partial<{
    [K in SonicHookEvent['type']]: SonicHookHandler<K, Caps>
  }>>

  /** Cron declarations (also list in wrangler.toml; generate-triggers.ts assists). */
  readonly crons?: readonly CronDeclaration[]
  readonly onCronTick?: (event: CronTickEvent, ctx: SonicPluginBootContext<Caps>) => void | Promise<void>

  /** Async setup. Runs after ALL plugins have completed `register`. */
  readonly onBoot?: (ctx: SonicPluginBootContext<Caps>) => void | Promise<void>

  /** Schema-driven settings (PR-2a). Auto-renders admin UI. */
  readonly configSchema?: Record<string, ConfigSchemaField>

  /** Declarative admin sidebar entries (PR-1). */
  readonly menu?: readonly PluginMenuEntry[]

  /** DB/schema lifecycle (no routes). */
  readonly install?: (ctx: unknown) => void | Promise<void>
  readonly uninstall?: (ctx: unknown) => void | Promise<void>
  readonly activate?: (ctx: unknown) => void | Promise<void>
  readonly deactivate?: (ctx: unknown) => void | Promise<void>
}

// ── Registry returned by registerPlugins ──
export interface PluginsRegistry {
  readonly byId: ReadonlyMap<string, RegisteredPluginMetadata>
  readonly order: readonly string[]
  readonly menu: readonly PluginMenuEntry[]
  readonly crons: readonly CronDeclaration[]
}

export interface RegisteredPluginMetadata {
  id: string
  version: string
  displayName: string
  capabilities: readonly SonicCapability[]
  active: boolean
}
```

### P1.4 — `sdk/define-plugin.ts`

```ts
// packages/core/src/plugins/sdk/define-plugin.ts
import type { SonicCapability } from './capabilities'
import type { SonicPlugin } from './types'

/**
 * Identity factory. Preserves the `Caps` tuple literal type so downstream code
 * (registerPlugins, hook handlers, ctx.cap) narrows on the declared capabilities.
 *
 * ALL validation (semver, capability membership, hook keys, cycle detection)
 * lives in `registerPlugins`. This factory only preserves types.
 */
export function definePlugin<const Caps extends readonly SonicCapability[]>(
  plugin: SonicPlugin<Caps>,
): SonicPlugin<Caps> {
  return plugin
}
```

### P1.5 — `sdk/index.ts`

```ts
// packages/core/src/plugins/sdk/index.ts
export { definePlugin } from './define-plugin'

export type {
  SonicPlugin,
  SonicHookHandler,
  SonicHookContext,
  SonicPluginBootContext,
  CapabilityContext,
  PluginMenuEntry,
  PluginsRegistry,
  RegisteredPluginMetadata,
  EmailService,
  StorageService,
  CacheService,
  CronService,
  SettingsAccessor,
} from './types'

export type { SonicCapability } from './capabilities'
export {
  KNOWN_CAPABILITIES,
  CAPABILITY_RENAMES,
  normalizeCapability,
  normalizeCapabilities,
} from './capabilities'

export type { SonicHookEvent } from './events'
export { SONIC_HOOK_EVENT_TYPES, isSonicHookEvent } from './events'

export type { ConfigSchemaField } from './config-schema'
export { parseConfigSchema, renderSchemaFields } from './config-schema'

export {
  registerPlugins,
  RegisterPluginsError,
  SonicCapabilityError,
} from './register-plugins'
```

### P1 verification

```bash
cd packages/core && npm run type-check  # MUST be clean
npm test -- sdk/                         # any existing sdk tests pass
```

No behavior change yet — old engine still wired. New types exist parallel.

---

## 4. Phase P2 — `registerPlugins` pipeline + delete mount/wire

**Goal**: Replace `mount.ts` + `wire.ts` + old `definePlugin` with single `registerPlugins` chokepoint. Switch app entry to the new API. Delete legacy.

### P2.1 — `sdk/register-plugins.ts`

Pipeline (~28KB based on infowall):

```ts
// packages/core/src/plugins/sdk/register-plugins.ts
import semver from 'semver' // OK to add dep — Workers handle it fine; lightweight
import type { Hono } from 'hono'
import type { Bindings, Variables } from '../../app'
import type { HookSystem } from '../../types/plugin'
import { topoSort } from '../topo-sort'
import { setHookSystem, getHookSystem } from '../hooks/hook-system-singleton'
import { setPluginMenu } from '../../services/plugin-menu-singleton'
import { collectCronSchedules } from '../cron'
import { normalizeCapability, KNOWN_CAPABILITIES } from './capabilities'
import { SONIC_HOOK_EVENT_TYPES } from './events'
import type {
  SonicPlugin, SonicCapability, PluginsRegistry, RegisteredPluginMetadata,
  SonicPluginBootContext, EmailService, StorageService, CacheService,
} from './types'
import { createSettingsAccessor } from './settings-accessor' // built in P5
import { getCoreVersion } from '../../utils/version'

export type RegisterPluginsErrorReason =
  | 'invalid_id' | 'invalid_semver' | 'duplicate_id'
  | 'unknown_capability' | 'unknown_hook_event' | 'unknown_dep'
  | 'cycle' | 'capability_missing'
  | 'register_failed' | 'register_returned_promise' | 'onboot_failed'

export class RegisterPluginsError extends Error {
  constructor(
    public readonly reason: RegisterPluginsErrorReason,
    public readonly details: Readonly<Record<string, unknown>>,
  ) {
    super(`registerPlugins(${reason}): ${JSON.stringify(details)}`)
    this.name = 'RegisterPluginsError'
  }
}

export class SonicCapabilityError extends Error {
  constructor(
    public readonly pluginId: string,
    public readonly missingCapability: SonicCapability,
    public readonly accessedApi: string,
  ) {
    super(
      `SonicCapabilityError: plugin '${pluginId}' accessed '${accessedApi}' ` +
      `without declaring capability '${missingCapability}'`,
    )
    this.name = 'SonicCapabilityError'
  }
}

export interface RegisterPluginsHostContext {
  hookSystem: HookSystem
  env: Record<string, unknown>
  /** Capability provider factories — host injects real impls. */
  providers: {
    email?: () => EmailService
    storage?: () => StorageService
    cache?: () => CacheService
  }
  /** Best-effort DB activation reflection. */
  pluginService?: { activatePlugin(id: string, version: string): Promise<void> }
}

export async function registerPlugins(
  app: Hono<{ Bindings: Bindings; Variables: Variables }>,
  plugins: readonly SonicPlugin[],
  host: RegisterPluginsHostContext,
): Promise<PluginsRegistry> {
  // ── 1. Validate each plugin
  const byId = new Map<string, SonicPlugin>()
  for (const p of plugins) {
    if (!p.id || typeof p.id !== 'string')
      throw new RegisterPluginsError('invalid_id', { plugin: p })
    if (!semver.valid(p.version))
      throw new RegisterPluginsError('invalid_semver', { id: p.id, version: p.version })
    if (byId.has(p.id))
      throw new RegisterPluginsError('duplicate_id', { id: p.id })

    // Capability membership
    for (const c of p.capabilities) {
      if (!normalizeCapability(c))
        throw new RegisterPluginsError('unknown_capability', { id: p.id, capability: c })
    }

    // Hook key membership + capability gate
    for (const [eventName] of Object.entries(p.hooks ?? {})) {
      if (!SONIC_HOOK_EVENT_TYPES.includes(eventName as never))
        throw new RegisterPluginsError('unknown_hook_event', { id: p.id, event: eventName })
      const requiredCap = mapEventToCapability(eventName as never)
      if (requiredCap && !p.capabilities.includes(requiredCap))
        throw new RegisterPluginsError('capability_missing', {
          id: p.id, event: eventName, requiredCapability: requiredCap,
        })
    }

    // sonicjsVersionRange compatibility (warn-only, never block)
    if (p.sonicjsVersionRange && !semver.satisfies(getCoreVersion(), p.sonicjsVersionRange)) {
      console.warn(
        `[plugins] ${p.id} declares sonicjsVersionRange "${p.sonicjsVersionRange}" ` +
        `but core is "${getCoreVersion()}". Plugin may not work correctly.`
      )
    }

    byId.set(p.id, p)
  }

  // ── 2. Topo-sort by `requires`
  const order = topoSort(
    Array.from(byId.values()),
    (p) => p.id,
    (p) => p.requires ?? [],
    { strict: true }, // throws PluginDependencyCycleError + unknown-dep
  )

  // ── 3. Register pass — ALL plugins, sync, BEFORE any onBoot
  setHookSystem(host.hookSystem)
  for (const id of order) {
    const p = byId.get(id)!
    if (!p.register) continue
    try {
      const result = p.register(app)
      if (result && typeof (result as Promise<unknown>).then === 'function') {
        throw new RegisterPluginsError('register_returned_promise', { id })
      }
    } catch (e) {
      if (e instanceof RegisterPluginsError) throw e
      throw new RegisterPluginsError('register_failed', { id, error: String(e) })
    }
  }

  // ── 4. Wire hook subscriptions (after register, before onBoot)
  for (const id of order) {
    const p = byId.get(id)!
    for (const [eventName, handler] of Object.entries(p.hooks ?? {})) {
      host.hookSystem.register(eventName, async (data: unknown, ctx: unknown) => {
        const event = { type: eventName, ...data } as never
        await (handler as (e: unknown, c: unknown) => unknown)(event, buildBootCtx(p, host))
        return data // legacy chain expects data passthrough
      })
    }
  }

  // ── 5. Collect menu + crons
  const menu = order.flatMap((id) => byId.get(id)!.menu ?? [])
  setPluginMenu(menu)
  const crons = order.flatMap((id) => byId.get(id)!.crons ?? [])

  // ── 6. onBoot pass — ALL plugins, after ALL registered, hooks wired
  for (const id of order) {
    const p = byId.get(id)!
    if (!p.onBoot) continue
    try {
      await p.onBoot(buildBootCtx(p, host))
    } catch (e) {
      throw new RegisterPluginsError('onboot_failed', { id, error: String(e) })
    }
  }

  // ── 7. Best-effort DB activation reflection
  if (host.pluginService) {
    for (const id of order) {
      const p = byId.get(id)!
      try { await host.pluginService.activatePlugin(p.id, p.version) }
      catch (e) { console.warn(`[plugins] DB activation reflection failed for ${id}:`, e) }
    }
  }

  // ── 8. Return registry
  const registryById = new Map<string, RegisteredPluginMetadata>()
  for (const id of order) {
    const p = byId.get(id)!
    registryById.set(id, {
      id: p.id, version: p.version,
      displayName: p.displayName ?? p.id,
      capabilities: p.capabilities, active: true,
    })
  }
  return { byId: registryById, order, menu, crons }
}

// ── Ctx builder — capability-gated getters throw on undeclared access
function buildBootCtx<Caps extends readonly SonicCapability[]>(
  plugin: SonicPlugin<Caps>,
  host: RegisterPluginsHostContext,
): SonicPluginBootContext<Caps> {
  const caps = new Set(plugin.capabilities)
  return {
    hooks: host.hookSystem,
    env: host.env,
    settings: createSettingsAccessor(plugin),
    cap: new Proxy({} as never, {
      get(_t, prop: string) {
        if (prop === 'email') {
          if (!caps.has('email:send'))
            throw new SonicCapabilityError(plugin.id, 'email:send', 'cap.email')
          return host.providers.email?.() ?? throwNoProvider(plugin.id, 'email')
        }
        if (prop === 'storage') {
          if (!caps.has('storage:read') && !caps.has('storage:write'))
            throw new SonicCapabilityError(plugin.id, 'storage:read', 'cap.storage')
          return host.providers.storage?.() ?? throwNoProvider(plugin.id, 'storage')
        }
        if (prop === 'cache') {
          if (!caps.has('cache:read') && !caps.has('cache:write'))
            throw new SonicCapabilityError(plugin.id, 'cache:read', 'cap.cache')
          return host.providers.cache?.() ?? throwNoProvider(plugin.id, 'cache')
        }
        return undefined
      },
    }),
  }
}

function throwNoProvider(pluginId: string, api: string): never {
  throw new Error(`[plugins] No host provider for cap.${api} (requested by ${pluginId})`)
}

// ── Map declarative hook event → required capability
function mapEventToCapability(event: string): SonicCapability | null {
  if (event.startsWith('content:before:') || event.startsWith('content:after:')) {
    return event.includes(':create') || event.includes(':update') || event.includes(':delete')
      ? 'hooks.content-write:register'
      : 'hooks.content-read:register'
  }
  if (event.startsWith('auth:')) return 'hooks.auth:register'
  if (event === 'cron:tick') return 'hooks.cron:register'
  return null
}
```

### P2.2 — Topo-sort signature

Update `topo-sort.ts` to accept `(items, idFn, depsFn, opts)`. Current shape uses `dependencies`; this is mostly rename to `requires`. Keep accepting both for the duration of P6 port (alias `dependencies` → `requires`). Tests in `__tests__/plugins/topo-sort.test.ts` stay valid.

### P2.3 — DELETE files

```bash
git rm packages/core/src/plugins/mount.ts
git rm packages/core/src/plugins/wire.ts
git rm packages/core/src/plugins/sdk/plugin-builder.ts
git rm packages/core/src/plugins/capabilities.ts  # moved to sdk/
```

Search-and-replace imports:
- `from '../mount'` / `from './mount'` → DELETE (no callers should remain after P6)
- `from '../wire'` / `from './wire'` → DELETE
- `from '../capabilities'` → `from './sdk/capabilities'`
- `MountablePlugin` / `WirablePlugin` → `SonicPlugin`
- `PluginBuilder` import → DELETE caller

### P2.4 — Update `plugins/index.ts` (the barrel)

Strip mount/wire exports. Re-export from `sdk/`:

```ts
// packages/core/src/plugins/index.ts
export * from './sdk'                   // ALL new SDK surface
export { HookSystemImpl, ScopedHookSystem, HookUtils } from './hook-system'
export { PluginRegistryImpl } from './plugin-registry'
export { PluginManager } from './plugin-manager'
export { PluginValidator } from './plugin-validator'
export { collectCrons, collectCronSchedules, dispatchCronTick, createScheduledHandler } from './cron'
export type { CronDeclaration, CronTickEvent, CronContext, CollectedCron, CronDispatchResult } from './cron'
export { parseCronTriggers, updateWranglerTriggers, generateTriggersComment } from './generate-triggers'
// NOTE: setHookSystem / getHookSystem stay exported for tests + bootstrap
export { setHookSystem, getHookSystem, hasHookSystem, resetHookSystem } from './hooks/hook-system-singleton'
```

### P2.5 — Update `@sonicjs-cms/core` top-level barrel

`packages/core/src/index.ts` must re-export `definePlugin`, `registerPlugins`, `SonicPlugin`, etc.

### P2 verification

```bash
cd packages/core && npm run type-check  # MUST be clean (some core-plugins will break — fix in P6)
# At this phase: type errors in core-plugins/* are EXPECTED; they get ported in P6.
# Workaround for the gap: add a single-line `// @ts-nocheck` to each broken
# core-plugin index.ts at start of P2 so the build greens; remove per plugin in P6.
```

E2E spec `tests/e2e/75-register-plugins.spec.ts`:
- App boots cleanly with two test plugins registered via `registerPlugins`
- Cycle detection: define A→B→A, expect `RegisterPluginsError('cycle', ...)` thrown at startup
- Capability gating: plugin declares `hooks: { 'cron:tick': ... }` without `hooks.cron:register` cap → `capability_missing` thrown
- Duplicate id → `duplicate_id` thrown
- Invalid semver `'abc'` → `invalid_semver` thrown
- `register()` returns Promise → `register_returned_promise` thrown
- Capability runtime gate: plugin declares `email:send`, accesses `ctx.cap.cache` → `SonicCapabilityError` at runtime

---

## 5. Phase P3 — Bootstrap hookSystem fix

**Goal**: Cherry-pick infowall commit `60c0846f9` — attach `hookSystem` to the request BEFORE heavy bootstrap work, so any hook-subscribed code path (e.g. cron firing during cold start, document-bootstrap hooks) sees a live bus.

### P3.1 — Edit `packages/core/src/middleware/bootstrap.ts`

Pattern (verbatim from infowall logic):

```ts
// BEFORE:
export async function bootstrapMiddleware(c: Context, next: Next) {
  if (alreadyBooted) return next()
  await runMigrations(c.env)
  await loadCollections(c.env)
  await registerPluginsForRequest(c)     // ← hookSystem set HERE — too late
  // ...
}

// AFTER:
export async function bootstrapMiddleware(c: Context, next: Next) {
  // Attach hookSystem to the request FIRST so any in-flight bootstrap code path
  // that emits hooks (cron-driven cold starts, document seed events) sees a live bus.
  const hookSystem = getOrCreateHookSystem()
  c.set('hookSystem', hookSystem)
  setHookSystem(hookSystem) // module singleton

  if (alreadyBooted) return next()
  await runMigrations(c.env)
  await loadCollections(c.env)
  await registerPluginsForRequest(c)
  // ...
}
```

### P3 verification

```bash
cd packages/core && npm test -- bootstrap
# Existing bootstrap tests should pass; add one:
#   "hookSystem is attached to request before runMigrations"
```

No new E2E spec — covered by unit test.

---

## 6. Phase P4 — Declarative menu surface (PR-1)

**Goal**: Replace per-plugin `addMenuItem` calls with `menu: [...]` field on `SonicPlugin`. Sidebar reads from a singleton populated by `registerPlugins`.

### P4.1 — `services/plugin-menu-singleton.ts` (NEW)

```ts
// packages/core/src/services/plugin-menu-singleton.ts
import type { PluginMenuEntry } from '../plugins/sdk/types'

let menuItems: readonly PluginMenuEntry[] = []

export function setPluginMenu(items: readonly PluginMenuEntry[]): void {
  menuItems = items
}

export function getPluginMenu(): readonly PluginMenuEntry[] {
  return menuItems
}

export function resetPluginMenu(): void {
  menuItems = []
}

/**
 * Pure: filter by user permissions, sort by `order` ASC (default 100),
 * project to render-ready shape with default icon.
 */
export function resolvePluginMenuItems(
  user?: { permissions?: readonly string[] },
): Array<Required<Pick<PluginMenuEntry, 'label' | 'path' | 'icon'>> & { order: number }> {
  const userPerms = new Set(user?.permissions ?? [])
  return menuItems
    .filter((m) => {
      if (!m.permissions || m.permissions.length === 0) return true
      return m.permissions.some((p) => userPerms.has(p))
    })
    .slice()
    .sort((a, b) => (a.order ?? 100) - (b.order ?? 100))
    .map((m) => ({
      label: m.label,
      path: m.path,
      icon: m.icon ?? 'puzzle-piece',
      order: m.order ?? 100,
    }))
}
```

### P4.2 — Sidebar template consumption

Edit `packages/core/src/templates/layouts/admin-layout-catalyst.template.ts` (path on v3; verify with codegraph). Splice plugin menu items into the static nav:

```ts
import { resolvePluginMenuItems } from '../../services/plugin-menu-singleton'

// Inside the sidebar render:
const pluginItems = data.dynamicMenuItems ?? resolvePluginMenuItems(data.user)
// ...render each pluginItems[i] under "Plugins" section
```

Add `data.user.permissions?: readonly string[]` to `AdminLayoutCatalystData`.

### P4.3 — `registerPlugins` already collects + calls `setPluginMenu(menu)` (step 5 in P2.1).

### P4 verification

E2E spec `tests/e2e/76-plugin-menu.spec.ts`:
- Register two test plugins with `menu: [...]`
- Admin sidebar shows both, in correct order
- Permission-restricted entry hidden from user without the perm
- `dynamicMenuItems` override path still works (back-compat for admin)

---

## 7. Phase P5 — Schema-driven settings (PR-2a)

**Goal**: Plugin declares `configSchema: { ... }` → admin UI auto-rendered at `/admin/settings/plugins/:id`. No more per-plugin settings form code.

### P5.1 — `sdk/config-schema.ts` (NEW)

```ts
// packages/core/src/plugins/sdk/config-schema.ts
export type ConfigSchemaField =
  | StringField | NumberField | BooleanField | SelectField

interface BaseField {
  label: string
  description?: string
  required?: boolean
  default?: unknown
}

export interface StringField extends BaseField {
  type: 'string'
  default?: string
  format?: 'email' | 'url' | 'password'
  sensitive?: boolean           // → input type=password
  placeholder?: string
  minLength?: number
  maxLength?: number
}

export interface NumberField extends BaseField {
  type: 'number'
  default?: number
  min?: number
  max?: number
}

export interface BooleanField extends BaseField {
  type: 'boolean'
  default?: boolean
}

export interface SelectField extends BaseField {
  type: 'select'
  default?: string
  options: readonly string[] | readonly { value: string; label: string }[]
}

/** Parse `Record<string, ConfigSchemaField>` → typed field array w/ keys. */
export function parseConfigSchema(
  schema: Record<string, ConfigSchemaField>,
): Array<{ key: string; field: ConfigSchemaField }> {
  return Object.entries(schema).map(([key, field]) => ({ key, field }))
}

/** Render one HTML control per field. Returns HTML string for the admin form. */
export function renderSchemaFields(
  schema: Record<string, ConfigSchemaField>,
  currentValues: Record<string, unknown>,
): string {
  return parseConfigSchema(schema)
    .map(({ key, field }) => renderOne(key, field, currentValues[key] ?? field.default))
    .join('\n')
}

function renderOne(key: string, field: ConfigSchemaField, value: unknown): string {
  const required = field.required ? 'required' : ''
  const id = `field-${key}`
  switch (field.type) {
    case 'string': {
      const inputType = field.sensitive ? 'password' : field.format === 'email' ? 'email'
        : field.format === 'url' ? 'url' : 'text'
      return `
        <div class="field">
          <label for="${id}">${escape(field.label)}${field.required ? ' *' : ''}</label>
          <input id="${id}" name="${key}" type="${inputType}"
            value="${escape(String(value ?? ''))}"
            placeholder="${escape(field.placeholder ?? '')}"
            ${field.minLength ? `minlength="${field.minLength}"` : ''}
            ${field.maxLength ? `maxlength="${field.maxLength}"` : ''}
            ${required} />
          ${field.description ? `<p class="help">${escape(field.description)}</p>` : ''}
        </div>`
    }
    case 'number':
      return `
        <div class="field">
          <label for="${id}">${escape(field.label)}${field.required ? ' *' : ''}</label>
          <input id="${id}" name="${key}" type="number"
            value="${value ?? ''}"
            ${field.min !== undefined ? `min="${field.min}"` : ''}
            ${field.max !== undefined ? `max="${field.max}"` : ''}
            ${required} />
        </div>`
    case 'boolean':
      return `
        <div class="field">
          <label><input name="${key}" type="checkbox" ${value ? 'checked' : ''} /> ${escape(field.label)}</label>
        </div>`
    case 'select': {
      const opts = field.options.map((o) => typeof o === 'string'
        ? `<option value="${escape(o)}" ${o === value ? 'selected' : ''}>${escape(o)}</option>`
        : `<option value="${escape(o.value)}" ${o.value === value ? 'selected' : ''}>${escape(o.label)}</option>`
      ).join('')
      return `
        <div class="field">
          <label for="${id}">${escape(field.label)}${field.required ? ' *' : ''}</label>
          <select id="${id}" name="${key}" ${required}>${opts}</select>
        </div>`
    }
  }
}

function escape(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]!))
}

/** Parse FormData into typed values per schema. */
export function parseFormDataToSettings(
  schema: Record<string, ConfigSchemaField>,
  form: FormData,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const { key, field } of parseConfigSchema(schema)) {
    switch (field.type) {
      case 'string':
        result[key] = form.get(key)?.toString() ?? field.default ?? ''
        break
      case 'number': {
        const raw = form.get(key)?.toString()
        result[key] = raw === '' || raw == null ? field.default : Number(raw)
        break
      }
      case 'boolean':
        result[key] = form.get(key) === 'on' // unchecked => omitted by browser
        break
      case 'select':
        result[key] = form.get(key)?.toString() ?? field.default ?? ''
        break
    }
  }
  return result
}
```

### P5.2 — `SettingsAccessor` impl

```ts
// packages/core/src/plugins/sdk/settings-accessor.ts
import type { SonicPlugin, SettingsAccessor } from './types'
import { getDb } from '../../services/db' // or however settings are stored on v3

export function createSettingsAccessor<T = Record<string, unknown>>(
  plugin: SonicPlugin,
): SettingsAccessor<T> {
  return {
    async load(): Promise<T> {
      // Pulls from plugins table (or document_types settings) by plugin.id.
      // Apply defaults from plugin.configSchema where missing.
      const stored = await loadPluginSettings(plugin.id)
      return applyDefaults(stored, plugin.configSchema) as T
    },
    async save(patch: Partial<T>): Promise<void> {
      await savePluginSettings(plugin.id, patch as Record<string, unknown>)
    },
  }
}

function applyDefaults(
  stored: Record<string, unknown>,
  schema?: Record<string, import('./config-schema').ConfigSchemaField>,
): Record<string, unknown> {
  if (!schema) return stored
  const result = { ...stored }
  for (const [k, f] of Object.entries(schema)) {
    if (result[k] === undefined && 'default' in f) result[k] = f.default
  }
  return result
}

// loadPluginSettings / savePluginSettings — call existing v3 plugin-service
// (packages/core/src/services/plugin-service.ts).
declare function loadPluginSettings(id: string): Promise<Record<string, unknown>>
declare function savePluginSettings(id: string, patch: Record<string, unknown>): Promise<void>
```

### P5.3 — Admin route — generic settings handler

Replace per-plugin handler routes (which currently live in `routes/admin-plugins.ts`) with:

```ts
// packages/core/src/routes/admin-plugins.ts
import { renderSchemaFields, parseFormDataToSettings } from '../plugins/sdk/config-schema'
import { getPluginById } from '../services/plugin-service'

// GET /admin/settings/plugins/:id
admin.get('/settings/plugins/:id', async (c) => {
  const id = c.req.param('id')
  const plugin = getPluginById(id)
  if (!plugin) return c.notFound()
  if (!plugin.configSchema) return c.html(renderNoSettings(plugin))
  const values = await loadPluginSettings(id)
  return c.html(renderSettingsPage(plugin, renderSchemaFields(plugin.configSchema, values)))
})

// POST /admin/settings/plugins/:id
admin.post('/settings/plugins/:id', async (c) => {
  const id = c.req.param('id')
  const plugin = getPluginById(id)
  if (!plugin?.configSchema) return c.notFound()
  const form = await c.req.formData()
  const parsed = parseFormDataToSettings(plugin.configSchema, form)
  await savePluginSettings(id, parsed)
  return c.redirect(`/admin/settings/plugins/${id}`)
})
```

NO per-plugin `renderXSettingsForm` functions. They're all gone.

### P5 verification

E2E spec `tests/e2e/77-schema-settings.spec.ts`:
- Plugin with `configSchema: { apiKey: { type: 'string', sensitive: true }, region: { type: 'select', options: ['us','eu'] }, enabled: { type: 'boolean', default: true } }`
- Navigate to `/admin/settings/plugins/test-plugin` — sees 3 controls, password field for apiKey, select with 2 options, checkbox pre-checked
- Submit form with `apiKey=secret&region=eu&enabled=on` — settings persisted
- Toggle `enabled` off, submit — boolean false correctly persisted (the D4 bug from infowall PR-2a)
- Defaults: load page with empty stored settings → form shows `enabled` checked (default `true`)
- `ctx.settings.load()` inside `onBoot` returns typed object with defaults applied

---

## 8. Phase P6 — Port all core-plugins to `SonicPlugin` shape

**Goal**: Convert every plugin under `packages/core/src/plugins/core-plugins/*/index.ts` and `my-sonicjs-app/src/plugins/*/index.ts` to the new `definePlugin({ ... })` shape.

### P6.1 — Plugins to port (27 total)

From `git ls-tree -r origin/v3 --name-only packages/core/src/plugins/core-plugins | grep -E '/index\.ts$'`:

1. `_shared/` — shared utils, NOT a plugin (skip)
2. `ai-search-plugin`
3. `analytics`
4. `auth` (core-auth — critical, do FIRST)
5. `code-examples`
6. `dashboard-plugin`
7. `database-tools-plugin`
8. `demo-login`
9. `email-plugin`
10. `email-reconciliation`
11. `forms-plugin`
12. `global-variables-plugin`
13. `hello-world-plugin`
14. `media` (core-media)
15. `multi-tenant-plugin`
16. `oauth-providers`
17. `otp-login-plugin`
18. `quill-editor`
19. `security-audit-plugin`
20. `seed-data-plugin`
21. `shortcodes-plugin`
22. `stripe-plugin`
23. `testimonials`
24. `turnstile-plugin`
25. `user-profiles`
26. `workflow-plugin`

Plus `packages/core/src/plugins/available/`:
- `easy-mdx`, `email-templates-plugin`, `magic-link-auth`, `tinymce-plugin`

Plus `packages/core/src/plugins/cache/` and `packages/core/src/plugins/redirect-management/`.

Plus `packages/core/src/plugins/design/`.

### P6.2 — Port template (apply to every plugin)

**Before (current v3 shape)**:

```ts
// packages/core/src/plugins/core-plugins/email-plugin/index.ts
import { definePlugin } from '../../../sdk/define-plugin' // OLD path
import { capabilityProvider } from '../../sdk/capability-provider'

export const emailPlugin = definePlugin({
  id: 'email',
  name: 'Email',
  version: '3.0.0',
  capabilities: ['email:send'],
  routes: [{ path: '/admin/email', handler: emailRoutes }], // OLD MountableRoute
  hooks: {
    'auth:registration:completed': async (payload, ctx) => { ... },
  },
  async onBoot(ctx) {
    // ctx is DefinedPluginContext (OLD)
  },
})
```

**After (Payload-shaped)**:

```ts
// packages/core/src/plugins/core-plugins/email-plugin/index.ts
import { definePlugin } from '../../sdk'

export default definePlugin({
  id: 'email',
  version: '3.0.0',
  displayName: 'Email',
  sonicjsVersionRange: '^3.0.0',
  capabilities: ['email:send', 'hooks.auth:register'] as const,
  configSchema: {
    defaultFrom: { type: 'string', label: 'Default From Address', format: 'email', required: true },
    replyTo:     { type: 'string', label: 'Reply-To',             format: 'email' },
  },
  menu: [
    { label: 'Email Log', path: '/admin/settings/email-log', icon: 'envelope', order: 60 },
  ],
  register(app) {
    app.route('/admin/email', emailAdminRoutes)
    app.route('/api/email',   emailApiRoutes)
  },
  hooks: {
    'auth:registration:completed': async (event, ctx) => {
      // event is narrowed to AuthRegistrationCompletedPayload
      await ctx.cap.email.send({
        to: event.email,
        subject: 'Welcome',
        html: '<h1>Hi</h1>',
      })
    },
  },
  async onBoot(ctx) {
    const settings = await ctx.settings.load()
    // settings is { defaultFrom: string; replyTo?: string }
  },
})
```

### P6.3 — Port order (do in this sequence — each may unblock the next)

1. `hello-world-plugin` — simplest, prove the pattern
2. `auth` (core-auth) — critical, blocks everything else
3. `media` (core-media)
4. `cache`
5. `forms-plugin`
6. `email-plugin` + `email-reconciliation`
7. All remaining core-plugins (any order)
8. `available/*` plugins
9. `redirect-management`, `design`
10. App-level `my-sonicjs-app/src/plugins/*`

For each, **remove `// @ts-nocheck`** (added in P2) once port is complete.

### P6.4 — Update app entry

```ts
// my-sonicjs-app/src/index.ts
import { Hono } from 'hono'
import { registerPlugins, HookSystemImpl } from '@sonicjs-cms/core'
import coreAuth from '@sonicjs-cms/core/plugins/core-plugins/auth'
import coreMedia from '@sonicjs-cms/core/plugins/core-plugins/media'
import cache from '@sonicjs-cms/core/plugins/cache'
import forms from '@sonicjs-cms/core/plugins/core-plugins/forms-plugin'
// ... etc
import myQrGenerator from './plugins/qr-generator'
import myContactForm from './plugins/contact-form'

const app = new Hono()

app.use('*', async (c, next) => {
  const hookSystem = new HookSystemImpl()
  await registerPlugins(app, [
    coreAuth, coreMedia, cache, forms,
    /* ... */
    myQrGenerator, myContactForm,
  ], {
    hookSystem,
    env: c.env,
    providers: {
      email: () => buildEmailService(c.env),
      cache: () => buildCacheService(c.env),
      storage: () => buildStorageService(c.env),
    },
    pluginService: buildPluginService(c.env),
  })
  await next()
})

export default app
```

Or — better — call `registerPlugins` inside the existing `bootstrapMiddleware` so it runs once per isolate (already the pattern on v3 — preserve).

### P6 verification

```bash
cd packages/core && npm run type-check   # MUST be clean
npm test                                  # full suite
npm run e2e                               # all existing E2E pass
```

E2E spec `tests/e2e/78-plugin-shape-port.spec.ts`:
- Each ported plugin's primary admin route loads (HTTP 200)
- Each ported plugin's primary hook fires (smoke test)
- Settings page loads for plugins that declared `configSchema`

---

## 9. Phase P7 — App bootstrap cleanup

**Goal**: Remove the legacy `plugins.register(...)` API (PR #829 era), `loadCollections` interaction with old plugin shape, and any remaining hand-rolled mount/wire calls.

### P7.1 — Audit + delete

```bash
# Search for callers of old surfaces and DELETE them
grep -rn "registerPluginRoutes\|wireRegisteredPlugins\|MountablePlugin\|WirablePlugin\|PluginBuilder" packages/ my-sonicjs-app/
```

Each call site → replace with `registerPlugins(...)` or delete (some are dead).

### P7.2 — Update `bootstrap.ts`

Replace old `registerPluginRoutes` + `wireRegisteredPlugins` calls with single `registerPlugins(app, plugins, host)`.

### P7 verification

E2E spec `tests/e2e/79-app-bootstrap.spec.ts`:
- Cold start: app boots in fresh isolate, all plugins activate, all routes mounted, all hooks wired
- Cron-first cold start: scheduled event fires before any HTTP → `registerPlugins` still runs, cron handler dispatches correctly
- `/admin/plugins` page lists all 27+ plugins as active
- `/admin/settings/plugins/email` form renders schema-driven

---

## 10. Phase P8 — Author docs

**Goal**: One clean author guide for the new shape. Kill the old multi-page legacy guide.

### P8.1 — Create `docs/plugins/v4-author-guide.md`

Content outline:

1. **Anatomy of a plugin** — one big annotated `definePlugin({...})` example
2. **The five capability families** — table of `SonicCapability` values with what each unlocks
3. **Lifecycle: register → wire → onBoot** — diagram + when each runs
4. **Declaring hooks** — discriminated union, capability-gated, typed narrowing
5. **Schema-driven settings** — `configSchema` field types + admin UI auto-render
6. **Declarative menu** — `menu: [...]`, ordering, permissions
7. **Cron jobs** — `crons: [...]` + `onCronTick` + wrangler.toml sync
8. **Async vs sync** — `register` is sync (Hono constraint); `onBoot` is async (env-dependent)
9. **Testing** — how to use `__tests__/utils/mock-factories.ts`
10. **Common patterns** — sending email, reading/writing storage, scheduled tasks, custom admin pages

### P8.2 — Delete

- `docs/plugins/plugin-development-guide.md` (legacy)
- `docs/ai/plans/plugin-documentation-fix-plan.md` (legacy)

Keep `docs/ai/plugin-system-documentation.md` as the AI-targeted reference (update for new shape).

---

## 11. File-by-file change inventory

### NEW

- `packages/core/src/plugins/sdk/capabilities.ts`
- `packages/core/src/plugins/sdk/events.ts`
- `packages/core/src/plugins/sdk/types.ts`
- `packages/core/src/plugins/sdk/define-plugin.ts` (REWRITTEN — 1.3KB identity factory)
- `packages/core/src/plugins/sdk/register-plugins.ts`
- `packages/core/src/plugins/sdk/config-schema.ts`
- `packages/core/src/plugins/sdk/settings-accessor.ts`
- `packages/core/src/plugins/sdk/index.ts`
- `packages/core/src/services/plugin-menu-singleton.ts`
- `docs/plugins/v4-author-guide.md`
- `tests/e2e/75-register-plugins.spec.ts`
- `tests/e2e/76-plugin-menu.spec.ts`
- `tests/e2e/77-schema-settings.spec.ts`
- `tests/e2e/78-plugin-shape-port.spec.ts`
- `tests/e2e/79-app-bootstrap.spec.ts`

### DELETED

- `packages/core/src/plugins/mount.ts`
- `packages/core/src/plugins/wire.ts`
- `packages/core/src/plugins/capabilities.ts` (moved to sdk/)
- `packages/core/src/plugins/sdk/plugin-builder.ts`
- `docs/plugins/plugin-development-guide.md`

### REWRITTEN

- `packages/core/src/plugins/index.ts` (barrel)
- `packages/core/src/index.ts` (top-level barrel — add new exports)
- `packages/core/src/middleware/bootstrap.ts` (P3 + P7)
- `packages/core/src/routes/admin-plugins.ts` (generic schema-driven settings handler)
- `packages/core/src/templates/layouts/admin-layout-catalyst.template.ts` (sidebar splice)
- `my-sonicjs-app/src/index.ts` (single `registerPlugins` call)

### PORTED (each gets a `definePlugin({ ... })` rewrite per P6.2 template)

All files in `packages/core/src/plugins/core-plugins/*/index.ts` (26 files, excluding `_shared/`)
All files in `packages/core/src/plugins/available/*/index.ts` (4 files)
`packages/core/src/plugins/cache/index.ts`
`packages/core/src/plugins/redirect-management/index.ts`
`packages/core/src/plugins/design/index.ts`
All files in `my-sonicjs-app/src/plugins/*/index.ts`

---

## 12. Capability vocabulary — final closed list (Phase 1)

The `SonicCapability` union in `sdk/capabilities.ts` is the closed vocabulary for this refactor. New capabilities require a core PR. Authors cannot add their own.

| Capability | Unlocks | Notes |
|---|---|---|
| `email:send` | `ctx.cap.email.send(...)` | Provider injected by host (MailChannels / CF Email Routing) |
| `storage:read` | `ctx.cap.storage.get(...)` | R2 binding |
| `storage:write` | `ctx.cap.storage.put(...)` | R2 binding |
| `cache:read` | `ctx.cap.cache.get(...)` | KV binding |
| `cache:write` | `ctx.cap.cache.put(...)` | KV binding |
| `hooks.auth:register` | Subscribe to `auth:*` events | Required for declarative `hooks` w/ auth events |
| `hooks.content-write:register` | Subscribe to `content:before/after:create/update/delete` | |
| `hooks.content-read:register` | Subscribe to content read events | Used by `global-variables`, `shortcodes` |
| `hooks.cron:register` | Subscribe to `cron:tick` | Required to use the `hooks: { 'cron:tick': ... }` field |
| `hooks.email-events:register` | Subscribe to email delivery events | Used by reconciliation |
| `request:intercept` | Return `Response` from a hook to short-circuit | Used by `redirect-management` |

---

## 13. Test strategy

### Unit tests (vitest)

For each new file in `sdk/`:

- `sdk/__tests__/capabilities.test.ts` — `normalizeCapability` rename + unknown handling
- `sdk/__tests__/events.test.ts` — `isSonicHookEvent` membership
- `sdk/__tests__/define-plugin.test.ts` — identity, type preservation, no validation done at define time
- `sdk/__tests__/register-plugins.test.ts` — all 10 error reasons + happy path + topo-sort integration + capability runtime gate (Proxy throws)
- `sdk/__tests__/config-schema.test.ts` — parse + render all 4 field types + form-data round-trip + boolean-false bug (PR-2a D4)
- `services/__tests__/plugin-menu-singleton.test.ts` — filter, sort, project; permission-filter purity

### E2E tests (Playwright, numbered 75–79)

Per phase, listed in §4 above.

### Integration tests

- `__tests__/integration/plugin-bootstrap.integration.test.ts` — full `registerPlugins(app, [...allCorePlugins], host)` cold-start. Must complete without throwing. Verify every plugin's `register` ran, every `onBoot` ran, every cron declared.

---

## 14. Rollout — branch + PR strategy

Stack the 8 PRs on top of `origin/v3`. Each PR is independently mergeable to v3 (no `main` involved).

```
v3
└── lane711/plugin-sdk-v4-p1-shell                  (P1)
    └── lane711/plugin-sdk-v4-p2-register-plugins   (P2)
        └── lane711/plugin-sdk-v4-p3-bootstrap-fix  (P3)
            └── lane711/plugin-sdk-v4-p4-menu       (P4)
                └── lane711/plugin-sdk-v4-p5-schema-settings  (P5)
                    └── lane711/plugin-sdk-v4-p6-port-plugins (P6 — biggest)
                        └── lane711/plugin-sdk-v4-p7-bootstrap-cleanup (P7)
                            └── lane711/plugin-sdk-v4-p8-docs          (P8)
```

P6 is the big one — break into sub-branches per plugin family if needed:
- `p6a-core-auth-media-cache`
- `p6b-email-forms-reconciliation`
- `p6c-cms-features` (content, workflow, testimonials, user-profiles, etc.)
- `p6d-utilities` (turnstile, oauth, magic-link, otp, demo-login)
- `p6e-app-plugins` (qr-generator, contact-form)

---

## 15. Acceptance criteria

This refactor ships when ALL of:

- [ ] `definePlugin({...})` is the ONLY way to author a plugin (no `PluginBuilder`, no hand-built `MountablePlugin` objects)
- [ ] `registerPlugins(app, plugins, host)` is the ONLY way for the app to mount plugins
- [ ] `mount.ts`, `wire.ts`, `capabilities.ts` (top-level), `sdk/plugin-builder.ts` are DELETED
- [ ] `npm run type-check` clean across `packages/core` and `my-sonicjs-app`
- [ ] `npm test` — full suite passes (target: same count as v3 today, +unit tests for new sdk modules)
- [ ] `npm run e2e` — all existing specs pass + 5 new specs (75–79) pass
- [ ] Every core-plugin and app plugin successfully boots via `registerPlugins`
- [ ] At least 3 core-plugins are enrolled on the schema-driven settings renderer with their settings UI rendering correctly
- [ ] Admin sidebar shows plugin menu entries declared via `menu: [...]` field
- [ ] Cycle in `requires` throws `RegisterPluginsError('cycle')` at startup, not at first request
- [ ] Hook subscription without matching capability throws `RegisterPluginsError('capability_missing')` at startup
- [ ] `ctx.cap.X` access without capability throws `SonicCapabilityError` at runtime
- [ ] `register()` returning a Promise throws `RegisterPluginsError('register_returned_promise')` at startup
- [ ] All ported plugins are typed end-to-end (no `any`, no `// @ts-nocheck`)
- [ ] `docs/plugins/v4-author-guide.md` exists and covers all 10 sections
- [ ] CLAUDE.md updated to reflect new SDK shape (the "Files (cheat-sheet)" table)

---

## 16. Out-of-scope (explicitly NOT in this plan)

- Removing the document-model `documents` table (separate plan in `document-model-poc-plan.md`)
- Multi-tenant plugin behavior changes (already shipped on v3)
- Migrating to Payload's React admin (deferred — keep HTMX)
- Custom React components in plugin sidebar (deferred — strings + paths only)
- GraphQL endpoint generation from `configSchema` (future — `configSchema` is settings-only here)
- Plugin marketplace / dynamic install (future)

---

## 17. Risk + rollback

**Risk**: P6 is large (30+ plugins). If a single plugin's port breaks runtime, the whole app may not boot.

**Mitigation**:
- Port core-auth FIRST and stop. Run full E2E. Only proceed once green.
- Keep each plugin port a separate commit so `git revert` is cheap.
- Use the `// @ts-nocheck` escape per plugin during P2; remove per plugin in P6 in dependency order.

**Rollback**: every phase is a separate PR off v3. Revert any single PR cleanly. If P6 reveals a missing surface in the new SDK, land a P1.5 follow-up before continuing P6 — don't hack around it in the plugin port.

---

## 18. Open questions (resolve before P1 starts)

1. **Capability provider injection** — do we put providers on the request context (`c.set('providers', ...)`) or pass into `registerPlugins(..., host)` once at bootstrap? Plan assumes the latter (bootstrap once, shared across requests).
2. **Settings storage backend** — `loadPluginSettings`/`savePluginSettings` currently use the `plugins` table on v3. Keep using that (plugins-as-documents has its own settings field) — confirm before P5.
3. **`requires` vs `dependencies` field name** — plan uses `requires` (matches infowall + Payload `plugins.requires`). v3 currently uses `dependencies`. Both work in topo-sort if we accept both for one cycle, then deprecate `dependencies`.

---

## 19. Implementation notes for downstream coder

- **Edit one file at a time during P6**. After each plugin port, run `npm run type-check`. Don't batch 5 plugin ports into one commit — too painful to revert.
- **Run `npm test` after each phase**. The real-SQLite harness (`__tests__/utils/d1-sqlite.ts`) catches the SQL/constraint stuff that mock tests can't (R10 in CLAUDE.md).
- **E2E specs are NOT optional** (R11). Each phase ships with its spec. Run with `npx playwright test tests/e2e/7X-*.spec.ts --headed` while developing.
- **No new migration files needed**. This refactor is pure code — no schema changes.
- **Token-efficient lookups**: use `codegraph_explore` for "where does X exist on v3" instead of grep+read. Plan already includes the file paths; use codegraph only when something doesn't match.
- **Caveman mode in chat is OK** (per CLAUDE.md), but commit messages + PR descriptions follow Conventional Commits in normal English.
- **Commit message template per phase**:
  ```
  feat(plugins): Pn — <one-line phase summary>

  <2-4 sentence what + why>

  Implements: docs/ai/plans/plugin-sdk-payload-shaped-plan.md §<phase #>
  ```

End of plan.
