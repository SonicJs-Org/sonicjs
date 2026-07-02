/**
 * definePlugin() — the v3 plugin authoring entry point
 *
 * A plugin is authored as a single typed declaration and consumed, unchanged, by
 * every part of the runtime:
 *
 *   export const emailPlugin = definePlugin({
 *     id: 'email',
 *     version: '3.0.0',
 *     capabilities: ['email:send', 'hooks.auth:subscribe', 'cron:register'],
 *     register(app) { app.route('/admin/plugins/email', emailRoutes) },   // SYNC
 *     async onBoot(ctx) {                                                  // ASYNC
 *       ctx.hooks.on('auth:registration:completed', (p) => { ... })       // typed
 *       ctx.cap.email                                                     // gated
 *     },
 *     crons: [{ schedule: '*\/15 * * * *', hookFamily: 'email-reconciliation' }],
 *     async onCronTick(event, ctx) { ... },
 *   })
 *
 * The object it returns satisfies the structural contracts the runtime already
 * uses — `MountablePlugin` (mount.ts), `WirablePlugin` (wire.ts), `CronablePlugin`
 * (cron.ts) — plus the legacy `Plugin` metadata fields the admin/registry read.
 * No adapters: a defined plugin drops straight into `plugins.register` or the core
 * plugin list.
 *
 * The value definePlugin adds over a hand-written object is the enriched context:
 * inside `onBoot`/`onCronTick` the author gets a *typed* hook facade (`ctx.hooks`)
 * and the *capability-gated* service context (`ctx.cap`), instead of the raw
 * string-keyed hook system. See the two-phase boot contract: `register` is
 * synchronous (routes only); everything env-dependent lives in `onBoot`.
 */

import type { Hono } from 'hono'
import type { Capability } from '../capabilities'
import {
  createCapabilityContext,
  normalizeCapabilities,
  type CapabilityProviders,
  type CapabilityContext,
} from '../capabilities'
import { createTypedHooks, type TypedHooks, type TypedHookHandler } from '../hooks/typed-hooks'
import type { HookEventName } from '../hooks/catalog'
import type { PluginBootContext, WirableHook } from '../wire'
import type { CronContext, CronDeclaration, CronTickEvent } from '../cron'
import type { MountableRoute } from '../mount'
import { getCoreVersion } from '../../utils/version'
import type { ConfigSchema } from './config-schema'
import type { PluginMenuEntry } from '../../services/plugin-menu-singleton'

// ── Minimal semver helpers (no external dep — Workers are bundle-size constrained) ─

/** True if `v` is a valid semver string (X.Y.Z with optional pre-release). */
function isSemver(v: string): boolean {
  return /^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$/.test(v.trim())
}

/**
 * Very lightweight semver range satisfier. Handles the most common range forms:
 * exact (`1.2.3`), caret (`^1.2.3` = compatible major), tilde (`~1.2.3` = compatible
 * minor), comparators (`>=1.0.0`, `>1`, `<2.0.0`), and space-separated AND chains.
 * Not a full semver implementation — use the `semver` npm package if you need
 * full range syntax in a non-Workers environment.
 */
function semverSatisfies(version: string, range: string): boolean {
  try {
    const [major, minor, patch] = version.trim().split('-')[0]!.split('.').map(Number)
    const v = major! * 1_000_000 + (minor ?? 0) * 1_000 + (patch ?? 0)

    const toInt = (s: string) => {
      const [a, b, c] = s.split('.').map(Number)
      return a! * 1_000_000 + (b ?? 0) * 1_000 + (c ?? 0)
    }

    // AND chain: all clauses must pass.
    return range
      .trim()
      .split(/\s+(?=[><=^~])|\s+(?=\d)/)
      .filter(Boolean)
      .every((clause) => {
        const c = clause.trim()
        if (c.startsWith('^')) {
          const base = toInt(c.slice(1))
          const nextMajor = Math.floor(base / 1_000_000 + 1) * 1_000_000
          return v >= base && v < nextMajor
        }
        if (c.startsWith('~')) {
          const base = toInt(c.slice(1))
          const nextMinor = Math.floor(base / 1_000 + 1) * 1_000
          return v >= base && v < nextMinor
        }
        if (c.startsWith('>=')) return v >= toInt(c.slice(2))
        if (c.startsWith('<=')) return v <= toInt(c.slice(2))
        if (c.startsWith('>')) return v > toInt(c.slice(1))
        if (c.startsWith('<')) return v < toInt(c.slice(1))
        return v === toInt(c) // exact
      })
  } catch {
    return true // fail open — don't block a plugin on a parse error
  }
}

/**
 * Declarative typed hook subscriptions: a map of canonical event name → handler,
 * each narrowed to that event's payload. Flattened into the plugin's `hooks[]`
 * and subscribed during the wire phase. Use `onBoot`'s `ctx.hooks.on()` instead
 * for dynamic/conditional subscriptions.
 */
export type DeclarativeHooks = {
  [E in HookEventName]?: TypedHookHandler<E>
}

/**
 * Context handed to a defined plugin's `onBoot` / `onCronTick`.
 *
 * Enriches the raw boot/cron context with a typed hook facade and the gated
 * capability context, while keeping `raw` and `env` available as an escape hatch.
 */
export interface DefinedPluginContext<Caps extends readonly Capability[] = readonly Capability[]> {
  /** Typed hook facade — `ctx.hooks.on('auth:registration:completed', …)`. */
  hooks: TypedHooks
  /**
   * Capability-gated services. With a const-narrowed `Caps`, `ctx.cap.email` is
   * typed `EmailService` only when `'email:send'` was declared (else `never`),
   * and throws `SonicCapabilityError` at runtime if accessed undeclared.
   */
  cap: CapabilityContext<Caps>
  /** Runtime bindings, when available (absent during construction). */
  env?: Record<string, unknown>
  /** The unwrapped context the runtime passed. */
  raw: PluginBootContext | CronContext
}

/** Input to {@link definePlugin}. */
export interface DefinePluginInput<Caps extends readonly Capability[] = readonly []> {
  /** Unique, stable plugin id (kebab-case). Becomes the plugin `name`. */
  id: string
  /** Human-readable display name. Defaults to `id`. */
  name?: string
  /**
   * Semantic version of this plugin (e.g. `'1.2.3'`). Must be a valid semver
   * string — invalid values emit a console.warn at definition time.
   */
  version: string
  /**
   * A semver range expressing which SonicJS core versions this plugin supports
   * (e.g. `'^3.0.0'` or `'>=3.1.0 <4.0.0'`). Checked against the running
   * core version at registration; a mismatch logs a compatibility warning but
   * does not block activation (plugins remain resilient by default).
   */
  sonicjsVersionRange?: string
  description?: string
  author?: { name: string; email?: string; url?: string }
  /** Other plugin ids this one needs (load-order / activation). */
  dependencies?: string[]
  /**
   * Capabilities this plugin declares. The gated `ctx.cap` accessors throw for
   * anything not listed here. Pass as a literal (`['email:send'] as const` is not
   * needed — the `const` type param infers the tuple) to get `ctx.cap` narrowed.
   * Unknown/deprecated names are normalized then warned about at definition.
   */
  capabilities?: Caps

  // ── Synchronous registration (routes only) ──
  /** Declarative routes (mounted before the /admin catch-all). */
  routes?: MountableRoute[]
  /**
   * Imperative route registration. MUST be synchronous (Hono's router locks after
   * the first request). Async work belongs in `onBoot`.
   */
  register?: (app: Hono) => void

  // ── Asynchronous wiring ──
  /**
   * Declarative typed hook subscriptions (`{ 'content:after:create': (p) => … }`).
   * Subscribed during the wire phase; each handler is narrowed to its event payload.
   */
  hooks?: DeclarativeHooks
  /**
   * Run once on first request, after every plugin has registered. The place for
   * dynamic hook subscriptions (`ctx.hooks.on(...)`) and env-dependent setup.
   */
  onBoot?: (context: DefinedPluginContext<Caps>) => void | Promise<void>

  // ── Cron ──
  /** Scheduled-work declarations (also list the expressions in wrangler.toml). */
  crons?: CronDeclaration[]
  /** Handler for a fired cron; branch on `event.hookFamily`. */
  onCronTick?: (event: CronTickEvent, context: DefinedPluginContext<Caps>) => void | Promise<void>

  // ── Lifecycle (DB/schema only — never touches routes) ──
  install?: (context: unknown) => void | Promise<void>
  uninstall?: (context: unknown) => void | Promise<void>
  activate?: (context: unknown) => void | Promise<void>
  deactivate?: (context: unknown) => void | Promise<void>

  // ── Declarative admin surface ──
  /**
   * Declarative admin-sidebar entries collected by registerPlugins. The catalyst
   * sidebar renders them automatically; no per-plugin `addMenuItem(...)` call
   * required.
   */
  menu?: PluginMenuEntry[]
  /**
   * Schema-driven settings. Declaring this auto-renders the admin form at
   * `/admin/settings/plugins/:id`, parses FormData back into typed values, and
   * persists them via the plugin-service. Authors no longer hand-roll settings
   * routes/templates.
   */
  configSchema?: ConfigSchema
  /**
   * Custom settings-tab renderer for the plugin detail page (`/admin/plugins/:id`).
   * `loadData` is called server-side with the D1 database before the page renders;
   * its result is forwarded to `render` as `data`. Plugins that need DB access
   * (e.g. fetching their own document records) declare `loadData`; static content
   * can omit it and read only from `plugin` / `settings`.
   */
  settingsTabContent?: {
    loadData?: (db: any) => Promise<any>
    render: (props: { plugin: any; settings: any; data?: any }) => string
  }
}

/**
 * The runtime shape produced by {@link definePlugin}. Carries the legacy metadata
 * fields plus the v3 surfaces; structurally satisfies `MountablePlugin`,
 * `WirablePlugin`, and `CronablePlugin`.
 */
export interface DefinedPlugin {
  id: string
  name: string
  version: string
  /** The semver range for SonicJS core compatibility declared by the author. */
  sonicjsVersionRange?: string
  description?: string
  author?: { name: string; email?: string; url?: string }
  dependencies?: string[]
  capabilities: Capability[]
  routes?: MountableRoute[]
  register?: (app: Hono) => void
  /** Declarative hook subscriptions, flattened for the wire phase. */
  hooks?: WirableHook[]
  /** Wrapped onBoot accepting the runtime's raw boot context. */
  onBoot?: (context: PluginBootContext) => void | Promise<void>
  crons?: CronDeclaration[]
  /** Wrapped onCronTick accepting the runtime's raw cron context. */
  onCronTick?: (event: CronTickEvent, context: CronContext) => void | Promise<void>
  install?: (context: unknown) => void | Promise<void>
  uninstall?: (context: unknown) => void | Promise<void>
  activate?: (context: unknown) => void | Promise<void>
  deactivate?: (context: unknown) => void | Promise<void>
  /** Declarative admin sidebar entries. registerPlugins collects + sets the menu singleton. */
  menu?: PluginMenuEntry[]
  /** Schema-driven settings. Renders the admin settings form for this plugin. */
  configSchema?: ConfigSchema
  /** Custom settings-tab renderer. loadData runs server-side; render produces the tab HTML. */
  settingsTabContent?: {
    loadData?: (db: any) => Promise<any>
    render: (props: { plugin: any; settings: any; data?: any }) => string
  }
  /** Marker so tooling/tests can detect a v3-defined plugin. */
  // eslint-disable-next-line @typescript-eslint/naming-convention -- intentional internal marker
  readonly __sonicV3: true
}

/**
 * Build the enriched context from whatever raw context the runtime passed.
 *
 * Capability providers ride on the raw context (`raw.providers`) — the host
 * supplies real `email`/`cache`/`http` factories there. When none are supplied, a
 * declared-but-used capability throws "no provider supplied by host", which is the
 * correct signal during early bring-up.
 */
function enrich<Caps extends readonly Capability[]>(
  raw: PluginBootContext | CronContext,
  runtimeCaps: readonly Capability[],
  pluginName: string
): DefinedPluginContext<Caps> {
  const providers = (raw as { providers?: CapabilityProviders }).providers ?? {}
  return {
    hooks: createTypedHooks(raw.hooks),
    // Runtime gating uses the normalized capability set; the context TYPE reflects
    // the declared `Caps` tuple (the narrowing the author sees).
    cap: createCapabilityContext(runtimeCaps as unknown as Caps, providers, pluginName),
    env: raw.env,
    raw,
  }
}

/**
 * Define a v3 plugin. Validates declared capabilities (warns on unknown), then
 * returns a runtime-ready plugin whose `onBoot`/`onCronTick` receive the enriched,
 * typed, capability-gated context. The `const Caps` type parameter captures the
 * declared capability tuple so `ctx.cap` is narrowed at the author's call site.
 */
export function definePlugin<const Caps extends readonly Capability[] = readonly []>(
  input: DefinePluginInput<Caps>
): DefinedPlugin {
  if (!input.id) throw new Error('definePlugin: `id` is required')
  if (!input.version) throw new Error(`definePlugin: \`version\` is required (plugin "${input.id}")`)

  // Semver validation: warn if the plugin's own version is not a valid semver string.
  if (!isSemver(input.version)) {
    // eslint-disable-next-line no-console
    console.warn(
      `[plugins] Plugin "${input.id}" has an invalid version: "${input.version}". ` +
        `Use a valid semver string (e.g. "1.0.0") to participate in version-range checks.`
    )
  }

  // SonicJS core compatibility range check.
  if (input.sonicjsVersionRange) {
    const coreVersion = getCoreVersion()
    if (!semverSatisfies(coreVersion, input.sonicjsVersionRange)) {
      // eslint-disable-next-line no-console
      console.warn(
        `[plugins] Plugin "${input.id}" declares sonicjsVersionRange "${input.sonicjsVersionRange}" ` +
          `but running core version is "${coreVersion}". ` +
          `The plugin may not work correctly. Consider updating the plugin or the version range.`
      )
    }
  }

  // Normalize declared capabilities to canonical names first (resolves deprecated
  // / cross-fork spellings like `storage:write` → `media:write`), then warn on any
  // that remain unknown. Strict-reject at registration is layered in Phase 5d.
  const { capabilities, unknown } = normalizeCapabilities(input.capabilities ?? [])
  if (unknown.length > 0) {
    // eslint-disable-next-line no-console
    console.warn(
      `[plugins] Plugin "${input.id}" declares unknown capabilities: ${unknown.join(', ')}. ` +
        `These will gate nothing. Check for typos or update the capability vocabulary.`
    )
  }

  const name = input.id

  const onBoot = input.onBoot
    ? (raw: PluginBootContext) => input.onBoot!(enrich(raw, capabilities, name))
    : undefined

  const onCronTick = input.onCronTick
    ? (event: CronTickEvent, raw: CronContext) => input.onCronTick!(event, enrich(raw, capabilities, name))
    : undefined

  // Flatten the declarative typed `hooks` map into the wirable `hooks[]` array.
  // Each handler is wrapped to the raw (data, context) shape, coalescing a void
  // return back to the incoming payload (matching createTypedHooks().on()).
  const hooks: WirableHook[] | undefined = input.hooks
    ? Object.entries(input.hooks)
        .filter(([, h]) => typeof h === 'function')
        .map(([eventName, h]) => ({
          name: eventName,
          handler: async (data: any, context: any) => {
            const result = await (h as TypedHookHandler<HookEventName>)(data, context ?? {})
            return result === undefined ? data : result
          },
        }))
    : undefined

  return {
    id: input.id,
    name,
    version: input.version,
    sonicjsVersionRange: input.sonicjsVersionRange,
    description: input.description,
    author: input.author,
    dependencies: input.dependencies,
    capabilities,
    routes: input.routes,
    register: input.register,
    hooks,
    onBoot,
    crons: input.crons,
    onCronTick,
    install: input.install,
    uninstall: input.uninstall,
    activate: input.activate,
    deactivate: input.deactivate,
    menu: input.menu,
    configSchema: input.configSchema,
    settingsTabContent: input.settingsTabContent,
    // eslint-disable-next-line @typescript-eslint/naming-convention -- intentional internal marker
    __sonicV3: true,
  }
}

/** True if `plugin` was produced by {@link definePlugin}. */
export function isDefinedPlugin(plugin: unknown): plugin is DefinedPlugin {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- intentional internal marker
  return !!plugin && typeof plugin === 'object' && (plugin as { __sonicV3?: unknown }).__sonicV3 === true
}
