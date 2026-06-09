/**
 * Plugin wiring phase (the async half of two-phase boot)
 *
 * Route mounting is synchronous and happens at construction (see `mount.ts`).
 * Everything that needs the runtime environment — hook subscriptions and the
 * `onBoot` lifecycle — happens here, lazily, on the first request, after every
 * plugin has registered. Splitting the two avoids Hono's "matcher already built"
 * lock (routes must mount before the first request; env-dependent wiring can
 * only run once a request supplies `c.env`).
 *
 * This module is the wiring mechanism. Where/when it is invoked (a once-guarded
 * first-request step) is the caller's concern; `createPluginWirer()` provides
 * the once-guard.
 */

import type { HookSystemLike } from './hooks/typed-hooks'
import type { HookEventName } from './hooks/catalog'
import { isKnownHookEvent } from './hooks/catalog'
import { HOOK_CAPABILITY_MAP, SonicCapabilityError } from './capabilities'
import { topoSort } from './topo-sort'

/** A hook subscription declared by a plugin (the legacy `hooks[]` shape). */
export interface WirableHook {
  name: string
  handler: (data: any, context: any) => any
  priority?: number
}

/**
 * Structural contract this module needs from a plugin. Deliberately minimal (and
 * not the full `Plugin` interface) so the `src`/`dist` duplicate `Plugin`
 * identities and user-supplied plugins all satisfy it without casts.
 */
export interface WirablePlugin {
  /** Stable unique id (used by topo-sort). Falls back to `name`. */
  id?: string
  name?: string
  /** IDs of plugins that must be wired before this one. */
  dependencies?: string[]
  /**
   * Capabilities declared by the plugin. When present (even as an empty array),
   * the wire phase enforces that each declarative hook subscription is covered by
   * a matching capability in {@link HOOK_CAPABILITY_MAP}. Absent on old-style
   * `PluginBuilder` plugins — the gate is skipped for backwards compatibility.
   */
  capabilities?: readonly string[]
  hooks?: WirableHook[]
  /**
   * Async lifecycle hook run once, after all plugins have registered and their
   * hooks are subscribed. The place for env-dependent setup (services, seeding,
   * cron registration). Errors are isolated per-plugin.
   */
  onBoot?: (context: PluginBootContext) => void | Promise<void>
}

/** Options forwarded to {@link wireRegisteredPlugins}. */
export interface WireOptions {
  /**
   * Strict mode: capability violations are captured as errors in `WireResult`
   * (and the hook is skipped) instead of only logging a warning.
   * Also makes unknown dependency ids hard errors instead of warnings.
   * Enable in CI or development; leave off in production for resilience.
   */
  strict?: boolean
  /**
   * When false, skip dependency-aware ordering. Defaults to true (plugins with
   * `dependencies` are wired after their declared dependencies).
   */
  sortByDependencies?: boolean
}

/** Context handed to `onBoot`. Kept loose; concrete bindings are filled by the host. */
export interface PluginBootContext {
  /** The live hook system (already carrying every plugin's subscriptions). */
  hooks: HookSystemLike
  /** Runtime bindings, when available. */
  env?: Record<string, unknown>
  [key: string]: unknown
}

/** Outcome of a wiring pass. */
export interface WireResult {
  /** Total hook subscriptions registered. */
  subscribed: number
  /** Names of plugins whose `onBoot` completed successfully. */
  booted: string[]
  /** Per-plugin errors (wiring never throws; one bad plugin can't break boot). */
  errors: Array<{ plugin: string; phase: 'subscribe' | 'onBoot'; error: unknown }>
}

/**
 * Subscribe every plugin's declarative `hooks[]` to the live hook system, then
 * run each plugin's `onBoot`, in array order.
 *
 * Subscriptions happen for ALL plugins first, so that one plugin's `onBoot` can
 * rely on another plugin's hooks already being registered. Per-plugin errors are
 * captured in the result rather than thrown.
 */
export async function wireRegisteredPlugins(
  plugins: Array<WirablePlugin | undefined | null>,
  context: PluginBootContext,
  options: WireOptions = {}
): Promise<WireResult> {
  const result: WireResult = { subscribed: 0, booted: [], errors: [] }

  // Sort by dependencies (default on). Plugins with no `dependencies` keep their
  // original position; v3 plugins that declare deps are moved after them.
  const sortByDeps = options.sortByDependencies ?? true
  const raw = plugins.filter((p): p is WirablePlugin => !!p && typeof p === 'object')
  const valid = sortByDeps ? topoSort(raw, { strict: options.strict }) : raw

  // Phase A: subscribe all hooks first.
  for (const plugin of valid) {
    const name = plugin.name ?? 'unknown'
    if (!Array.isArray(plugin.hooks) || plugin.hooks.length === 0) continue
    for (const hook of plugin.hooks) {
      if (!hook || typeof hook.name !== 'string' || typeof hook.handler !== 'function') {
        result.errors.push({ plugin: name, phase: 'subscribe', error: new Error('invalid hook entry') })
        continue
      }

      // Capability gate: only applies to v3 plugins that declare capabilities.
      // Old-style PluginBuilder plugins (capabilities === undefined) are exempt
      // for backwards compatibility.
      if (plugin.capabilities !== undefined && isKnownHookEvent(hook.name)) {
        const requiredCap = HOOK_CAPABILITY_MAP[hook.name as HookEventName]
        if (requiredCap && !plugin.capabilities.includes(requiredCap)) {
          const capErr = new SonicCapabilityError(requiredCap, name)
          if (options.strict) {
            result.errors.push({ plugin: name, phase: 'subscribe', error: capErr })
          } else {
            console.warn(`[plugins] ${capErr.message} Hook "${hook.name}" will not be registered.`)
          }
          continue
        }
      }

      try {
        context.hooks.register(hook.name, hook.handler, hook.priority)
        result.subscribed++
      } catch (error) {
        result.errors.push({ plugin: name, phase: 'subscribe', error })
      }
    }
  }

  // Phase B: run onBoot, after all subscriptions exist.
  for (const plugin of valid) {
    const name = plugin.name ?? 'unknown'
    if (typeof plugin.onBoot !== 'function') continue
    try {
      await plugin.onBoot(context)
      result.booted.push(name)
    } catch (error) {
      result.errors.push({ plugin: name, phase: 'onBoot', error })
    }
  }

  // Phase C (best-effort): reflect wired plugin list into the `plugins` DB table
  // so the admin view stays in sync with what's actually running. Errors are
  // non-fatal — DB unavailable during cron-first boot should not break wiring.
  if (context.env?.DB) {
    reflectWiredPlugins(valid, context.env.DB as D1DatabaseLike).catch((err) => {
      console.warn('[plugins] DB reflection failed (non-fatal):', err)
    })
  }

  return result
}

/** Minimal D1 interface needed for reflection (avoids a hard @cloudflare/workers-types dep). */
interface D1DatabaseLike {
  prepare(sql: string): { bind(...args: unknown[]): { run(): Promise<unknown> } }
  batch(stmts: unknown[]): Promise<unknown>
}

/**
 * Best-effort: register each wired plugin in the `plugins` table so the admin
 * can see and manage it. New plugins start as 'inactive' — an admin must
 * explicitly activate them via the Plugins admin page. Existing rows keep
 * their current status so admin deactivation survives reboots.
 * Non-fatal on any error.
 */
async function reflectWiredPlugins(plugins: WirablePlugin[], db: D1DatabaseLike): Promise<void> {
  const now = Date.now()
  for (const plugin of plugins) {
    const id = (plugin as any).id ?? plugin.name
    if (!id) continue
    const displayName = (plugin as any).name ?? id
    const version = (plugin as any).version ?? '0.0.0'
    const description = (plugin as any).description ?? ''
    try {
      await db
        .prepare(
          `INSERT INTO plugins (id, name, display_name, description, version, author, category,
              status, is_core, installed_at, last_updated)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', 1, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             version = excluded.version,
             display_name = excluded.display_name,
             last_updated = excluded.last_updated`
        )
        .bind(id, id, displayName, description, version, 'core', 'core', now, now)
        .run()
    } catch {
      // Individual plugin upsert failure is silently skipped — one bad row
      // must not abort the rest of the reflection pass.
    }
  }
}

/**
 * Wrap {@link wireRegisteredPlugins} in a once-guard.
 *
 * The returned function runs the wiring at most once per process: the first call
 * starts it and caches the promise; every later call returns that same promise.
 * This is the first-request trigger — many concurrent first requests all await
 * one wiring pass.
 *
 * @param plugins     Plugins to wire (evaluated lazily at first call).
 * @param ctxFactory  Builds the boot context at first-call time (so it can read
 *                    per-request env).
 */
export function createPluginWirer(
  plugins: Array<WirablePlugin | undefined | null> | (() => Array<WirablePlugin | undefined | null>),
  ctxFactory: () => PluginBootContext
): () => Promise<WireResult> {
  let started: Promise<WireResult> | undefined
  return () => {
    if (!started) {
      const list = typeof plugins === 'function' ? plugins() : plugins
      started = wireRegisteredPlugins(list, ctxFactory())
    }
    return started
  }
}
