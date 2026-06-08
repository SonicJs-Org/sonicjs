/**
 * Plugin route mounting primitive
 *
 * This is the shared, position-aware primitive that mounts plugin routes into
 * the Hono app. It replaces the hand-wired, copy-pasted
 * `if (plugin.routes) { for (...) app.route(...) }` blocks that previously lived
 * in `app.ts`.
 *
 * ## Why synchronous
 *
 * Hono's `SmartRouter` builds (and then locks) its match tree on the first
 * request. Calling `app.route()` after that throws:
 *
 *   `Error: Can not add a route since the matcher is already built`
 *
 * Therefore route mounting MUST happen synchronously at app-construction time,
 * before any request is served. A plugin's imperative `register(app)` hook is
 * held to the same contract: returning a Promise is a hard error
 * (`PluginRegisterMustBeSyncError`) rather than a silent hang. Asynchronous,
 * env-dependent work (hook subscriptions, services, crons) belongs in a later
 * lazy "wire" phase — not here.
 *
 * ## Position-awareness
 *
 * Plugin routes must be mounted BEFORE the bare `/admin` catch-all so that a
 * plugin's own `/admin/<x>` pages are not shadowed. Callers are responsible for
 * invoking `registerPluginRoutes()` at the correct position in `app.ts`; this
 * module just performs the mounting deterministically.
 */

import type { Hono } from 'hono'

/**
 * Minimal structural contract this module needs to mount a plugin.
 *
 * Deliberately NOT the full `Plugin` interface: the core plugins are typed
 * against the built `@sonicjs-cms/core` `dist` declarations, while this file
 * lives in `src`, and TypeScript treats those two `Plugin` types as distinct
 * nominal identities. Accepting a structural subset lets both the `src` and
 * `dist` `Plugin` shapes (and user-supplied plugins) be mounted without casts,
 * and keeps `mount.ts` honest about what it actually reads.
 */
export interface MountableRoute {
  path: string
  handler: unknown
  priority?: number
}

export interface MountablePlugin {
  name?: string
  routes?: MountableRoute[]
  /** Synchronous imperative route registration. A Promise return is rejected. */
  register?: (app: any) => unknown
}

/**
 * Thrown when a plugin's `register(app)` hook returns a Promise.
 *
 * `register()` runs synchronously at construction time (see module docs). Move
 * any async work to a lifecycle hook (`install`/`activate`) or the async wiring
 * phase instead.
 */
export class PluginRegisterMustBeSyncError extends Error {
  constructor(pluginName: string) {
    super(
      `Plugin "${pluginName}" register() returned a Promise. ` +
        `register() must be synchronous because Hono's router locks after the first request. ` +
        `Move async work (hook subscriptions, services, crons) to onBoot()/lifecycle hooks.`
    )
    this.name = 'PluginRegisterMustBeSyncError'
  }
}

/** A single mounted route, for diagnostics/introspection. */
export interface MountedRoute {
  plugin: string
  path: string
}

/** Outcome of a mount pass. */
export interface MountResult {
  /** Routes successfully mounted, in mount order. */
  mounted: MountedRoute[]
  /** Plugins (or routes) skipped, with a human-readable reason. */
  skipped: Array<{ plugin: string; reason: string }>
}

// Loosely-typed Hono app. The host app is `Hono<{ Bindings; Variables }>`, but
// route handlers come from many plugins with varying generics, so — mirroring
// the historical `app.route(path, handler as any)` usage — we accept any Hono.
type AnyHono = Hono<any, any, any>

/**
 * Sort a plugin's routes so higher-priority routes mount first.
 *
 * Priority defaults to 0. Equal priorities preserve declaration order (V8's
 * sort is stable). Most plugins declare non-overlapping paths, so this only
 * matters when two routes could match the same request.
 */
function sortRoutesByPriority(routes: MountableRoute[]): MountableRoute[] {
  return routes
    .map((route, index) => ({ route, index }))
    .sort((a, b) => {
      const pa = a.route.priority ?? 0
      const pb = b.route.priority ?? 0
      if (pb !== pa) return pb - pa
      return a.index - b.index
    })
    .map((entry) => entry.route)
}

/**
 * Mount a single plugin's routes into `app`.
 *
 * Applies, in order:
 *  1. The plugin's declarative `routes[]` (sorted by priority), and
 *  2. The plugin's imperative `register(app)` hook, if present (sync-guarded).
 *
 * @param app    Host Hono app (mount BEFORE the `/admin` catch-all).
 * @param plugin Plugin to mount.
 * @param result Optional accumulator for diagnostics.
 */
export function mountPlugin(app: AnyHono, plugin: MountablePlugin, result?: MountResult): void {
  if (!plugin || typeof plugin !== 'object' || !plugin.name) {
    result?.skipped.push({ plugin: String((plugin as any)?.name ?? 'unknown'), reason: 'not a valid plugin object' })
    return
  }

  // 1. Declarative routes
  if (Array.isArray(plugin.routes) && plugin.routes.length > 0) {
    for (const route of sortRoutesByPriority(plugin.routes)) {
      if (!route || !route.path || !route.handler) {
        result?.skipped.push({ plugin: plugin.name, reason: `invalid route entry (missing path or handler)` })
        continue
      }
      app.route(route.path, route.handler as AnyHono)
      result?.mounted.push({ plugin: plugin.name, path: route.path })
    }
  }

  // 2. Imperative register(app) — must be synchronous
  if (typeof plugin.register === 'function') {
    const maybePromise = plugin.register(app)
    if (maybePromise && typeof (maybePromise as any).then === 'function') {
      throw new PluginRegisterMustBeSyncError(plugin.name)
    }
  }
}

/** Options for {@link registerPluginRoutes}. */
export interface RegisterPluginRoutesOptions {
  /**
   * Label used in dev warnings (e.g. `'core'` or `'user'`). Purely cosmetic.
   */
  source?: string
  /**
   * When true, log a warning if two plugins mount the exact same route path
   * (later registration is shadowed by Hono's first-match semantics). Defaults
   * to true in non-production.
   */
  warnOnDuplicatePath?: boolean
}

/**
 * Mount a list of plugins into `app`, in array order.
 *
 * This is the generic replacement for the hand-wired plugin blocks. Plugins are
 * mounted in the order given (the caller decides ordering — typically core
 * plugins first, then user `plugins.register` plugins), each before the bare
 * `/admin` catch-all.
 *
 * Invalid entries are skipped (recorded in the result) rather than throwing, so
 * one malformed plugin can't take down the whole app. The one hard error is a
 * plugin whose `register()` is asynchronous — that is a contract violation that
 * must surface loudly.
 *
 * @returns A {@link MountResult} describing what was mounted/skipped.
 */
export function registerPluginRoutes(
  app: AnyHono,
  plugins: Array<MountablePlugin | undefined | null>,
  options: RegisterPluginRoutesOptions = {}
): MountResult {
  const result: MountResult = { mounted: [], skipped: [] }
  const warnOnDuplicatePath =
    options.warnOnDuplicatePath ?? (typeof process === 'undefined' || process.env?.NODE_ENV !== 'production')
  const seenPaths = new Map<string, string>() // path -> first plugin that claimed it

  for (const plugin of plugins) {
    if (!plugin) continue
    const before = result.mounted.length
    mountPlugin(app, plugin, result)

    if (warnOnDuplicatePath) {
      for (let i = before; i < result.mounted.length; i++) {
        const entry = result.mounted[i]
        if (!entry) continue
        const { plugin: owner, path } = entry
        const prior = seenPaths.get(path)
        if (prior && prior !== owner) {
          // eslint-disable-next-line no-console
          console.warn(
            `[plugins] Duplicate route path "${path}" mounted by "${owner}" — already claimed by "${prior}". ` +
              `The first registration wins; the later one is shadowed.`
          )
        } else if (!prior) {
          seenPaths.set(path, owner)
        }
      }
    }
  }

  return result
}
