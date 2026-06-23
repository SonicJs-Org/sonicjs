/**
 * registerPlugins — single chokepoint for plugin registration.
 *
 * Replaces the historical pattern of calling `registerPluginRoutes` + scheduling
 * `wireRegisteredPlugins` + manually wiring `addMenuItem` calls + per-plugin
 * settings-route handlers.
 *
 * Authors write:
 *   const myPlugin = definePlugin({ id, version, capabilities, register, hooks, menu, configSchema, ... })
 *
 * Hosts call:
 *   const reg = registerPlugins(app, [pluginA, pluginB], { hookSystem, env, ... })
 *   // ...
 *   await reg.boot(env)   // first-request lazy wire
 *
 * What this fn does, in order:
 *   1. Validate each plugin (id, semver, dep references) — throws on hard errors
 *   2. Topologically order by `dependencies`
 *   3. MOUNT pass — invoke `registerPluginRoutes()` (sync, routes only)
 *   4. Collect declarative `menu[]` entries → setPluginMenu (overwrites prior)
 *   5. Collect declarative `crons[]` for the host scheduled() handler
 *   6. Return a registry + a one-shot `boot(env)` that lazily runs the WIRE pass
 *      (subscribe hooks + run onBoot + DB-reflect) on first request
 *
 * The mount/wire split is preserved (Hono's router locks after first request, so
 * routes MUST mount synchronously at construction; env-dependent setup is lazy).
 * That split is now an implementation detail — authors see ONE function.
 */

import type { Hono } from 'hono'
import semver from 'semver'
import {
  registerPluginRoutes,
  type MountablePlugin,
  type RegisterPluginRoutesOptions,
  type MountResult,
} from '../mount'
import {
  wireRegisteredPlugins,
  type WirablePlugin,
  type PluginBootContext,
  type WireResult,
} from '../wire'
import { setPluginMenu, type PluginMenuEntry } from '../../services/plugin-menu-singleton'
import { setPluginDefinitions } from '../../services/plugin-definition-registry'
import { collectCronSchedules, type CronDeclaration } from '../cron'
import { getCoreVersion } from '../../utils/version'
import type { ConfigSchema } from './config-schema'

// ── Discriminated error class ────────────────────────────────────────────────

export type RegisterPluginsErrorReason =
  | 'invalid_id'
  | 'invalid_semver'
  | 'duplicate_id'
  | 'register_returned_promise'

export class RegisterPluginsError extends Error {
  constructor(
    public readonly reason: RegisterPluginsErrorReason,
    public readonly details: Readonly<Record<string, unknown>>
  ) {
    super(`registerPlugins(${reason}): ${JSON.stringify(details)}`)
    this.name = 'RegisterPluginsError'
  }
}

// ── Plugin shape consumed by registerPlugins ─────────────────────────────────

/**
 * Structural contract: the union of MountablePlugin + WirablePlugin + the
 * declarative admin surface. Plugins built via `definePlugin()` satisfy this
 * automatically; hand-rolled objects need at minimum `id`, `version`.
 */
export interface RegisterablePlugin extends MountablePlugin, WirablePlugin {
  id: string
  version: string
  displayName?: string
  sonicjsVersionRange?: string
  menu?: PluginMenuEntry[]
  crons?: CronDeclaration[]
  /** Schema-driven settings — the admin route reads this via getPluginDefinition(id). */
  configSchema?: ConfigSchema
  /** Custom settings-tab renderer — loadData runs server-side, render produces the tab HTML. */
  settingsTabContent?: {
    loadData?: (db: any) => Promise<any>
    render: (props: { plugin: any; settings: any; data?: any }) => string
  }
}

// ── Host context ─────────────────────────────────────────────────────────────

export interface RegisterPluginsHostContext {
  /** Hook system the wire phase subscribes to. */
  hookSystem: PluginBootContext['hooks']
  /** Runtime bindings (env.DB, env.KV, env.R2, etc.). Used by the wire phase. */
  env?: Record<string, unknown>
  /** Forwarded to the mount pass as the `source` label in dev warnings. */
  source?: string
  /** Strict-mode: cycle / unknown-dep / capability errors throw instead of warn. */
  strict?: boolean
  /** Forwarded to registerPluginRoutes. */
  mountOptions?: Omit<RegisterPluginRoutesOptions, 'source' | 'strict'>
}

// ── Result ───────────────────────────────────────────────────────────────────

export interface RegistryEntry {
  id: string
  displayName: string
  version: string
  capabilities: readonly string[]
}

export interface PluginsRegistry {
  /** Plugins indexed by id, in topo-sorted order. */
  readonly byId: ReadonlyMap<string, RegistryEntry>
  /** Plugin ids in registration order (post topo-sort). */
  readonly order: readonly string[]
  /** Aggregated menu entries (also pushed to the menu singleton). */
  readonly menu: readonly PluginMenuEntry[]
  /** Aggregated cron declarations. */
  readonly crons: readonly CronDeclaration[]
  /** Aggregated cron schedule expressions (deduped) — useful for wrangler.toml codegen. */
  readonly cronSchedules: readonly string[]
  /** Mount-pass diagnostics. */
  readonly mountResult: MountResult
  /**
   * Lazy wire pass — call from the first-request middleware. Idempotent
   * (subsequent calls return the cached result of the first run).
   */
  boot(env?: Record<string, unknown>): Promise<WireResult>
}

// ── Main entry ───────────────────────────────────────────────────────────────

export function registerPlugins(
  app: Hono<any, any, any>,
  plugins: ReadonlyArray<RegisterablePlugin | undefined | null>,
  host: RegisterPluginsHostContext
): PluginsRegistry {
  const list = plugins.filter((p): p is RegisterablePlugin => !!p && typeof p === 'object')

  // ── 1. Validate
  const seen = new Set<string>()
  for (const p of list) {
    if (!p.id || typeof p.id !== 'string')
      throw new RegisterPluginsError('invalid_id', { plugin: p })
    if (!semver.valid(p.version))
      throw new RegisterPluginsError('invalid_semver', { id: p.id, version: p.version })
    if (seen.has(p.id))
      throw new RegisterPluginsError('duplicate_id', { id: p.id })
    seen.add(p.id)

    // sonicjsVersionRange — warn-only (resilient by default)
    if (p.sonicjsVersionRange) {
      try {
        if (!semver.satisfies(getCoreVersion(), p.sonicjsVersionRange)) {
          console.warn(
            `[plugins] ${p.id} declares sonicjsVersionRange "${p.sonicjsVersionRange}" ` +
              `but core is "${getCoreVersion()}". Plugin may not work correctly.`
          )
        }
      } catch {
        // Invalid range — let it through, definePlugin already warned at author time.
      }
    }
  }

  // ── 2. Mount (registerPluginRoutes also runs topo-sort)
  let mountResult: MountResult
  try {
    mountResult = registerPluginRoutes(app, list, {
      source: host.source,
      strict: host.strict,
      ...host.mountOptions,
    })
  } catch (err) {
    // The one hard error from mount is PluginRegisterMustBeSyncError — re-wrap
    // as RegisterPluginsError so the chokepoint surfaces a consistent reason.
    const pluginId =
      err && typeof err === 'object' && 'message' in err
        ? String((err as Error).message).match(/Plugin "([^"]+)"/)?.[1] ?? 'unknown'
        : 'unknown'
    throw new RegisterPluginsError('register_returned_promise', { id: pluginId, error: String(err) })
  }

  // ── 3. Collect menu (overwrites previous registration — last registerPlugins wins)
  const menu = list.flatMap((p) => p.menu ?? [])
  setPluginMenu(menu)

  // Make plugin definitions discoverable by id (admin settings route reads
  // configSchema from here; future tools / introspection can use the rest).
  setPluginDefinitions(list)

  // ── 4. Collect crons
  const crons = list.flatMap((p) => p.crons ?? [])
  const cronSchedules = collectCronSchedules(list)

  // ── 5. Build registry
  const byId = new Map<string, RegistryEntry>()
  for (const p of list) {
    byId.set(p.id, {
      id: p.id,
      displayName: p.displayName ?? (p as { name?: string }).name ?? p.id,
      version: p.version,
      capabilities: (p as { capabilities?: readonly string[] }).capabilities ?? [],
    })
  }

  // ── 6. Lazy boot (wire) — one-shot
  let wirePromise: Promise<WireResult> | undefined
  const boot = (envOverride?: Record<string, unknown>): Promise<WireResult> => {
    if (!wirePromise) {
      const env = envOverride ?? host.env ?? {}
      wirePromise = wireRegisteredPlugins(list, { hooks: host.hookSystem, env }, { strict: host.strict })
    }
    return wirePromise
  }

  return {
    byId,
    order: list.map((p) => p.id),
    menu,
    crons,
    cronSchedules,
    mountResult,
    boot,
  }
}
