/**
 * Plugin cron surface
 *
 * A plugin declares scheduled work as data:
 *
 *   crons: [{ schedule: '*\/15 * * * *', hookFamily: 'email-reconciliation' }]
 *   async onCronTick(event, ctx) {
 *     if (event.hookFamily !== 'email-reconciliation') return
 *     ...
 *   }
 *
 * Declaring a schedule does NOT by itself run anything (same as Payload's jobs
 * queue): on Cloudflare Workers the execution mechanism is a Cron Trigger, which
 * the runtime delivers to the Worker's `scheduled()` handler. `createScheduledHandler`
 * builds that handler; it fans a fired trigger out to the plugins whose declared
 * schedule matches, tagging each call with the matching `hookFamily` so a plugin
 * with several crons can branch on it.
 *
 * The consumer must still register the cron expressions in `wrangler.toml`
 * (`[triggers] crons = [...]`); the schedules declared here are the source of
 * truth for which plugin handles which expression.
 *
 * Cron runs OUTSIDE the HTTP request context (no per-request `c.env`), which is
 * exactly why services are reached through env-independent singletons.
 */

import type { HookSystemLike } from './hooks/typed-hooks'

/** A scheduled-work declaration on a plugin. */
export interface CronDeclaration {
  /** Cron expression, e.g. `'*\/15 * * * *'`. Must also be in wrangler.toml triggers. */
  schedule: string
  /** Logical family the handler branches on (e.g. `'email-reconciliation'`). */
  hookFamily: string
}

/** The event passed to a plugin's `onCronTick`. */
export interface CronTickEvent {
  /** The cron expression that fired. */
  cron: string
  /** Epoch ms the trigger was scheduled for. */
  scheduledTime: number
  /** The matching declaration's family, so a multi-cron plugin can branch. */
  hookFamily: string
}

/** Context handed to `onCronTick`. Mirrors the boot context; carries no request env. */
export interface CronContext {
  /** The live hook system (so cron work can dispatch/observe hooks). */
  hooks: HookSystemLike
  /** Runtime bindings supplied by the Worker's scheduled() invocation. */
  env?: Record<string, unknown>
  [key: string]: unknown
}

/**
 * Structural contract this module needs from a plugin. Deliberately minimal (not
 * the full `Plugin`) so the `src`/`dist` duplicate identities and user plugins all
 * satisfy it without casts.
 */
export interface CronablePlugin {
  name?: string
  crons?: CronDeclaration[]
  onCronTick?: (event: CronTickEvent, context: CronContext) => void | Promise<void>
}

/** A flattened view of every declared cron across a set of plugins. */
export interface CollectedCron {
  plugin: string
  schedule: string
  hookFamily: string
}

/** Flatten every plugin's `crons[]` into one list (for diagnostics / wrangler sync). */
export function collectCrons(plugins: Array<CronablePlugin | undefined | null>): CollectedCron[] {
  const out: CollectedCron[] = []
  for (const plugin of plugins) {
    if (!plugin || !Array.isArray(plugin.crons)) continue
    const name = plugin.name ?? 'unknown'
    for (const cron of plugin.crons) {
      if (cron && typeof cron.schedule === 'string' && typeof cron.hookFamily === 'string') {
        out.push({ plugin: name, schedule: cron.schedule, hookFamily: cron.hookFamily })
      }
    }
  }
  return out
}

/** The set of distinct cron expressions declared across plugins. */
export function collectCronSchedules(plugins: Array<CronablePlugin | undefined | null>): string[] {
  return [...new Set(collectCrons(plugins).map((c) => c.schedule))]
}

/** Outcome of a cron dispatch. */
export interface CronDispatchResult {
  /** Plugins whose `onCronTick` ran successfully (one entry per matching declaration). */
  invoked: Array<{ plugin: string; hookFamily: string }>
  /** Per-plugin errors (dispatch never throws). */
  errors: Array<{ plugin: string; hookFamily: string; error: unknown }>
  /** True if the fired cron matched no declared schedule. */
  unmatched: boolean
}

/**
 * Dispatch one fired cron expression to the plugins that declared it.
 *
 * For each plugin whose `crons[]` contains a declaration with `schedule === cron`,
 * its `onCronTick` is invoked once per matching declaration, with the event's
 * `hookFamily` set to that declaration's family. Errors are isolated per plugin.
 */
export async function dispatchCronTick(
  plugins: Array<CronablePlugin | undefined | null>,
  cron: string,
  scheduledTime: number,
  context: CronContext
): Promise<CronDispatchResult> {
  const result: CronDispatchResult = { invoked: [], errors: [], unmatched: true }

  for (const plugin of plugins) {
    if (!plugin || typeof plugin.onCronTick !== 'function' || !Array.isArray(plugin.crons)) continue
    const name = plugin.name ?? 'unknown'
    const matches = plugin.crons.filter((c) => c && c.schedule === cron)
    for (const match of matches) {
      result.unmatched = false
      const event: CronTickEvent = { cron, scheduledTime, hookFamily: match.hookFamily }
      try {
        await plugin.onCronTick(event, context)
        result.invoked.push({ plugin: name, hookFamily: match.hookFamily })
      } catch (error) {
        result.errors.push({ plugin: name, hookFamily: match.hookFamily, error })
      }
    }
  }

  return result
}

/** Minimal shape of a Cloudflare `ScheduledController`. */
export interface ScheduledControllerLike {
  cron: string
  scheduledTime: number
}

/** Minimal shape of a Cloudflare `ExecutionContext`. */
export interface ExecutionContextLike {
  waitUntil?(promise: Promise<unknown>): void
}

export interface CreateScheduledHandlerOptions {
  /** Plugins to consider (evaluated lazily at fire time). */
  plugins: Array<CronablePlugin | undefined | null> | (() => Array<CronablePlugin | undefined | null>)
  /** Provides the hook system (e.g. the singleton getter). */
  getHooks: () => HookSystemLike
  /** Optional: when true, skip dispatch entirely (mirrors plugins.disableAll). */
  disabled?: boolean
  /**
   * Boot function from {@link SonicJSApp.boot}. Called before the first cron
   * dispatch so a cron-first cold isolate (one that never handled an HTTP
   * request) still has a wired hook bus and reachable email service.
   * Without this, `getHookSystem()` may throw in cron handlers.
   */
  boot?: (env: Record<string, unknown>) => Promise<void>
}

/**
 * Build a Cloudflare `scheduled(controller, env, ctx)` handler that fans cron
 * triggers out to plugins.
 *
 * Usage in a Worker entry:
 *   export default {
 *     fetch: app.fetch,
 *     scheduled: createScheduledHandler({ plugins, getHooks: getHookSystem }),
 *   }
 */
export function createScheduledHandler(
  options: CreateScheduledHandlerOptions
): (controller: ScheduledControllerLike, env: Record<string, unknown>, ctx?: ExecutionContextLike) => Promise<CronDispatchResult> {
  return async (controller, env, ctx) => {
    if (options.disabled) {
      return { invoked: [], errors: [], unmatched: true }
    }

    // Boot the isolate before dispatching so a cron-first cold isolate (which
    // may never have handled an HTTP request) still has a populated hook bus and
    // reachable email service. The boot function is once-guarded, so warm
    // isolates return immediately.
    if (options.boot) {
      try {
        await options.boot(env)
      } catch (err) {
        console.error('[cron] boot failed:', err)
      }
    }

    const plugins = typeof options.plugins === 'function' ? options.plugins() : options.plugins
    const work = dispatchCronTick(plugins, controller.cron, controller.scheduledTime, {
      hooks: options.getHooks(),
      env,
    })
    // Keep the Worker alive until cron work settles, when the runtime supports it.
    ctx?.waitUntil?.(work.catch(() => {}))
    return work
  }
}
