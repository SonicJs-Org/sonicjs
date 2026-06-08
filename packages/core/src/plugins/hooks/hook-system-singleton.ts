/**
 * Hook-system singleton
 *
 * Gives env-independent access to the app's hook system. Code that runs outside
 * the HTTP request context — most importantly scheduled (cron) handlers, which
 * have no per-request `c.env` — needs a way to reach the hook system without
 * threading it through every call. The app sets the singleton eagerly at
 * construction; everything else reads it.
 *
 * Contract: `getHookSystem()` throws if read before the app has set one
 * (throw-before-get), which surfaces wiring-order bugs loudly instead of
 * silently no-oping. `setHookSystem()` is idempotent (last write wins) so that
 * constructing multiple apps in one process — e.g. across tests — does not
 * throw; call `resetHookSystem()` in test teardown for isolation.
 */

import type { HookSystemLike, TypedHooks } from './typed-hooks'
import { createTypedHooks } from './typed-hooks'

let current: HookSystemLike | undefined

/** Set the process-wide hook system. Last write wins. */
export function setHookSystem(hookSystem: HookSystemLike): void {
  current = hookSystem
}

/**
 * Get the process-wide hook system.
 * @throws if no hook system has been set yet.
 */
export function getHookSystem(): HookSystemLike {
  if (!current) {
    throw new Error(
      'Hook system has not been initialized. ' +
        'setHookSystem() must be called (the app factory does this at construction) before getHookSystem().'
    )
  }
  return current
}

/** True if a hook system has been set. */
export function hasHookSystem(): boolean {
  return current !== undefined
}

/** Clear the singleton. Intended for test isolation. */
export function resetHookSystem(): void {
  current = undefined
}

/** Convenience: a typed facade over the current singleton hook system. */
export function getTypedHooks(): TypedHooks {
  return createTypedHooks(getHookSystem())
}
