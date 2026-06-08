/**
 * Generic service-singleton factory
 *
 * Generalizes the hook-system-singleton pattern: a process-wide slot for a
 * service that code outside the HTTP request context — most importantly cron /
 * `scheduled()` handlers, which have no per-request `c.env` — can reach without
 * threading it through every call.
 *
 * Contract (same as the hook-system singleton):
 *  - `get()` throws if read before `set()` (throw-before-get) so wiring-order
 *    bugs surface loudly rather than silently no-oping.
 *  - `set()` is idempotent (last write wins) so constructing multiple apps in one
 *    process (e.g. across tests) never throws.
 *  - `reset()` clears the slot for test isolation.
 */

export interface ServiceSingleton<T> {
  /** Set the process-wide instance. Last write wins. */
  set(instance: T): void
  /** Get the instance; throws if not yet set. */
  get(): T
  /** True if an instance has been set. */
  has(): boolean
  /** Clear the slot (test isolation). */
  reset(): void
}

/**
 * Create a service singleton.
 *
 * @param label Human-readable name used in the throw-before-get error message
 *              (e.g. `'EmailService'`).
 */
export function createServiceSingleton<T>(label: string): ServiceSingleton<T> {
  let current: T | undefined
  return {
    set(instance: T) {
      current = instance
    },
    get(): T {
      if (current === undefined) {
        throw new Error(
          `${label} has not been initialized. Its setter must be called (the app factory does this at construction) before reading it.`
        )
      }
      return current
    },
    has(): boolean {
      return current !== undefined
    },
    reset() {
      current = undefined
    },
  }
}
