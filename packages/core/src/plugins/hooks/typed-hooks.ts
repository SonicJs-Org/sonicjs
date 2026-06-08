/**
 * Typed hook facade
 *
 * Wraps the (string-keyed, untyped) hook system in a catalog-aware API:
 *
 *   const hooks = createTypedHooks(hookSystem)
 *   hooks.on('auth:registration:completed', (payload) => {
 *     payload.user.email   // ✓ narrowed — no cast
 *     payload.user.nope    // ✗ type error
 *   })
 *   await hooks.dispatch('auth:registration:completed', { user: {...} })
 *
 * The facade is intentionally structural about the underlying hook system (see
 * `HookSystemLike`) so both `HookSystemImpl` and `ScopedHookSystem` — and the
 * `src`/`dist` duplicate type identities — all satisfy it without casts.
 */

import type { HookEventName, HookPayload } from './catalog'

/**
 * Minimal structural contract the typed facade needs from a hook system.
 * Satisfied by `HookSystemImpl` and `ScopedHookSystem`.
 */
export interface HookSystemLike {
  register(hookName: string, handler: (data: any, context: any) => any, priority?: number): void
  execute(hookName: string, data: any, context?: any): Promise<any>
  unregister?(hookName: string, handler: (data: any, context: any) => any): void
}

/** Context passed to a typed hook handler (kept loose; mirrors the legacy HookContext). */
export interface TypedHookContext {
  /** Plugin that registered the hook, if known. */
  plugin?: string
  /** Cancel the remaining hook chain. */
  cancel?: () => void
  [key: string]: unknown
}

/**
 * A typed hook handler. May mutate and return the payload (threaded to the next
 * handler), or return nothing (the current payload is preserved).
 */
export type TypedHookHandler<E extends HookEventName> = (
  payload: HookPayload<E>,
  context: TypedHookContext
) => HookPayload<E> | void | Promise<HookPayload<E> | void>

export interface TypedHooks {
  /**
   * Subscribe to a catalog event. Lower priority runs earlier (matches the
   * underlying hook system; default 10).
   */
  on<E extends HookEventName>(event: E, handler: TypedHookHandler<E>, priority?: number): void
  /**
   * Dispatch a catalog event through the handler chain. Returns the (possibly
   * mutated) payload after all handlers run.
   */
  dispatch<E extends HookEventName>(
    event: E,
    payload: HookPayload<E>,
    context?: TypedHookContext
  ): Promise<HookPayload<E>>
}

/**
 * Build a typed facade over a hook system.
 *
 * `on()` wraps the typed handler so that returning `void` preserves the current
 * payload in the chain (the underlying `execute()` threads whatever each handler
 * returns, so we coalesce `undefined` back to the incoming data).
 */
export function createTypedHooks(hookSystem: HookSystemLike): TypedHooks {
  return {
    on(event, handler, priority) {
      hookSystem.register(
        event,
        async (data: any, context: any) => {
          const result = await handler(data, context ?? {})
          return result === undefined ? data : result
        },
        priority
      )
    },
    async dispatch(event, payload, context) {
      return (await hookSystem.execute(event, payload, context)) as any
    },
  }
}
