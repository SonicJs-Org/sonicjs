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

import type { HookEventName, HookPayload, LegacyHookEventName, LegacyHookEventPayloads } from './catalog'
import { isLegacyHookEvent, resolveHookEventName } from './catalog'

/** A name accepted at subscribe time: a canonical event or a deprecated alias. */
export type SubscribableEvent = HookEventName | LegacyHookEventName

/** The payload type for a subscribable name — canonical payload, even for aliases. */
export type PayloadForEvent<E extends SubscribableEvent> = E extends HookEventName
  ? HookPayload<E>
  : E extends LegacyHookEventName
    ? LegacyHookEventPayloads[E]
    : never

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
   * Subscribe to a catalog event. Accepts canonical names and (for one release)
   * deprecated aliases — an alias resolves to its canonical name and emits a
   * one-time deprecation warning. Lower priority runs earlier (default 10).
   */
  on<E extends SubscribableEvent>(
    event: E,
    handler: (
      payload: PayloadForEvent<E>,
      context: TypedHookContext
    ) => PayloadForEvent<E> | void | Promise<PayloadForEvent<E> | void>,
    priority?: number
  ): void
  /**
   * Dispatch a catalog event through the handler chain. Canonical names only —
   * the host owns dispatch sites. Returns the (possibly mutated) payload.
   */
  dispatch<E extends HookEventName>(
    event: E,
    payload: HookPayload<E>,
    context?: TypedHookContext
  ): Promise<HookPayload<E>>
}

// One-time deprecation warnings, keyed by the deprecated name (process-wide).
const warnedLegacyEvents = new Set<string>()

/**
 * Build a typed facade over a hook system.
 *
 * `on()` resolves deprecated aliases to canonical names (warning once), then
 * registers under the canonical name so a legacy subscriber fires when the host
 * dispatches the canonical event. Returning `void` from a handler preserves the
 * current payload in the chain (the underlying `execute()` threads whatever each
 * handler returns, so we coalesce `undefined` back to the incoming data).
 */
export function createTypedHooks(hookSystem: HookSystemLike): TypedHooks {
  return {
    on(event, handler, priority) {
      const canonical = resolveHookEventName(event) ?? event
      if (isLegacyHookEvent(event) && !warnedLegacyEvents.has(event)) {
        warnedLegacyEvents.add(event)
        // eslint-disable-next-line no-console
        console.warn(
          `[hooks] event "${event}" is deprecated; subscribe to "${canonical}" instead. ` +
            `The alias will be removed in a future release.`
        )
      }
      hookSystem.register(
        canonical,
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
