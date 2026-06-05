/**
 * Typed hook dispatch helper for route handlers.
 *
 * Route handlers call this with their Hono context `c` — executionCtx is
 * extracted safely (it's not available in all environments). Two modes:
 *
 *   'fire-and-forget'  — event runs off the response path via waitUntil. The
 *                        original payload is returned immediately. Use for
 *                        `after` events (analytics, audit, webhooks).
 *
 *   'in-band'          — awaits the full handler chain and returns the
 *                        (possibly mutated) payload. Use for `before` events
 *                        (gate, transform, cancel). Errors propagate — the
 *                        caller should catch and return an appropriate response.
 *
 * A missing hook system (pre-boot cold start) is a silent no-op in both modes.
 */

import type { HookEventName, HookPayload } from './catalog'
import { getTypedHooks, hasHookSystem } from './hook-system-singleton'

type ExecutionCtxLike = { waitUntil(p: Promise<unknown>): void }

export type DispatchMode = 'fire-and-forget' | 'in-band'

/** Safely extract executionCtx from a Hono context (not available in all envs). */
function safeExecutionCtx(c: unknown): ExecutionCtxLike | undefined {
  try {
    const exec = (c as any)?.executionCtx
    return typeof exec?.waitUntil === 'function' ? (exec as ExecutionCtxLike) : undefined
  } catch {
    return undefined
  }
}

/**
 * Dispatch a hook event from a route handler.
 *
 * @param c    The Hono request context. executionCtx is extracted safely.
 * @param event  Catalog event name.
 * @param payload  Event payload.
 * @param mode   'fire-and-forget' (default) or 'in-band'.
 */
export async function dispatchHookEvent<E extends HookEventName>(
  c: unknown,
  event: E,
  payload: HookPayload<E>,
  mode: DispatchMode = 'fire-and-forget'
): Promise<HookPayload<E>> {
  if (!hasHookSystem()) return payload

  const hooks = getTypedHooks()
  const executionCtx = safeExecutionCtx(c)

  if (mode === 'fire-and-forget') {
    const p = hooks.dispatch(event, payload).catch((err) => {
      console.error(`[hooks] dispatch error for "${event}":`, err)
    })
    executionCtx?.waitUntil(p)
    return payload
  }

  // in-band: let errors propagate so the caller can return a proper response.
  // Note: the underlying HookSystemImpl only re-throws errors whose message
  // contains 'CRITICAL'. Soft errors are swallowed+logged and the chain continues.
  // A plugin that wants to hard-cancel a write should throw new Error('CRITICAL: ...')
  return hooks.dispatch(event, payload)
}
