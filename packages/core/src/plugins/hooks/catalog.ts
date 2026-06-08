/**
 * Typed hook event catalog
 *
 * The single source of truth for which lifecycle events a plugin may subscribe
 * to, and the payload shape each one carries. Subscribing through the typed
 * facade (`createTypedHooks`) gives a plugin the narrowed payload type with no
 * casting — TypeScript rejects a wrong field name at the `.on()` call site.
 *
 * Scope note: this catalog lists the events that are (or are being) dispatched
 * in production. The legacy string-keyed `HOOKS` map in `../types` declared many
 * more events than were ever fired; reconciling that list down to what actually
 * dispatches is tracked in the plugin-overhaul plan. Add an event here only when
 * a real dispatch site exists (or is landing in the same change).
 */

/** Common shape for content lifecycle events. */
export interface ContentEventPayload {
  /** Collection / content-type slug the event is about. */
  collection: string
  /** Content row id, when known (absent for pre-create events). */
  id?: string
  /** The content data being read/written. Mutable by handlers in the chain. */
  data: Record<string, unknown>
  /** The acting user, when the event originates from an authenticated request. */
  user?: { userId: string; email: string; role: string }
}

/** Emitted after a user completes self-registration. */
export interface AuthRegistrationCompletedPayload {
  user: { id: string; email: string; role: string }
}

/** Emitted when a password reset is requested (carries the reset token internally). */
export interface AuthPasswordResetRequestedPayload {
  user: { id: string; email: string }
  /** Single-use reset token. Never expose this in an API response. */
  resetToken: string
}

/** Emitted after a password reset is confirmed. */
export interface AuthPasswordResetCompletedPayload {
  user: { id: string; email: string }
}

/**
 * The catalog: event name → payload type.
 *
 * Keep keys in sync with `HookEventName` (derived below) and with the dispatch
 * sites. This is an interface (not a const) so it participates in type-level
 * lookups and can be augmented via declaration merging if a downstream package
 * needs to extend it.
 */
export interface HookEventPayloads {
  // Content lifecycle
  'content:read': ContentEventPayload
  'content:create': ContentEventPayload
  'content:update': ContentEventPayload
  'content:delete': ContentEventPayload
  'content:publish': ContentEventPayload
  'content:save': ContentEventPayload

  // Auth events
  'auth:registration:completed': AuthRegistrationCompletedPayload
  'auth:password-reset:requested': AuthPasswordResetRequestedPayload
  'auth:password-reset:completed': AuthPasswordResetCompletedPayload
}

/** Union of all catalog event names. */
export type HookEventName = keyof HookEventPayloads

/** The payload type for a given event name. */
export type HookPayload<E extends HookEventName> = HookEventPayloads[E]

/**
 * Runtime list of catalog event names.
 *
 * Useful for validation (e.g. "is this a known event?") and for diagnostics.
 * Kept as a typed tuple so it can't silently drift from the interface: any new
 * key added to `HookEventPayloads` should be added here too, and the
 * `satisfies` check below fails the build if the list references an unknown
 * event.
 */
export const HOOK_EVENT_NAMES = [
  'content:read',
  'content:create',
  'content:update',
  'content:delete',
  'content:publish',
  'content:save',
  'auth:registration:completed',
  'auth:password-reset:requested',
  'auth:password-reset:completed',
] as const satisfies readonly HookEventName[]

/** True if `name` is a known catalog event. */
export function isKnownHookEvent(name: string): name is HookEventName {
  return (HOOK_EVENT_NAMES as readonly string[]).includes(name)
}
