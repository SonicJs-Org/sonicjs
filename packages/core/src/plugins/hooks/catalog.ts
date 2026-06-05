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

/**
 * The acting user on a hook event. ONE canonical shape across every event —
 * always `id` (never `userId`), so a plugin reading `payload.user.id` works on
 * content events and auth events alike.
 */
export interface HookActor {
  id: string
  email: string
  role?: string
}

/** Common shape for content lifecycle events. */
export interface ContentEventPayload {
  /** Collection / content-type slug the event is about. */
  collection: string
  /** Content row id, when known (absent for pre-create events). */
  id?: string
  /** The content data being read/written. Mutable by `before` handlers in the chain. */
  data: Record<string, unknown>
  /** The acting user, when the event originates from an authenticated request. */
  user?: HookActor
}

/** Emitted after a user completes self-registration. */
export interface AuthRegistrationCompletedPayload {
  user: HookActor
}

/** Emitted when a password reset is requested (carries the reset token internally). */
export interface AuthPasswordResetRequestedPayload {
  user: HookActor
  /** Single-use reset token. Never expose this in an API response. */
  resetToken: string
}

/** Emitted after a password reset is confirmed. */
export interface AuthPasswordResetCompletedPayload {
  user: HookActor
}

/** Emitted after a magic-link sign-in link is successfully consumed. */
export interface AuthMagicLinkConsumedPayload {
  user: HookActor
}

/** Emitted after an OTP code is successfully verified. */
export interface AuthOtpVerifiedPayload {
  user: HookActor
}

/**
 * The catalog: event name → payload type.
 *
 * Keep keys in sync with `HookEventName` (derived below) and with the dispatch
 * sites. This is an interface (not a const) so it participates in type-level
 * lookups and can be augmented via declaration merging if a downstream package
 * needs to extend it.
 */
/* eslint-disable @typescript-eslint/naming-convention -- event names are domain identifiers that contain colons (e.g. content:after:create) */
export interface HookEventPayloads {
  // Content lifecycle — read
  'content:read': ContentEventPayload

  // Content lifecycle — before (gate/transform; handlers may mutate the payload
  // or throw to cancel the write)
  'content:before:create': ContentEventPayload
  'content:before:update': ContentEventPayload
  'content:before:delete': ContentEventPayload

  // Content lifecycle — after (side effects; the write has happened)
  'content:after:create': ContentEventPayload
  'content:after:update': ContentEventPayload
  'content:after:delete': ContentEventPayload
  'content:after:publish': ContentEventPayload

  // Auth events
  'auth:registration:completed': AuthRegistrationCompletedPayload
  'auth:password-reset:requested': AuthPasswordResetRequestedPayload
  'auth:password-reset:completed': AuthPasswordResetCompletedPayload
  'auth:magic-link:consumed': AuthMagicLinkConsumedPayload
  'auth:otp:verified': AuthOtpVerifiedPayload
}
/* eslint-enable @typescript-eslint/naming-convention */

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
  'content:before:create',
  'content:before:update',
  'content:before:delete',
  'content:after:create',
  'content:after:update',
  'content:after:delete',
  'content:after:publish',
  'auth:registration:completed',
  'auth:password-reset:requested',
  'auth:password-reset:completed',
  'auth:magic-link:consumed',
  'auth:otp:verified',
] as const satisfies readonly HookEventName[]

/** True if `name` is a canonical catalog event. */
export function isKnownHookEvent(name: string): name is HookEventName {
  return (HOOK_EVENT_NAMES as readonly string[]).includes(name)
}

// ── Legacy event aliases (one-release deprecation window) ────────────────────
// The pre-before/after names. Subscribing to one still works but resolves to the
// canonical name and emits a one-time deprecation warning (see typed-hooks `on`).
// Dispatch is canonical-only — the host controls dispatch sites.

/** Deprecated event names mapped to their canonical payload type. */
/* eslint-disable @typescript-eslint/naming-convention -- legacy event identifiers contain colons */
export interface LegacyHookEventPayloads {
  'content:create': ContentEventPayload
  'content:update': ContentEventPayload
  'content:delete': ContentEventPayload
  'content:publish': ContentEventPayload
  /** No after-only successor; folded into update. */
  'content:save': ContentEventPayload
}

/** Map each deprecated name to the canonical name it resolves to. */
export const LEGACY_EVENT_ALIASES = {
  'content:create': 'content:after:create',
  'content:update': 'content:after:update',
  'content:delete': 'content:after:delete',
  'content:publish': 'content:after:publish',
  'content:save': 'content:after:update',
} as const satisfies Record<keyof LegacyHookEventPayloads, HookEventName>
/* eslint-enable @typescript-eslint/naming-convention */

/** A deprecated event name accepted (with a warning) at subscribe time. */
export type LegacyHookEventName = keyof LegacyHookEventPayloads

/** True if `name` is a deprecated alias. */
export function isLegacyHookEvent(name: string): name is LegacyHookEventName {
  return Object.prototype.hasOwnProperty.call(LEGACY_EVENT_ALIASES, name)
}

/**
 * Resolve a subscribe-time event name to its canonical form: returns the name
 * itself if canonical, the aliased canonical name if deprecated, or `undefined`
 * if unknown.
 */
export function resolveHookEventName(name: string): HookEventName | undefined {
  if (isKnownHookEvent(name)) return name
  if (isLegacyHookEvent(name)) return LEGACY_EVENT_ALIASES[name]
  return undefined
}
