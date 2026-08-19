/**
 * Refuse passwordless (email-possession) sign-in for accounts that hold a verified second
 * factor.
 *
 * ── The hole this closes ──
 * Better Auth's `twoFactor` plugin challenges on `/sign-in/email|username|phone-number` and
 * nothing else. `auth/config.ts` also composes `magicLink` and `emailOTP`, both of which mint a
 * full session on their own endpoints. So without this guard, a user who enrolled in TOTP could
 * sign in with a link or code mailed to their inbox and never see a second factor — with
 * `/admin/profile` still reading "Enabled". A control that reports success and does nothing is
 * worse than no control.
 *
 * It is also incoherent on its own terms: email possession is exactly what the design refuses to
 * accept AS a second factor, so it cannot be allowed to stand in for the first one plus the
 * second.
 *
 * ── Why here and not in a BA hook ──
 * `magic-link/verify` finishes with `throw ctx.redirect(callbackURL)`, so a BA `after` hook is
 * not a dependable chokepoint. The `/auth/*` catch-all in `app.ts` is our own code, runs ahead
 * of `auth.handler()`, and can read the request body — so the block lands on the request that
 * would START the flow, before any token or code is mailed.
 *
 * ── Enumeration ──
 * Every refusal is byte-identical to what Better Auth itself would answer, so an unauthenticated
 * caller learns nothing about who has a second factor:
 *   - the INITIATE endpoints return BA's own success shape and send nothing. BA already answers
 *     `{success:true}` for an address with no account at all, so this adds no new signal.
 *   - the COMPLETE endpoint returns BA's own `INVALID_OTP` error. An earlier revision returned a
 *     distinctive `403 TWO_FACTOR_REQUIRED` here, justified by "the caller already produced a
 *     code from the inbox" — which was FALSE: this guard runs before BA validates the code, so
 *     `{"email":"…","otp":"000000"}` with no inbox access was a free oracle for both
 *     account-existence and 2FA-enrolment status. Do not reintroduce a distinguishable response.
 *
 * ── Deliberately NOT guarded ──
 *   - `/auth/callback/*` (social/OAuth). BA does not challenge there either. Delegating MFA to
 *     the identity provider is the conventional contract, and blocking it would lock out an
 *     account whose only credential is the provider.
 *   - `GET /auth/magic-link/verify`. **A residual window remains here, and it is not closed.**
 *     Blocking the send means an enrolled user never receives a NEW link, but a link mailed in
 *     the 15 minutes BEFORE they enrolled still resolves to a session with no second factor. It
 *     is not guarded because the token cannot be resolved to a user without consuming it: BA
 *     stores verification values in KV (this app supplies `secondaryStorage`, and
 *     `verification.storeInDatabase` is unset, so `auth_verification` is not used), keyed by
 *     BA's internal format, and `storeToken` is not exported. Closing it properly means moving
 *     verification values into D1 — a repo-wide change affecting magic-link, email-OTP and email
 *     verification, out of scope here. The exposure requires an attacker who owns the inbox AND a
 *     link requested in the same 15-minute window in which the victim enrolled.
 *   - `/auth/email-otp/verify-email`. It mints a session only under
 *     `emailVerification.autoSignInAfterVerification`, which SonicJS does not set; guarding it
 *     unconditionally would 403 legitimate email verification for enrolled users. **If that
 *     option is ever enabled, add the path to {@link COMPLETE_PATHS}.**
 *   - `/auth/email-otp/request-password-reset`, `/forget-password/email-otp`,
 *     `/email-otp/reset-password`. Password reset does not mint a session in this codebase — it
 *     redirects to the login page, where the second factor is enforced.
 *
 * Bespoke SonicJS session-minting endpoints under `/auth/` (the `otp-login` and
 * `oauth-providers` plugins) are mounted BEFORE this catch-all and so never reach it; they call
 * {@link hasVerifiedSecondFactor} directly in their own handlers.
 */
import type { Context } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import { hasVerifiedSecondFactor } from './second-factor-guard'

/**
 * Endpoints that START a passwordless flow. Blocked by answering BA's success shape without
 * forwarding, so no link/code is ever mailed and nothing is leaked.
 *
 * Keyed by the full request path (BA's `basePath` is `/auth` — see `getDefaultAuthOptions`).
 * `sign-in/magic-link` answers `{status:true}`; `email-otp/send-verification-otp` answers
 * `{success:true}` — mirrored exactly so a client cannot distinguish a blocked call.
 */
const INITIATE_PATHS: Record<string, Record<string, boolean>> = {
  '/auth/sign-in/magic-link': { status: true },
  '/auth/email-otp/send-verification-otp': { success: true },
}

/** Endpoints that COMPLETE a passwordless sign-in. Blocked with BA's own invalid-code error. */
const COMPLETE_PATHS = new Set(['/auth/sign-in/email-otp'])

/**
 * Better Auth's own answer to a bad OTP — `email-otp/routes.mjs` throws
 * `APIError.from('BAD_REQUEST', EMAIL_OTP_ERROR_CODES.INVALID_OTP)`. Mirrored verbatim so a
 * refusal is indistinguishable from a wrong code.
 */
const BA_INVALID_OTP = { message: 'Invalid OTP', code: 'INVALID_OTP' }

/**
 * `send-verification-otp` is multi-purpose. Only the sign-in variant mints a session; the other
 * two are email verification and password reset, and blocking those would break unrelated flows
 * for an enrolled user.
 */
const OTP_SIGN_IN_TYPE = 'sign-in'

/** Outcome of resolving an email to a user id. */
type UserLookup =
  | { kind: 'found'; userIds: string[] }
  | { kind: 'absent' }
  /** The query threw. Callers must fail CLOSED — see resolveUsersByEmail. */
  | { kind: 'error' }

/**
 * Inspect a request bound for the Better Auth handler. Returns a `Response` when the request
 * must be refused, or `null` to let it through.
 *
 * Body handling: reads a **clone**, never `c.req.json()`. Hono caches a parsed body on the
 * request, but the underlying `c.req.raw` stream would be consumed and `auth.handler(c.req.raw)`
 * would then fail to parse it.
 */
export async function guardPasswordlessSecondFactor(
  c: Context<{ Bindings: { DB: D1Database } }>
): Promise<Response | null> {
  const path = new URL(c.req.url).pathname
  const initiateResponse = INITIATE_PATHS[path]
  const isComplete = COMPLETE_PATHS.has(path)
  if (!initiateResponse && !isComplete) return null
  if (c.req.method !== 'POST') return null

  const body = await readBody(c)
  if (!body) {
    // Nothing parseable, so there is no email to check and BA will reject the request itself
    // (its router pins these endpoints to application/json). Passing through cannot bypass
    // anything: a request BA refuses to parse never reaches a session mint.
    return null
  }

  const email = typeof body.email === 'string' ? body.email.trim() : ''
  if (!email) return null

  // Only the sign-in variant of send-verification-otp leads to a session.
  if (path === '/auth/email-otp/send-verification-otp' && body.type !== OTP_SIGN_IN_TYPE) {
    return null
  }

  const lookup = await resolveUsersByEmail(c.env.DB, email)
  if (lookup.kind === 'absent') return null

  // Fail CLOSED on a lookup error. The earlier revision passed these through, reasoning that a
  // user we cannot resolve cannot be shown to be enrolled — but BA performs its OWN lookup
  // afterwards and can succeed where ours failed, mailing a link to an enrolled account. That
  // made a transient D1 error a bypass, one line away from the deliberate fail-closed in
  // hasVerifiedSecondFactor.
  const enrolled =
    lookup.kind === 'error' ||
    (await anyEnrolled(c.env.DB, lookup.userIds))
  if (!enrolled) return null

  if (initiateResponse) {
    console.warn('[two-factor] passwordless initiation refused for an enrolled account:', path)
    return c.json(initiateResponse)
  }
  console.warn('[two-factor] passwordless completion refused for an enrolled account:', path)
  return c.json(BA_INVALID_OTP, 400)
}

/**
 * Parse the request body as JSON, falling back to form encodings.
 *
 * Today only JSON can reach these endpoints — BA's router pins them to
 * `allowedMediaTypes: ["application/json"]`, so a form-encoded POST 415s before the handler. The
 * fallback is here so this guard does not depend on that default: if BA ever accepts form bodies
 * on `/sign-in/magic-link` or `/sign-in/email-otp`, or an app widens `allowedMediaTypes` through
 * `extendBetterAuth`, the block still applies instead of silently opening.
 */
async function readBody(
  c: Context<{ Bindings: { DB: D1Database } }>
): Promise<Record<string, unknown> | null> {
  const contentType = c.req.header('Content-Type') ?? ''
  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    try {
      const form = await c.req.raw.clone().formData()
      return Object.fromEntries(form.entries())
    } catch {
      return null
    }
  }
  try {
    const parsed = (await c.req.raw.clone().json()) as unknown
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/**
 * Resolve every user id whose email matches, case-insensitively.
 *
 * `COLLATE NOCASE` deliberately, even though it forgoes `idx_auth_user_email`: SonicJS's own
 * login routes lowercase before storing, but BA's magic-link endpoint passes `ctx.body.email`
 * through verbatim, so a case-sensitive compare could MISS an enrolled account — and a miss here
 * is a bypass, not a slow query. These endpoints are low-traffic by nature.
 *
 * Returns ALL matches rather than `LIMIT 1`. `auth_user.email` is UNIQUE under BINARY collation,
 * so `alice@x.com` and `ALICE@x.com` can both exist; an unordered `LIMIT 1` could return the
 * non-enrolled twin and let the enrolled account through.
 */
async function resolveUsersByEmail(db: D1Database, email: string): Promise<UserLookup> {
  try {
    const rows = await db
      .prepare(`SELECT id FROM auth_user WHERE email = ? COLLATE NOCASE`)
      .bind(email)
      .all<{ id: string }>()
    const userIds = (rows.results ?? []).map((r) => r.id)
    return userIds.length === 0 ? { kind: 'absent' } : { kind: 'found', userIds }
  } catch (e) {
    console.error('[two-factor] user lookup failed in passwordless guard; failing closed', e)
    return { kind: 'error' }
  }
}

/** True if ANY of the matched accounts holds a verified second factor. */
async function anyEnrolled(db: D1Database, userIds: string[]): Promise<boolean> {
  for (const id of userIds) {
    if (await hasVerifiedSecondFactor(db, id)) return true
  }
  return false
}

/** Exported for tests — the exact set of paths this guard is responsible for. */
export const GUARDED_PASSWORDLESS_PATHS = Object.freeze({
  initiate: Object.freeze(Object.keys(INITIATE_PATHS)),
  complete: Object.freeze([...COMPLETE_PATHS]),
})
