/**
 * Second-factor enforcement for sign-in paths Better Auth's `twoFactor` plugin does not cover.
 *
 * ── Why this file exists ──
 * BA's twoFactor plugin installs exactly one after-hook, and its matcher is:
 *
 *     context.path === '/sign-in/email' || '/sign-in/username' || '/sign-in/phone-number'
 *
 * (better-auth/dist/plugins/two-factor/index.mjs). Every OTHER path that mints a session
 * therefore issues one with no second factor. In SonicJS that means the two BA plugins
 * composed alongside it in `auth/config.ts`:
 *
 *   - `magicLink`  → POST /auth/sign-in/magic-link, GET /auth/magic-link/verify
 *   - `emailOTP`   → POST /auth/sign-in/email-otp, POST /auth/email-otp/verify-email
 *
 * A user who enrols in TOTP could request a magic link and sign in with no second factor at
 * all — while `/admin/profile` reads "Enabled". That is strictly worse than having no second
 * factor, because it is a control that reports success and does nothing. It is also the same
 * channel the design refuses to accept AS a second factor (whoever owns the inbox owns the
 * code), so leaving it as a complete FIRST-factor bypass would be incoherent.
 *
 * Social/OAuth sign-in (`/auth/callback/*`) is deliberately NOT covered — see
 * `passwordless-second-factor-guard.ts`.
 *
 * ── Fail closed, deliberately ──
 * Most SonicJS DB helpers degrade open on a D1 error, which is right in front of a CMS read.
 * This sits in front of a session mint, and the failure mode of guessing "no second factor"
 * is handing an unchallenged session to precisely the account that asked for the extra
 * factor. So a query error here BLOCKS.
 */
import type { D1Database } from '@cloudflare/workers-types'

/**
 * True when `userId` has a COMPLETED second-factor enrolment, and must therefore not be
 * handed a session by any path that has not verified one.
 *
 * Keys off `auth_two_factor.verified = 1`, NOT `auth_user.two_factor_enabled`. In BA 1.6.22 the
 * two flip together — `verifyTOTP` sets both at the first successful verification, and
 * `/two-factor/enable` sets neither unless `skipVerificationOnEnable` is on (which this app does
 * not enable). `verified` is still the right column: it is the one BA's own sign-in gate consults
 * (`if (isSignIn && twoFactor.verified === false) throw TOTP_NOT_ENABLED`), it stays correct if
 * `skipVerificationOnEnable` is ever turned on (where the user flag WOULD lead enrolment), and it
 * is scoped to the enrolment row rather than to a user column other features may come to write.
 *
 * Returns `true` (blocking) if the query throws — see the fail-closed note above. A missing
 * `auth_two_factor` table is the one exception: it means nobody can possibly be enrolled, so
 * it resolves `false` rather than locking everyone out of a deployment whose schema predates
 * the table.
 */
export async function hasVerifiedSecondFactor(db: D1Database, userId: string): Promise<boolean> {
  if (!userId) {
    // No principal to check. Callers resolve the id from a request body, so an empty value
    // means "user not found" — nothing to protect, and returning true would break sign-up.
    return false
  }
  try {
    const row = await db
      .prepare(`SELECT 1 AS present FROM auth_two_factor WHERE user_id = ? AND verified = 1 LIMIT 1`)
      .bind(userId)
      .first<{ present: number }>()
    return row?.present === 1
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    // "no such table" is structural, not a failure: the table does not exist in this
    // deployment, so there are no enrolments to protect. Anything else is a real error and
    // must block rather than silently wave a session through.
    if (/no such table/i.test(message)) return false
    console.error('[second-factor-guard] enrolment lookup failed; blocking session mint', e)
    return true
  }
}

/** What the enrolment UI needs in order to pick which of its three states to render. */
export interface TwoFactorEnrolmentState {
  /** A row exists — enrolment has at least been started. */
  enrolled: boolean
  /**
   * The enrolment was proven against a live code. Only a verified enrolment actually
   * challenges at sign-in, and only a verified enrolment blocks the passwordless paths.
   */
  verified: boolean
}

/**
 * Read one user's enrolment state.
 *
 * Read-only over BA's own table: this codebase never writes `auth_two_factor`. BA owns the
 * secret, the backup codes and the lockout counters, and the secret is encrypted with BA's
 * key — writing them from here would mean two authorities over one table.
 *
 * Fails OPEN to `{enrolled:false, verified:false}`, unlike {@link hasVerifiedSecondFactor}:
 * this feeds a UI, not a security decision. A DB hiccup should render "not enrolled", not a
 * 500 on the account page.
 */
export async function getEnrolmentState(
  db: D1Database,
  userId: string
): Promise<TwoFactorEnrolmentState> {
  try {
    const row = await db
      .prepare(`SELECT verified FROM auth_two_factor WHERE user_id = ? LIMIT 1`)
      .bind(userId)
      .first<{ verified: number }>()
    if (!row) return { enrolled: false, verified: false }
    return { enrolled: true, verified: row.verified === 1 }
  } catch (e) {
    console.error('[second-factor-guard] enrolment state read failed; rendering not-enrolled', e)
    return { enrolled: false, verified: false }
  }
}
