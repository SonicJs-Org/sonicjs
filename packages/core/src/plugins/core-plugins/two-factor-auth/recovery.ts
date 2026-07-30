/**
 * Administrative recovery for two-factor auth — the break-glass path.
 *
 * ── Why this exists ──
 * Without it, the complete list of ways back into an account with a lost authenticator is:
 * an unused backup code, or `wrangler d1 execute --remote`. Everything an operator would
 * reasonably reach for is closed by design:
 *
 *   - Password reset does not mint a session (`passwordless-second-factor-guard.ts`), so it
 *     hands the user a new password and the same unpassable challenge.
 *   - Magic link and email OTP are refused outright for enrolled users — whoever owns the
 *     inbox would otherwise own the account, which is the thing the second factor is for.
 *   - Self-service disable requires a session, which requires the second factor.
 *
 * So a sole admin who enrols and then loses phone and codes locks the entire organisation out
 * of the admin portal, recoverable only by someone holding Cloudflare credentials. This turns
 * that incident into another admin clicking a button.
 *
 * ── The cost, stated plainly ──
 * This makes any admin account a path around any user's second factor. It does NOT hand over
 * the account — the password is still required, and this never touches it — but it does remove
 * a control from someone else's account. Hence: admin role required, the target's email must be
 * typed back, and every use writes a `two_factor_reset` security event.
 *
 * ── Not behind the deactivate→404 gate ──
 * `twoFactorAdminRoutes` 404s when the plugin is deactivated. These routes deliberately do not,
 * for the same reason the login challenge does not: `auth/config.ts` composes Better Auth's
 * `twoFactor` plugin unconditionally, so deactivating this plugin stops nothing about
 * verification — enrolled users are still challenged. A recovery path that disappeared exactly
 * when the surface was turned off would be worse than none, because the lockout it is meant to
 * fix would still be happening.
 *
 * Mounted on its own prefix (`/admin/two-factor-reset`) rather than under `/admin/two-factor`:
 * Hono flattens `app.route()` sub-apps into the parent, so anything mounted at the enrolment
 * prefix would inherit that sub-app's `use('*')` deactivate gate — the very thing this must not
 * have.
 */
import { Hono } from 'hono'
import type { Context, MiddlewareHandler } from 'hono'
import { z } from 'zod'
import { requireAuth, requireRole } from '../../../middleware'
import { isPluginActive } from '../../../middleware/plugin-middleware'
import { TWO_FACTOR_PLUGIN_ID } from '../../../auth/two-factor-settings'
import type { D1Database } from '@cloudflare/workers-types'
import type { Bindings, Variables } from '../../../app'

/** Where a user who owes an enrolment is sent, and the one place they may go until they finish. */
export const ENROLMENT_PATH = '/admin/two-factor'

/** Public prefix for the reset endpoint. Mounted in app.ts — see the module docblock. */
export const RECOVERY_PREFIX = '/admin/two-factor-reset'

const resetRequestSchema = z.object({
  /** Target user. Never the acting admin implicitly — it must always be named. */
  userId: z.string().min(1, 'userId is required'),
  /**
   * The target's email, typed by the operator. Compared case-insensitively against the record.
   *
   * This is not theatre and it is not a second authentication factor: it defends against the
   * realistic failure, which is resetting the wrong row. The action is invoked from a list of
   * similar-looking rows, it is irreversible for the user (their enrolment is destroyed), and
   * the ids are opaque. A password confirmation would be the stronger control, but Better Auth
   * hashes with its own scrypt (`salt:key`) that `AuthManager.verifyPassword` cannot read, and
   * reimplementing it wrong would break the break-glass itself.
   */
  confirmEmail: z.string().min(1, 'confirmEmail is required'),
  /**
   * Leave `two_factor_required = 1` so the user must enrol again before using the portal.
   *
   * Defaults to true because the alternative is worse than it looks: a reset with no follow-up
   * silently converts "protected by 2FA" into "password only" and nothing ever prompts the user
   * about it. Set false deliberately — e.g. offboarding, or a user who should not have been
   * enrolled at all.
   */
  requireReenrolment: z.boolean().optional().default(true),
})

export type TwoFactorResetRequest = z.infer<typeof resetRequestSchema>

export interface TwoFactorResetOutcome {
  /** The row actually cleared, for the audit record and the confirmation message. */
  email: string
  /** Whether the user had a completed enrolment before this ran (false = reset was a no-op repair). */
  wasEnrolled: boolean
  requireReenrolment: boolean
}

/**
 * Clear one user's second factor.
 *
 * Both statements go in a single `batch` so the pair cannot half-apply. A DELETE that landed
 * without the UPDATE would leave `two_factor_enabled = 1` with no enrolment row behind it —
 * a user who reads "Enabled" everywhere and is challenged by nothing.
 *
 * Deleting the `auth_two_factor` row also clears `failed_verification_count` and `locked_until`
 * (migration 0003 put both there), so this fixes a lockout as well as a lost device.
 *
 * Exported separately from the route so the DB effect is testable without a Hono context.
 */
export async function resetUserTwoFactor(
  db: D1Database,
  userId: string,
  requireReenrolment: boolean,
): Promise<void> {
  await db.batch([
    db.prepare(`DELETE FROM auth_two_factor WHERE user_id = ?`).bind(userId),
    db
      .prepare(`UPDATE auth_user SET two_factor_enabled = 0, two_factor_required = ? WHERE id = ?`)
      .bind(requireReenrolment ? 1 : 0, userId),
  ])
}

/** Both halves of a user's second-factor policy state, in one round trip. */
interface TwoFactorPolicyState {
  /** `auth_user.two_factor_required` — an admin demanded a second factor on this account. */
  required: boolean
  /** A COMPLETED enrolment exists (`auth_two_factor.verified = 1`). */
  verified: boolean
}

/**
 * Read the policy state.
 *
 * One query rather than two, because the enforcement middleware runs on every admin request and a
 * second sequential D1 read there would be felt.
 *
 * Resolves to "no policy, not enrolled" on any error — see the fail-open note on
 * {@link enforceTwoFactorEnrolment}. Every caller here shares it, so the banner the enrolment page
 * shows, the redirect that sent the user there, and the disable guard can never disagree.
 */
async function readPolicyState(db: D1Database, userId: string): Promise<TwoFactorPolicyState> {
  if (!userId) return { required: false, verified: false }
  try {
    const row = await db
      .prepare(
        `SELECT u.two_factor_required AS required,
                (SELECT tf.verified FROM auth_two_factor tf WHERE tf.user_id = u.id LIMIT 1) AS verified
           FROM auth_user u
          WHERE u.id = ?`,
      )
      .bind(userId)
      .first<{ required: number; verified: number | null }>()
    return { required: row?.required === 1, verified: row?.verified === 1 }
  } catch (e) {
    console.error('[two-factor] policy state lookup failed; treating as unset', e)
    return { required: false, verified: false }
  }
}

/**
 * Does this user owe an enrolment right now?
 *
 * `required && verified` is a user who has enrolled and may not turn it back off — the flag stays
 * set, and this must not act on it. Only `required && !verified` owes anything.
 */
export async function owesTwoFactorEnrolment(db: D1Database, userId: string): Promise<boolean> {
  const { required, verified } = await readPolicyState(db, userId)
  return required && !verified
}

/**
 * Is a second factor MANDATED on this account, regardless of whether one currently exists?
 *
 * Distinct from {@link owesTwoFactorEnrolment} on purpose, and the difference is the whole point
 * of the disable guard: a user who has satisfied the requirement is `required && verified`, so
 * "owes an enrolment" is false for them while "may not turn it off" is still true.
 */
export async function isTwoFactorRequired(db: D1Database, userId: string): Promise<boolean> {
  return (await readPolicyState(db, userId)).required
}

/**
 * Write the audit record.
 *
 * Best-effort, and that is a deliberate ranking: this feature exists so that nobody is ever
 * locked out of their own admin panel, so an unavailable audit sink (the security-audit plugin
 * is separately installable, and its document type may not be registered) must not be the reason
 * a break-glass fails. A failure here is loud in the logs rather than silent.
 */
async function auditReset(
  db: D1Database,
  fields: {
    actorId: string
    actorEmail: string
    targetId: string
    targetEmail: string
    wasEnrolled: boolean
    requireReenrolment: boolean
    ipAddress?: string
    userAgent?: string
  },
): Promise<void> {
  try {
    const { SecurityAuditService } = await import(
      '../security-audit-plugin/services/security-audit-service'
    )
    await new SecurityAuditService(db).logEvent({
      eventType: 'two_factor_reset',
      // Not 'info': someone's second factor was removed by someone else. This is the kind of
      // event that should stand out when an account is later found to be compromised.
      severity: 'warning',
      // The SUBJECT of the event, so it surfaces when filtering by the affected account. The
      // actor is in details — losing that would make the record useless for accountability.
      userId: fields.targetId,
      email: fields.targetEmail,
      ipAddress: fields.ipAddress,
      userAgent: fields.userAgent,
      requestPath: RECOVERY_PREFIX,
      requestMethod: 'POST',
      details: {
        actorId: fields.actorId,
        actorEmail: fields.actorEmail,
        wasEnrolled: fields.wasEnrolled,
        requireReenrolment: fields.requireReenrolment,
        selfService: fields.actorId === fields.targetId,
      },
      blocked: false,
    })
  } catch (e) {
    console.error('[two-factor] reset succeeded but the audit event could not be written', e)
  }
}

const twoFactorRecoveryRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// `/admin/*` is already gated globally by requireAuth + requireRbac('portal','access'). Both are
// asserted again locally: this is the one route in the plugin that acts on somebody ELSE's
// account, so its gate should be readable at the route rather than inferred from where it is
// mounted. `requireRole(['admin'])` matches how routes/admin-users.ts gates every other
// user-management action — a reset is user management, and reusing that gate means it is
// governed by the same role assignment operators already reason about.
twoFactorRecoveryRoutes.use('*', requireAuth())
twoFactorRecoveryRoutes.use('*', requireRole(['admin']))

/**
 * POST /admin/two-factor-reset — clear a user's second factor.
 *
 * Self-reset is permitted. Reaching this route already required passing the second factor being
 * reset (or never having had one), so it grants nothing new, and it is the natural "I replaced my
 * phone" flow. It is recorded with `selfService: true` so it is still distinguishable in the log.
 *
 * Deliberately does NOT revoke the target's existing sessions: a reset is a recovery action, not
 * a containment action, and signing a colleague out mid-work to fix their lost phone would be a
 * surprise. Containment is what deactivating the account is for.
 */
twoFactorRecoveryRoutes.post('/', async (c) => {
  const actor = c.get('user')!

  const parsed = resetRequestSchema.safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) {
    return c.json({ error: parsed.error.issues[0]?.message ?? 'Invalid request' }, 400)
  }
  const { userId, confirmEmail, requireReenrolment } = parsed.data

  const target = await c.env.DB.prepare(
    `SELECT u.id, u.email, u.two_factor_enabled AS enabled,
            (SELECT tf.verified FROM auth_two_factor tf WHERE tf.user_id = u.id LIMIT 1) AS verified
       FROM auth_user u
      WHERE u.id = ?`,
  )
    .bind(userId)
    .first<{ id: string; email: string; enabled: number; verified: number | null }>()

  if (!target) {
    return c.json({ error: 'User not found' }, 404)
  }

  // Case- and whitespace-insensitive: the operator is retyping what the page showed them, and
  // failing on a trailing space would only teach them to paste it, which defeats the check.
  if (confirmEmail.trim().toLowerCase() !== target.email.trim().toLowerCase()) {
    return c.json(
      { error: 'The email you typed does not match this user. Nothing was changed.' },
      400,
    )
  }

  const wasEnrolled = target.verified === 1 || target.enabled === 1

  try {
    await resetUserTwoFactor(c.env.DB, target.id, requireReenrolment)
  } catch (e) {
    console.error('[two-factor] reset failed', e)
    return c.json({ error: 'Failed to reset two-factor authentication' }, 500)
  }

  await auditReset(c.env.DB, {
    actorId: actor.userId,
    actorEmail: actor.email,
    targetId: target.id,
    targetEmail: target.email,
    wasEnrolled,
    requireReenrolment,
    ipAddress: c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for'),
    userAgent: c.req.header('user-agent'),
  })

  const outcome: TwoFactorResetOutcome = {
    email: target.email,
    wasEnrolled,
    requireReenrolment,
  }
  return c.json({ ok: true, ...outcome })
})

/**
 * Force a user who owes an enrolment back to the enrolment page.
 *
 * Without this, "reset" quietly means "downgrade to password-only": the user's enrolment is gone,
 * nothing ever prompts them, and the account stays unprotected indefinitely while the admin who
 * pressed the button believes they restored access to a 2FA-protected account.
 *
 * `two_factor_required` lives on `auth_user`, not `auth_two_factor`, precisely because the reset
 * DELETEs that row — a flag stored there would be destroyed by the action that needs to set it.
 *
 * ── Deliberately fails OPEN ──
 * Every failure mode here resolves to "let the request through":
 *
 *   - a DB error → `next()`. This gate enforces a policy; it does not authenticate anybody. The
 *     session was already validated upstream by requireAuth. Failing closed would convert a
 *     transient D1 error into every admin being locked out of the portal, which is the exact
 *     class of outage this whole feature exists to prevent.
 *   - the plugin being deactivated → `next()`, checked FIRST. `/admin/two-factor` 404s when the
 *     plugin is off, so enforcing then would redirect the user in a loop to a page that cannot
 *     exist. Deactivating the plugin is the operator's own escape hatch from a bad required-flag.
 *
 * Mounted from app.ts alongside the other `/admin/*` middleware rather than from the plugin's
 * `register()`, because Hono composes matched handlers in registration order: plugin registration
 * runs interleaved with `app.route('/admin/...')` calls, so middleware added there would silently
 * not run for the admin routes mounted before it.
 */
export function enforceTwoFactorEnrolment(): MiddlewareHandler<{
  Bindings: Bindings
  Variables: Variables
}> {
  return async (c, next) => {
    const user = c.get('user') as { userId?: string } | undefined
    if (!user?.userId) return next()

    const path = new URL(c.req.url).pathname
    // The enrolment surface itself, or the user could never satisfy the requirement. Covers
    // `/admin/two-factor` and `/admin/two-factor/qr`; the trailing-boundary check keeps it from
    // also exempting `/admin/two-factor-reset`, which a user who owes an enrolment has no
    // business reaching.
    if (path === ENROLMENT_PATH || path.startsWith(`${ENROLMENT_PATH}/`)) return next()

    try {
      if (!(await isPluginActive(c.env.DB, TWO_FACTOR_PLUGIN_ID))) return next()
      if (!(await owesTwoFactorEnrolment(c.env.DB, user.userId))) return next()
    } catch (e) {
      console.error('[two-factor] enrolment enforcement check failed; allowing request', e)
      return next()
    }

    const accept = c.req.header('Accept') || ''
    if (accept.includes('text/html')) {
      // No explanatory query parameter: the enrolment page reads the same flag and renders the
      // banner itself. A `?message=` would be attacker-controlled text on a security page —
      // anyone could hand a colleague a link that claims their 2FA was reset.
      return c.redirect(ENROLMENT_PATH)
    }
    return c.json(
      {
        error: 'Two-factor enrolment required',
        message: 'Your administrator reset your two-factor authentication. Enrol again to continue.',
        enrolmentPath: ENROLMENT_PATH,
      },
      403,
    )
  }
}

/** Better Auth's disable endpoint, as mounted under this app's `/auth` basePath. */
export const BA_DISABLE_PATH = '/auth/two-factor/disable'

/**
 * Refuse `POST /auth/two-factor/disable` for an account where an admin has MANDATED a second
 * factor.
 *
 * ── Why the redirect middleware is not enough ──
 * `enforceTwoFactorEnrolment` is an access gate, not a write-block: it makes the portal
 * unreachable while a demanded factor is missing, but it never sees this request. Two independent
 * reasons — the path is `/auth/*`, not `/admin/*`, and `/admin/two-factor` (which hosts the
 * disable form) has to stay exempt or nobody could ever complete an enrolment.
 *
 * So without this, a user told to enrol could enrol, walk back to the same page, and switch it
 * off. They would be bounced to the enrolment page on their next admin request, so it is a loop
 * rather than an escape — but in the interval the account is genuinely password-only: BA stops
 * challenging (its after-hook reads `user.twoFactorEnabled`), the passwordless sign-in paths
 * re-open (`hasVerifiedSecondFactor` keys off the row this deletes), and nothing gates `/api/*`.
 * Meanwhile the admin who set the requirement has no signal, because a BA disable writes none of
 * our audit events.
 *
 * ── Why here ──
 * Same chokepoint and same reasoning as {@link guardPasswordlessSecondFactor}: the `/auth/*`
 * catch-all in `app.ts` is our own code and runs ahead of `auth.handler()`, so the refusal lands
 * before BA deletes anything. A BA `after` hook would fire after the write.
 *
 * ── Not an enumeration risk ──
 * Unlike the passwordless guard, this answers a caller already authenticated AS the account in
 * question, so a plain-language reason leaks nothing about anyone else — and the user needs to
 * know why the button did not work.
 *
 * Fails OPEN, matching {@link enforceTwoFactorEnrolment}: `readPolicyState` resolves to "not
 * required" on a DB error. A transient D1 fault should not permanently freeze a user's ability to
 * manage their own second factor, and the admin reset remains available either way.
 */
export async function guardRequiredSecondFactorDisable(
  c: Context<{ Bindings: { DB: D1Database }; Variables: { user?: { userId?: string } } }>,
): Promise<Response | null> {
  if (c.req.method !== 'POST') return null
  if (new URL(c.req.url).pathname !== BA_DISABLE_PATH) return null

  // Resolved by the session middleware in app.ts, which runs on `*` ahead of this catch-all. No
  // session means BA will refuse the call itself (`sensitiveSessionMiddleware`), so there is
  // nothing to protect and nothing to leak.
  const user = c.get('user')
  if (!user?.userId) return null

  if (!(await isTwoFactorRequired(c.env.DB, user.userId))) return null

  console.warn('[two-factor] disable refused — an administrator requires 2FA on this account')
  return c.json(
    {
      error: 'Two-factor authentication is required on this account',
      message:
        'An administrator requires two-factor authentication on your account, so it cannot be turned off. Contact an administrator if this needs to change.',
      code: 'TWO_FACTOR_REQUIRED',
    },
    403,
  )
}

export { twoFactorRecoveryRoutes }
