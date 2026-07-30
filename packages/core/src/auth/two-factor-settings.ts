/**
 * Two-factor policy: the knobs `twoFactor()` is composed from in `auth/config.ts`.
 *
 * ── Why the getter is synchronous ──
 * `createAuth()` is synchronous and runs on EVERY request (app.ts session middleware), and
 * BA reads `issuer` / `accountLockout` / `backupCodeOptions` off the static options object it
 * was constructed with — `verify-two-factor.mjs` pulls the lockout config via
 * `ctx.context.getPlugin('two-factor')?.options`, not through a resolver. So the values have
 * to be available *at construction time*, and construction cannot await a D1 read without
 * putting a round-trip on the authenticated hot path.
 *
 * The split is therefore: {@link loadTwoFactorPolicy} (async, one D1 read) is called once per
 * isolate from the plugin's `onBoot`, and {@link getTwoFactorPolicy} (sync) is what
 * `getDefaultAuthOptions` reads. Ordering is guaranteed by app.ts: the `boot()` middleware
 * that runs plugin `onBoot` is registered ahead of the session middleware, and it is awaited.
 *
 * ── Staleness contract ──
 * One load per isolate, no TTL — the same contract `isPluginActive()` already ships with.
 * A settings change takes effect on new isolates immediately and on a warm one when it
 * recycles, or right away in the isolate that performed the write if it calls
 * {@link invalidateTwoFactorPolicy}. Before the first load, and on any read failure, the
 * DEFAULTS below apply.
 *
 * Be precise about what that buys, because an earlier version of this comment overstated it:
 * the defaults are the SHIPPED defaults, not the extreme end of each range (5 attempts and 900s
 * sit mid-way through BOUNDS' 3–10 and 300–3600). So a failed load reverts an operator's
 * override in EITHER direction — someone who tightened `maxFailedAttempts` to 3 gets 5 back.
 * What is actually guaranteed is the BOUND, not the direction: every value the policy can ever
 * take, loaded or defaulted, is inside BOUNDS, so no read failure and no stored value can
 * disable the lockout or reduce backup codes below 5.
 *
 * Note what is NOT here: nothing gates whether `twoFactor()` is composed at all. That is
 * deliberate — see the ADR in project-plan.md. Plugin status gates the enrolment surface;
 * it must never gate verification, or deactivating the plugin would silently downgrade every
 * enrolled account to password-only while the UI still read "Enabled".
 */
import type { D1Database } from '@cloudflare/workers-types'

export interface TwoFactorPolicy {
  /** Label shown beside the account in the user's authenticator app. */
  issuer: string
  /** Consecutive failed second-factor verifications before the account locks. */
  maxFailedAttempts: number
  /** How long that lock lasts, in seconds. */
  lockoutDurationSeconds: number
  /** How many single-use backup codes are minted at enrolment. */
  backupCodeCount: number
}

/** Plugin id — must match `manifest.json` `id` and the plugin document's slug. */
export const TWO_FACTOR_PLUGIN_ID = 'two-factor-auth'

export const TWO_FACTOR_POLICY_DEFAULTS: Readonly<TwoFactorPolicy> = Object.freeze({
  issuer: 'SonicJS',
  maxFailedAttempts: 5,
  lockoutDurationSeconds: 900,
  backupCodeCount: 10,
})

/**
 * Bounds every knob. An operator-supplied value outside these is clamped rather than
 * rejected: a settings form should not be able to disable the lockout (maxFailedAttempts:
 * 10_000) or mint a single backup code, and a value that arrives as a string from FormData
 * must not silently become NaN inside BA's arithmetic.
 */
const BOUNDS = {
  maxFailedAttempts: { min: 3, max: 10 },
  lockoutDurationSeconds: { min: 300, max: 3600 },
  backupCodeCount: { min: 5, max: 20 },
} as const

let cached: TwoFactorPolicy | null = null

function clampInt(value: unknown, fallback: number, bounds: { min: number; max: number }): number {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.min(bounds.max, Math.max(bounds.min, Math.round(n)))
}

/** Normalize whatever is stored in the plugin document into a usable, bounded policy. */
export function normalizeTwoFactorPolicy(raw: unknown): TwoFactorPolicy {
  const s = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const issuer = typeof s.issuer === 'string' && s.issuer.trim() !== '' ? s.issuer.trim() : TWO_FACTOR_POLICY_DEFAULTS.issuer
  return {
    // The issuer lands in an `otpauth://` URI. Strip the two characters that would let a
    // stored value break out of the label segment and forge a different account entry.
    issuer: issuer.replace(/[:?#]/g, ' ').slice(0, 64),
    maxFailedAttempts: clampInt(s.maxFailedAttempts, TWO_FACTOR_POLICY_DEFAULTS.maxFailedAttempts, BOUNDS.maxFailedAttempts),
    lockoutDurationSeconds: clampInt(s.lockoutDurationSeconds, TWO_FACTOR_POLICY_DEFAULTS.lockoutDurationSeconds, BOUNDS.lockoutDurationSeconds),
    backupCodeCount: clampInt(s.backupCodeCount, TWO_FACTOR_POLICY_DEFAULTS.backupCodeCount, BOUNDS.backupCodeCount),
  }
}

/**
 * Read the policy from the plugin's settings document, once per isolate.
 *
 * Plugin settings are document-backed (`type_id = 'plugin'`, `slug = <plugin id>`) — the
 * legacy `plugins` table does not exist on greenfield SonicJS v3. This reads the same place
 * `PluginService.updatePluginSettings()` writes, so the admin form is not save-nowhere chrome.
 */
export async function loadTwoFactorPolicy(db: D1Database): Promise<TwoFactorPolicy> {
  if (cached) return cached
  let stored: unknown = {}
  try {
    const row = (await db
      .prepare(
        `SELECT data FROM documents
         WHERE slug = ? AND type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL`
      )
      .bind(TWO_FACTOR_PLUGIN_ID)
      .first()) as { data: string | Record<string, unknown> } | null
    if (row?.data) {
      const data = typeof row.data === 'string' ? JSON.parse(row.data) : row.data
      stored = (data as { settings?: unknown })?.settings ?? {}
    }
  } catch (e) {
    // Degrades to the shipped defaults — still inside BOUNDS, so the lockout stays enabled and
    // backup codes stay >= 5. It does NOT preserve an operator's tighter override; see the
    // staleness note in the module header.
    console.warn('[two-factor] settings read failed; using policy defaults', e)
  }
  cached = normalizeTwoFactorPolicy(stored)
  return cached
}

/**
 * The policy `getDefaultAuthOptions` composes from. Returns the defaults until
 * {@link loadTwoFactorPolicy} has run in this isolate.
 */
export function getTwoFactorPolicy(): TwoFactorPolicy {
  return cached ?? { ...TWO_FACTOR_POLICY_DEFAULTS }
}

/**
 * Drop the isolate cache. Prefer {@link refreshTwoFactorPolicy} on a settings write: the
 * loader is once-guarded, so invalidating alone would leave this isolate on the DEFAULTS for
 * the rest of its life rather than on the operator's saved values.
 */
export function invalidateTwoFactorPolicy(): void {
  cached = null
}

/**
 * Re-read the policy after a settings write, so the change lands in the writing isolate
 * immediately instead of waiting for it to recycle. Other warm isolates still pick it up on
 * recycle — the same staleness contract as `isPluginActive`.
 */
export async function refreshTwoFactorPolicy(db: D1Database): Promise<TwoFactorPolicy> {
  cached = null
  return loadTwoFactorPolicy(db)
}
