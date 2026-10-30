/**
 * Does the per-account second-factor lockout actually LOCK?
 *
 * `two-factor-roundtrip.test.ts` proves the failure COUNTER reaches the column, and calls that
 * counter "the control that actually bounds guessing". Those are different claims, and only the
 * second one matters: BA writes `lockedUntil` only when the value RETURNED by its increment-update
 * is >= maxFailedAttempts —
 *
 *   ((await ctx.context.adapter.update({ ..., increment: { failedVerificationCount: 1 } }))
 *      ?.failedVerificationCount ?? 0) >= maxFailedAttempts
 *
 * — so an adapter whose update returns null, or a row without that field, leaves the `?? 0` in
 * charge and the account never locks. With BA rate limiting off repo-wide, that lockout is the
 * only thing bounding TOTP guessing: BA's own per-challenge `beginAttempt(5)` is keyed to the
 * challenge cookie, so an attacker just signs in again for a fresh one.
 *
 * It also pins the OPTION NAMES. `verify-two-factor.mjs` reads `accountLockout.maxFailedAttempts`
 * and `accountLockout.durationSeconds` off the composed plugin options and falls back to
 * `?? 10` / `?? 900` per key. A rename on either side (ours or a BA upgrade) silently reverts to
 * BA's defaults while every composition test — which asserts our own object back at us — stays
 * green.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createAuth } from '../../auth/config'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import { totpFromOtpauthUri } from '../utils/totp'
import type { Bindings } from '../../app'

const EMAIL = 'lockout@roundtrip.test'
const PASSWORD = 'correct-horse-battery-staple'
const ORIGIN = 'https://sonic.test'

let db: TestD1
let kv: Map<string, string>

function makeAuth() {
  const env = {
    DB: db,
    CACHE_KV: {
      get: async (k: string) => kv.get(k) ?? null,
      put: async (k: string, v: string) => void kv.set(k, v),
      delete: async (k: string) => void kv.delete(k),
    },
    BETTER_AUTH_SECRET: 'test-better-auth-secret-at-least-32-chars',
    BETTER_AUTH_URL: ORIGIN,
    JWT_SECRET: 'test-jwt-secret-value-32-chars-long!!',
  } as unknown as Bindings
  return createAuth(env, undefined, ORIGIN)
}

async function call(path: string, body: unknown, cookies: string[] = []) {
  const auth = makeAuth()
  const headers: Record<string, string> = { 'Content-Type': 'application/json', Origin: ORIGIN }
  if (cookies.length) headers.Cookie = cookies.map((c) => c.split(';')[0]).join('; ')
  const res = await auth.handler(
    new Request(`${ORIGIN}/auth${path}`, { method: 'POST', headers, body: JSON.stringify(body) }),
  )
  const setCookie =
    (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? []
  return { status: res.status, body: await res.json().catch(() => null), cookies: setCookie }
}

function lockRow() {
  return db.raw
    .prepare(`SELECT failed_verification_count AS n, locked_until AS until FROM auth_two_factor`)
    .get() as { n: number; until: number | null }
}

beforeEach(() => {
  db = createTestD1()
  kv = new Map()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
})

afterEach(() => {
  db.close()
  vi.restoreAllMocks()
})

describe('per-account second-factor lockout', () => {
  it('locks the account after maxFailedAttempts and refuses even a CORRECT code', async () => {
    await call('/sign-up/email', { email: EMAIL, password: PASSWORD, name: 'Lockout User' })
    const first = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    const enable = await call('/two-factor/enable', { password: PASSWORD }, first.cookies)
    const totpUri: string = enable.body.totpURI
    await call('/two-factor/verify-totp', { code: await totpFromOtpauthUri(totpUri) }, first.cookies)

    // Default policy = 5 consecutive failures. Take a FRESH challenge each time so BA's
    // per-challenge beginAttempt(5) limiter is never the thing that stops us — the claim under
    // test is the per-ACCOUNT lockout, which is what bounds an attacker who simply re-signs-in.
    for (let i = 0; i < 5; i++) {
      const challenged = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
      expect(challenged.body).toMatchObject({ twoFactorRedirect: true })
      const bad = await call('/two-factor/verify-totp', { code: '000000' }, challenged.cookies)
      expect(bad.status).not.toBe(200)
      console.info(`attempt ${i + 1}:`, JSON.stringify(lockRow()))
    }

    const after = lockRow()
    expect(after.n, 'failure counter did not reach the threshold').toBeGreaterThanOrEqual(5)
    expect(after.until, 'lockedUntil was never written — the lockout does not engage').not.toBeNull()
    expect(after.until!).toBeGreaterThan(Date.now())

    // The real proof: a VALID code must now be refused.
    const challenged = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    const good = await call(
      '/two-factor/verify-totp',
      { code: await totpFromOtpauthUri(totpUri) },
      challenged.cookies,
    )
    expect(good.status, `a valid code still worked while locked: ${JSON.stringify(good.body)}`).toBe(
      429,
    )
    // Explicit timeout, not the 5s default. This test makes ~10 sequential Better Auth round
    // trips, several of which run BA's real scrypt password hash, and lands around 5s on an idle
    // machine — close enough to the default that adding any concurrent test file to the run tips
    // it into a timeout that looks exactly like a broken lockout. The work is genuinely slow, so
    // the limit is what should move.
  }, 30_000)
})
