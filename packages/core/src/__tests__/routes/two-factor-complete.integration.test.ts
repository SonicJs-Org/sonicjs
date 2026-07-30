/**
 * `POST /auth/two-factor/complete` — the session upgrade that mints the same `auth_token` JWT a
 * password login mints, so a post-challenge session is not weaker than a password one.
 *
 * Driven against a REAL better-sqlite3 D1 with the REAL `hasVerifiedSecondFactor`,
 * `AuthManager.generateToken` and `getJwtExpirySecondsFromDb`.
 *
 * Why this file exists: this route is the newest code in the two-factor change and it MINTS A
 * CREDENTIAL, but every other test in the feature stops at Better Auth's own endpoints. The
 * claims worth pinning down are that it refuses an anonymous caller, refuses a caller with no
 * verified second factor, and derives the token from the SESSION rather than from request input.
 *
 * ── What this file does NOT prove ──
 * The harness supplies `c.get('user')` directly, and `requireAuth()` only checks that key for
 * presence — so `c.get('user')` IS half the security decision, and the half that lives in
 * app.ts's Better Auth session middleware is replaced here. The property that a caller holding
 * only the `better-auth.two_factor` CHALLENGE cookie (password proven, code not yet entered)
 * cannot reach this route is therefore asserted nowhere in the suite: it rests on that middleware
 * resolving no user from a pending challenge. If anything ever teaches it to read the challenge
 * cookie — say, to render the user's email on the challenge page — this route would hand out a
 * full JWT for a factor that was never verified, and every test here would stay green. The E2E
 * spec's `expectSessionUpgraded` is the only place the composed path is exercised.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { twoFactorChallengeRoutes } from '../../plugins/core-plugins/two-factor-auth/routes'
import { AuthManager } from '../../middleware/auth'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

const JWT_SECRET = 'test-jwt-secret-value-32-chars-long!!'
const USER_ID = 'user-enrolled-1'
const EMAIL = 'enrolled@test.local'

let db: TestD1

/** Build an app that mounts the challenge routes with an optional signed-in principal. */
function makeApp(user?: { userId: string; email: string; role?: string }) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    c.env = { DB: db, JWT_SECRET, ENVIRONMENT: 'production' } as never
    if (user) c.set('user' as never, user as never)
    await next()
  })
  app.route('/auth/two-factor', twoFactorChallengeRoutes)
  return app
}

function post(app: Hono, body: unknown = {}) {
  return app.request('/auth/two-factor/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

/** Insert an `auth_two_factor` row directly — BA owns the real writes. */
function seedEnrolment(userId: string, verified: 0 | 1) {
  db.raw
    .prepare(
      `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, verified, created_at, updated_at)
       VALUES (?, 'enc-secret', '[]', ?, ?, ?, ?)`,
    )
    .run(`tf-${userId}-${verified}`, userId, verified, Date.now(), Date.now())
}

beforeEach(() => {
  db = createTestD1()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  db.close()
  vi.restoreAllMocks()
})

describe('POST /auth/two-factor/complete', () => {
  it('refuses an anonymous caller with 401 and sets no cookie', async () => {
    const res = await post(makeApp())
    expect(res.status).toBe(401)
    expect(res.headers.get('set-cookie')).toBeNull()
  })

  it('refuses an authenticated caller who holds no second factor, and mints nothing', async () => {
    // A password-only session must not be able to convert itself through this route: it is a
    // session upgrade for the population that just passed a challenge, not a token vending machine.
    const res = await post(makeApp({ userId: 'no-2fa', email: 'plain@test.local', role: 'admin' }))
    expect(res.status).toBe(400)
    expect(res.headers.get('set-cookie')).toBeNull()
  })

  it('refuses a STARTED-but-unconfirmed enrolment (verified = 0)', async () => {
    // The window between /two-factor/enable and the first successful verify-totp. No challenge
    // has been passed, so there is nothing to upgrade.
    seedEnrolment(USER_ID, 0)
    const res = await post(makeApp({ userId: USER_ID, email: EMAIL, role: 'admin' }))
    expect(res.status).toBe(400)
    expect(res.headers.get('set-cookie')).toBeNull()
  })

  it('mints auth_token for a verified enrolment, with the same cookie attributes as a password login', async () => {
    seedEnrolment(USER_ID, 1)
    const res = await post(makeApp({ userId: USER_ID, email: EMAIL, role: 'admin' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })

    const cookie = res.headers.get('set-cookie') ?? ''
    expect(cookie).toContain('auth_token=')
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Strict')
    expect(cookie).toContain('Path=/')
    // ENVIRONMENT is 'production' in this harness, so the cookie must be Secure.
    expect(cookie).toContain('Secure')

    // Max-Age must be the resolved JWT TTL. A 0 or NaN here would sail past every other
    // assertion in this file while making the cookie a session cookie (or dropping it outright).
    const maxAge = Number(/Max-Age=(\d+)/.exec(cookie)?.[1])
    expect(Number.isFinite(maxAge)).toBe(true)
    expect(maxAge).toBeGreaterThan(0)

    const token = /auth_token=([^;]+)/.exec(cookie)?.[1] ?? ''
    const payload = await AuthManager.verifyToken(decodeURIComponent(token), JWT_SECRET)
    expect(payload).toBeTruthy()
    expect(payload!.userId).toBe(USER_ID)
    expect(payload!.email).toBe(EMAIL)
    expect(payload!.role).toBe('admin')
    // The JWT's own expiry must agree with the cookie's, or the cookie outlives the credential.
    expect(payload!.exp - payload!.iat).toBe(maxAge)
  })

  it('derives the token from the SESSION, never from request input', async () => {
    // The route's core safety claim. If it ever read identity off the body, this is the request
    // that would turn a viewer's post-challenge session into an admin credential.
    seedEnrolment(USER_ID, 1)
    const app = makeApp({ userId: USER_ID, email: EMAIL, role: 'viewer' })
    const res = await post(app, {
      userId: 'attacker',
      email: 'attacker@evil.test',
      role: 'admin',
      isSuperAdmin: true,
    })
    expect(res.status).toBe(200)

    const token = /auth_token=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')?.[1] ?? ''
    const payload = await AuthManager.verifyToken(decodeURIComponent(token), JWT_SECRET)
    expect(payload!.userId).toBe(USER_ID)
    expect(payload!.email).toBe(EMAIL)
    expect(payload!.role).toBe('viewer')
  })

  it('does not let one user upgrade on another user\'s enrolment', async () => {
    // hasVerifiedSecondFactor is keyed by user_id; a row for someone else must not satisfy it.
    seedEnrolment('somebody-else', 1)
    const res = await post(makeApp({ userId: USER_ID, email: EMAIL, role: 'admin' }))
    expect(res.status).toBe(400)
    expect(res.headers.get('set-cookie')).toBeNull()
  })
})
