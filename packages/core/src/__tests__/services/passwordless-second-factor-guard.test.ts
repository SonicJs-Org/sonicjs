/**
 * `guardPasswordlessSecondFactor` — the block that stops a magic link or an emailed code from
 * standing in for password + TOTP.
 *
 * These tests exist mostly to pin the properties that are easy to lose:
 *   - INITIATE endpoints must answer BA's own success shape (no 2FA-enrolment oracle) and must
 *     answer the RIGHT one per endpoint
 *   - the COMPLETE endpoint must answer 403 with a message
 *   - the request body must survive the guard, because BA parses it afterwards
 *   - unrelated /auth paths must pass straight through
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import type { Context } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import {
  guardPasswordlessSecondFactor,
  GUARDED_PASSWORDLESS_PATHS,
} from '../../auth/passwordless-second-factor-guard'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

let db: TestD1

function seedUser(id: string, email: string) {
  db.raw
    .prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
       VALUES (?, ?, 'A', 'B', 0, 0)`,
    )
    .run(id, email)
}

function seedEnrolment(userId: string, verified: 0 | 1) {
  db.raw
    .prepare(
      `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, verified, created_at, updated_at)
       VALUES (?, 'enc', 'enc', ?, ?, 0, 0)`,
    )
    .run(`tf-${userId}`, userId, verified)
}

/**
 * Drive the guard through a real Hono app so the body-clone behaviour is exercised for real
 * rather than mocked. `downstream` records what Better Auth would have seen.
 */
async function run(
  path: string,
  body: unknown,
  method = 'POST',
): Promise<{ status: number; json: unknown; reachedBetterAuth: boolean; downstreamBody: unknown }> {
  let reachedBetterAuth = false
  let downstreamBody: unknown = undefined

  const app = new Hono<{ Bindings: { DB: unknown } }>()
  app.on(['GET', 'POST'], '/auth/*', async (c) => {
    const refused = await guardPasswordlessSecondFactor(
      c as unknown as Context<{ Bindings: { DB: D1Database } }>,
    )
    if (refused) return refused
    reachedBetterAuth = true
    // Stand-in for auth.handler(c.req.raw): proves the stream the guard cloned is still intact.
    downstreamBody = await c.req.raw.json().catch(() => 'UNPARSEABLE')
    return c.json({ downstream: true })
  })

  const res = await app.request(
    path,
    {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    { DB: db },
  )
  return {
    status: res.status,
    json: await res.json().catch(() => null),
    reachedBetterAuth,
    downstreamBody,
  }
}

beforeEach(() => {
  db = createTestD1()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  db.close()
  vi.restoreAllMocks()
})

describe('guardPasswordlessSecondFactor — enrolled accounts', () => {
  beforeEach(() => {
    seedUser('u1', 'enrolled@test.local')
    seedEnrolment('u1', 1)
  })

  it('refuses a magic-link request with BA\'s own {status:true}', async () => {
    const r = await run('/auth/sign-in/magic-link', { email: 'enrolled@test.local' })
    expect(r.status).toBe(200)
    expect(r.json).toEqual({ status: true })
    expect(r.reachedBetterAuth).toBe(false)
  })

  it('refuses a sign-in OTP request with BA\'s own {success:true}', async () => {
    // Deliberately a DIFFERENT shape from magic-link: matching each endpoint's own success body
    // is what makes the block indistinguishable from a real send.
    const r = await run('/auth/email-otp/send-verification-otp', {
      email: 'enrolled@test.local',
      type: 'sign-in',
    })
    expect(r.status).toBe(200)
    expect(r.json).toEqual({ success: true })
    expect(r.reachedBetterAuth).toBe(false)
  })

  it('refuses OTP sign-in completion with Better Auth\'s own invalid-code error', async () => {
    // Deliberately indistinguishable from a wrong code. A distinctive response here would be a
    // free oracle: this guard runs BEFORE BA validates the OTP, so an unauthenticated caller
    // could post any 6 digits and learn from the reply whether the address has an account with
    // a second factor. Mirrors APIError.from('BAD_REQUEST', EMAIL_OTP_ERROR_CODES.INVALID_OTP).
    const r = await run('/auth/sign-in/email-otp', { email: 'enrolled@test.local', otp: '000000' })
    expect(r.status).toBe(400)
    expect(r.json).toEqual({ message: 'Invalid OTP', code: 'INVALID_OTP' })
    expect(r.reachedBetterAuth).toBe(false)
  })

  it('refuses a form-encoded initiation too, so the block does not rest on BA\'s media-type default', async () => {
    // BA currently pins these endpoints to application/json, so a form body 415s before the
    // handler. If that ever widens, the guard must still apply rather than silently opening.
    const app = new Hono<{ Bindings: { DB: unknown } }>()
    let reached = false
    app.post('/auth/*', async (c) => {
      const refused = await guardPasswordlessSecondFactor(
        c as unknown as Context<{ Bindings: { DB: D1Database } }>,
      )
      if (refused) return refused
      reached = true
      return c.json({ downstream: true })
    })
    const res = await app.request(
      '/auth/sign-in/magic-link',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'email=enrolled%40test.local',
      },
      { DB: db },
    )
    expect(reached).toBe(false)
    expect(await res.json()).toEqual({ status: true })
  })

  it('fails CLOSED when the user lookup throws', async () => {
    // BA does its own lookup afterwards and can succeed where ours failed, so passing through on
    // error would mail a link to an enrolled account.
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const brokenDb = {
      prepare: () => ({ bind: () => ({ all: async () => { throw new Error('D1_ERROR: offline') } }) }),
    }
    const app = new Hono<{ Bindings: { DB: unknown } }>()
    let reached = false
    app.post('/auth/*', async (c) => {
      const refused = await guardPasswordlessSecondFactor(
        c as unknown as Context<{ Bindings: { DB: D1Database } }>,
      )
      if (refused) return refused
      reached = true
      return c.json({ downstream: true })
    })
    const res = await app.request(
      '/auth/sign-in/magic-link',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'enrolled@test.local' }),
      },
      { DB: brokenDb },
    )
    expect(reached).toBe(false)
    expect(await res.json()).toEqual({ status: true })
  })

  it('checks every case-insensitive match, not just the first row', async () => {
    // auth_user.email is UNIQUE under BINARY collation, so a capitalised twin can coexist. An
    // unordered LIMIT 1 could return the non-enrolled twin and let the enrolled account through.
    //
    // SEED ORDER IS THE WHOLE TEST. `email = ? COLLATE NOCASE` cannot use the BINARY index, so
    // SQLite full-scans in rowid order and `LIMIT 1` yields whichever row was inserted first.
    // The earlier version of this test seeded the non-enrolled twin SECOND, behind the enrolled
    // `u1` from the enclosing beforeEach — so reverting resolveUsersByEmail to `LIMIT 1` still
    // returned the enrolled row and the test stayed green while the bypass was wide open.
    // Re-seed from scratch with the NON-enrolled twin first so the assertion can actually fail.
    db.raw.prepare(`DELETE FROM auth_two_factor`).run()
    db.raw.prepare(`DELETE FROM auth_user`).run()
    seedUser('u-twin-plain', 'ENROLLED@test.local') // first row scanned; NOT enrolled
    seedUser('u-twin-enrolled', 'enrolled@test.local')
    seedEnrolment('u-twin-enrolled', 1)

    const r = await run('/auth/sign-in/magic-link', { email: 'enrolled@test.local' })
    expect(r.reachedBetterAuth).toBe(false)
  })

  it('matches the address case-insensitively — a miss here would be a bypass', async () => {
    // BA's magic-link endpoint passes ctx.body.email through verbatim, so an address that
    // arrives capitalised must still resolve to the enrolled account.
    const r = await run('/auth/sign-in/magic-link', { email: 'Enrolled@Test.Local' })
    expect(r.reachedBetterAuth).toBe(false)
    expect(r.json).toEqual({ status: true })
  })

  it('lets password reset through — it mints no session', async () => {
    const r = await run('/auth/email-otp/send-verification-otp', {
      email: 'enrolled@test.local',
      type: 'forget-password',
    })
    expect(r.reachedBetterAuth).toBe(true)
  })

  it('lets email verification through — it mints no session in this configuration', async () => {
    const r = await run('/auth/email-otp/send-verification-otp', {
      email: 'enrolled@test.local',
      type: 'email-verification',
    })
    expect(r.reachedBetterAuth).toBe(true)
  })
})

describe('guardPasswordlessSecondFactor — pass-through cases', () => {
  it('lets a user with no enrolment through', async () => {
    seedUser('u1', 'plain@test.local')
    const r = await run('/auth/sign-in/magic-link', { email: 'plain@test.local' })
    expect(r.reachedBetterAuth).toBe(true)
  })

  it('lets a user whose enrolment is unconfirmed through', async () => {
    seedUser('u1', 'pending@test.local')
    seedEnrolment('u1', 0)
    const r = await run('/auth/sign-in/magic-link', { email: 'pending@test.local' })
    expect(r.reachedBetterAuth).toBe(true)
  })

  it('lets an unknown address through, so the guard adds no enumeration signal of its own', async () => {
    const r = await run('/auth/sign-in/magic-link', { email: 'nobody@test.local' })
    expect(r.reachedBetterAuth).toBe(true)
  })

  it('does not touch password sign-in — BA challenges there itself', async () => {
    seedUser('u1', 'enrolled@test.local')
    seedEnrolment('u1', 1)
    const r = await run('/auth/sign-in/email', { email: 'enrolled@test.local', password: 'x' })
    expect(r.reachedBetterAuth).toBe(true)
  })

  it('does not touch OAuth callbacks — MFA there is the provider\'s contract', async () => {
    seedUser('u1', 'enrolled@test.local')
    seedEnrolment('u1', 1)
    const r = await run('/auth/callback/github', undefined, 'GET')
    expect(r.reachedBetterAuth).toBe(true)
  })

  it('passes an unparseable body through for BA to reject', async () => {
    const app = new Hono<{ Bindings: { DB: unknown } }>()
    let reached = false
    app.post('/auth/*', async (c) => {
      const refused = await guardPasswordlessSecondFactor(
        c as unknown as Context<{ Bindings: { DB: D1Database } }>,
      )
      if (refused) return refused
      reached = true
      return c.json({ ok: true })
    })
    const res = await app.request(
      '/auth/sign-in/magic-link',
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: 'not-json' },
      { DB: db },
    )
    expect(res.status).toBe(200)
    expect(reached).toBe(true)
  })

  it('ignores a GET to a guarded path', async () => {
    seedUser('u1', 'enrolled@test.local')
    seedEnrolment('u1', 1)
    const r = await run('/auth/sign-in/magic-link', undefined, 'GET')
    expect(r.reachedBetterAuth).toBe(true)
  })
})

describe('guardPasswordlessSecondFactor — body preservation', () => {
  it('leaves the request stream intact for Better Auth', async () => {
    // The guard reads c.req.raw.clone(). Using c.req.json() would consume the stream and BA's
    // own parse would then fail on every passwordless request — a total outage, not a subtle bug.
    seedUser('u1', 'plain@test.local')
    const r = await run('/auth/sign-in/magic-link', { email: 'plain@test.local', extra: 42 })
    expect(r.reachedBetterAuth).toBe(true)
    expect(r.downstreamBody).toEqual({ email: 'plain@test.local', extra: 42 })
  })
})

describe('guarded path inventory', () => {
  it('is exactly the set of BA endpoints that mint a session without a 2FA challenge', async () => {
    expect(GUARDED_PASSWORDLESS_PATHS.initiate).toEqual([
      '/auth/sign-in/magic-link',
      '/auth/email-otp/send-verification-otp',
    ])
    expect(GUARDED_PASSWORDLESS_PATHS.complete).toEqual(['/auth/sign-in/email-otp'])
  })
})
