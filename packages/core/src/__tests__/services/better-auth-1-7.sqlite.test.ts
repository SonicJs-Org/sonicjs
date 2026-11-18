/**
 * Better Auth 1.7 upgrade — the behaviours the upgrade changed, driven through a REAL Better Auth
 * instance over REAL (better-sqlite3) D1, with `CACHE_KV` as a Map.
 *
 * Each case pins one thing that broke, or would have broken, on the 1.6.25 → 1.7.7 move:
 *   - password accounts written outside Better Auth (register form, join, bootstrap repair, seeds)
 *     still sign in — 1.7.0–1.7.2 keyed accounts by an `issuer` column that 1.7.3+ dropped again;
 *   - single-use values (email OTP, magic link) consume from D1, once, and never via KV;
 *   - organization writes match the drizzle schema (startup schema check, NOT NULL updatedAt),
 *     and users cannot create organizations (tenants belong to TenantService);
 *   - an enabled rate limiter has a real store (KV has no atomic increment) and actually limits;
 *   - GHSA-965c-763c-88jm: an OAuth `state` value cannot be redeemed as a magic-link token.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { hashPassword as baHashPassword } from 'better-auth/crypto'
import { createAuth, type ExtendBetterAuth } from '../../auth/config'
import { AuthManager } from '../../middleware/auth'
import { MAX_PASSWORD_LENGTH, authValidationService } from '../../services/auth-validation'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import type { Bindings } from '../../app'

const ORIGIN = 'https://sonic.test'
const PASSWORD = 'correct-horse-battery-staple'

let db: TestD1
let kv: Map<string, string>
let mails: string[]
let ip: string

function makeAuth(extend?: ExtendBetterAuth, extraEnv: Record<string, string> = {}) {
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
    ...extraEnv,
  } as unknown as Bindings
  return createAuth(env, extend, ORIGIN)
}

type Res = { status: number; body: any; cookies: string[]; location: string | null }

async function req(
  method: 'GET' | 'POST',
  path: string,
  opts: { body?: unknown; cookies?: string[]; extend?: ExtendBetterAuth; env?: Record<string, string> } = {},
): Promise<Res> {
  const headers: Record<string, string> = { Origin: ORIGIN, 'cf-connecting-ip': ip }
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (opts.cookies?.length) headers.Cookie = opts.cookies.map((c) => c.split(';')[0]).join('; ')
  const url = path.startsWith('http') ? path : `${ORIGIN}/auth${path}`
  const res = await makeAuth(opts.extend, opts.env).handler(
    new Request(url, {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      redirect: 'manual',
    }),
  )
  const text = await res.text()
  let body: any = text
  try { body = JSON.parse(text) } catch { /* not JSON */ }
  const cookies = ((res.headers as any).getSetCookie?.() ?? []) as string[]
  return { status: res.status, body, cookies, location: res.headers.get('location') }
}

const hasSession = (cs: string[]) =>
  cs.some((c) => c.includes('session_token=') && !/session_token=;/.test(c) && !/Max-Age=0/.test(c))

const verificationRows = () =>
  (db.raw.prepare('SELECT identifier FROM auth_verification').all() as { identifier: string }[]).map((r) => r.identifier)

const kvVerificationKeys = () => [...kv.keys()].filter((k) => k.startsWith('verification'))

async function signUp(email: string) {
  const r = await req('POST', '/sign-up/email', { body: { email, password: PASSWORD, name: 'Some User' } })
  expect(r.status, `sign-up: ${JSON.stringify(r.body)}`).toBe(200)
  return r.cookies
}

let seq = 0
beforeEach(() => {
  db = createTestD1()
  kv = new Map()
  mails = []
  ip = `203.0.113.${++seq}` // the memory rate-limit store is module-level: keep tests apart
  // Route outgoing mail through the email plugin's Resend path and capture the HTML.
  db.raw.exec(`CREATE TABLE IF NOT EXISTS plugins (id TEXT PRIMARY KEY, settings TEXT)`)
  db.raw
    .prepare(`INSERT OR REPLACE INTO plugins (id, settings) VALUES ('email', ?)`)
    .run(JSON.stringify({ apiKey: 're_test', fromEmail: 'noreply@sonic.test' }))
  vi.stubGlobal('fetch', async (_url: string, init: { body: string }) => {
    mails.push(JSON.parse(init.body).html)
    return new Response('{}', { status: 200 })
  })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
})

afterEach(() => {
  db.close()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Better Auth 1.7 — accounts written outside Better Auth still sign in', () => {
  // The same rows routes/auth.ts (register form), multi-tenant join and the bootstrap repair write:
  // auth_user in ms, auth_account in seconds, provider_id 'credential', no `issuer`.
  function insertCredentialUser(email: string, hash: string) {
    const id = crypto.randomUUID()
    const now = Date.now()
    const nowSec = Math.floor(now / 1000)
    db.raw
      .prepare(
        `INSERT INTO auth_user (id, email, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
         VALUES (?, ?, 'Old', 'User', ?, 'admin', 1, ?, ?)`,
      )
      .run(id, email, hash, now, now)
    db.raw
      .prepare(
        `INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
         VALUES (?, ?, ?, 'credential', ?, ?, ?)`,
      )
      .run(`cred-${id}`, id, id, hash, nowSec, nowSec)
    return id
  }

  it('a SonicJS PBKDF2 hash signs in and is rehashed to the Better Auth format', async () => {
    const id = insertCredentialUser('pbkdf2@sonic.test', await AuthManager.hashPassword(PASSWORD))
    const res = await req('POST', '/sign-in/email', { body: { email: 'pbkdf2@sonic.test', password: PASSWORD } })
    expect(res.status, JSON.stringify(res.body)).toBe(200)
    expect(hasSession(res.cookies)).toBe(true)
    const { password } = db.raw.prepare(`SELECT password FROM auth_account WHERE user_id = ?`).get(id) as { password: string }
    expect(password.startsWith('pbkdf2:')).toBe(false)

    const again = await req('POST', '/sign-in/email', { body: { email: 'pbkdf2@sonic.test', password: PASSWORD } })
    expect(again.status, JSON.stringify(again.body)).toBe(200)
  })

  it('a Better Auth hash written by a seed script signs in, and a wrong password does not', async () => {
    insertCredentialUser('seeded@sonic.test', await baHashPassword(PASSWORD))
    const ok = await req('POST', '/sign-in/email', { body: { email: 'seeded@sonic.test', password: PASSWORD } })
    expect(ok.status, JSON.stringify(ok.body)).toBe(200)
    expect(hasSession(ok.cookies)).toBe(true)
    const bad = await req('POST', '/sign-in/email', { body: { email: 'seeded@sonic.test', password: 'wrong-password-123' } })
    expect(bad.status).toBe(401)
    expect(hasSession(bad.cookies)).toBe(false)
  })

  it('SonicJS caps passwords where Better Auth does: the longest it accepts signs in, one more is refused', async () => {
    const longest = 'p'.repeat(MAX_PASSWORD_LENGTH)
    insertCredentialUser('long@sonic.test', await baHashPassword(longest))
    const ok = await req('POST', '/sign-in/email', { body: { email: 'long@sonic.test', password: longest } })
    expect(ok.status, JSON.stringify(ok.body)).toBe(200)
    const tooLong = await req('POST', '/sign-in/email', { body: { email: 'long@sonic.test', password: `${longest}p` } })
    expect(tooLong.body?.code).toBe('PASSWORD_TOO_LONG')

    const schema = await authValidationService.buildRegistrationSchema(db as never)
    expect(schema.safeParse({ email: 'a@sonic.test', password: longest }).success).toBe(true)
    expect(schema.safeParse({ email: 'a@sonic.test', password: `${longest}p` }).success).toBe(false)
  })
})

describe('Better Auth 1.7 — single-use values consume from D1', () => {
  it('email OTP: signs in once, rejects a replay, and never touches KV getAndDelete', async () => {
    const warn = console.warn as unknown as ReturnType<typeof vi.fn>
    await signUp('otp@sonic.test')
    const send = await req('POST', '/email-otp/send-verification-otp', { body: { email: 'otp@sonic.test', type: 'sign-in' } })
    expect(send.status, JSON.stringify(send.body)).toBe(200)
    expect(verificationRows()).toContain('sign-in-otp-otp@sonic.test')

    const otp = /letter-spacing:8px;color:#465FFF">(\d{6})</.exec(mails.at(-1) ?? '')?.[1]
    expect(otp).toMatch(/^\d{6}$/)
    const first = await req('POST', '/sign-in/email-otp', { body: { email: 'otp@sonic.test', otp } })
    expect(first.status, JSON.stringify(first.body)).toBe(200)
    expect(hasSession(first.cookies)).toBe(true)
    expect(verificationRows()).not.toContain('sign-in-otp-otp@sonic.test')

    const replay = await req('POST', '/sign-in/email-otp', { body: { email: 'otp@sonic.test', otp } })
    expect(replay.status).not.toBe(200)
    expect(hasSession(replay.cookies)).toBe(false)
    // Our KV storage warns if the non-atomic KV consume is ever reached.
    expect(warn.mock.calls.flat().join(' ')).not.toMatch(/getAndDelete was called/)
  })

  it('magic link: signs in once from D1 (cold KV) and rejects a replay', async () => {
    await signUp('link@sonic.test')
    const before = verificationRows().length
    const send = await req('POST', '/sign-in/magic-link', { body: { email: 'link@sonic.test', callbackURL: '/admin' } })
    expect(send.status, JSON.stringify(send.body)).toBe(200)
    const url = /href="([^"]+)"/.exec(mails.at(-1) ?? '')?.[1]?.replace(/&amp;/g, '&')
    expect(url).toBeTruthy()
    expect(verificationRows().length).toBe(before + 1)

    // Another edge location whose KV has not seen the write: verify must resolve from D1.
    for (const k of kvVerificationKeys()) kv.delete(k)
    const first = await req('GET', url!)
    expect(first.location ?? '').not.toMatch(/error=/)
    expect(hasSession(first.cookies), `verify: ${first.status} ${first.location}`).toBe(true)
    expect(verificationRows().length).toBe(before)

    const replay = await req('GET', url!)
    expect(hasSession(replay.cookies)).toBe(false)
    expect(replay.location ?? '').toMatch(/error=/)
  })

  it('verification values are written to D1, so a cold KV cannot lose them', async () => {
    await signUp('cold@sonic.test')
    await req('POST', '/email-otp/send-verification-otp', { body: { email: 'cold@sonic.test', type: 'sign-in' } })
    const otp = /letter-spacing:8px;color:#465FFF">(\d{6})</.exec(mails.at(-1) ?? '')?.[1]
    // Simulate another edge location whose KV has not seen the write.
    for (const k of kvVerificationKeys()) kv.delete(k)
    const res = await req('POST', '/sign-in/email-otp', { body: { email: 'cold@sonic.test', otp } })
    expect(res.status, JSON.stringify(res.body)).toBe(200)
    expect(hasSession(res.cookies)).toBe(true)
  })
})

describe('Better Auth 1.7 — organizations', () => {
  it('a signed-in user cannot create an organization (tenants belong to TenantService)', async () => {
    const cookies = await signUp('viewer@sonic.test')
    // `disabledPaths` would answer 404 first; clear it so this pins `allowUserToCreateOrganization`
    // on its own. The path-level layers are covered in better-auth-organization-routes.sqlite.test.ts.
    const res = await req('POST', '/organization/create', {
      body: { name: 'Acme', slug: 'acme', domain: 'acme.test' },
      cookies,
      extend: (o) => ({ ...o, disabledPaths: [] }),
    })
    expect(res.status, JSON.stringify(res.body)).toBe(403)
    expect(db.raw.prepare(`SELECT COUNT(*) AS n FROM auth_tenant`).get()).toEqual({ n: 0 })
  })

  it('a server-side organization write matches the schema (NOT NULL updated_at, tenantId mapping)', async () => {
    await signUp('owner@sonic.test')
    const { id: userId } = db.raw.prepare(`SELECT id FROM auth_user WHERE email = 'owner@sonic.test'`).get() as { id: string }
    await makeAuth().api.createOrganization({ body: { name: 'Acme', slug: 'acme', userId } })
    const tenant = db.raw.prepare(`SELECT id, updated_at FROM auth_tenant WHERE slug = 'acme'`).get() as {
      id: string
      updated_at: number
    }
    expect(tenant?.updated_at).toBeGreaterThan(0)
    const member = db.raw.prepare(`SELECT tenant_id, role FROM auth_tenant_member`).get() as { tenant_id: string; role: string }
    expect(member).toEqual({ tenant_id: tenant.id, role: 'owner' })
  })
})

describe('Better Auth 1.7 — rate limiting has a real store', () => {
  // Enabled explicitly: on Workers NODE_ENV is unset (off); the Docker image sets production (on).
  const enable: ExtendBetterAuth = (o) => ({ ...o, rateLimit: { ...o.rateLimit, enabled: true, window: 60, max: 3 } })

  it('limits across per-request auth instances instead of throwing on KV increment', async () => {
    await signUp('rl@sonic.test')
    const statuses: number[] = []
    for (let i = 0; i < 6; i++) {
      const r = await req('POST', '/sign-in/email', {
        body: { email: 'rl@sonic.test', password: 'wrong-password-123' },
        extend: enable,
      })
      statuses.push(r.status)
    }
    expect(statuses).not.toContain(500)
    expect(statuses).toContain(429)
  })
})

describe('GHSA-965c-763c-88jm — OAuth state is not a magic-link token', () => {
  const github = { GITHUB_CLIENT_ID: 'gh-client-id', GITHUB_CLIENT_SECRET: 'gh-client-secret' }

  it('does not sign an attacker in as the victim by redeeming an OAuth state', async () => {
    await signUp('victim@sonic.test')
    const start = await req('POST', '/sign-in/social', {
      body: { provider: 'github', callbackURL: '/admin', additionalData: { email: 'victim@sonic.test', name: 'x' } },
      env: github,
    })
    expect(start.status, JSON.stringify(start.body)).toBe(200)
    const state = new URL(start.body.url).searchParams.get('state')
    expect(state).toBeTruthy()

    const attempt = await req('GET', `/magic-link/verify?token=${encodeURIComponent(state!)}&callbackURL=%2Fadmin`, {
      env: github,
    })
    expect(hasSession(attempt.cookies), `takeover: ${attempt.status} ${attempt.location}`).toBe(false)
  })

  it('does not create a pre-verified account for an unknown address via an OAuth state', async () => {
    const start = await req('POST', '/sign-in/social', {
      body: { provider: 'github', callbackURL: '/admin', additionalData: { email: 'nobody@sonic.test', name: 'x' } },
      env: github,
    })
    const state = new URL(start.body.url).searchParams.get('state')
    await req('GET', `/magic-link/verify?token=${encodeURIComponent(state!)}&callbackURL=%2Fadmin`, { env: github })
    const row = db.raw.prepare(`SELECT id FROM auth_user WHERE email = 'nobody@sonic.test'`).get()
    expect(row).toBeUndefined()
  })
})
