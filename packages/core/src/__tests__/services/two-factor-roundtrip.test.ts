/**
 * The full second-factor round trip, driven through a REAL Better Auth instance over REAL
 * (better-sqlite3) D1: sign-up → sign-in → enable → verify-totp → sign-in → challenge → verify.
 *
 * ── Why this file exists ──
 * The donor commit this feature was ported from concluded that "better-auth cannot be driven below
 * E2E" — no `BETTER_AUTH_SECRET` in the harness, no KV, and `withCloudflare` needing a Workers `cf`
 * context. That conclusion was inherited into this port and it is **false**. All three are trivially
 * satisfiable, as the Infowall agent demonstrated independently:
 *
 *   - `BETTER_AUTH_SECRET` — just put it in the env object.
 *   - KV — `createKVStorage` uses only get/put/delete, so a Map is a complete substitute.
 *   - `cf` — `withCloudflare` only checks truthiness; `getDefaultAuthOptions` already passes `{}`.
 *
 * The one real blocker in THIS repo was the test D1 shim missing `Statement.raw()`, which drizzle's
 * D1 driver needs for the RETURNING clause on every adapter write. Added in `utils/d1-sqlite.ts`.
 *
 * It matters because the critical defect in this port — `auth_two_factor.created_at/updated_at`
 * declared NOT NULL with no default, so BA's own INSERT died and the UI reported it as a wrong
 * password — was invisible to every test that seeded rows by hand, and would have failed HERE on
 * the first assertion. Tests that assert on generated SQL and composed options prove the wiring;
 * only running the thing proves the feature.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createAuth } from '../../auth/config'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import { totpFromOtpauthUri } from '../utils/totp'
import type { Bindings } from '../../app'

const EMAIL = 'admin@roundtrip.test'
const PASSWORD = 'correct-horse-battery-staple'
const ORIGIN = 'https://sonic.test'

let db: TestD1
/** Map-backed KV. `createKVStorage` only ever calls get/put/delete. */
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

/** POST a JSON body to a BA endpoint, forwarding cookies in and collecting them out. */
async function call(
  path: string,
  body: unknown,
  cookies: string[] = [],
): Promise<{ status: number; body: any; cookies: string[] }> {
  const auth = makeAuth()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Origin: ORIGIN,
  }
  if (cookies.length) headers.Cookie = cookies.map((c) => c.split(';')[0]).join('; ')
  const res = await auth.handler(
    new Request(`${ORIGIN}/auth${path}`, { method: 'POST', headers, body: JSON.stringify(body) }),
  )
  const setCookie =
    (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? []
  return {
    status: res.status,
    body: await res.json().catch(() => null),
    cookies: setCookie,
  }
}

/** True when a Set-Cookie list contains a live (non-cleared) BA session cookie. */
function hasSession(cookies: string[]): boolean {
  return cookies.some(
    (c) => c.includes('better-auth.session_token=') && !/session_token=;/.test(c) && !/Max-Age=0/.test(c),
  )
}

/** Merge two cookie jars, later values winning. */
function mergeCookies(a: string[], b: string[]): string[] {
  const jar = new Map<string, string>()
  for (const c of [...a, ...b]) jar.set(c.split('=')[0]!, c)
  return [...jar.values()]
}

/** Sign up (first user is always allowed) and return the resulting cookie jar. */
async function signUp() {
  const res = await call('/sign-up/email', { email: EMAIL, password: PASSWORD, name: 'Admin User' })
  expect(res.status, `sign-up failed: ${JSON.stringify(res.body)}`).toBe(200)
  return res.cookies
}

beforeEach(() => {
  db = createTestD1()
  kv = new Map()
  // The user-create `after` hook seeds RBAC documents; noisy but non-fatal on this harness.
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
})

afterEach(() => {
  db.close()
  vi.restoreAllMocks()
})

describe('two-factor round trip against real Better Auth', () => {
  it('enrols, then challenges the next password sign-in, then verifies with a live code', async () => {
    // ── 1. Account exists and password sign-in works with no second factor ──────────────
    await signUp()
    const first = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    expect(first.status).toBe(200)
    expect(first.body?.twoFactorRedirect).toBeUndefined()
    expect(hasSession(first.cookies)).toBe(true)

    // ── 2. Enable — this is the call that the NOT NULL defect made impossible ───────────
    const enable = await call('/two-factor/enable', { password: PASSWORD }, first.cookies)
    expect(enable.status, `enable failed: ${JSON.stringify(enable.body)}`).toBe(200)
    const totpUri: string = enable.body.totpURI
    expect(totpUri).toMatch(/^otpauth:\/\/totp\//)
    expect(Array.isArray(enable.body.backupCodes)).toBe(true)
    expect(enable.body.backupCodes.length).toBe(10)

    // The row BA wrote — assert on storage, not on the mapping we asked it to resolve.
    const row = db.raw
      .prepare(`SELECT user_id, verified, failed_verification_count, locked_until, created_at FROM auth_two_factor`)
      .get() as { user_id: string; verified: number; failed_verification_count: number; locked_until: number | null; created_at: number }
    expect(row).toBeTruthy()
    expect(row.verified).toBe(0) // not proven yet
    expect(row.failed_verification_count).toBe(0)
    expect(row.locked_until).toBeNull()
    expect(row.created_at).toBeGreaterThan(0) // the defect: this used to be an unsatisfiable NULL

    // ── 3. Confirm with a live code ────────────────────────────────────────────────────
    const confirm = await call(
      '/two-factor/verify-totp',
      { code: await totpFromOtpauthUri(totpUri) },
      first.cookies,
    )
    expect(confirm.status, `verify-totp failed: ${JSON.stringify(confirm.body)}`).toBe(200)
    expect(
      (db.raw.prepare(`SELECT verified AS v FROM auth_two_factor`).get() as { v: number }).v,
    ).toBe(1)
    expect(
      (db.raw.prepare(`SELECT two_factor_enabled AS e FROM auth_user`).get() as { e: number }).e,
    ).toBe(1)

    // ── 4. The password alone is no longer enough ───────────────────────────────────────
    const second = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    expect(second.status).toBe(200) // 200, not 401 — the password was correct
    expect(second.body).toMatchObject({ twoFactorRedirect: true })
    expect(second.body.user).toBeUndefined()
    expect(second.body.token).toBeUndefined()
    expect(hasSession(second.cookies)).toBe(false)

    // ── 5. The challenge resolves into a session ────────────────────────────────────────
    const challenge = await call(
      '/two-factor/verify-totp',
      { code: await totpFromOtpauthUri(totpUri) },
      second.cookies,
    )
    expect(challenge.status, `challenge failed: ${JSON.stringify(challenge.body)}`).toBe(200)
    expect(hasSession(challenge.cookies)).toBe(true)
  })

  it('accepts a backup code at the challenge, and spends it', async () => {
    const session = await signUp()
    const enable = await call('/two-factor/enable', { password: PASSWORD }, session)
    const totpUri: string = enable.body.totpURI
    const backupCodes: string[] = enable.body.backupCodes
    await call('/two-factor/verify-totp', { code: await totpFromOtpauthUri(totpUri) }, session)

    const challenged = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    expect(challenged.body).toMatchObject({ twoFactorRedirect: true })

    const used = await call('/two-factor/verify-backup-code', { code: backupCodes[0]! }, challenged.cookies)
    expect(used.status, `backup code rejected: ${JSON.stringify(used.body)}`).toBe(200)
    expect(hasSession(used.cookies)).toBe(true)

    // Single-use: the same code must not resolve a second challenge.
    const again = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    const reuse = await call('/two-factor/verify-backup-code', { code: backupCodes[0]! }, again.cookies)
    expect(reuse.status).not.toBe(200)
    expect(hasSession(reuse.cookies)).toBe(false)
  })

  it('rejects a wrong code and counts it against the per-account lockout', async () => {
    const session = await signUp()
    const enable = await call('/two-factor/enable', { password: PASSWORD }, session)
    await call('/two-factor/verify-totp', { code: await totpFromOtpauthUri(enable.body.totpURI) }, session)

    const challenged = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    const bad = await call('/two-factor/verify-totp', { code: '000000' }, challenged.cookies)
    expect(bad.status).not.toBe(200)
    expect(hasSession(bad.cookies)).toBe(false)

    // The lockout counter is the control that actually bounds guessing (BA rate limiting is off —
    // see the note in auth/config.ts), so prove the increment reaches the column.
    const count = (
      db.raw.prepare(`SELECT failed_verification_count AS n FROM auth_two_factor`).get() as { n: number }
    ).n
    expect(count).toBeGreaterThanOrEqual(1)
  })

  it('does NOT honour trustDevice — the 30-day bypass stays closed', async () => {
    // Break-it proof for `trustDeviceMaxAge: 0` in auth/config.ts. Remove that line and this test
    // goes red: the second sign-in returns a session instead of a challenge, which is precisely the
    // bypass. Asserting `options.trustDeviceMaxAge === undefined` — the intuitive thing to write —
    // would have LOCKED IN the bug, because BA reads `?? 2592e3`.
    const session = await signUp()
    const enable = await call('/two-factor/enable', { password: PASSWORD }, session)
    const totpUri: string = enable.body.totpURI
    await call('/two-factor/verify-totp', { code: await totpFromOtpauthUri(totpUri) }, session)

    const challenged = await call('/sign-in/email', { email: EMAIL, password: PASSWORD })
    expect(challenged.body).toMatchObject({ twoFactorRedirect: true })

    // Ask to be trusted, exactly as a hand-rolled client could.
    const trusted = await call(
      '/two-factor/verify-totp',
      { code: await totpFromOtpauthUri(totpUri), trustDevice: true },
      challenged.cookies,
    )
    expect(trusted.status).toBe(200)
    expect(hasSession(trusted.cookies)).toBe(true)

    // Sign in again carrying every cookie BA just set, including any trust cookie.
    const after = await call(
      '/sign-in/email',
      { email: EMAIL, password: PASSWORD },
      mergeCookies(challenged.cookies, trusted.cookies),
    )
    expect(after.body, 'trustDevice bought a password-only sign-in').toMatchObject({
      twoFactorRedirect: true,
    })
    expect(hasSession(after.cookies)).toBe(false)
  })
})

describe('the shared TOTP helper produces codes Better Auth accepts', () => {
  it('verifies against BA, which is what de-risks the E2E spec', async () => {
    // tests/e2e/106-two-factor-auth.spec.ts imports this same function. If it drifted — most
    // likely by handing BA the base32 URI value instead of the decoded secret — the browser round
    // trip would fail in CI with a 401 indistinguishable from a real product bug.
    const session = await signUp()
    const enable = await call('/two-factor/enable', { password: PASSWORD }, session)
    const code = await totpFromOtpauthUri(enable.body.totpURI)
    expect(code).toMatch(/^\d{6}$/)
    const res = await call('/two-factor/verify-totp', { code }, session)
    expect(res.status, `BA rejected our computed code (${code})`).toBe(200)
  })

  it('a code from the previous step no longer verifies, proving it is time-based', async () => {
    const session = await signUp()
    const enable = await call('/two-factor/enable', { password: PASSWORD }, session)
    // Two full periods back is outside BA's tolerance window.
    const stale = await totpFromOtpauthUri(enable.body.totpURI, Date.now() - 90_000)
    const res = await call('/two-factor/verify-totp', { code: stale }, session)
    expect(res.status).not.toBe(200)
  })
})
