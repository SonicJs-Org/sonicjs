/**
 * The `twoFactorRedirect` branch in both login handlers.
 *
 * Better Auth answers a pending second factor with HTTP **200** and `{twoFactorRedirect:true}` —
 * no `user`, no `token`, and it deletes the session it had just created. Both SonicJS login
 * handlers read BA's outcome through `if (!baRes.ok)`, so before this branch existed a CORRECT
 * password fell straight through into the success path:
 *
 *   POST /auth/login       → minted a JWT from `baBody.user ?? {}`, i.e.
 *                            generateToken(undefined, undefined, 'viewer') — a signed token for
 *                            a principal that does not exist, set as `auth_token` AND returned
 *                            as `token`. app.ts's Bearer-JWT fallback then populates
 *                            c.get('user') = {userId: undefined}, which requireAuth() accepts.
 *   POST /auth/login/form  → reported "Login successful! Redirecting…" and sent the browser to
 *                            /admin/content with no session, bouncing back to login.
 *
 * These tests drive the real handlers with `createAuth` replaced by a stub that reproduces BA's
 * three outcomes.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'

/** What the stubbed BA handler should answer on /auth/sign-in/email. */
let baOutcome: 'twoFactorRedirect' | 'success' | 'failure' = 'twoFactorRedirect'

const generateToken = vi.fn(async () => 'signed.jwt.token')

vi.mock('../../auth/config', () => ({
  createAuth: () => ({
    handler: async () => {
      if (baOutcome === 'failure') {
        return new Response(JSON.stringify({ message: 'Invalid email or password' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (baOutcome === 'twoFactorRedirect') {
        // The real shape: 200, a challenge cookie, and no user/token.
        return new Response(JSON.stringify({ twoFactorRedirect: true, twoFactorMethods: ['totp'] }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': 'better-auth.two_factor=chal; Path=/; HttpOnly',
          },
        })
      }
      return new Response(
        JSON.stringify({ user: { id: 'u1', email: 'a@test.local', role: 'admin', name: 'A B' }, token: 'ba-token' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    },
  }),
}))

vi.mock('../../middleware', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>
  return {
    ...actual,
    requireAuth: () => async (_c: unknown, next: () => Promise<void>) => next(),
    AuthManager: { ...(actual.AuthManager as object), generateToken },
  }
})

// The security-audit / logging / lockout helpers all reach for D1; the stub DB below answers
// enough for the handler to run, and none of it is what these tests assert.
function stubDb() {
  const stmt = {
    bind: () => stmt,
    first: async () => null,
    all: async () => ({ results: [] }),
    run: async () => ({ success: true }),
  }
  return { prepare: () => stmt, batch: async () => [] }
}

async function post(path: string, body: Record<string, string>, htmx = false) {
  const { default: authRoutes } = await import('../../routes/auth')
  const app = new Hono()
  app.route('/auth', authRoutes as never)

  const isForm = path.endsWith('/form')
  const headers: Record<string, string> = isForm
    ? {}
    : { 'Content-Type': 'application/json' }
  if (htmx) headers['HX-Request'] = 'true'

  let payload: BodyInit
  if (isForm) {
    const fd = new FormData()
    for (const [k, v] of Object.entries(body)) fd.append(k, v)
    payload = fd
  } else {
    payload = JSON.stringify(body)
  }

  return app.request(
    path,
    { method: 'POST', headers, body: payload },
    { DB: stubDb(), JWT_SECRET: 'test-secret-value-32-chars-long!!', CACHE_KV: undefined },
  )
}

const CREDS = { email: 'a@test.local', password: 'correct-horse-battery' }

beforeEach(() => {
  vi.clearAllMocks()
  baOutcome = 'twoFactorRedirect'
})

describe('POST /auth/login — second factor pending', () => {
  it('answers 200 with twoFactorRequired, not 401', async () => {
    const res = await post('/auth/login', CREDS)
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({
      twoFactorRequired: true,
      twoFactorMethods: ['totp'],
      redirectTo: '/auth/two-factor',
    })
  })

  it('mints NO token — the whole point of the branch', async () => {
    const res = await post('/auth/login', CREDS)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.token).toBeUndefined()
    expect(body.user).toBeUndefined()
    expect(generateToken).not.toHaveBeenCalled()
  })

  it('sets no auth_token cookie', async () => {
    const res = await post('/auth/login', CREDS)
    const cookies = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? []
    expect(cookies.some((c) => c.startsWith('auth_token='))).toBe(false)
  })

  it('forwards BA\'s challenge cookie, which verify-totp needs', async () => {
    const res = await post('/auth/login', CREDS)
    const cookies = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? []
    expect(cookies.some((c) => c.includes('better-auth.two_factor='))).toBe(true)
  })

  it('still mints a token on a plain successful sign-in', async () => {
    baOutcome = 'success'
    const res = await post('/auth/login', CREDS)
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ token: 'signed.jwt.token' })
    expect(generateToken).toHaveBeenCalledWith('u1', 'a@test.local', 'admin', expect.anything(), expect.anything())
  })

  it('still 401s a genuinely bad password', async () => {
    baOutcome = 'failure'
    const res = await post('/auth/login', CREDS)
    expect(res.status).toBe(401)
    expect(generateToken).not.toHaveBeenCalled()
  })
})

describe('POST /auth/login/form — second factor pending', () => {
  it('sends the browser to the challenge page, not to /admin/content', async () => {
    const html = await (await post('/auth/login/form', CREDS)).text()
    expect(html).toContain("window.location.href = '/auth/two-factor'")
    expect(html).not.toContain('/admin/content')
  })

  it('does not claim the login succeeded', async () => {
    const html = await (await post('/auth/login/form', CREDS)).text()
    expect(html).not.toMatch(/Login successful/i)
    expect(html).toMatch(/two-step verification/i)
  })

  it('uses HX-Redirect for an HTMX submit', async () => {
    const res = await post('/auth/login/form', CREDS, true)
    expect(res.headers.get('HX-Redirect')).toBe('/auth/two-factor')
  })

  it('still redirects to /admin/content on a plain successful sign-in', async () => {
    baOutcome = 'success'
    const res = await post('/auth/login/form', CREDS, true)
    expect(res.headers.get('HX-Redirect')).toBe('/admin/content')
  })
})
