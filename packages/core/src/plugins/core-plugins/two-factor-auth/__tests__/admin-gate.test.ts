/**
 * Gate tests for the plugin's two mounts, against a real (SQLite) D1 and live requests through
 * the actual sub-apps.
 *
 * The two mounts are deliberately asymmetric, and that asymmetry is the thing most likely to be
 * "tidied up" by a later reader — so both directions are pinned here:
 *
 *   /admin/two-factor  → requireAuth + deactivate→404
 *   /auth/two-factor   → NO auth, NO plugin gate (a gated challenge page would strand every
 *                        enrolled user mid-login, because BA has already deleted the session
 *                        cookie by the time the challenge is issued)
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { twoFactorAdminRoutes, twoFactorChallengeRoutes } from '../routes'
import { TWO_FACTOR_PLUGIN_ID } from '../../../../auth/two-factor-settings'
import { invalidatePluginStatusCache } from '../../../../middleware/plugin-middleware'
import { createTestD1, type TestD1 } from '../../../../__tests__/utils/d1-sqlite'

let db: TestD1

const ADMIN = { userId: 'u1', email: 'admin@test.local', role: 'admin' }
const VIEWER = { userId: 'u2', email: 'viewer@test.local', role: 'viewer' }

function seedStatus(status: 'active' | 'inactive') {
  db.raw
    .prepare(
      `INSERT INTO documents (id, root_id, type_id, slug, tenant_id, is_current_draft, data)
       VALUES (?, ?, 'plugin', ?, 'default', 1, ?)`,
    )
    .run('doc-2fa', 'root-2fa', TWO_FACTOR_PLUGIN_ID, JSON.stringify({ status }))
}

function seedEnrolment(userId: string, verified: 0 | 1) {
  db.raw
    .prepare(
      `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, verified, created_at, updated_at)
       VALUES (?, 'enc', 'enc', ?, ?, 0, 0)`,
    )
    .run(`tf-${userId}`, userId, verified)
}

function request(
  mount: 'admin' | 'challenge',
  path: string,
  opts: { user?: typeof ADMIN; accept?: string } = {},
) {
  const app = new Hono<{ Bindings: { DB: unknown }; Variables: { user?: typeof ADMIN } }>()
  app.use('*', async (c, next) => {
    if (opts.user) c.set('user', opts.user)
    await next()
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test env binding
  const routes = (mount === 'admin' ? twoFactorAdminRoutes : twoFactorChallengeRoutes) as any
  app.route(mount === 'admin' ? '/admin/two-factor' : '/auth/two-factor', routes)
  return app.request(path, { headers: opts.accept ? { Accept: opts.accept } : {} }, { DB: db })
}

/** POST through the challenge mount, returning the response plus its Set-Cookie list. */
async function requestPost(
  path: string,
  opts: { user?: typeof ADMIN; accept?: string } = {},
  body: Record<string, unknown> = {},
) {
  const app = new Hono<{ Bindings: { DB: unknown }; Variables: { user?: typeof ADMIN } }>()
  app.use('*', async (c, next) => {
    if (opts.user) c.set('user', opts.user)
    await next()
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test env binding
  app.route('/auth/two-factor', twoFactorChallengeRoutes as any)
  const res = await app.request(
    path,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(opts.accept ? { Accept: opts.accept } : {}) },
      body: JSON.stringify(body),
    },
    { DB: db, JWT_SECRET: 'test-secret-value-32-chars-long!!', ENVIRONMENT: 'development' },
  )
  const cookies = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? []
  return { status: res.status, cookies }
}

beforeEach(() => {
  db = createTestD1()
  invalidatePluginStatusCache(TWO_FACTOR_PLUGIN_ID)
})

afterEach(() => {
  db.close()
  invalidatePluginStatusCache(TWO_FACTOR_PLUGIN_ID)
})

describe('two-factor enrolment page gate (/admin/two-factor)', () => {
  it('404s when the plugin has no row at all', async () => {
    const res = await request('admin', '/admin/two-factor', { user: ADMIN })
    expect(res.status).toBe(404)
  })

  it('404s when the plugin row is explicitly inactive', async () => {
    seedStatus('inactive')
    const res = await request('admin', '/admin/two-factor', { user: ADMIN })
    expect(res.status).toBe(404)
  })

  it('401s an unauthenticated request — the auth gate runs before the plugin gate', async () => {
    seedStatus('active')
    const res = await request('admin', '/admin/two-factor', { accept: 'application/json' })
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: 'Authentication required' })
  })

  it('serves the page to any authenticated role — enrolment is self-service, not admin-only', async () => {
    seedStatus('active')
    const res = await request('admin', '/admin/two-factor', { user: VIEWER })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('Two-Factor Authentication')
  })

  it('renders the "off" state with the setup form when there is no enrolment', async () => {
    seedStatus('active')
    const html = await (await request('admin', '/admin/two-factor', { user: ADMIN })).text()
    expect(html).toContain('id="enrolForm"')
    expect(html).toContain('>Disabled<')
    // The "on" panel exists in the DOM but must start hidden.
    expect(html).toMatch(/id="state-on" class="hidden/)
  })

  it('renders the "started, not confirmed" state for verified = 0, and says what to do', async () => {
    // The status label alone would leave a user staring at a "Begin setup" button with no
    // indication that pressing it discards the half-finished enrolment (BA's /enable deletes and
    // recreates the row), or that 2FA is not actually protecting them yet.
    seedStatus('active')
    seedEnrolment(ADMIN.userId, 0)
    const html = await (await request('admin', '/admin/two-factor', { user: ADMIN })).text()
    expect(html).toContain('Started, not confirmed')
    expect(html).toMatch(/never confirmed with a live code/)
    expect(html).toMatch(/discards the unconfirmed one/)
  })

  it('renders the "on" state for verified = 1, with the setup form hidden', async () => {
    seedStatus('active')
    seedEnrolment(ADMIN.userId, 1)
    const html = await (await request('admin', '/admin/two-factor', { user: ADMIN })).text()
    expect(html).toContain('>Enabled<')
    expect(html).toMatch(/id="state-off" class="hidden/)
    expect(html).toContain('id="disableForm"')
  })

  it('does not leak another user\'s enrolment into this user\'s page', async () => {
    seedStatus('active')
    seedEnrolment(VIEWER.userId, 1)
    const html = await (await request('admin', '/admin/two-factor', { user: ADMIN })).text()
    expect(html).toContain('>Disabled<')
  })

  it('tells the user that enrolling disables the emailed sign-in paths', async () => {
    // Not decoration: passwordless-second-factor-guard.ts really does refuse magic links for
    // enrolled accounts, and a user who found that out by having links stop arriving would
    // reasonably file it as a bug.
    seedStatus('active')
    const html = await (await request('admin', '/admin/two-factor', { user: ADMIN })).text()
    expect(html).toMatch(/magic links and emailed sign-in codes are\s+disabled/)
  })
})

describe('two-factor challenge page (/auth/two-factor)', () => {
  it('serves unauthenticated — the caller has no session by construction', async () => {
    const res = await request('challenge', '/auth/two-factor')
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('Two-step verification')
  })

  it('serves even when the plugin is deactivated, so enrolled users are never stranded', async () => {
    seedStatus('inactive')
    const res = await request('challenge', '/auth/two-factor')
    expect(res.status).toBe(200)
  })

  it('offers backup-code entry unconditionally', async () => {
    // BA's twoFactorMethods only ever contains 'totp'/'otp' — never 'backup_code'. Keying the
    // UI off that list would hide this form exactly when the device is lost.
    const html = await (await request('challenge', '/auth/two-factor')).text()
    expect(html).toContain('id="backupForm"')
    expect(html).toContain('verify-backup-code')
  })

  it('posts to the Better Auth mount, not to /api/auth (the sibling port\'s basePath)', async () => {
    const html = await (await request('challenge', '/auth/two-factor')).text()
    expect(html).toContain("'/auth/two-factor/' + path")
    expect(html).not.toContain('/api/auth/')
  })

  it('sends the CSRF double-submit header on every verify POST', async () => {
    const html = await (await request('challenge', '/auth/two-factor')).text()
    expect(html).toContain("'X-CSRF-Token': csrf()")
  })

  it('upgrades the session via /complete before navigating', async () => {
    // Without this call the post-2FA browser holds only better-auth.session_token, and
    // csrfProtection exempts any request with no auth_token cookie — so CSRF validation would be
    // silently off for the whole session of every 2FA user.
    const html = await (await request('challenge', '/auth/two-factor')).text()
    expect(html).toContain("post('complete', {})")
    expect(html.indexOf("post('complete', {})")).toBeLessThan(html.indexOf("window.location.href = '/admin/content'"))
  })
})

describe('POST /auth/two-factor/complete', () => {
  it('mints a Strict auth_token for a user who holds a verified second factor', async () => {
    seedEnrolment(ADMIN.userId, 1)
    const res = await requestPost('/auth/two-factor/complete', { user: ADMIN })
    expect(res.status).toBe(200)
    const setCookie = res.cookies.find((c) => c.startsWith('auth_token='))
    expect(setCookie).toBeTruthy()
    expect(setCookie).toContain('HttpOnly')
    expect(setCookie).toContain('SameSite=Strict')
  })

  it('401s an unauthenticated caller', async () => {
    const res = await requestPost('/auth/two-factor/complete', { accept: 'application/json' })
    expect(res.status).toBe(401)
    expect(res.cookies.some((c) => c.startsWith('auth_token='))).toBe(false)
  })

  it('refuses a user with no verified second factor — nothing was challenged', async () => {
    const res = await requestPost('/auth/two-factor/complete', { user: ADMIN })
    expect(res.status).toBe(400)
    expect(res.cookies.some((c) => c.startsWith('auth_token='))).toBe(false)
  })

  it('refuses a user whose enrolment is unconfirmed', async () => {
    seedEnrolment(ADMIN.userId, 0)
    const res = await requestPost('/auth/two-factor/complete', { user: ADMIN })
    expect(res.status).toBe(400)
  })

  it('derives the JWT subject from the session, never from the request body', async () => {
    seedEnrolment(ADMIN.userId, 1)
    const res = await requestPost(
      '/auth/two-factor/complete',
      { user: ADMIN },
      { userId: 'someone-else', role: 'admin' },
    )
    expect(res.status).toBe(200)
    const token = res.cookies.find((c) => c.startsWith('auth_token='))!.split('=')[1]!.split(';')[0]!
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString(),
    ) as { userId: string; email: string }
    expect(payload.userId).toBe(ADMIN.userId)
    expect(payload.email).toBe(ADMIN.email)
  })
})
