/**
 * The OAuth callback mints a session cookie itself, without going through Better Auth — so BA's
 * second-factor challenge never runs on this path and the gate has to be explicit.
 *
 * Both branches that can produce a session for a PRE-EXISTING local account are covered:
 *
 *   - `existingOAuth` — the provider is already linked to the account.
 *   - the auto-link branch — no link yet, but the provider's email matches a local user, so the
 *     callback links it on the spot.
 *
 * Neither may hand out a cookie while the account has a verified second factor, because that is
 * exactly the promise the enrolment page makes ("you'll be asked for a code on every sign-in").
 * The third branch (brand-new user) cannot be enrolled by definition and is not covered here.
 *
 * Everything the provider would answer is stubbed at `OAuthService`; the parts under test — the
 * `auth_user` read, `hasVerifiedSecondFactor`, and which redirect comes back — run for real
 * against SQLite.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { oauthProvidersPlugin } from '../../plugins/core-plugins/oauth-providers'
import { OAuthService } from '../../plugins/core-plugins/oauth-providers/oauth-service'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

let db: TestD1

const USER = { id: 'user-1', email: 'victim@test.local', role: 'admin' }
const STATE = 'state-token'

/**
 * `plugins` is not in the greenfield migrations — the OAuth plugin reads its credentials from a
 * legacy table. Created here so `loadSettings` finds enabled provider credentials; without them
 * the callback short-circuits before reaching anything under test.
 */
function seedPluginSettings() {
  db.raw.exec(`CREATE TABLE IF NOT EXISTS plugins (id TEXT PRIMARY KEY, settings TEXT)`)
  db.raw
    .prepare(`INSERT INTO plugins (id, settings) VALUES ('oauth-providers', ?)`)
    .run(
      JSON.stringify({
        providers: { github: { enabled: true, clientId: 'cid', clientSecret: 'secret' } },
      }),
    )
}

function seedUser(isActive = 1) {
  db.raw
    .prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, role, is_active, created_at, updated_at)
       VALUES (?, ?, 'V', 'C', ?, ?, 0, 0)`,
    )
    .run(USER.id, USER.email, USER.role, isActive)
}

function seedEnrolment(verified: 0 | 1) {
  db.raw
    .prepare(
      `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, verified, created_at, updated_at)
       VALUES ('tf-1', 'enc', 'enc', ?, ?, 0, 0)`,
    )
    .run(USER.id, verified)
}

/** Stub the provider round trip. `linked` decides which callback branch the request lands in. */
function stubProvider(linked: boolean) {
  vi.spyOn(OAuthService.prototype, 'exchangeCode').mockResolvedValue({
    access_token: 'at',
    refresh_token: 'rt',
    expires_in: 3600,
  } as never)
  vi.spyOn(OAuthService.prototype, 'fetchUserProfile').mockResolvedValue({
    providerAccountId: 'gh-1',
    email: USER.email,
    name: 'Victim',
  } as never)
  vi.spyOn(OAuthService.prototype, 'findOAuthAccount').mockResolvedValue(
    linked ? ({ id: 'oa-1', user_id: USER.id } as never) : null,
  )
  vi.spyOn(OAuthService.prototype, 'updateOAuthTokens').mockResolvedValue(undefined as never)
  vi.spyOn(OAuthService.prototype, 'findUserByEmail').mockResolvedValue({
    id: USER.id,
    email: USER.email,
    role: USER.role,
    is_active: 1,
  } as never)
  vi.spyOn(OAuthService.prototype, 'createOAuthAccount').mockResolvedValue(undefined as never)
}

function callback() {
  const app = new Hono()
  oauthProvidersPlugin.register?.(app as never)
  return app.request(
    `/auth/oauth/github/callback?code=abc&state=${STATE}`,
    { headers: { Cookie: `oauth_state=${STATE}`, host: 'test.local' } },
    { DB: db, JWT_SECRET: 'test-secret' },
  )
}

beforeEach(() => {
  db = createTestD1()
  seedPluginSettings()
  seedUser()
})

afterEach(() => {
  vi.restoreAllMocks()
  db.close()
})

describe('OAuth callback — already-linked provider', () => {
  beforeEach(() => stubProvider(true))

  it('refuses to mint a session for an account with a verified second factor', async () => {
    seedEnrolment(1)
    const res = await callback()

    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/auth/login?error=')
    expect(decodeURIComponent(res.headers.get('location') ?? '')).toContain(
      'two-factor authentication',
    )
    // The actual failure this guards against: a usable cookie handed out anyway.
    expect(res.headers.get('set-cookie') ?? '').not.toContain('auth_token=')
  })

  it('signs in normally when the enrolment was never completed', async () => {
    // verified = 0 is a half-finished setup. Better Auth does not challenge on it, so refusing
    // here would lock the user out of an account nothing is actually protecting.
    seedEnrolment(0)
    const res = await callback()

    expect(res.headers.get('location')).toBe('/admin')
    expect(res.headers.get('set-cookie') ?? '').toContain('auth_token=')
  })

  it('signs in normally when the user is not enrolled at all', async () => {
    const res = await callback()

    expect(res.headers.get('location')).toBe('/admin')
    expect(res.headers.get('set-cookie') ?? '').toContain('auth_token=')
  })

  it('still refuses a deactivated account before looking at the second factor', async () => {
    db.raw.prepare(`UPDATE auth_user SET is_active = 0 WHERE id = ?`).run(USER.id)
    const res = await callback()

    expect(decodeURIComponent(res.headers.get('location') ?? '')).toContain('deactivated')
  })
})

describe('OAuth callback — auto-link by email', () => {
  beforeEach(() => stubProvider(false))

  it('refuses to link and sign in when the account has a verified second factor', async () => {
    seedEnrolment(1)
    const res = await callback()

    expect(decodeURIComponent(res.headers.get('location') ?? '')).toContain(
      'two-factor authentication',
    )
    expect(res.headers.get('set-cookie') ?? '').not.toContain('auth_token=')
    // Nothing was linked either — a refused sign-in must not leave the provider attached.
    expect(OAuthService.prototype.createOAuthAccount).not.toHaveBeenCalled()
  })

  it('links and signs in when the user is not enrolled', async () => {
    const res = await callback()

    expect(res.headers.get('location')).toBe('/admin')
    expect(OAuthService.prototype.createOAuthAccount).toHaveBeenCalled()
  })
})
