/**
 * Administrative two-factor reset, against a real (SQLite) D1 and live requests through the
 * actual sub-app.
 *
 * This is the break-glass path — the only thing standing between a lost phone and a Cloudflare
 * credentials incident — so the tests here are deliberately about SQL effects and gate behavior
 * rather than shapes. A mock DB would pass every one of them while the UPDATE silently touched
 * no rows (R10).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import {
  twoFactorRecoveryRoutes,
  resetUserTwoFactor,
  owesTwoFactorEnrolment,
  enforceTwoFactorEnrolment,
  guardRequiredSecondFactorDisable,
  isTwoFactorRequired,
  ENROLMENT_PATH,
} from '../recovery'
import { TWO_FACTOR_PLUGIN_ID } from '../../../../auth/two-factor-settings'
import { invalidatePluginStatusCache } from '../../../../middleware/plugin-middleware'
import { ensureTwoFactorRequiredColumn } from '../../../../services/migrations'
import { createTestD1, type TestD1 } from '../../../../__tests__/utils/d1-sqlite'

let db: TestD1

const ADMIN = { userId: 'admin-1', email: 'admin@test.local', role: 'admin' }
const EDITOR = { userId: 'editor-1', email: 'editor@test.local', role: 'editor' }
const TARGET = { userId: 'user-1', email: 'locked.out@test.local', role: 'editor' }

function seedUser(u: { userId: string; email: string; role: string }, twoFactorEnabled = 0) {
  db.raw
    .prepare(
      `INSERT INTO auth_user (id, email, email_verified, created_at, updated_at,
                              first_name, last_name, role, two_factor_enabled)
       VALUES (?, ?, 1, 0, 0, 'Test', 'User', ?, ?)`,
    )
    .run(u.userId, u.email, u.role, twoFactorEnabled)
}

/** A completed enrolment, plus a live lockout — the state a locked-out user is actually in. */
function seedEnrolment(userId: string, verified: 0 | 1 = 1, lockedUntil: number | null = null) {
  db.raw
    .prepare(
      `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, verified, created_at,
                                    updated_at, failed_verification_count, locked_until)
       VALUES (?, 'enc', 'enc', ?, ?, 0, 0, 5, ?)`,
    )
    .run(`tf-${userId}`, userId, verified, lockedUntil)
}

function seedPluginStatus(status: 'active' | 'inactive') {
  db.raw
    .prepare(
      `INSERT INTO documents (id, root_id, type_id, slug, tenant_id, is_current_draft, data)
       VALUES (?, ?, 'plugin', ?, 'default', 1, ?)`,
    )
    .run('doc-2fa', 'root-2fa', TWO_FACTOR_PLUGIN_ID, JSON.stringify({ status }))
}

function readUser(userId: string) {
  return db.raw
    .prepare(`SELECT two_factor_enabled AS enabled, two_factor_required AS required
                FROM auth_user WHERE id = ?`)
    .get(userId) as { enabled: number; required: number } | undefined
}

/** POST through the real sub-app with `user` pre-set, the way requireAuth would leave it. */
function postReset(body: unknown, user?: typeof ADMIN) {
  const app = new Hono<{ Bindings: { DB: unknown }; Variables: { user?: typeof ADMIN } }>()
  app.use('*', async (c, next) => {
    if (user) c.set('user', user)
    await next()
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test env binding
  app.route('/admin/two-factor-reset', twoFactorRecoveryRoutes as any)
  return app.request(
    '/admin/two-factor-reset',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
    { DB: db },
  )
}

/** Drive the enforcement middleware in front of a trivial handler. */
function requestGuarded(path: string, user?: typeof ADMIN, accept = 'text/html') {
  const app = new Hono<{ Bindings: { DB: unknown }; Variables: { user?: typeof ADMIN } }>()
  app.use('*', async (c, next) => {
    if (user) c.set('user', user)
    await next()
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test env binding
  app.use('/admin/*', enforceTwoFactorEnrolment() as any)
  app.get('/admin/*', (c) => c.text('reached the handler'))
  return app.request(path, { headers: { Accept: accept } }, { DB: db })
}

beforeEach(() => {
  db = createTestD1()
  invalidatePluginStatusCache(TWO_FACTOR_PLUGIN_ID)
  seedUser(ADMIN)
  seedUser(EDITOR)
})

afterEach(() => {
  db.close()
  invalidatePluginStatusCache(TWO_FACTOR_PLUGIN_ID)
})

describe('resetUserTwoFactor — the SQL effect', () => {
  beforeEach(() => {
    seedUser(TARGET, 1)
    seedEnrolment(TARGET.userId, 1, Date.now() + 900_000)
  })

  it('destroys the enrolment and clears the user flag together', async () => {
    await resetUserTwoFactor(db as never, TARGET.userId, true)

    const enrolment = db.raw
      .prepare(`SELECT 1 FROM auth_two_factor WHERE user_id = ?`)
      .get(TARGET.userId)
    expect(enrolment).toBeUndefined()
    // Both halves, because either one alone is a broken state: an orphaned enabled=1 makes the
    // UI claim a protection that no longer exists.
    expect(readUser(TARGET.userId)).toEqual({ enabled: 0, required: 1 })
  })

  it('clears an active lockout as a side effect of deleting the row', async () => {
    // failed_verification_count and locked_until live on auth_two_factor (migration 0006), so
    // the DELETE is also the lockout fix. If those columns ever move to auth_user, this test is
    // what should fail.
    await resetUserTwoFactor(db as never, TARGET.userId, true)
    const locked = db.raw
      .prepare(`SELECT locked_until FROM auth_two_factor WHERE user_id = ?`)
      .get(TARGET.userId)
    expect(locked).toBeUndefined()
  })

  it('leaves the account password-only when re-enrolment is not demanded', async () => {
    await resetUserTwoFactor(db as never, TARGET.userId, false)
    expect(readUser(TARGET.userId)).toEqual({ enabled: 0, required: 0 })
  })

  it('touches nobody else', async () => {
    seedUser({ userId: 'bystander', email: 'bystander@test.local', role: 'editor' }, 1)
    seedEnrolment('bystander', 1)

    await resetUserTwoFactor(db as never, TARGET.userId, true)

    expect(readUser('bystander')).toEqual({ enabled: 1, required: 0 })
    expect(
      db.raw.prepare(`SELECT 1 FROM auth_two_factor WHERE user_id = 'bystander'`).get(),
    ).toBeDefined()
  })
})

describe('POST /admin/two-factor-reset', () => {
  beforeEach(() => {
    seedUser(TARGET, 1)
    seedEnrolment(TARGET.userId, 1)
  })

  it('resets when an admin confirms the target email', async () => {
    const res = await postReset(
      { userId: TARGET.userId, confirmEmail: TARGET.email },
      ADMIN,
    )
    expect(res.status).toBe(200)
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      email: TARGET.email,
      wasEnrolled: true,
      // Defaults on, because a reset with no follow-up silently downgrades the account.
      requireReenrolment: true,
    })
    expect(readUser(TARGET.userId)).toEqual({ enabled: 0, required: 1 })
  })

  it('accepts the confirmation regardless of case or surrounding space', async () => {
    const res = await postReset(
      { userId: TARGET.userId, confirmEmail: `  ${TARGET.email.toUpperCase()} ` },
      ADMIN,
    )
    expect(res.status).toBe(200)
  })

  it('changes nothing when the typed email does not match', async () => {
    const res = await postReset(
      { userId: TARGET.userId, confirmEmail: 'someone.else@test.local' },
      ADMIN,
    )
    expect(res.status).toBe(400)
    // The whole point of the confirmation is the mis-click, so assert the DB is untouched
    // rather than just the status code.
    expect(readUser(TARGET.userId)).toEqual({ enabled: 1, required: 0 })
    expect(
      db.raw.prepare(`SELECT 1 FROM auth_two_factor WHERE user_id = ?`).get(TARGET.userId),
    ).toBeDefined()
  })

  it('refuses a non-admin', async () => {
    const res = await postReset({ userId: TARGET.userId, confirmEmail: TARGET.email }, EDITOR)
    expect(res.status).toBe(403)
    expect(readUser(TARGET.userId)).toEqual({ enabled: 1, required: 0 })
  })

  it('refuses an anonymous caller', async () => {
    const res = await postReset({ userId: TARGET.userId, confirmEmail: TARGET.email })
    expect(res.status).toBe(401)
    expect(readUser(TARGET.userId)).toEqual({ enabled: 1, required: 0 })
  })

  it('404s an unknown user without leaking whether the email was right', async () => {
    const res = await postReset({ userId: 'nope', confirmEmail: TARGET.email }, ADMIN)
    expect(res.status).toBe(404)
  })

  it('rejects a malformed body rather than guessing', async () => {
    const res = await postReset({ confirmEmail: TARGET.email }, ADMIN)
    expect(res.status).toBe(400)
  })

  it('permits self-reset — reaching here already required passing the factor', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_enabled = 1 WHERE id = ?`).run(ADMIN.userId)
    seedEnrolment(ADMIN.userId, 1)

    const res = await postReset({ userId: ADMIN.userId, confirmEmail: ADMIN.email }, ADMIN)
    expect(res.status).toBe(200)
    expect(readUser(ADMIN.userId)).toEqual({ enabled: 0, required: 1 })
  })

  it('still works when the plugin is deactivated', async () => {
    // Deactivating the plugin does not stop Better Auth challenging enrolled users, so recovery
    // must outlive the surface. This is the assertion that stops someone "tidying" the
    // deactivate→404 gate onto this mount.
    seedPluginStatus('inactive')
    const res = await postReset({ userId: TARGET.userId, confirmEmail: TARGET.email }, ADMIN)
    expect(res.status).toBe(200)
  })
})

describe('owesTwoFactorEnrolment', () => {
  beforeEach(() => seedUser(TARGET))

  it('is true only for required-and-not-enrolled', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    await expect(owesTwoFactorEnrolment(db as never, TARGET.userId)).resolves.toBe(true)
  })

  it('is false once they enrol, even though the flag stays set', async () => {
    // required && verified means "enrolled, and may not turn it off" — the flag is not cleared,
    // so reading it alone would trap the user on the enrolment page forever.
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    seedEnrolment(TARGET.userId, 1)
    await expect(owesTwoFactorEnrolment(db as never, TARGET.userId)).resolves.toBe(false)
  })

  it('is false for an unconfirmed enrolment, so a half-finished setup still enforces', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    seedEnrolment(TARGET.userId, 0)
    await expect(owesTwoFactorEnrolment(db as never, TARGET.userId)).resolves.toBe(true)
  })

  it('is false when nothing was demanded', async () => {
    await expect(owesTwoFactorEnrolment(db as never, TARGET.userId)).resolves.toBe(false)
  })

  it('is false for an unknown or empty user id', async () => {
    await expect(owesTwoFactorEnrolment(db as never, 'ghost')).resolves.toBe(false)
    await expect(owesTwoFactorEnrolment(db as never, '')).resolves.toBe(false)
  })
})

describe('enforceTwoFactorEnrolment', () => {
  beforeEach(() => {
    seedUser(TARGET)
    seedPluginStatus('active')
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
  })

  it('redirects a user who owes an enrolment', async () => {
    const res = await requestGuarded('/admin/content', TARGET)
    expect(res.status).toBe(302)
    // Bare path, no explanatory query string — the enrolment page reads the flag itself, so
    // nobody can hand a colleague a link that fakes "your admin reset your 2FA".
    expect(res.headers.get('location')).toBe(ENROLMENT_PATH)
  })

  it('lets them reach the enrolment page and its QR endpoint', async () => {
    await expect((await requestGuarded(ENROLMENT_PATH, TARGET)).text()).resolves.toContain(
      'reached the handler',
    )
    await expect((await requestGuarded(`${ENROLMENT_PATH}/qr`, TARGET)).text()).resolves.toContain(
      'reached the handler',
    )
  })

  it('does NOT exempt the reset route, which shares the enrolment prefix as a string', async () => {
    // `/admin/two-factor-reset`.startsWith('/admin/two-factor') is true — a naive prefix check
    // would hand a user who owes an enrolment the break-glass endpoint.
    const res = await requestGuarded('/admin/two-factor-reset', TARGET)
    expect(res.status).toBe(302)
  })

  it('answers a JSON caller with 403 rather than a redirect', async () => {
    const res = await requestGuarded('/admin/api/whatever', TARGET, 'application/json')
    expect(res.status).toBe(403)
    await expect(res.json()).resolves.toMatchObject({ enrolmentPath: ENROLMENT_PATH })
  })

  it('stands aside for a user who owes nothing', async () => {
    await expect((await requestGuarded('/admin/content', ADMIN)).text()).resolves.toContain(
      'reached the handler',
    )
  })

  it('stands aside for an anonymous request', async () => {
    await expect((await requestGuarded('/admin/content')).text()).resolves.toContain(
      'reached the handler',
    )
  })

  it('stands aside when the plugin is deactivated, instead of looping to a 404', async () => {
    db.raw.prepare(`UPDATE documents SET data = ? WHERE id = 'doc-2fa'`).run(
      JSON.stringify({ status: 'inactive' }),
    )
    invalidatePluginStatusCache(TWO_FACTOR_PLUGIN_ID)
    // /admin/two-factor 404s while the plugin is off, so enforcing would redirect the user in a
    // loop to a page that cannot exist. Deactivating is the operator's escape hatch.
    await expect((await requestGuarded('/admin/content', TARGET)).text()).resolves.toContain(
      'reached the handler',
    )
  })

  it('fails OPEN when the column is missing, rather than locking out the portal', async () => {
    db.raw.exec(`ALTER TABLE auth_user DROP COLUMN two_factor_required`)
    await expect((await requestGuarded('/admin/content', TARGET)).text()).resolves.toContain(
      'reached the handler',
    )
  })
})

describe('guardRequiredSecondFactorDisable', () => {
  /** Drive the guard the way app.ts does: in front of a stub standing in for auth.handler. */
  function post(path: string, user?: typeof ADMIN, method = 'POST') {
    const app = new Hono<{ Bindings: { DB: unknown }; Variables: { user?: typeof ADMIN } }>()
    app.use('*', async (c, next) => {
      if (user) c.set('user', user)
      await next()
    })
    app.on(['GET', 'POST'], '/auth/*', async (c) => {
      const refused = await guardRequiredSecondFactorDisable(c as never)
      if (refused) return refused
      return c.json({ status: true, reachedBetterAuth: true })
    })
    return app.request(path, { method }, { DB: db })
  }

  beforeEach(() => {
    seedUser(TARGET, 1)
    seedEnrolment(TARGET.userId, 1)
  })

  it('refuses the disable when an admin requires 2FA on the account', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)

    const res = await post('/auth/two-factor/disable', TARGET)
    expect(res.status).toBe(403)
    await expect(res.json()).resolves.toMatchObject({ code: 'TWO_FACTOR_REQUIRED' })
  })

  it('refuses even though the user owes NO enrolment — the two conditions differ', async () => {
    // required && verified: `owesTwoFactorEnrolment` is false here, so a guard written against
    // that helper would wave this straight through. This is the whole reason isTwoFactorRequired
    // exists as a separate read.
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    await expect(owesTwoFactorEnrolment(db as never, TARGET.userId)).resolves.toBe(false)

    expect((await post('/auth/two-factor/disable', TARGET)).status).toBe(403)
  })

  it('lets the disable through when nothing was mandated', async () => {
    const res = await post('/auth/two-factor/disable', TARGET)
    expect(res.status).toBe(200)
    await expect(res.json()).resolves.toMatchObject({ reachedBetterAuth: true })
  })

  it('stands aside for an anonymous caller — Better Auth refuses it anyway', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    const res = await post('/auth/two-factor/disable')
    expect(res.status).toBe(200)
  })

  it('guards only the disable path, not the rest of the two-factor surface', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    // Enrolling and verifying must stay reachable — they are how the requirement gets satisfied.
    expect((await post('/auth/two-factor/enable', TARGET)).status).toBe(200)
    expect((await post('/auth/two-factor/verify-totp', TARGET)).status).toBe(200)
    expect((await post('/auth/sign-in/email', TARGET)).status).toBe(200)
  })

  it('ignores non-POST requests to the disable path', async () => {
    db.raw.prepare(`UPDATE auth_user SET two_factor_required = 1 WHERE id = ?`).run(TARGET.userId)
    expect((await post('/auth/two-factor/disable', TARGET, 'GET')).status).toBe(200)
  })

  it('fails OPEN when the column is missing, rather than freezing self-management', async () => {
    db.raw.exec(`ALTER TABLE auth_user DROP COLUMN two_factor_required`)
    expect((await post('/auth/two-factor/disable', TARGET)).status).toBe(200)
  })
})

describe('ensureTwoFactorRequiredColumn — the 0007 self-heal', () => {
  it('restores the column on a database that never got the migration', async () => {
    seedUser(TARGET, 1)
    db.raw.exec(`ALTER TABLE auth_user DROP COLUMN two_factor_required`)

    await ensureTwoFactorRequiredColumn(db as never)

    // DEFAULT 0 is the load-bearing part: an existing user must not become retroactively locked
    // out of the portal by the column appearing.
    expect(readUser(TARGET.userId)).toEqual({ enabled: 1, required: 0 })
  })

  it('is idempotent and silent when the column is already there', async () => {
    seedUser(TARGET)
    await ensureTwoFactorRequiredColumn(db as never)
    await ensureTwoFactorRequiredColumn(db as never)
    expect(readUser(TARGET.userId)).toEqual({ enabled: 0, required: 0 })
  })
})
