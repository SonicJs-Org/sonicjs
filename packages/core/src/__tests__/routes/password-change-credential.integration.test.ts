/**
 * Every SonicJS path that sets a password must reach Better Auth.
 *
 * Driven against a REAL better-sqlite3 D1, then signed in through a REAL Better Auth instance.
 *
 * Why this file exists: Better Auth's password sign-in reads `auth_account.password` (provider
 * 'credential'). The profile password change, admin edit-user, admin create-user, password reset
 * and accept-invitation wrote only `auth_user.password_hash`. So a changed password failed at
 * sign-in while the old one kept working, and an admin-created or invited user could not sign in
 * at all.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import authRoutes from '../../routes/auth'
import { userRoutes } from '../../routes/admin-users'
import { createAuth } from '../../auth/config'
import { AuthManager } from '../../middleware/auth'
import { RbacService } from '../../services/rbac'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import type { Bindings } from '../../app'

const ORIGIN = 'https://sonic.test'
const JWT_SECRET = 'test-jwt-secret-value-32-chars-long!!'
const OLD_PASSWORD = 'OldPassword12345'
const NEW_PASSWORD = 'NewPassword67890'
const ADMIN = { userId: 'admin-1', email: 'admin@pw.test', role: 'admin' }

let db: TestD1
let kv: Map<string, string>

function env() {
  return {
    DB: db,
    JWT_SECRET,
    BETTER_AUTH_SECRET: 'test-better-auth-secret-at-least-32-chars',
    BETTER_AUTH_URL: ORIGIN,
  } as unknown as Bindings
}

/** SonicJS routes with an optional signed-in principal. No CACHE_KV, so `rateLimit` passes through. */
function makeApp(user?: typeof ADMIN) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    c.env = env() as never
    if (user) c.set('user' as never, user as never)
    await next()
  })
  app.route('/auth', authRoutes)
  app.route('/admin', userRoutes)
  return app
}

function form(app: Hono, method: string, path: string, fields: Record<string, string>) {
  return app.request(path, {
    method,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  })
}

function baAuth() {
  return createAuth(
    {
      ...env(),
      CACHE_KV: {
        get: async (k: string) => kv.get(k) ?? null,
        put: async (k: string, v: string) => void kv.set(k, v),
        delete: async (k: string) => void kv.delete(k),
      },
    } as unknown as Bindings,
    undefined,
    ORIGIN,
  )
}

function baPost(path: string, body: unknown) {
  return baAuth().handler(
    new Request(`${ORIGIN}/auth${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
      body: JSON.stringify(body),
    }),
  )
}

/** Sign in through Better Auth itself — the path `/auth/login` delegates to. */
async function signInStatus(email: string, password: string) {
  return (await baPost('/sign-in/email', { email, password })).status
}

/** A user as `/auth/register` creates one: PBKDF2 hash in auth_user AND a `cred-` credential row. */
async function seedUser(id: string, email: string, password = OLD_PASSWORD, extra: Record<string, unknown> = {}) {
  const hash = await AuthManager.hashPassword(password)
  const now = Date.now()
  const cols = { id, email, first_name: 'Pw', last_name: 'User', password_hash: hash, role: 'viewer', is_active: 1, created_at: now, updated_at: now, ...extra }
  const keys = Object.keys(cols)
  db.raw.prepare(`INSERT INTO auth_user (${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`).run(...Object.values(cols))
  if (password) {
    const sec = Math.floor(now / 1000)
    db.raw
      .prepare(`INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at) VALUES (?, ?, ?, 'credential', ?, ?, ?)`)
      .run(`cred-${id}`, id, id, hash, sec, sec)
  }
}

function credentialRows(email: string) {
  return db.raw
    .prepare(
      `SELECT a.id FROM auth_account a JOIN auth_user u ON u.id = a.user_id WHERE u.email = ? AND a.provider_id = 'credential'`,
    )
    .all(email) as Array<{ id: string }>
}

beforeEach(async () => {
  db = createTestD1()
  kv = new Map()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
  await bootstrapDocumentTypes(db as never)
  await new RbacService(db as never).ensureSystemRbacSeed()
  await seedUser(ADMIN.userId, ADMIN.email, OLD_PASSWORD, { role: 'admin' })
})

afterEach(() => {
  db.close()
  vi.restoreAllMocks()
})

describe('password changes reach Better Auth', () => {
  it('profile password change: new password signs in, old one no longer does', async () => {
    await form(makeApp(ADMIN), 'POST', '/admin/profile/password', {
      current_password: OLD_PASSWORD,
      new_password: NEW_PASSWORD,
      confirm_password: NEW_PASSWORD,
    })

    expect(await signInStatus(ADMIN.email, NEW_PASSWORD)).toBe(200)
    expect(await signInStatus(ADMIN.email, OLD_PASSWORD)).toBe(401)
  })

  it('admin edit-user set password, for a user Better Auth signed up (random credential id)', async () => {
    const signUp = await baPost('/sign-up/email', { email: 'ba@pw.test', password: OLD_PASSWORD, name: 'Ba User' })
    expect(signUp.status).toBe(200)
    const { id } = db.raw.prepare(`SELECT id FROM auth_user WHERE email = ?`).get('ba@pw.test') as { id: string }

    await form(makeApp(ADMIN), 'PUT', `/admin/users/${id}`, {
      first_name: 'Ba',
      last_name: 'User',
      email: 'ba@pw.test',
      role: 'role-authenticated',
      is_active: '1',
      new_password: NEW_PASSWORD,
      confirm_password: NEW_PASSWORD,
    })

    expect(credentialRows('ba@pw.test')).toHaveLength(1) // updated in place, no second row
    expect(await signInStatus('ba@pw.test', NEW_PASSWORD)).toBe(200)
    expect(await signInStatus('ba@pw.test', OLD_PASSWORD)).toBe(401)
  })

  it('admin create-user: the new user can sign in', async () => {
    await form(makeApp(ADMIN), 'POST', '/admin/users/new', {
      first_name: 'New',
      last_name: 'User',
      email: 'created@pw.test',
      role: 'role-authenticated',
      is_active: '1',
      password: NEW_PASSWORD,
      confirm_password: NEW_PASSWORD,
    })

    expect(credentialRows('created@pw.test')).toHaveLength(1)
    expect(await signInStatus('created@pw.test', NEW_PASSWORD)).toBe(200)
  })

  it('password reset: new password signs in, old one no longer does', async () => {
    await seedUser('reset-1', 'reset@pw.test', OLD_PASSWORD, {
      password_reset_token: 'reset-token',
      password_reset_expires: Date.now() + 60_000,
    })

    const res = await form(makeApp(), 'POST', '/auth/reset-password', {
      token: 'reset-token',
      password: NEW_PASSWORD,
      confirm_password: NEW_PASSWORD,
    })
    expect(res.status).toBeLessThan(400)

    expect(await signInStatus('reset@pw.test', NEW_PASSWORD)).toBe(200)
    expect(await signInStatus('reset@pw.test', OLD_PASSWORD)).toBe(401)
  })

  it('accept invitation: the invited user (no credential row yet) can sign in', async () => {
    await seedUser('invite-1', 'invited@pw.test', '', {
      password_hash: null,
      is_active: 0,
      invitation_token: 'invite-token',
      invited_at: Date.now(),
    })
    expect(credentialRows('invited@pw.test')).toHaveLength(0)

    const res = await form(makeApp(), 'POST', '/auth/accept-invitation', {
      token: 'invite-token',
      password: NEW_PASSWORD,
      confirm_password: NEW_PASSWORD,
    })
    expect(res.status).toBeLessThan(400)

    expect(credentialRows('invited@pw.test')).toHaveLength(1)
    expect(await signInStatus('invited@pw.test', NEW_PASSWORD)).toBe(200)
  })
})
