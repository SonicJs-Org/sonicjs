/**
 * `POST /auth/register/form` — the endpoint the register page actually posts to (htmx).
 *
 * Driven against a REAL better-sqlite3 D1, then signed in through a REAL Better Auth instance.
 *
 * Why this file exists: the form handler inserted `auth_user` but never the `auth_account`
 * credential row that Better Auth's sign-in reads the password from. Registration returned 200,
 * the first user was even made admin, and every sign-in then failed with "Invalid email or
 * password" (BA logs "Credential account not found"). The JSON `/auth/register` route already
 * wrote both rows; only the path the UI uses was broken. Reported in #1054.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import authRoutes from '../../routes/auth'
import { createAuth } from '../../auth/config'
import { RbacService } from '../../services/rbac'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import type { Bindings } from '../../app'

const ORIGIN = 'https://sonic.test'
const JWT_SECRET = 'test-jwt-secret-value-32-chars-long!!'
const PASSWORD = 'FormTest12345'

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

/** The SonicJS auth routes. No CACHE_KV, so `rateLimit` passes through. */
function makeApp() {
  const app = new Hono()
  app.use('*', async (c, next) => {
    c.env = env() as never
    await next()
  })
  app.route('/auth', authRoutes)
  return app
}

function registerForm(email: string, password = PASSWORD) {
  const body = new URLSearchParams({ email, password, firstName: 'Form', lastName: 'User' })
  return makeApp().request('/auth/register/form', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
}

/** Sign in through Better Auth itself — the path `/auth/login` delegates to. */
async function baSignIn(email: string, password = PASSWORD) {
  const auth = createAuth(
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
  return auth.handler(
    new Request(`${ORIGIN}/auth/sign-in/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
      body: JSON.stringify({ email, password }),
    }),
  )
}

function credentialRows(email: string) {
  return db.raw
    .prepare(
      `SELECT a.id, a.password FROM auth_account a JOIN auth_user u ON u.id = a.user_id
       WHERE u.email = ? AND a.provider_id = 'credential'`,
    )
    .all(email) as Array<{ id: string; password: string }>
}

function rbacRoleNames(email: string) {
  const user = db.raw.prepare(`SELECT id FROM auth_user WHERE email = ?`).get(email) as { id: string } | undefined
  if (!user) return []
  return new RbacService(db as never).getRolesForUser(user.id).then((roles) => roles.map((r) => r.name))
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

describe('POST /auth/register/form', () => {
  // The handler assigns an RBAC role; give it the seeded roles a booted app has.
  beforeEach(async () => {
    await bootstrapDocumentTypes(db as never)
    await new RbacService(db as never).ensureSystemRbacSeed()
  })

  it('creates the credential row, so the first (admin) user can sign in', async () => {
    const res = await registerForm('first@form.test')
    expect(res.status).toBe(200)

    const user = db.raw
      .prepare(`SELECT id, role, password_hash FROM auth_user WHERE email = ?`)
      .get('first@form.test') as { id: string; role: string; password_hash: string }
    expect(user.role).toBe('admin')

    const creds = credentialRows('first@form.test')
    expect(creds).toHaveLength(1)
    expect(creds[0]!.password).toBe(user.password_hash)

    const signIn = await baSignIn('first@form.test')
    expect(signIn.status, `sign-in failed: ${await signIn.clone().text()}`).toBe(200)
  })

  it('does the same for a later (viewer) user', async () => {
    await registerForm('first@form.test')
    const res = await registerForm('second@form.test')
    expect(res.status).toBe(200)

    expect(credentialRows('second@form.test')).toHaveLength(1)
    expect((await baSignIn('second@form.test')).status).toBe(200)
  })

  it('still rejects a wrong password for a form-registered user', async () => {
    await registerForm('first@form.test')
    expect((await baSignIn('first@form.test', 'not-the-password')).status).toBe(401)
  })

  it('writes no rows when the email is already taken', async () => {
    await registerForm('first@form.test')
    await registerForm('first@form.test', 'AnotherPass12345')

    expect(
      (db.raw.prepare(`SELECT COUNT(*) AS n FROM auth_user WHERE email = ?`).get('first@form.test') as { n: number }).n,
    ).toBe(1)
    expect(credentialRows('first@form.test')).toHaveLength(1)
    expect((await baSignIn('first@form.test')).status).toBe(200)
  })
})

describe('POST /auth/register/form — first user and RBAC', () => {
  it('makes the first user an RBAC admin even when the first boot left RBAC unseeded', async () => {
    // No bootstrapDocumentTypes / ensureSystemRbacSeed here: the state a failed first boot leaves (#1017).
    const res = await registerForm('first@form.test')
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('Account created successfully')

    expect(await rbacRoleNames('first@form.test')).toEqual(['admin'])
    expect((await baSignIn('first@form.test')).status).toBe(200)
  })

  it('removes the account again when the admin role cannot be assigned, so a retry works', async () => {
    const spy = vi
      .spyOn(RbacService.prototype, 'addUserRoleByName')
      .mockRejectedValueOnce(new Error('D1 unavailable'))

    const failed = await registerForm('first@form.test')
    expect(await failed.text()).toContain('Registration failed')
    expect(db.raw.prepare(`SELECT COUNT(*) AS n FROM auth_user`).get()).toEqual({ n: 0 })
    expect(db.raw.prepare(`SELECT COUNT(*) AS n FROM auth_account`).get()).toEqual({ n: 0 })

    spy.mockRestore()
    const retry = await registerForm('first@form.test')
    expect(await retry.text()).toContain('Account created successfully')
    expect(await rbacRoleNames('first@form.test')).toEqual(['admin'])
  })
})
