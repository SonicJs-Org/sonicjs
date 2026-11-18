/**
 * Better Auth's `/auth/organization/*` endpoints are closed. SonicJS manages tenants through
 * TenantService; with Better Auth 1.7 and a correct `tenantId` field mapping those endpoints
 * would otherwise let any signed-in user create a tenant, and let a tenant member with a Better
 * Auth org role (`admin`/`owner`) rewrite `auth_tenant.domain`, which drives host routing.
 *
 * Two independent layers close them, and each is tested ALONE:
 *   1. the `/auth/organization/*` 404 block in app.ts (in front of the Better Auth handler);
 *   2. Better Auth's own `disabledPaths`, derived from the organization plugin's endpoints.
 * A positive control with both layers removed proves the endpoints are live underneath, so the
 * 404s are not vacuous. Driven over real (better-sqlite3) D1.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createSonicJSApp } from '../../app'
import { createAuth, type ExtendBetterAuth } from '../../auth/config'
import type { Bindings } from '../../app'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

const ORIGIN = 'https://sonic.test'
let db: TestD1
let kv: Map<string, string>

function env() {
  return {
    DB: db,
    CACHE_KV: {
      get: async (k: string) => kv.get(k) ?? null,
      put: async (k: string, v: string) => void kv.set(k, v),
      delete: async (k: string) => void kv.delete(k),
    },
    BETTER_AUTH_SECRET: 'test-better-auth-secret-at-least-32-chars',
    BETTER_AUTH_URL: ORIGIN,
    JWT_SECRET: 'test-jwt-secret-value-32-chars-long!!',
  }
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

describe('/auth/organization/* is closed', () => {
  it('a signed-in user gets 404 from organization create and no tenant row is written', async () => {
    const app = createSonicJSApp()
    const post = (path: string, body: unknown, cookie?: string) =>
      app.request(
        `${ORIGIN}${path}`,
        {
          method: 'POST',
          headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
          body: JSON.stringify(body),
        },
        env(),
      )

    const signUp = await post('/auth/sign-up/email', { email: 'viewer@sonic.test', password: 'correct-horse-battery-staple', name: 'V' })
    expect(signUp.status, await signUp.clone().text()).toBe(200)
    const cookie = signUp.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')

    const create = await post('/auth/organization/create', { name: 'Acme', slug: 'acme', domain: 'acme.test' }, cookie)
    expect(create.status).toBe(404)
    expect(db.raw.prepare(`SELECT COUNT(*) AS n FROM auth_tenant`).get()).toEqual({ n: 0 })

    const list = await app.request(`${ORIGIN}/auth/organization/list`, { headers: { Origin: ORIGIN, Cookie: cookie } }, env())
    expect(list.status).toBe(404)
  })
})

// ── update / invite-member, as a tenant member who holds a Better Auth org role ───────────────

const PASSWORD = 'correct-horse-battery-staple'
const TENANT_ID = 'tenant-acme'
const ORIGINAL_DOMAIN = 'acme.test'

/** A request sender: either the full SonicJS app or the bare Better Auth handler. */
type Send = (path: string, body: unknown, cookie?: string) => Promise<Response>

const withoutDisabledPaths: ExtendBetterAuth = (opts) => ({ ...opts, disabledPaths: [] })

function viaApp(extendBetterAuth?: ExtendBetterAuth): Send {
  const app = createSonicJSApp(extendBetterAuth ? { auth: { extendBetterAuth } } : {})
  return (path, body, cookie) =>
    Promise.resolve(
      app.request(
        `${ORIGIN}${path}`,
        {
          method: 'POST',
          headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
          body: JSON.stringify(body),
        },
        env(),
      ),
    )
}

/** Better Auth's handler with NO app.ts in front of it. */
function viaBetterAuthOnly(extendBetterAuth?: ExtendBetterAuth): Send {
  return (path, body, cookie) =>
    createAuth(env() as unknown as Bindings, extendBetterAuth, ORIGIN).handler(
      new Request(`${ORIGIN}${path}`, {
        method: 'POST',
        headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
        body: JSON.stringify(body),
      }),
    )
}

/** Sign up, then make the user an `admin` member of an existing tenant (as TenantService would). */
async function signedInTenantAdmin(send: Send): Promise<string> {
  const signUp = await send('/auth/sign-up/email', { email: 'member@sonic.test', password: PASSWORD, name: 'M' })
  expect(signUp.status, await signUp.clone().text()).toBe(200)
  const cookie = signUp.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
  const userId = (db.raw.prepare(`SELECT id FROM auth_user WHERE email = ?`).get('member@sonic.test') as { id: string }).id
  const now = Date.now()
  db.raw
    .prepare(`INSERT INTO auth_tenant (id, name, slug, domain, created_at, updated_at) VALUES (?, 'Acme', 'acme', ?, ?, ?)`)
    .run(TENANT_ID, ORIGINAL_DOMAIN, now, now)
  db.raw
    .prepare(`INSERT INTO auth_tenant_member (id, tenant_id, user_id, role, created_at, updated_at) VALUES ('m-1', ?, ?, 'admin', ?, ?)`)
    .run(TENANT_ID, userId, now, now)
  return cookie
}

function tenantDomain() {
  return (db.raw.prepare(`SELECT domain FROM auth_tenant WHERE id = ?`).get(TENANT_ID) as { domain: string }).domain
}
function invitationCount() {
  return (db.raw.prepare(`SELECT COUNT(*) AS n FROM auth_tenant_invitation`).get() as { n: number }).n
}

async function expectClosed(send: Send) {
  const cookie = await signedInTenantAdmin(send)

  const update = await send(
    '/auth/organization/update',
    { organizationId: TENANT_ID, data: { domain: 'evil.example' } },
    cookie,
  )
  expect(update.status).toBe(404)
  expect(tenantDomain()).toBe(ORIGINAL_DOMAIN)

  const invite = await send(
    '/auth/organization/invite-member',
    { organizationId: TENANT_ID, email: 'outsider@sonic.test', role: 'admin' },
    cookie,
  )
  expect(invite.status).toBe(404)
  expect(invitationCount()).toBe(0)
}

describe('/auth/organization/update and invite-member are closed', () => {
  it('with both layers (the shipped configuration)', async () => {
    await expectClosed(viaApp())
  })

  it('by the app.ts block alone (Better Auth disabledPaths cleared)', async () => {
    await expectClosed(viaApp(withoutDisabledPaths))
  })

  it('by Better Auth disabledPaths alone (no app.ts in front)', async () => {
    await expectClosed(viaBetterAuthOnly())
  })

  it('disabledPaths covers every path the organization plugin mounts', () => {
    const paths = createAuth(env() as unknown as Bindings, undefined, ORIGIN).options.disabledPaths ?? []
    expect(paths).toEqual(expect.arrayContaining(['/organization/create', '/organization/update', '/organization/invite-member']))
    expect(paths.every((p) => p.startsWith('/organization/'))).toBe(true)
  })

  it('positive control: with both layers removed, a tenant admin CAN rewrite the domain', async () => {
    const send = viaBetterAuthOnly(withoutDisabledPaths)
    const cookie = await signedInTenantAdmin(send)
    const update = await send(
      '/auth/organization/update',
      { organizationId: TENANT_ID, data: { domain: 'evil.example' } },
      cookie,
    )
    expect(update.status, await update.clone().text()).toBe(200)
    expect(tenantDomain()).toBe('evil.example')
  })
})
