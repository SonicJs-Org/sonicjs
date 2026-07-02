import { test, expect } from '@playwright/test'
import { ADMIN_CREDENTIALS } from './utils/test-helpers'

/**
 * Programmatic API keys — api-keys plugin (admin manage API at
 * /admin/plugins/api-keys) + the core resolve middleware (x-api-key auth).
 *
 * Proves the headless-auth path end to end: a logged-in user mints a key, and a
 * SEPARATE cookieless request context authenticates purely via the `x-api-key`
 * (or `Authorization: Bearer sk_…`) header. Using a fresh context is essential —
 * the shared `request` fixture carries the login session cookie, which would
 * mask whether the header alone authenticated.
 *
 * The key-management calls (POST/DELETE) send `Authorization: Bearer <token>`.
 * That token (returned by /auth/login) makes the request CSRF-exempt — the
 * server skips CSRF when an Authorization header is present, since an attacker
 * can't forge it cross-origin — while the session still authenticates the user.
 */
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

async function loginToken(request: any): Promise<string> {
  const res = await request.post('/auth/login', {
    data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
  })
  expect(res.ok()).toBe(true)
  const { token } = await res.json()
  expect(typeof token).toBe('string')
  return token
}

async function createKey(request: any, token: string, name: string) {
  const res = await request.post('/admin/plugins/api-keys/api/keys', {
    headers: { Authorization: `Bearer ${token}` },
    data: { name },
  })
  expect(res.status()).toBe(201)
  const body = await res.json()
  return body.apiKey as { id: string; key: string; prefix: string; name: string }
}

test.describe('Programmatic API keys', () => {
  test.beforeAll(async ({ request }) => {
    await request.post('/auth/seed-admin').catch(() => {})
  })

  test('x-api-key authenticates an API request as the owning user', async ({ request, playwright }) => {
    const token = await loginToken(request)
    const key = await createKey(request, token, 'e2e-xapikey')
    expect(key.key).toMatch(/^sk_[0-9a-f]{48}$/)
    expect(key.prefix).toBe(key.key.slice(0, 11))

    // Cookieless context: only the header can authenticate.
    const clean = await playwright.request.newContext({ baseURL: BASE_URL })
    const me = await clean.get('/auth/me', { headers: { 'x-api-key': key.key } })
    expect(me.ok()).toBe(true)
    const body = await me.json()
    expect(body.user?.email).toBe(ADMIN_CREDENTIALS.email)
    await clean.dispose()
  })

  test('Authorization: Bearer sk_ header also authenticates', async ({ request, playwright }) => {
    const token = await loginToken(request)
    const key = await createKey(request, token, 'e2e-bearer')

    const clean = await playwright.request.newContext({ baseURL: BASE_URL })
    const me = await clean.get('/auth/me', { headers: { Authorization: `Bearer ${key.key}` } })
    expect(me.ok()).toBe(true)
    await clean.dispose()
  })

  test('an invalid key is rejected with 401', async ({ playwright }) => {
    const clean = await playwright.request.newContext({ baseURL: BASE_URL })
    const me = await clean.get('/auth/me', {
      headers: { 'x-api-key': 'sk_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', Accept: 'application/json' },
    })
    expect(me.status()).toBe(401)
    await clean.dispose()
  })

  test('list returns metadata only — never the secret or hash', async ({ request }) => {
    const token = await loginToken(request)
    const created = await createKey(request, token, 'e2e-list')

    const res = await request.get('/admin/plugins/api-keys/api/keys', { headers: { Authorization: `Bearer ${token}` } })
    expect(res.ok()).toBe(true)
    const { keys } = await res.json()
    const mine = keys.find((k: any) => k.id === created.id)
    expect(mine).toBeTruthy()
    expect(mine.prefix).toBe(created.prefix)
    expect(mine.key).toBeUndefined()
    expect(mine.keyHash).toBeUndefined()
    // No full secret anywhere in the listing payload.
    expect(JSON.stringify(keys)).not.toMatch(/sk_[0-9a-f]{48}/)
  })

  test('revoking a key disables it immediately', async ({ request, playwright }) => {
    const token = await loginToken(request)
    const key = await createKey(request, token, 'e2e-revoke')

    const clean = await playwright.request.newContext({ baseURL: BASE_URL })
    // Works before revoke.
    expect((await clean.get('/auth/me', { headers: { 'x-api-key': key.key } })).ok()).toBe(true)

    const del = await request.delete(`/admin/plugins/api-keys/api/keys/${key.id}`, { headers: { Authorization: `Bearer ${token}` } })
    expect(del.ok()).toBe(true)

    // Rejected after revoke.
    const after = await clean.get('/auth/me', { headers: { 'x-api-key': key.key, Accept: 'application/json' } })
    expect(after.status()).toBe(401)
    await clean.dispose()
  })

  test('creating a key requires authentication', async ({ playwright }) => {
    const clean = await playwright.request.newContext({ baseURL: BASE_URL })
    const res = await clean.post('/admin/plugins/api-keys/api/keys', { data: { name: 'nope' }, headers: { Accept: 'application/json' } })
    expect(res.status()).toBe(401)
    await clean.dispose()
  })

  test('admin manage page renders for an admin', async ({ request }) => {
    await loginToken(request)
    const res = await request.get('/admin/plugins/api-keys', { headers: { Accept: 'text/html' } })
    expect(res.ok()).toBe(true)
    const html = await res.text()
    expect(html).toContain('API Keys')
    expect(html).toContain('Create API key')
  })
})
