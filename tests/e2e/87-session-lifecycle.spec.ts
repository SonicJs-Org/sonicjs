import { test, expect } from '@playwright/test'
import { ADMIN_CREDENTIALS } from './utils/test-helpers'

/**
 * Session lifecycle (Better Auth, app-wide session middleware).
 *
 * Mirrors Payload's auth Sessions suite: logging out destroys the session so a
 * subsequent /auth/me is rejected, and logging out ONE session leaves other
 * concurrent sessions for the same user untouched.
 *
 * Every test uses isolated request contexts so logging out here never disturbs
 * the session cookies of parallel spec shards.
 *
 * Logout uses GET /auth/logout: it performs the same Better Auth server-side
 * sign-out as the POST variant but, being a safe method, is exempt from CSRF
 * validation — so a header-less request context can call it directly.
 */
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

async function newSession(playwright: any) {
  const ctx = await playwright.request.newContext({ baseURL: BASE_URL })
  const res = await ctx.post('/auth/sign-in/email', {
    data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
    headers: { 'Content-Type': 'application/json', 'Origin': BASE_URL },
  })
  expect(res.ok()).toBe(true)
  return ctx
}

// Force a JSON (not HTML-redirect) response from requireAuth, so an
// unauthenticated /auth/me is a clean 401 rather than a 302 to the login page.
function me(ctx: any) {
  return ctx.get('/auth/me', { headers: { Accept: 'application/json' } })
}

test.describe('Session lifecycle @smoke @auth', () => {
  test.beforeAll(async ({ request }) => {
    await request.post('/auth/seed-admin').catch(() => {})
  })

  test('logout destroys the session — /auth/me then rejects', async ({ playwright }) => {
    const ctx = await newSession(playwright)

    const before = await me(ctx)
    expect(before.ok()).toBe(true)
    expect((await before.json()).user?.email).toBe(ADMIN_CREDENTIALS.email)

    const logout = await ctx.get('/auth/logout')
    expect(logout.ok()).toBe(true)

    const after = await me(ctx)
    expect(after.status()).toBe(401)

    await ctx.dispose()
  })

  test('logging out one session leaves a concurrent session alive', async ({ playwright }) => {
    const a = await newSession(playwright)
    const b = await newSession(playwright)

    // Both sessions valid.
    expect((await me(a)).ok()).toBe(true)
    expect((await me(b)).ok()).toBe(true)

    // Log out only session A.
    expect((await a.get('/auth/logout')).ok()).toBe(true)

    // A is dead, B is unaffected — sessions are independent rows.
    expect((await me(a)).status()).toBe(401)
    expect((await me(b)).ok()).toBe(true)

    await a.dispose()
    await b.dispose()
  })

  test('an unauthenticated context cannot reach /auth/me', async ({ playwright }) => {
    const ctx = await playwright.request.newContext({ baseURL: BASE_URL })
    const res = await me(ctx)
    expect(res.status()).toBe(401)
    await ctx.dispose()
  })
})
