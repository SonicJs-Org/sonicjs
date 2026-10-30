import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { TEST_ORIGIN } from './utils/test-helpers'

/**
 * Better Auth 1.7.7 upgrade — the behaviours the upgrade changed, against the deployed Worker.
 *
 * What each test would catch:
 *  - session round trip: Better Auth 1.7.3+ validates the drizzle schema on the first adapter
 *    call and rejects EVERY auth request on a mismatch (the organization `tenantId` mapping);
 *  - organization endpoints: closed at the mount — tenants belong to TenantService, and with the
 *    corrected `tenantId` mapping they would otherwise let any user create and own a tenant;
 *  - magic-link error path: an unknown token is refused and mints no session;
 *  - GHSA-965c-763c-88jm: an OAuth `state` must not be redeemable as a magic-link token
 *    (runs only where a GitHub provider is configured; skipped otherwise).
 *
 * The OTP / magic-link SUCCESS paths need the emailed code, which the preview cannot deliver
 * (no email service). They are covered against real Better Auth + real SQLite in
 * `packages/core/src/__tests__/services/better-auth-1-7.sqlite.test.ts`.
 *
 * Every test brings its own throwaway `…@example.com` account (`fullyParallel: true`).
 */

function json(data: unknown) {
  return { headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN }, data }
}

async function signUpThrowaway(page: Page, slot: string) {
  const email = `ba17-${slot}-${Date.now().toString(36)}@example.com`
  await page.context().clearCookies()
  const res = await page.request.post('/auth/sign-up/email', json({ email, password: 'BetterAuth17!xyz', name: 'BA17 User' }))
  expect(res.status(), await res.text()).toBe(200)
  return email
}

async function hasSessionCookie(page: Page) {
  const cookies = await page.context().cookies()
  return cookies.some((c) => c.name.endsWith('session_token') && c.value.length > 0)
}

test.describe('Better Auth 1.7 upgrade @auth', () => {
  test('sign-up → get-session → sign-out round trip', async ({ page }) => {
    const email = await signUpThrowaway(page, 'session')
    const session = await page.request.get('/auth/get-session', { headers: { Origin: TEST_ORIGIN } })
    expect(session.status()).toBe(200)
    expect((await session.json())?.user?.email).toBe(email)

    const out = await page.request.post('/auth/sign-out', json({}))
    expect(out.status()).toBe(200)
    const after = await page.request.get('/auth/get-session', { headers: { Origin: TEST_ORIGIN } })
    expect(await after.json()).toBeNull()
  })

  test('a signed-in user cannot reach Better Auth organization endpoints', async ({ page }) => {
    await signUpThrowaway(page, 'org')
    const slug = `ba17-${Date.now().toString(36)}`
    const res = await page.request.post('/auth/organization/create', json({ name: 'BA17 Org', slug, domain: `${slug}.example.com` }))
    expect(res.status()).toBe(404)
    const bare = await page.request.get('/auth/organization', { headers: { Origin: TEST_ORIGIN } })
    expect(bare.status()).toBe(404)
    const list = await page.request.get('/auth/organization/list', { headers: { Origin: TEST_ORIGIN } })
    expect(list.status()).toBe(404)
  })

  test('an unknown magic-link token is rejected without a session', async ({ page }) => {
    await page.context().clearCookies()
    const res = await page.request.get('/auth/magic-link/verify?token=not-a-real-token&callbackURL=%2Fadmin', {
      maxRedirects: 0,
    })
    expect(res.status()).toBe(302)
    expect(res.headers()['location']).toContain('error=INVALID_TOKEN')
    expect(await hasSessionCookie(page)).toBe(false)
  })

  test('GHSA-965c-763c-88jm: an OAuth state cannot be redeemed as a magic-link token', async ({ page }) => {
    const victim = await signUpThrowaway(page, 'victim')
    await page.context().clearCookies()

    const start = await page.request.post(
      '/auth/sign-in/social',
      json({ provider: 'github', callbackURL: '/admin', additionalData: { email: victim, name: 'x' } }),
    )
    const body = await start.json().catch(() => null)
    if (start.status() >= 500) throw new Error(`OAuth social sign-in returned server error ${start.status()}`)
    test.skip(start.status() !== 200 || !body?.url, 'No GitHub provider configured on this deployment')

    const state = new URL(body.url).searchParams.get('state')
    expect(state).toBeTruthy()
    const attempt = await page.request.get(
      `/auth/magic-link/verify?token=${encodeURIComponent(state!)}&callbackURL=%2Fadmin`,
      { maxRedirects: 0 },
    )
    expect(attempt.status()).toBe(302)
    expect(await hasSessionCookie(page)).toBe(false)
    const session = await page.request.get('/auth/get-session', { headers: { Origin: TEST_ORIGIN } })
    expect(await session.json()).toBeNull()
  })
})
