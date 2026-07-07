import { test, expect } from '@playwright/test'

/**
 * Demo app (demo.sonicjs.com) E2E.
 *
 * These tests run ONLY against a deployed/local demo instance — set
 * DEMO_BASE_URL (e.g. https://demo.sonicjs.com or http://localhost:9xxx). They
 * are skipped in the normal my-sonicjs-app CI run because they assert demo-only
 * behavior (credential prefill, seeded content, the reseed endpoint).
 *
 * Validates:
 *   1. The demo-login plugin prefills admin credentials on the login page.
 *   2. The public content API serves the seeded collections.
 *   3. POST /__demo/reseed is rejected without the bearer token.
 */

const DEMO_BASE_URL = process.env.DEMO_BASE_URL

test.describe('Demo app', () => {
  test.skip(!DEMO_BASE_URL, 'Set DEMO_BASE_URL to run demo E2E against a demo instance')

  test('login page prefills demo credentials', async ({ page }) => {
    await page.goto(`${DEMO_BASE_URL}/auth/login`)

    // The core renderLoginPage prefills the email/password inputs when the
    // demo-login-prefill plugin is active.
    const email = page.locator('input[type="email"], input[name="email"]').first()
    const password = page.locator('input[type="password"], input[name="password"]').first()

    await expect(email).toHaveValue('admin@sonicjs.com')
    await expect(password).toHaveValue('sonicjs!')
  })

  test('public API serves seeded blog posts', async ({ request }) => {
    const res = await request.get(`${DEMO_BASE_URL}/api/blog_post`)
    expect(res.ok()).toBeTruthy()
    const body = await res.json()
    const items = body.data ?? body.documents ?? body
    expect(Array.isArray(items) ? items.length : 0).toBeGreaterThan(0)
  })

  test('reseed endpoint rejects requests without the bearer token', async ({ request }) => {
    const res = await request.post(`${DEMO_BASE_URL}/__demo/reseed`)
    // 401 (no/invalid token) or 403 (non-demo) — never a successful wipe.
    expect([401, 403]).toContain(res.status())
  })
})
