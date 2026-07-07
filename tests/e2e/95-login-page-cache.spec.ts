import { test, expect } from '@playwright/test'

/**
 * Login page CDN-caching invariants (demo-app static short-circuit).
 *
 * The demo Worker serves GET /auth/login (no query string) as a static,
 * pre-rendered, edge-cacheable form — bypassing bootstrap/D1/Better-Auth so it
 * loads instantly. These tests pin the SECURITY + correctness invariants that
 * make that safe:
 *   1. The cacheable login response must NEVER carry a Set-Cookie header (a
 *      cached Set-Cookie would be replayed cross-user — account-takeover risk).
 *   2. It must be publicly cacheable (Cache-Control: public).
 *   3. Dynamic variants (?error=, ?redirect=) must NOT be served the cached
 *      static page — they fall through to the live handler.
 *   4. Login still works end-to-end through the (non-cached) POST path.
 */
test.describe('Login page CDN caching', () => {
  test('GET /auth/login is static, public-cacheable, and sets no cookie', async ({ request }) => {
    const res = await request.get('/auth/login')
    expect(res.status()).toBe(200)

    const headers = res.headers()
    // Publicly cacheable
    expect(headers['cache-control'] || '').toContain('public')
    // SECURITY: the shared, cacheable login page must never set a cookie
    expect(headers['set-cookie']).toBeUndefined()

    // It is the real login form
    const body = await res.text()
    expect(body).toContain('id="login-form"')
    expect(body).toContain('/auth/login/form')
  })

  test('?error= variant falls through to the dynamic handler (not the cached static page)', async ({ request }) => {
    const res = await request.get('/auth/login?error=Invalid%20credentials')
    expect(res.status()).toBe(200)
    const body = await res.text()
    // Dynamic render surfaces the error text; the static cached page never would
    expect(body).toContain('Invalid credentials')
  })

  test('login still works end-to-end through the non-cached POST path', async ({ page }) => {
    await page.goto('/auth/login')
    // Demo prefills admin creds; submit and expect to reach the admin area
    await page.fill('input[name="email"]', 'admin@sonicjs.com')
    await page.fill('input[name="password"]', 'sonicjs!')
    await page.click('#login-form button[type="submit"]')
    await page.waitForURL(/\/admin(\/|$)/, { timeout: 15_000 })
    expect(page.url()).toContain('/admin')
  })
})
