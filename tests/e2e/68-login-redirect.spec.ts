import { test, expect } from './fixtures'
import { ensureAdminUserExists, ADMIN_CREDENTIALS, TEST_ORIGIN } from './utils/test-helpers'

test.describe('Login redirect param @smoke @auth', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
  })

  test('redirects to /admin by default', async ({ page }) => {
    await page.goto('/auth/login')
    await page.fill('#email', ADMIN_CREDENTIALS.email)
    await page.fill('#password', ADMIN_CREDENTIALS.password)
    await page.click('button[type="submit"]')
    await page.waitForURL(/\/admin/, { timeout: 20000 })
    expect(page.url()).toContain('/admin')
  })

  test('redirects to ?redirect= path after login', async ({ page }) => {
    await page.goto('/auth/login?redirect=/admin/settings')
    await page.fill('#email', ADMIN_CREDENTIALS.email)
    await page.fill('#password', ADMIN_CREDENTIALS.password)
    await page.click('button[type="submit"]')
    // Not a regex: `waitForURL` matches the whole URL string, and the page it is called from is
    // `/auth/login?redirect=/admin/settings` — which contains '/admin/settings'. Both the wait
    // and the assertion below were already true before the submit, so this test passed whether
    // or not the redirect param was honoured. Match the pathname.
    // Prefix, not equality: /admin/settings is itself a 302 on to /admin/settings/general, so
    // the browser lands a hop past the requested path. Still a real assertion — the page this
    // is called from has pathname /auth/login.
    await page.waitForURL((url) => url.pathname.startsWith('/admin/settings'), { timeout: 20000 })
    expect(new URL(page.url()).pathname).toMatch(/^\/admin\/settings/)
  })

  test('ignores external redirect (open-redirect guard)', async ({ page }) => {
    await page.goto('/auth/login?redirect=https://evil.example.com')
    await page.fill('#email', ADMIN_CREDENTIALS.email)
    await page.fill('#password', ADMIN_CREDENTIALS.password)
    await page.click('button[type="submit"]')
    // Must NOT navigate to the external URL — falls back to /admin
    await page.waitForURL(/\/admin/, { timeout: 20000 })
    expect(page.url()).not.toContain('evil.example.com')
  })
})
