import { test, expect } from '@playwright/test'
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
    await page.waitForURL(/\/admin\/settings/, { timeout: 20000 })
    expect(page.url()).toContain('/admin/settings')
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
