import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Issue #783: viewer role sees all sidebar items.
 * Admins create a viewer account; viewer sidebar must not expose
 * Users, Plugins, or Settings navigation.
 */
test.describe('Viewer role sidebar scope', () => {
  const viewerEmail = `viewer-test-${Date.now()}@example.com`
  const viewerPassword = 'ViewerPass1!'

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage()
    await loginAsAdmin(page)

    // Create viewer user via admin UI
    await page.goto('/admin/users/new')
    await page.fill('input[name="email"]', viewerEmail)
    await page.fill('input[name="password"]', viewerPassword)
    // role defaults to viewer; no extra action needed
    await page.click('button[type="submit"]')
    await page.close()
  })

  test('viewer sees Content and Collections but not Users/Plugins/Settings', async ({ page }) => {
    // Sign in as viewer
    await page.goto('/auth/login')
    await page.fill('input[name="email"]', viewerEmail)
    await page.fill('input[name="password"]', viewerPassword)
    await page.click('button[type="submit"]')
    await page.waitForURL(/\/admin/)

    // Content link present
    await expect(page.locator('a[href="/admin/content"]')).toBeVisible()
    // Collections link present
    await expect(page.locator('a[href="/admin/collections"]')).toBeVisible()

    // Users, Plugins, Settings must NOT be in the sidebar
    await expect(page.locator('a[href="/admin/users"]')).not.toBeVisible()
    await expect(page.locator('a[href="/admin/plugins"]')).not.toBeVisible()
    await expect(page.locator('a[href="/admin/settings"]')).not.toBeVisible()
  })

  test('admin sees all sidebar items', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/content')

    await expect(page.locator('a[href="/admin/users"]')).toBeVisible()
    await expect(page.locator('a[href="/admin/plugins"]')).toBeVisible()
    await expect(page.locator('a[href="/admin/settings"]')).toBeVisible()
  })
})
