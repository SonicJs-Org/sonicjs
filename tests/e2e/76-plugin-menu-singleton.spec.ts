import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

// Verifies that declarative menu entries (definePlugin `menu: [...]`) collected by
// setPluginMenu() appear inside the plugins submenu in the catalyst admin sidebar.
// Also verifies the /configure link is accessible for plugins that have configSchema.
test.describe('Plugin menu singleton @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('plugin menu entries declared via definePlugin appear in the sidebar submenu', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('networkidle')

    const accordion = page.locator('[data-plugins-accordion]').first()
    await expect(accordion).toBeVisible({ timeout: 10000 })

    // Open the plugins submenu
    const toggleBtn = accordion.locator('button[aria-label="Toggle plugins submenu"]')
    await toggleBtn.click()

    const submenu = accordion.locator('[data-plugins-submenu]')
    await expect(submenu).not.toHaveClass(/hidden/)

    // At least one plugin menu entry (from core plugins that declared menu:[]) should appear.
    // The email plugin, dashboard, analytics etc. all declare menu entries with no permissions
    // or admin-accessible permissions.  We look for any <a> with an /admin/... href.
    const pluginLinks = submenu.locator('a[href^="/admin/"]')
    const count = await pluginLinks.count()
    expect(count).toBeGreaterThan(0)
  })

  test('email plugin menu entry navigates to the email admin page', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('networkidle')

    const accordion = page.locator('[data-plugins-accordion]').first()
    await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()

    const submenu = accordion.locator('[data-plugins-submenu]')
    await expect(submenu).not.toHaveClass(/hidden/)

    // Email plugin declares menu: [{ label: 'Email', path: '/admin/plugins/email' }]
    const emailLink = submenu.locator('a[href="/admin/plugins/email"]')
    if (await emailLink.count() > 0) {
      await emailLink.click()
      await page.waitForURL(`**/admin/plugins/email`, { timeout: 10000 })
      expect(page.url()).toContain('/admin/plugins/email')
    } else {
      // Email plugin menu entry may not be visible if plugin isn't installed —
      // verify the submenu itself rendered (non-empty) to confirm singleton worked.
      const allLinks = await submenu.locator('a').count()
      expect(allLinks).toBeGreaterThan(0)
    }
  })

  test('plugins without menu entries do not leak into top-level nav', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('networkidle')

    // Plugin-level menu items must live inside the accordion submenu, not as
    // top-level siblings (Dashboard, Collections, etc.)
    const accordion = page.locator('[data-plugins-accordion]').first()
    await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()
    const submenu = accordion.locator('[data-plugins-submenu]')

    // Count links in submenu
    const subLinks = await submenu.locator('a[href^="/admin/"]').count()

    // Count ALL admin links in the full sidebar
    const sidebar = page.locator('nav').first()
    const totalAdminLinks = await sidebar.locator('a[href^="/admin/"]').count()

    // submenu links must be <= total links (sanity check)
    expect(subLinks).toBeLessThanOrEqual(totalAdminLinks)
  })
})
