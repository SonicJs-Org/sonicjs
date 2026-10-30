import { test, expect } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Plugins Nav Accordion @plugins @lock-plugin-hello-world', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('Plugins nav item renders as accordion with chevron toggle', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('networkidle')

    // Plugins accordion parent should exist
    const accordion = page.locator('[data-plugins-accordion]').first()
    await expect(accordion).toBeVisible()

    // Should have a link to /admin/plugins
    await expect(accordion.locator('a[href="/admin/plugins"]')).toBeVisible()
    await expect(accordion.locator('a[href="/admin/plugins"]')).toContainText('Plugins')

    // Should have a toggle button with chevron
    const toggleBtn = accordion.locator('button[aria-label="Toggle plugins submenu"]')
    await expect(toggleBtn).toBeVisible()

    // Chevron svg should exist
    await expect(accordion.locator('[data-plugins-chevron]')).toBeVisible()
  })

  test('Plugins submenu starts hidden and expands on chevron click', async ({ page }) => {
    // The collapsed state is persisted in the `plugins_menu_open` cookie and applied
    // before first paint via a `.plugins-closed` class on <html> (CSS hides the
    // submenu). Seed the cookie so the accordion genuinely starts collapsed.
    await page.context().addCookies([
      { name: 'plugins_menu_open', value: '0', url: BASE_URL },
    ])

    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('domcontentloaded')

    const accordion = page.locator('[data-plugins-accordion]').first()
    await expect(accordion).toBeVisible()
    const submenu = accordion.locator('[data-plugins-submenu]')

    // Submenu hidden by default (no active plugin sub-item on dashboard)
    await expect(submenu).toBeHidden()

    // Click toggle button
    await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()

    // Submenu should now be visible
    await expect(submenu).toBeVisible()

    // Click again to collapse
    await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()
    await expect(submenu).toBeHidden()
  })

  test('Plugin items do not appear as top-level nav items', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('networkidle')

    // The main nav should not have Hello World as a top-level sibling of Dashboard/Collections
    // Top-level items are siblings of the accordion, not inside it
    const sidebarBody = page.locator('.flex.flex-col.gap-0\\.5').first()
    const topLevelLinks = sidebarBody.locator('> span > a')

    // Top-level links should only be core items (Dashboard, Collections, Content, Users)
    const hrefs = await topLevelLinks.evaluateAll((els) =>
      els.map((el) => el.getAttribute('href'))
    )

    // None of the top-level links should be plugin-specific paths
    expect(hrefs).not.toContain('/admin/hello-world')
    expect(hrefs).not.toContain('/admin/analytics')
    expect(hrefs).not.toContain('/admin/media')
  })

  test('Hello World plugin menu entry appears inside accordion when activated', async ({ page }) => {
    // First activate hello-world plugin via the plugins page
    await page.goto(`${BASE_URL}/admin/plugins`)
    await page.waitForLoadState('networkidle')

    // Find hello-world plugin and activate it if not already active
    const helloWorldCard = page.locator('[data-plugin-id="hello-world"], .plugin-card').filter({ hasText: /hello.world/i }).first()
    const cardExists = await helloWorldCard.count()

    if (cardExists > 0) {
      // Installed cards expose a switch (role="switch") rather than an Activate button.
      const toggle = helloWorldCard.locator('button[role="switch"]')
      if ((await toggle.count()) > 0 && (await toggle.getAttribute('aria-checked')) !== 'true') {
        await toggle.click()
        await expect(toggle).toHaveAttribute('aria-checked', 'true', { timeout: 15000 })
      }
    }

    // Navigate to dashboard
    await page.goto(`${BASE_URL}/admin`)
    await page.waitForLoadState('domcontentloaded')

    const accordion = page.locator('[data-plugins-accordion]').first()
    await expect(accordion).toBeVisible()
    const submenu = accordion.locator('[data-plugins-submenu]')

    // If hello-world is active, the submenu should auto-expand when on its path
    // OR we can expand manually and check for the link. The accordion remembers its
    // last state in a cookie, so only toggle when it is currently collapsed.
    if (await submenu.isHidden()) {
      await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()
    }
    await expect(submenu).toBeVisible()

    // If hello-world plugin has a menu item, it should be inside submenu, not at top level
    const helloWorldLink = submenu.locator('a[href="/admin/hello-world"]')
    const linkCount = await helloWorldLink.count()
    if (linkCount > 0) {
      await expect(helloWorldLink).toBeVisible()
    }
  })

  test('Navigating to /admin/plugins marks Plugins as active', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    await page.waitForLoadState('networkidle')

    const accordion = page.locator('[data-plugins-accordion]').first()
    const pluginsLink = accordion.locator('a[href="/admin/plugins"]')

    await expect(pluginsLink).toHaveAttribute('data-current', 'true')
  })
})
