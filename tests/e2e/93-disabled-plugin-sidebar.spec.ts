import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * #971 — Disabled plugins must not appear in the admin sidebar.
 *
 * A plugin disabled via /admin/plugins should have its sidebar link removed
 * immediately; re-enabling it should restore the link.
 */
test.describe('Disabled plugin hidden from sidebar (#971) @plugins @lock-plugin-hello-world', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  // Always re-enable core-media in case the test fails mid-execution
  test.afterEach(async ({ page }) => {
    await page.request.post('/admin/plugins/core-media/enable', {
      headers: { 'Content-Type': 'application/json' },
    }).catch(() => {})
  })

  test('disabling a plugin removes it from the sidebar', async ({ page }) => {
    // Find an installed, non-core plugin that has an admin sidebar entry.
    // hello-world is a demo plugin, so toggling it has no functional side effects.
    // (core-media is currently uninstalled, so it contributes no sidebar entry.)
    const pluginId = 'hello-world'
    const sidebarHref = '/admin/hello-world'
    // The enable/disable endpoints are /activate and /deactivate.
    const enable = () =>
      page.request.post(`/admin/plugins/${pluginId}/activate`, {
        headers: { 'Content-Type': 'application/json' },
      })

    try {
      // First ensure it's enabled
      expect((await enable()).ok()).toBe(true)

      await page.goto('/admin')
      await page.waitForLoadState('domcontentloaded')

      // Sidebar should have a link for this plugin. The layout renders both a desktop
      // and a mobile <nav>; the desktop one comes first and is the visible one.
      const pluginLink = page.locator(`nav a[href="${sidebarHref}"]`).first()
      await expect(pluginLink).toBeVisible()

      // Disable the plugin
      await page.goto(`/admin/plugins/${pluginId}`)
      await page.waitForLoadState('domcontentloaded')

      const disableBtn = page.getByRole('button', { name: 'Deactivate', exact: true })
      if (await disableBtn.count() > 0) {
        await disableBtn.click()
        // The detail page reloads ~1s after a successful toggle
        await expect(page.getByRole('button', { name: 'Activate', exact: true })).toBeVisible({
          timeout: 20000,
        })
      } else {
        // Use direct API
        const res = await page.request.post(`/admin/plugins/${pluginId}/deactivate`, {
          headers: { 'Content-Type': 'application/json' },
        })
        expect(res.ok()).toBe(true)
      }

      // Reload admin — sidebar should no longer show the plugin link
      await page.goto('/admin')
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator(`nav a[href="${sidebarHref}"]`)).toHaveCount(0)
    } finally {
      // Re-enable to restore state
      await enable()
    }

    // …and the link comes back once the plugin is enabled again
    await page.goto('/admin')
    await page.waitForLoadState('domcontentloaded')
    await expect(page.locator(`nav a[href="${sidebarHref}"]`).first()).toBeVisible()
  })
})
