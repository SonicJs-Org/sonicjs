import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * #971 — Disabled plugins must not appear in the admin sidebar.
 *
 * A plugin disabled via /admin/plugins should have its sidebar link removed
 * immediately; re-enabling it should restore the link.
 */
test.describe('Disabled plugin hidden from sidebar (#971)', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('disabling a plugin removes it from the sidebar', async ({ page }) => {
    // Find a plugin that has an admin sidebar entry. Core-media is a safe choice.
    const pluginId = 'core-media'

    // First ensure it's enabled
    await page.request.post(`/admin/plugins/${pluginId}/enable`, {
      headers: { 'Content-Type': 'application/json' },
    })

    await page.goto('/admin')
    await page.waitForLoadState('networkidle')

    // Sidebar should have a link for this plugin (e.g. /admin/media)
    const mediaLink = page.locator('nav a[href="/admin/media"]')
    await expect(mediaLink).toBeVisible()

    // Disable the plugin
    await page.goto(`/admin/plugins/${pluginId}`)
    await page.waitForLoadState('networkidle')

    const disableBtn = page.locator('button:has-text("Disable"), button[data-action="disable"]').first()
    if (await disableBtn.count() > 0) {
      await disableBtn.click()
      await page.waitForLoadState('networkidle')
    } else {
      // Use direct API
      await page.request.post(`/admin/plugins/${pluginId}/disable`, {
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // Reload admin — sidebar should no longer show the media link
    await page.goto('/admin')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('nav a[href="/admin/media"]')).toHaveCount(0)

    // Re-enable to restore state
    await page.request.post(`/admin/plugins/${pluginId}/enable`, {
      headers: { 'Content-Type': 'application/json' },
    })
  })
})
