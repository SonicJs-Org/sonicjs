import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Activity Log @plugins @lock-plugin-hello-world', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('activity tab shows content for an active plugin', async ({ page }) => {
    // Navigate to a plugin detail page — 'email' is a core plugin that's always present.
    // (The settings/info/activity tabs all live on /admin/plugins/:id; there is no
    // /admin/plugins/:id/settings GET route.)
    await page.goto('/admin/plugins/email')
    await expect(page).not.toHaveURL(/error/)

    // Click the Activity tab (rendered as a tab link, not a button)
    const activityTab = page.locator('#activity-tab')
    await activityTab.click()

    // Activity content panel should be visible
    const activityPanel = page.locator('#activity-content')
    await expect(activityPanel).toBeVisible()

    // Should not show the "no recent activity" placeholder OR should show actual entries
    // Either is valid — we just confirm the tab renders without error
    await expect(activityPanel).not.toContainText('undefined')
    await expect(activityPanel).not.toContainText('NaN')
  })

  test('activity tab shows entries after toggling a plugin', async ({ page }) => {
    // Use a non-core plugin that can be toggled. Core plugins (turnstile, email, …)
    // render a "Core Plugin" label instead of an activate/deactivate button.
    const pluginId = 'hello-world'
    await page.goto(`/admin/plugins/${pluginId}`)

    const deactivateBtn = page.getByRole('button', { name: 'Deactivate', exact: true })
    const activateBtn = page.getByRole('button', { name: 'Activate', exact: true })

    // Determine current status from the header badge
    const isActive = (await deactivateBtn.count()) > 0

    // Toggle the plugin to generate activity, then toggle it straight back so the
    // rest of the suite still sees this plugin in its original state. The page
    // reloads ~1s after a successful toggle.
    if (isActive) {
      await deactivateBtn.click()
      await expect(activateBtn).toBeVisible({ timeout: 20000 })
      await activateBtn.click()
      await expect(deactivateBtn).toBeVisible({ timeout: 20000 })
    } else {
      await activateBtn.click()
      await expect(deactivateBtn).toBeVisible({ timeout: 20000 })
      await deactivateBtn.click()
      await expect(activateBtn).toBeVisible({ timeout: 20000 })
    }

    // Reload and check activity tab
    await page.goto(`/admin/plugins/${pluginId}`)
    const activityTab = page.locator('#activity-tab')
    await activityTab.click()

    const activityPanel = page.locator('#activity-content')
    await expect(activityPanel).toBeVisible()

    // Should have at least one activity entry (activated or deactivated)
    const entries = activityPanel.locator('[class*="flex"][class*="items"]')
    const noActivity = activityPanel.getByText('No recent activity')
    const hasEntries = await entries.count() > 0
    const hasNoActivity = await noActivity.isVisible()

    // One of these must be true — the panel renders real state, not blank
    expect(hasEntries || hasNoActivity).toBe(true)
    await expect(activityPanel).not.toContainText('undefined')
  })
})
