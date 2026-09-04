import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Install Click Behavior @smoke @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('clicking uninstalled plugin card navigates to detail page without auto-installing @plugins', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Find an uninstalled plugin card (status badge says "Uninstalled")
    const uninstalledCard = page.locator('.plugin-card').filter({
      has: page.locator('.status-badge', { hasText: 'Uninstalled' })
    }).first()

    const cardExists = await uninstalledCard.count() > 0
    test.skip(!cardExists, 'No uninstalled plugins available to test')

    // Get plugin name before clicking
    const pluginName = await uninstalledCard.locator('h3').textContent()

    // Click the card — should navigate to detail page
    await uninstalledCard.click()
    await page.waitForLoadState('networkidle')

    // Should be on plugin detail page
    await expect(page).toHaveURL(/\/admin\/plugins\//)

    // Should show "Uninstalled" status badge on detail page
    const statusBadge = page.locator('span').filter({ hasText: 'Uninstalled' })
    await expect(statusBadge).toBeVisible()

    // Should show Install button (not Activate/Deactivate)
    const installButton = page.locator('button', { hasText: 'Install' })
    await expect(installButton).toBeVisible()

    // Should NOT show Activate or Deactivate buttons
    const activateButton = page.locator('button', { hasText: 'Activate' })
    const deactivateButton = page.locator('button', { hasText: 'Deactivate' })
    await expect(activateButton).toHaveCount(0)
    await expect(deactivateButton).toHaveCount(0)

    // Go back to plugins list — plugin should still show as uninstalled
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    const stillUninstalled = page.locator('.plugin-card').filter({
      has: page.locator('h3', { hasText: pluginName! })
    }).locator('.status-badge')

    await expect(stillUninstalled).toContainText('Uninstalled')
  })

  test('install button on detail page installs plugin @plugins', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Find an uninstalled non-core plugin
    const uninstalledCard = page.locator('.plugin-card').filter({
      has: page.locator('.status-badge', { hasText: 'Uninstalled' })
    }).first()

    const cardExists = await uninstalledCard.count() > 0
    test.skip(!cardExists, 'No uninstalled plugins available to test')

    // Navigate to detail page
    await uninstalledCard.click()
    await page.waitForLoadState('networkidle')

    // Click Install button
    const installButton = page.locator('button', { hasText: 'Install' })
    await expect(installButton).toBeVisible()
    await installButton.click()

    // Wait for page reload after install
    await page.waitForLoadState('networkidle')
    await page.waitForTimeout(2000)

    // After reload, plugin should no longer show "Uninstalled"
    const statusBadge = page.locator('span').filter({ hasText: /^(Active|Inactive)$/ })
    await expect(statusBadge.first()).toBeVisible({ timeout: 5000 })
  })
})
