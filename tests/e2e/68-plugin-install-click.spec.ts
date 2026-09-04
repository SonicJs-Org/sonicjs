import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Install Click Behavior @smoke @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('uninstalled plugin detail page shows Install button instead of auto-installing @plugins', async ({ page }) => {
    // Ensure hello-world is uninstalled so we have a known test target
    await page.request.post('/admin/plugins/hello-world/uninstall', {
      headers: { 'Content-Type': 'application/json' },
    }).catch(() => {})

    // Navigate directly to the uninstalled plugin's detail page
    await page.goto('/admin/plugins/hello-world')
    await page.waitForLoadState('networkidle')

    // Should show Install button — NOT auto-install the plugin
    const installButton = page.locator('button', { hasText: 'Install' })
    await expect(installButton).toBeVisible({ timeout: 10000 })

    // Should NOT show Activate or Deactivate buttons (plugin was not auto-installed)
    await expect(page.locator('button', { hasText: 'Activate' })).toHaveCount(0)
    await expect(page.locator('button', { hasText: 'Deactivate' })).toHaveCount(0)

    // Verify plugin still shows as uninstalled on list page
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    const helloWorldCard = page.locator('.plugin-card').filter({
      has: page.locator('h3', { hasText: 'Hello World' })
    }).locator('.status-badge')

    await expect(helloWorldCard).toContainText('Uninstalled')
  })

  test('install button on detail page installs plugin @plugins', async ({ page }) => {
    // Ensure hello-world is uninstalled
    await page.request.post('/admin/plugins/hello-world/uninstall', {
      headers: { 'Content-Type': 'application/json' },
    }).catch(() => {})

    // Navigate to detail page
    await page.goto('/admin/plugins/hello-world')
    await page.waitForLoadState('networkidle')

    // Click Install button
    const installButton = page.locator('button', { hasText: 'Install' })
    await expect(installButton).toBeVisible({ timeout: 10000 })
    await installButton.click()

    // Wait for page reload after install
    await page.waitForLoadState('networkidle')
    await page.waitForTimeout(2000)

    // After reload, plugin should show as Active or Inactive (not Uninstalled)
    const statusBadge = page.locator('span').filter({ hasText: /^(Active|Inactive)$/ })
    await expect(statusBadge.first()).toBeVisible({ timeout: 10000 })
  })
})
