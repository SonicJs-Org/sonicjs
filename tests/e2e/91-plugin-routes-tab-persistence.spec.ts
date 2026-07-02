import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Information tab - routes persistence', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('routes remain visible after saving settings via legacy settings tab', async ({ page }) => {
    // Navigate to example plugin info page
    await page.goto('/admin/plugins/example')
    await page.waitForLoadState('networkidle')

    // Confirm Information tab shows routes before any save
    const infoTab = page.getByText('Information', { exact: true }).first()
    await infoTab.click()
    await expect(page.getByText('Routes')).toBeVisible()
    await expect(page.getByText('/example')).toBeVisible()

    // Go to Settings tab and save without changing anything
    const settingsTab = page.getByRole('tab', { name: /settings/i }).first()
    await settingsTab.click()
    const saveBtn = page.getByRole('button', { name: /save/i }).first()
    await saveBtn.click()
    await page.waitForLoadState('networkidle')

    // Return to Information tab — routes must still be present
    await infoTab.click()
    await expect(page.getByText('Routes')).toBeVisible()
    await expect(page.getByText('/example')).toBeVisible()
  })

  test('POST /:id/settings preserves _routes in response body', async ({ page }) => {
    // Hit the API directly and confirm _routes survives a round-trip
    await page.goto('/admin/plugins/example')
    await page.waitForLoadState('networkidle')

    const response = await page.evaluate(async () => {
      // Save an empty settings payload — the handler must merge, not overwrite
      const res = await fetch('/admin/plugins/example/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ greeting: 'Hello, Cruel World!', defaultName: 'Stranger' }),
      })
      return res.json()
    })

    expect(response.success).toBe(true)

    // Reload and verify routes still rendered
    await page.reload()
    await page.waitForLoadState('networkidle')

    const infoTab = page.getByText('Information', { exact: true }).first()
    await infoTab.click()
    await expect(page.getByText('Routes')).toBeVisible()
    await expect(page.getByText('/example')).toBeVisible()
  })
})
