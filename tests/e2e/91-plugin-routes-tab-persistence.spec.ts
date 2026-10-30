import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Information tab - routes persistence @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('routes remain visible after saving settings via legacy settings tab', async ({ page }) => {
    // Navigate to example plugin info page
    await page.goto('/admin/plugins/example')
    await page.waitForLoadState('domcontentloaded')

    // Confirm Information tab shows routes before any save.
    // Tabs are anchors with ids `<tab>-tab`; the routes list renders each path as a
    // link, so match it exactly (several routes start with "/example").
    const infoTab = page.locator('#info-tab')
    await infoTab.click()
    await expect(page.getByText('Routes', { exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: '/example', exact: true })).toBeVisible()

    // Go to Settings tab and save without changing anything
    await page.locator('#settings-tab').click()
    const saveBtn = page.locator('#settings-content').getByRole('button', { name: /save/i }).first()
    await saveBtn.click()
    // The page auto-reloads ~1s after a successful save
    await expect(page.getByText('Settings saved successfully')).toBeVisible({ timeout: 15000 })
    await page.waitForTimeout(2500)
    await page.waitForLoadState('domcontentloaded')

    // Return to Information tab — routes must still be present
    await page.locator('#info-tab').click()
    await expect(page.getByText('Routes', { exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: '/example', exact: true })).toBeVisible()
  })

  test('POST /:id/settings preserves _routes in response body', async ({ page }) => {
    // Hit the API directly and confirm _routes survives a round-trip
    await page.goto('/admin/plugins/example')
    await page.waitForLoadState('domcontentloaded')
    await expect(page.locator('#info-tab')).toBeVisible()

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
    await page.waitForLoadState('domcontentloaded')

    const infoTab = page.locator('#info-tab')
    await infoTab.click()
    await expect(page.getByText('Routes', { exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: '/example', exact: true })).toBeVisible()
  })
})
