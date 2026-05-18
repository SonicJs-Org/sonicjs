import { test, expect } from '@playwright/test'
import { ensureAdminUserExists, loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin settings activity log', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('should show a readable activity entry after saving cache plugin settings', async ({ page }) => {
    await page.goto('/admin/plugins/core-cache')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('h1')).toContainText('Plugin Settings')
    await expect(page.locator('button#save-button')).toBeVisible()

    const defaultTtlField = page.locator('input#setting_defaultTTL')
    await expect(defaultTtlField).toBeVisible()

    await defaultTtlField.fill('3601')

    const saveResponsePromise = page.waitForResponse((response) => {
      return response.url().includes('/admin/plugins/core-cache/settings')
        && response.request().method() === 'POST'
    })

    await page.click('button#save-button')
    await saveResponsePromise

    await expect(page.locator('text=Settings saved successfully')).toBeVisible({ timeout: 10000 })
    await page.waitForTimeout(1500)
    await page.waitForLoadState('networkidle')

    await expect(page.locator('input#setting_defaultTTL')).toHaveValue('3601')

    await page.click('#activity-tab')

    const activityContent = page.locator('#activity-content')
    await expect(activityContent).toBeVisible()
    await expect(activityContent.locator('h2')).toContainText('Activity Log')
    await expect(activityContent).toContainText('settings updated')
  })
})
