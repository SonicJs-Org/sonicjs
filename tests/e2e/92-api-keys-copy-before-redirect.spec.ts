import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('API Keys - copy key before redirect @api-keys', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('shows key banner after create without page reload', async ({ page }) => {
    await page.goto('/admin/plugins/api-keys')

    // Open create modal
    await page.getByRole('button', { name: 'Create API key' }).click()
    await expect(page.locator('#create-key-modal')).not.toHaveClass(/hidden/)

    // Fill form
    await page.locator('#new-key-name').fill('e2e-test-key')
    await page.getByRole('button', { name: 'Create' }).click()

    // Banner should appear with key value
    const banner = page.locator('#new-key-banner')
    await expect(banner).not.toHaveClass(/hidden/)

    const keyValue = page.locator('#new-key-value')
    const key = await keyValue.textContent()
    expect(key).toBeTruthy()
    expect(key!.length).toBeGreaterThan(10)

    // Page should NOT have reloaded yet (banner still visible)
    await expect(banner).not.toHaveClass(/hidden/)

    // Modal should be closed
    await expect(page.locator('#create-key-modal')).toHaveClass(/hidden/)
  })

  test('new key row appears in table without reload', async ({ page }) => {
    await page.goto('/admin/plugins/api-keys')

    const initialRowCount = await page.locator('#keys-tbody tr').count()

    await page.getByRole('button', { name: 'Create API key' }).click()
    await page.locator('#new-key-name').fill('e2e-table-row-test')
    await page.getByRole('button', { name: 'Create' }).click()

    // Banner visible
    await expect(page.locator('#new-key-banner')).not.toHaveClass(/hidden/)

    // Table row added without reload
    await expect(page.locator('#keys-tbody tr')).toHaveCount(initialRowCount + 1)
  })

  test('copy & dismiss button hides the banner', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await page.goto('/admin/plugins/api-keys')

    await page.getByRole('button', { name: 'Create API key' }).click()
    await page.locator('#new-key-name').fill('e2e-copy-dismiss-test')
    await page.getByRole('button', { name: 'Create' }).click()

    await expect(page.locator('#new-key-banner')).not.toHaveClass(/hidden/)

    await page.getByRole('button', { name: 'Copy & dismiss' }).click()

    // Banner should hide after copy
    await expect(page.locator('#new-key-banner')).toHaveClass(/hidden/)
  })

  test('dismiss X button hides banner without copy', async ({ page }) => {
    await page.goto('/admin/plugins/api-keys')

    await page.getByRole('button', { name: 'Create API key' }).click()
    await page.locator('#new-key-name').fill('e2e-dismiss-x-test')
    await page.getByRole('button', { name: 'Create' }).click()

    await expect(page.locator('#new-key-banner')).not.toHaveClass(/hidden/)

    // Click × button
    await page.locator('#new-key-banner button').first().click()

    await expect(page.locator('#new-key-banner')).toHaveClass(/hidden/)
  })
})
