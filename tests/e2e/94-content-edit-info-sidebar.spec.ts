import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Content edit - Content Info sidebar', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('dates show current year, not 1970', async ({ page }) => {
    // Navigate to content list and open first document-backed item
    await page.goto('/admin/content')
    await page.waitForSelector('table tbody tr', { timeout: 10000 })

    const firstEditLink = page.locator('table tbody tr a[href*="/edit"]').first()
    await firstEditLink.click()
    await page.waitForSelector('text=Content Info', { timeout: 10000 })

    const currentYear = new Date().getFullYear().toString()

    // All dates in the sidebar must show current year, not 1970
    const createdDt = page.locator('dl dt:has-text("Created") + dd')
    await expect(createdDt).not.toContainText('1970')
    await expect(createdDt).toContainText(currentYear)

    const modifiedDt = page.locator('dl dt:has-text("Last Modified") + dd')
    await expect(modifiedDt).not.toContainText('1970')
    await expect(modifiedDt).toContainText(currentYear)
  })

  test('author shows display name, not raw ID', async ({ page }) => {
    await page.goto('/admin/content')
    await page.waitForSelector('table tbody tr', { timeout: 10000 })

    const firstEditLink = page.locator('table tbody tr a[href*="/edit"]').first()
    await firstEditLink.click()
    await page.waitForSelector('text=Content Info', { timeout: 10000 })

    const authorDd = page.locator('dl dt:has-text("Author") + dd')
    const authorText = await authorDd.textContent()

    // Raw user IDs match pattern like "admin-<digits>-<alphanum>"
    expect(authorText).not.toMatch(/^admin-\d+-\w+$/)
    // Should show something meaningful (not empty, not "Unknown" if user exists)
    expect(authorText?.trim().length).toBeGreaterThan(0)
  })
})
