/**
 * Cache Plugin — Collection Settings Tab
 *
 * Verifies the Collection Settings tab on /admin/cache renders per-collection
 * cache config rows with clickable API path links that open in a new tab.
 */

import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Cache — Collection Settings tab', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/cache')
  })

  test('Collection Settings tab is present and activatable', async ({ page }) => {
    const tab = page.getByRole('button', { name: /collection settings/i })
    await expect(tab).toBeVisible()
    await tab.click()

    // Tab panel becomes visible
    const panel = page.locator('#tab-panel-collection-settings')
    await expect(panel).toBeVisible()
  })

  test('collection rows render with API path links', async ({ page }) => {
    await page.getByRole('button', { name: /collection settings/i }).click()

    // At least one API path link should exist
    const links = page.locator('#tab-panel-collection-settings a[href^="/api/"]')
    await expect(links.first()).toBeVisible()
  })

  test('API path links open in new tab', async ({ page }) => {
    await page.getByRole('button', { name: /collection settings/i }).click()

    const links = page.locator('#tab-panel-collection-settings a[href^="/api/"]')
    const count = await links.count()
    expect(count).toBeGreaterThan(0)

    // Every link must have target="_blank" and rel containing "noopener"
    for (let i = 0; i < count; i++) {
      const link = links.nth(i)
      await expect(link).toHaveAttribute('target', '_blank')
      const rel = await link.getAttribute('rel')
      expect(rel).toContain('noopener')
    }
  })

  test('blog-posts collection has correct /api/blog-posts link', async ({ page }) => {
    await page.getByRole('button', { name: /collection settings/i }).click()

    const link = page.locator('#tab-panel-collection-settings a[href="/api/blog-posts"]')
    await expect(link).toBeVisible()
    await expect(link).toHaveAttribute('target', '_blank')
  })

  test('API path link navigates to correct endpoint', async ({ page, context }) => {
    await page.getByRole('button', { name: /collection settings/i }).click()

    const links = page.locator('#tab-panel-collection-settings a[href^="/api/"]')
    const href = await links.first().getAttribute('href')
    expect(href).toBeTruthy()

    // Open in new page to verify endpoint responds
    const newPage = await context.newPage()
    const response = await newPage.goto(href!)
    expect(response?.status()).toBeLessThan(500)
    await newPage.close()
  })
})
