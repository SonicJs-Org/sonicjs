import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Filter URL Persistence', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('URL updates when category filter is checked', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Find a non-disabled category checkbox and click it
    const checkbox = page.locator('input[name="category"]:not([disabled])').first()
    const categoryValue = await checkbox.getAttribute('value')
    await checkbox.check()

    // URL should now contain the category param
    await expect(page).toHaveURL(new RegExp(`category=${categoryValue}`))
  })

  test('URL updates when status filter is checked', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    const checkbox = page.locator('input[name="status"]:not([disabled])').first()
    const statusValue = await checkbox.getAttribute('value')
    await checkbox.check()

    await expect(page).toHaveURL(new RegExp(`status=${statusValue}`))
  })

  test('filter state is restored from URL on page load', async ({ page }) => {
    // Navigate with pre-set URL params
    await page.goto('/admin/plugins?category=security&status=active')
    await page.waitForLoadState('networkidle')

    // Checkboxes should be checked based on URL params
    const securityCb = page.locator('#category-security')
    const activeCb = page.locator('#status-active')

    // Only check if these categories/statuses exist on the page
    if (await securityCb.count() > 0) {
      await expect(securityCb).toBeChecked()
    }
    if (await activeCb.count() > 0) {
      await expect(activeCb).toBeChecked()
    }
  })

  test('filter state is retained after page reload', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Check first available category checkbox
    const checkbox = page.locator('input[name="category"]:not([disabled])').first()
    const categoryValue = await checkbox.getAttribute('value')

    if (!categoryValue) {
      test.skip(true, 'No enabled category checkboxes found')
      return
    }

    await checkbox.check()
    await expect(page).toHaveURL(new RegExp(`category=${categoryValue}`))

    // Reload — URL params are preserved by the browser
    await page.reload()
    await page.waitForLoadState('networkidle')

    // Checkbox should be re-checked from URL
    const reloadedCheckbox = page.locator(`#category-${categoryValue}`)
    if (await reloadedCheckbox.count() > 0 && !(await reloadedCheckbox.isDisabled())) {
      await expect(reloadedCheckbox).toBeChecked()
    }
  })

  test('multiple category filters update URL with multiple params', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    const checkboxes = page.locator('input[name="category"]:not([disabled])')
    const count = await checkboxes.count()

    if (count < 2) {
      test.skip(true, 'Need at least 2 enabled category checkboxes')
      return
    }

    await checkboxes.nth(0).check()
    await checkboxes.nth(1).check()

    const url = page.url()
    const params = new URL(url).searchParams.getAll('category')
    expect(params.length).toBe(2)
  })

  test('sort selection is reflected in URL', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    await page.selectOption('#sort-filter', 'name-desc')
    await expect(page).toHaveURL(/sort=name-desc/)
  })

  test('default sort (name-asc) is not added to URL', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    await page.selectOption('#sort-filter', 'name-asc')
    const url = page.url()
    expect(url).not.toContain('sort=')
  })
})
