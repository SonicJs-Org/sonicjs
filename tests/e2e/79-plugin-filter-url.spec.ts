import { test, expect } from './fixtures'
import type { Page } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * A category or status checkbox is rendered `disabled` when no installed plugin falls into it
 * (admin-plugins-list.template.ts), and the categories are sorted by count descending — so the
 * enabled ones are whichever buckets this build's plugins actually occupy, and `#category-security`
 * is not guaranteed to be one of them.
 *
 * The three tests below used to cope with that by not testing: two bailed out through
 * `test.skip(true, 'No enabled category checkboxes found')` / `'Need at least 2 …'`, and the third
 * wrapped both of its assertions in `if (count > 0)`, so a page that rendered no filters at all
 * passed. Read the values off the page instead, and assert that they are there — a plugin list with
 * fewer than two occupied categories is a broken fixture, not a reason to skip.
 *
 * `networkidle` is also gone from this file: /admin/plugins pulls Tailwind, Alpine and HTMX from
 * CDNs and may never reach it, which in CI costs the test its whole budget before the first
 * assertion. Waiting for the control under test is both faster and a stronger statement.
 */

/** The filter checkboxes this build actually offers, in render order. */
function enabledFilters(page: Page, name: 'category' | 'status') {
  return page.locator(`input[name="${name}"]:not([disabled])`)
}

async function openPluginsList(page: Page) {
  await page.goto('/admin/plugins')
  await expect(page.locator('#search-input')).toBeVisible()
}

test.describe('Plugin Filter URL Persistence @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('URL updates when category filter is checked', async ({ page }) => {
    await openPluginsList(page)

    // Find a non-disabled category checkbox and click it
    const checkbox = enabledFilters(page, 'category').first()
    const categoryValue = await checkbox.getAttribute('value')
    await checkbox.check()

    // URL should now contain the category param
    await expect(page).toHaveURL(new RegExp(`category=${categoryValue}`))
  })

  test('URL updates when status filter is checked', async ({ page }) => {
    await openPluginsList(page)

    const checkbox = enabledFilters(page, 'status').first()
    const statusValue = await checkbox.getAttribute('value')
    await checkbox.check()

    await expect(page).toHaveURL(new RegExp(`status=${statusValue}`))
  })

  test('filter state is restored from URL on page load', async ({ page }) => {
    // Take the params off the page rather than hardcoding `category=security`, which is only
    // enabled when a security-category plugin happens to be installed.
    await openPluginsList(page)
    const categoryValue = await enabledFilters(page, 'category').first().getAttribute('value')
    const statusValue = await enabledFilters(page, 'status').first().getAttribute('value')
    expect(categoryValue, 'no enabled category filter rendered').toBeTruthy()
    expect(statusValue, 'no enabled status filter rendered').toBeTruthy()

    await page.goto(`/admin/plugins?category=${categoryValue}&status=${statusValue}`)

    await expect(page.locator(`#category-${categoryValue}`)).toBeChecked()
    await expect(page.locator(`#status-${statusValue}`)).toBeChecked()
  })

  test('filter state is retained after page reload', async ({ page }) => {
    await openPluginsList(page)

    // Check first available category checkbox
    const checkbox = enabledFilters(page, 'category').first()
    const categoryValue = await checkbox.getAttribute('value')
    expect(categoryValue, 'no enabled category filter rendered').toBeTruthy()

    await checkbox.check()
    await expect(page).toHaveURL(new RegExp(`category=${categoryValue}`))

    // Reload — URL params are preserved by the browser
    await page.reload()

    // Checkbox should be re-checked from URL
    await expect(page.locator(`#category-${categoryValue}`)).toBeChecked()
  })

  test('multiple category filters update URL with multiple params', async ({ page }) => {
    await openPluginsList(page)

    const checkboxes = enabledFilters(page, 'category')
    expect(
      await checkboxes.count(),
      'fewer than two categories are occupied by installed plugins'
    ).toBeGreaterThanOrEqual(2)

    await checkboxes.nth(0).check()
    await checkboxes.nth(1).check()

    const params = new URL(page.url()).searchParams.getAll('category')
    expect(params.length).toBe(2)
  })

  // The sort <select> was removed from /admin/plugins in "fix(plugins): remove
  // non-functional sort dropdown (#1007)". The remaining non-default-able control
  // that participates in URL state is the search box, so the two cases below cover
  // the same contract: a non-default value lands in the URL, the default does not.
  test('search text is reflected in URL', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('domcontentloaded')
    await expect(page.locator('#search-input')).toBeVisible()

    await page.fill('#search-input', 'turnstile')
    await expect(page).toHaveURL(/search=turnstile/)
  })

  test('default (empty) search is not added to URL', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('domcontentloaded')
    await expect(page.locator('#search-input')).toBeVisible()

    // Type then clear — back at the default the param must be gone again
    await page.fill('#search-input', 'turnstile')
    await expect(page).toHaveURL(/search=turnstile/)

    await page.fill('#search-input', '')
    await expect(page).not.toHaveURL(/search=/)
    expect(page.url()).not.toContain('search=')
  })
})
