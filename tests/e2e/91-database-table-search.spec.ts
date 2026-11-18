import { test, expect } from './fixtures'
import type { Page } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * A cell whose value is JSON (or longer than 120 chars) renders as a button carrying the raw value
 * in `data-json-val` — see `jsonButton` in admin-database-table.template.ts. The two modal tests
 * used to match on `button.text-indigo-600, button.text-indigo-400` and bail out through a bare
 * `test.skip()` when that found nothing, which turned both a restyle and an empty table into a
 * silent pass. `documents.data` is JSON on every row, so the button is always there.
 */
function jsonCellButton(page: Page) {
  return page.locator('button[data-json-val]').first()
}

test.describe('Database Table Viewer — Search & JSON Browser @database', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('table viewer loads and shows search bar', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents')
    await expect(page.locator('#searchInput')).toBeVisible()
    await expect(page.locator('#searchInput')).toHaveAttribute('placeholder', /search/i)
  })

  test('search filters rows via URL param', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents?search=blog')
    // Shows filtered badge
    await expect(page.locator('text=blog').first()).toBeVisible()
    // Search input pre-filled
    const input = page.locator('#searchInput')
    await expect(input).toHaveValue('blog')
  })

  test('pressing Enter in search navigates with search param', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents')
    await page.locator('#searchInput').fill('test')
    await page.locator('#searchInput').press('Enter')
    await expect(page).toHaveURL(/search=test/)
  })

  test('Search button navigates with search param', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents')
    await page.locator('#searchInput').fill('hello')
    // Exact match: JSON cells can render buttons whose accessible name contains "Search".
    await page.getByRole('button', { name: 'Search', exact: true }).click()
    await expect(page).toHaveURL(/search=hello/)
  })

  test('clear search button removes search param', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents?search=blog')
    const clearBtn = page.locator('button[title="Clear search"]')
    await expect(clearBtn).toBeVisible()
    await clearBtn.click()
    await expect(page).not.toHaveURL(/search=/)
  })

  test('empty search shows all rows without filter', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents')
    const input = page.locator('#searchInput')
    await expect(input).toHaveValue('')
    // No "Filtered:" badge visible
    await expect(page.locator('text=Filtered:')).not.toBeVisible()
  })

  test('JSON modal closes on backdrop click', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents')
    const jsonBtn = jsonCellButton(page)
    await expect(jsonBtn).toBeVisible()
    await jsonBtn.click()
    await expect(page.locator('#jsonModal')).not.toHaveClass(/hidden/)
    // Click backdrop (outside modal panel)
    await page.mouse.click(10, 10)
    await expect(page.locator('#jsonModal')).toHaveClass(/hidden/)
  })

  test('JSON modal closes on Escape key', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents')
    const jsonBtn = jsonCellButton(page)
    await expect(jsonBtn).toBeVisible()
    await jsonBtn.click()
    await page.keyboard.press('Escape')
    await expect(page.locator('#jsonModal')).toHaveClass(/hidden/)
  })

  test('search preserved across page navigation', async ({ page }) => {
    // `search=doc` matched by luck — whether it produced a second page depended on what the rest
    // of the suite had written — and the whole body sat inside `if (pagination.count() > 0)`, so a
    // single-page result reported a pass. Every documents row carries `tenant_id = 'default'`
    // (migration 0002), so this term matches all of them and five per page guarantees a page 2.
    await page.goto('/admin/database-tools/tables/documents?search=default&pageSize=5')

    // The `sm:hidden` Previous/Next pair is invisible at desktop width; the visible control is the
    // desktop pagination nav, whose Next button is labelled by an sr-only span.
    const pagination = page.locator('nav[aria-label="Pagination"]')
    await expect(pagination).toBeVisible()

    const nextBtn = pagination.getByRole('button', { name: 'Next' })
    await expect(nextBtn).toBeEnabled()
    await nextBtn.click()
    await expect(page).toHaveURL(/search=default/)
    await expect(page).toHaveURL(/page=2/)
  })

  test('search preserved when changing page size', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents?search=doc')
    await page.locator('#pageSize').selectOption('50')
    await expect(page).toHaveURL(/search=doc/)
  })

  test('search preserved when sorting columns', async ({ page }) => {
    await page.goto('/admin/database-tools/tables/documents?search=doc')
    const firstHeader = page.locator('thead th').first()
    await firstHeader.click()
    await expect(page).toHaveURL(/search=doc/)
  })
})
