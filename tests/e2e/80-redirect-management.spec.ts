import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

// Unique per-test sources — use index to avoid collisions between tests
const BASE_TS = Date.now()
const src = (n: number) => `/e2e-redir-${BASE_TS}-${n}`

test.describe('Redirect Management', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('admin/redirects page loads', async ({ page }) => {
    await page.goto('/admin/redirects')
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveURL('/admin/redirects')
    await expect(page.locator('h1')).toContainText('Redirects')
  })

  test('can navigate to new redirect form', async ({ page }) => {
    await page.goto('/admin/redirects')
    await page.waitForLoadState('networkidle')
    await page.click('a[href="/admin/redirects/new"]')
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveURL('/admin/redirects/new')
    await expect(page.locator('form')).toBeVisible()
  })

  test('can create a redirect and it appears in list', async ({ page }) => {
    const source = src(1)
    await page.goto('/admin/redirects/new')
    await page.waitForLoadState('networkidle')

    await page.fill('input[name="source"]', source)
    await page.fill('input[name="destination"]', '/destination-1')
    await page.selectOption('select[name="status_code"]', '301')

    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    await expect(page).toHaveURL('/admin/redirects')
    await expect(page.locator(`[data-source="${source}"]`)).toBeVisible()
  })

  test('redirect actually redirects HTTP requests', async ({ page, request }) => {
    const source = src(2)
    const destination = '/destination-2'

    // Create the redirect via admin UI
    await page.goto('/admin/redirects/new')
    await page.waitForLoadState('networkidle')
    await page.fill('input[name="source"]', source)
    await page.fill('input[name="destination"]', destination)
    await page.selectOption('select[name="status_code"]', '301')
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    // Verify redirect is in the list
    await expect(page.locator(`[data-source="${source}"]`)).toBeVisible()

    // Test that the redirect actually fires (no redirect following)
    const response = await request.get(source, { maxRedirects: 0 })
    expect(response.status()).toBe(301)
    expect(response.headers()['location']).toContain(destination)
  })

  test('can edit a redirect', async ({ page }) => {
    const source = src(3)
    const originalDest = '/original-destination-3'
    const updatedDest = '/updated-destination-3'

    // Create
    await page.goto('/admin/redirects/new')
    await page.waitForLoadState('networkidle')
    await page.fill('input[name="source"]', source)
    await page.fill('input[name="destination"]', originalDest)
    await page.selectOption('select[name="status_code"]', '301')
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    // Click edit in the row
    const row = page.locator(`[data-source="${source}"]`)
    await row.locator('a[href*="/edit"]').click()
    await page.waitForLoadState('networkidle')
    await expect(page.url()).toMatch(/\/admin\/redirects\/.+\/edit/)

    // Update destination
    await page.fill('input[name="destination"]', updatedDest)
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    await expect(page).toHaveURL('/admin/redirects')
    await expect(page.locator(`[data-destination="${updatedDest}"]`)).toBeVisible()
  })

  test('can delete a redirect', async ({ page }) => {
    const source = src(4)

    // Create
    await page.goto('/admin/redirects/new')
    await page.waitForLoadState('networkidle')
    await page.fill('input[name="source"]', source)
    await page.fill('input[name="destination"]', '/destination-4')
    await page.selectOption('select[name="status_code"]', '301')
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    await expect(page.locator(`[data-source="${source}"]`)).toBeVisible()

    // Click delete button — opens a <dialog>, NOT a native confirm
    const row = page.locator(`[data-source="${source}"]`)
    await row.locator('button', { hasText: 'Delete' }).click()

    // Confirm in the <dialog> element
    await page.locator('#confirmDeleteBtn').click()
    await page.waitForLoadState('networkidle')

    // Row should be gone after page refresh or HTMX removal
    await page.goto('/admin/redirects')
    await page.waitForLoadState('networkidle')
    await expect(page.locator(`[data-source="${source}"]`)).not.toBeVisible()
  })

  test('shows error for duplicate source URL', async ({ page }) => {
    const source = src(5)

    // Create first
    await page.goto('/admin/redirects/new')
    await page.waitForLoadState('networkidle')
    await page.fill('input[name="source"]', source)
    await page.fill('input[name="destination"]', '/destination-5a')
    await page.selectOption('select[name="status_code"]', '301')
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    // Try creating same source again
    await page.goto('/admin/redirects/new')
    await page.waitForLoadState('networkidle')
    await page.fill('input[name="source"]', source)
    await page.fill('input[name="destination"]', '/destination-5b')
    await page.selectOption('select[name="status_code"]', '301')
    await page.click('button[type="submit"]')

    // Wait for HTMX to insert the error into #form-messages
    await page.waitForTimeout(1000)

    // Error message should appear in the form-messages div
    await expect(page.locator('#form-messages')).toBeVisible()
    await expect(page.locator('#form-messages div')).toBeVisible()
  })
})
