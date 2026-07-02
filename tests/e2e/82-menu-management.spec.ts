import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Menu Management', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('admin menu page loads and shows seeded system items', async ({ page }) => {
    const resp = await page.goto(`${BASE_URL}/admin/menu`)
    await page.waitForLoadState('networkidle')

    expect(resp?.status()).not.toBe(404)
    expect(resp?.status()).not.toBe(500)

    const body = (await page.locator('body').textContent()) || ''
    // System items should be seeded and visible
    expect(body).toContain('Content')
    expect(body).toContain('Collections')
    expect(body).toContain('Users')
    expect(body).toContain('Settings')
  })

  test('can add a custom top-level link', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/menu/new`)
    await page.waitForLoadState('networkidle')

    await page.fill('input[name="label"]', 'Resources')
    await page.fill('input[name="url"]', 'https://docs.sonicjs.com')

    // Set target blank
    await page.selectOption('select[name="target"]', '_blank')

    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    // Should redirect back to list
    expect(page.url()).toContain('/admin/menu')
    const body = (await page.locator('body').textContent()) || ''
    expect(body).toContain('Resources')
  })

  test('cannot delete a system menu item via API', async ({ page, request }) => {
    // Get list to find a system item ID
    await page.goto(`${BASE_URL}/admin/menu`)
    await page.waitForLoadState('networkidle')

    // Try to delete a system item via API — should 403
    const sessionCookies = await page.context().cookies()
    const cookieHeader = sessionCookies.map((c) => `${c.name}=${c.value}`).join('; ')

    // Get CSRF token from cookie
    const csrfCookie = sessionCookies.find((c) => c.name === 'csrf_token')
    const csrfToken = csrfCookie?.value || ''

    // Find a system item id from the page HTML
    const html = await page.content()
    const systemIdMatch = html.match(/\/admin\/menu\/([^"']+)\/move-up/)
    if (systemIdMatch) {
      const itemId = systemIdMatch[1]
      const deleteResp = await request.delete(`${BASE_URL}/admin/menu/${itemId}`, {
        headers: {
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      })
      // System items return 403
      expect([403, 302]).toContain(deleteResp.status())
    }
  })

  test('hide and show a menu item', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/menu`)
    await page.waitForLoadState('networkidle')

    // Find the visibility toggle form for Settings
    const settingsRow = page.locator('tr', { hasText: 'Settings' }).first()
    const visibleCheckbox = settingsRow.locator('input[name="visible"]')

    if (await visibleCheckbox.count() > 0) {
      // Toggle visibility
      const toggleForm = settingsRow.locator('form').first()
      await toggleForm.evaluate((f: HTMLFormElement) => f.submit())
      await page.waitForLoadState('networkidle')

      const body = (await page.locator('body').textContent()) || ''
      expect(body).toContain('Visibility updated')
    }
  })

  test('sidebar shows data-driven items after menu plugin seeds', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')

    const nav = page.locator('nav')
    const navText = await nav.textContent() || ''

    // The data-driven sidebar should contain the seeded system items
    expect(navText).toContain('Content')
  })

  test('add item form rejects empty label', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/menu/new`)
    await page.waitForLoadState('networkidle')

    // Submit without label
    await page.fill('input[name="url"]', '/some/path')
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')

    const body = (await page.locator('body').textContent()) || ''
    expect(body).toContain('Label is required')
  })
})
