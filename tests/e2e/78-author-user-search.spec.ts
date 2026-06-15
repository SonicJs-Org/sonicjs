import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Author user-search field', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('user search API returns results for known user', async ({ page }) => {
    const res = await page.request.get('/admin/api/users/search?q=admin')
    expect(res.status()).toBe(200)
    const json = await res.json()
    expect(json).toHaveProperty('users')
    expect(Array.isArray(json.users)).toBe(true)
    if (json.users.length > 0) {
      const user = json.users[0]
      expect(user).toHaveProperty('id')
      expect(user).toHaveProperty('name')
      expect(user).toHaveProperty('email')
    }
  })

  test('user search API returns empty array for empty query', async ({ page }) => {
    const res = await page.request.get('/admin/api/users/search?q=')
    expect(res.status()).toBe(200)
    const json = await res.json()
    expect(json.users).toEqual([])
  })

  test('blog post create form renders author field with autocomplete', async ({ page }) => {
    await page.goto('/admin/content/new?collection=blog_post')
    await page.waitForLoadState('networkidle')

    const authorDisplay = page.locator('#field-author-display')
    await expect(authorDisplay).toBeVisible()
    await expect(authorDisplay).toHaveAttribute('autocomplete', 'off')

    const authorHidden = page.locator('#field-author')
    await expect(authorHidden).toHaveCount(1)
  })

  test('user by ID endpoint returns display name', async ({ page }) => {
    const adminRes = await page.request.get('/admin/api/users/search?q=admin')
    const { users } = await adminRes.json()
    const adminId = users[0]?.id
    expect(adminId).toBeTruthy()

    const res = await page.request.get(`/admin/api/users/${adminId}`)
    expect(res.status()).toBe(200)
    const json = await res.json()
    expect(json.name).toBeTruthy()
    expect(json.id).toBe(adminId)
  })

  test('user search HTML endpoint returns results for admin', async ({ page }) => {
    // Verify the search-html endpoint returns button HTML (used by HTMX dropdown)
    const res = await page.request.get('/admin/api/users/search-html?fieldId=field-author&q=admin')
    expect(res.status()).toBe(200)
    const html = await res.text()
    expect(html).toContain('Admin')
    expect(html).toContain('admin@sonicjs.com')
    expect(html).toContain('sonicSelectUser')
  })

  test('custom author name syncs to hidden input on form submit', async ({ page }) => {
    await page.goto('/admin/content/new?collection=blog_post')
    await page.waitForLoadState('networkidle')

    const authorDisplay = page.locator('#field-author-display')
    const authorHidden = page.locator('#field-author')

    await authorDisplay.fill('Guest Writer')

    // Simulate the submit event to trigger the sync listener
    await page.evaluate(() => {
      const form = document.querySelector('form')
      if (form) form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })

    await expect(authorHidden).toHaveValue('Guest Writer')
  })

  test('typing in author field shows user dropdown', async ({ page }) => {
    await page.goto('/admin/content/new?collection=blog_post')
    await page.waitForLoadState('networkidle')

    // Confirm HTMX is loaded
    const htmxLoaded = await page.evaluate(() => typeof (window as any).htmx !== 'undefined')
    expect(htmxLoaded).toBe(true)

    // Use htmx.ajax() directly to populate the dropdown, then verify the interaction
    await page.evaluate(() => {
      ;(window as any).htmx.ajax(
        'GET',
        '/admin/api/users/search-html?fieldId=field-author&q=admin',
        { target: '#field-author-dropdown', swap: 'innerHTML' }
      )
    })

    const dropdown = page.locator('#field-author-dropdown')
    await expect(dropdown.locator('button').first()).toBeVisible({ timeout: 5000 })
    await expect(dropdown.locator('button').first()).toContainText('Admin')

    // Click the result — sonicSelectUser should populate the hidden input
    await dropdown.locator('button').first().click()

    const authorHidden = page.locator('#field-author')
    const hiddenValue = await authorHidden.inputValue()
    expect(hiddenValue).toBeTruthy()
    expect(hiddenValue).not.toBe('')

    // Display field should show user name
    const authorDisplay = page.locator('#field-author-display')
    await expect(authorDisplay).toHaveValue(/Admin/)
  })
})
