import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Content title preserved after edit @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('editing Example item (no title in schema) preserves title on list page', async ({ page }) => {
    // Example collection schema has name/emoji/description but NO title property.
    // Title is derived from data.name on save. This test verifies that editing
    // an item doesn't replace its title with the document ID.

    // Navigate to Example collection content list
    await page.goto('/admin/content?collection=example')
    await page.waitForSelector('table')

    // Find a seeded mood that still has its title (e.g. "Melancholy" or "Cruel")
    const moodRow = page.locator('table tbody tr').filter({
      has: page.locator('td', { hasText: /^(Cruel|Melancholy|Chaotic)$/ })
    }).first()
    await expect(moodRow).toBeVisible({ timeout: 10000 })

    // Capture the displayed title before editing
    const titleCell = moodRow.locator('td').first()
    const originalTitle = (await titleCell.innerText()).trim()
    expect(originalTitle).toMatch(/^(Cruel|Melancholy|Chaotic)$/)

    // Click to edit
    const editLink = moodRow.locator('a').first()
    await editLink.click()
    await page.waitForURL(/\/admin\/content\/.*\/edit/)

    // Verify the name field has the correct value
    const nameInput = page.locator('input[name="name"]')
    await expect(nameInput).toBeVisible()
    const nameValue = await nameInput.inputValue()
    expect(nameValue).toBe(originalTitle)

    // Save without changing anything
    await page.click('button:has-text("Save")')

    // Wait for redirect back to list or edit confirmation
    await page.waitForURL(/\/admin\/content/, { timeout: 15000 })

    // Navigate to the Example collection list page
    await page.goto('/admin/content?collection=example')
    await page.waitForSelector('table')

    // Verify the title is still the mood name — NOT a document ID (nanoid)
    const titleAfterEdit = page.locator('table tbody tr').filter({
      has: page.locator('td', { hasText: originalTitle })
    })
    await expect(titleAfterEdit).toBeVisible({ timeout: 10000 })

    // Verify no row shows a nanoid-style string where this title should be
    // (nanoids are 21-char alphanumeric strings like "RgtZDMkLthGvEdnY6FePW")
    const allTitles = await page.locator('table tbody tr td:first-child').allInnerTexts()
    for (const t of allTitles) {
      const trimmed = t.trim()
      if (trimmed && /^[A-Za-z0-9_-]{15,25}$/.test(trimmed)) {
        // This looks like a nanoid — fail if it's in the Example collection
        expect.soft(trimmed).not.toMatch(/^[A-Za-z0-9_-]{15,25}$/)
      }
    }
  })

  test('creating new Example item derives title from name field', async ({ page }) => {
    const testName = `TestMood-${Date.now()}`

    // Create a new Example item via the admin form
    await page.goto('/admin/content/new?collection=example')
    await page.waitForSelector('form')

    // Fill in the name field (title should be derived from this)
    await page.fill('input[name="name"]', testName)
    await page.fill('input[name="emoji"]', '🧪')
    await page.fill('input[name="description"]', 'E2E test mood')

    // Save
    await page.click('button:has-text("Save")')
    await page.waitForURL(/\/admin\/content/, { timeout: 15000 })

    // Verify the list shows the name as the title
    await page.goto('/admin/content?collection=example')
    await page.waitForSelector('table')

    const newItem = page.locator('table tbody tr').filter({
      has: page.locator('td', { hasText: testName })
    })
    await expect(newItem).toBeVisible({ timeout: 10000 })
  })
})
