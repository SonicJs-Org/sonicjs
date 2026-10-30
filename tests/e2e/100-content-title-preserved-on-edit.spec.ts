import { test, expect } from './fixtures'
import { loginAsAdmin, saveNewContent } from './utils/test-helpers'

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

    // Find a seeded mood link by its title text (inside <a> tag in the title column)
    const moodLink = page.locator('table tbody tr a').filter({ hasText: /^(Cruel|Melancholy|Chaotic)$/ }).first()
    await expect(moodLink).toBeVisible({ timeout: 10000 })

    const originalTitle = (await moodLink.innerText()).trim()

    // Click to edit
    await moodLink.click()
    await page.waitForURL(/\/admin\/content\/.*\/edit/)

    // Verify the name field has the correct value
    const nameInput = page.locator('input[name="name"]')
    await expect(nameInput).toBeVisible()
    const nameValue = await nameInput.inputValue()
    expect(nameValue).toBe(originalTitle)

    // Save without changing anything
    await page.click('button:has-text("Save")')

    // A plain `save` over htmx does not navigate at all — the handler returns an inline
    // success banner and the URL stays on /admin/content/<id>/edit. So there was nothing for
    // `waitForURL(/\/admin\/content/)` to wait for, and it matched the current URL anyway; the
    // goto below could abort the POST this spec exists to assert on. Wait for the banner.
    // `.last()` because htmx holds the outgoing node alongside the swapped-in one for the
    // duration of the settle, so the id is briefly non-unique.
    await expect(page.locator('#form-messages').last()).toContainText(/successfully/i, {
      timeout: 15000,
    })

    // Navigate to the Example collection list page
    await page.goto('/admin/content?collection=example')
    await page.waitForSelector('table')

    // Verify the title link still shows the mood name — NOT a document ID
    const titleAfterEdit = page.locator('table tbody tr a').filter({ hasText: originalTitle })
    await expect(titleAfterEdit).toBeVisible({ timeout: 10000 })
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

    // Save. The POST's `HX-Redirect` is what says it worked — waiting on the navigation alone
    // cannot tell a save still in flight from one that came back with a validation error htmx will
    // never navigate for, and reported both as a 15s timeout pointing at fixtures.ts in CI.
    await saveNewContent(page, () => page.click('button:has-text("Save")'))

    // Navigate to the Example collection list page
    await page.goto('/admin/content?collection=example')
    await page.waitForSelector('table')

    const newItem = page.locator('table tbody tr a').filter({ hasText: testName })
    await expect(newItem).toBeVisible({ timeout: 10000 })
  })
})
