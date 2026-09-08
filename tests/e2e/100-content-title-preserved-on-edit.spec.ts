import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Content title preserved after edit @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('editing content item preserves title on list page @smoke', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content')
    await page.waitForSelector('table')

    // Create a new content item
    await page.click('a[href*="/admin/content/new"], button:has-text("New")')
    await page.waitForURL(/\/admin\/content\/new/)

    // Pick first available collection if prompted
    const collectionSelect = page.locator('select[name="collection_id"]')
    if (await collectionSelect.isVisible()) {
      await collectionSelect.selectOption({ index: 1 })
      await page.click('button[type="submit"], button:has-text("Continue")')
      await page.waitForURL(/\/admin\/content\/new/)
    }

    // Fill in title
    const testTitle = `E2E Title Test ${Date.now()}`
    await page.fill('input[name="title"]', testTitle)
    await page.fill('input[name="slug"]', `e2e-title-test-${Date.now()}`)

    // Save
    await page.click('button:has-text("Save")')
    await page.waitForURL(/\/admin\/content/)

    // Verify title appears on list page (not an ID)
    await page.goto('/admin/content')
    await page.waitForSelector('table')
    const titleCell = page.locator(`text=${testTitle}`)
    await expect(titleCell).toBeVisible()

    // Now edit the item
    await titleCell.click()
    await page.waitForURL(/\/admin\/content\/.*\/edit/)

    // Modify a non-title field if available, or just re-save
    const titleInput = page.locator('input[name="title"]')
    const currentTitle = await titleInput.inputValue()
    expect(currentTitle).toBe(testTitle)

    // Save again without changing title
    await page.click('button:has-text("Save")')
    await page.waitForURL(/\/admin\/content/)

    // Verify title is still correct — NOT replaced by an ID
    await page.goto('/admin/content')
    await page.waitForSelector('table')
    const titleAfterEdit = page.locator(`text=${testTitle}`)
    await expect(titleAfterEdit).toBeVisible()
  })
})
