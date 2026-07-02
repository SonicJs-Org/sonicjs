import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Regression spec for issue #889: new media uploads displayed as 1/1970 and
 * sorted to the bottom of the grid.
 *
 * Root cause: uploaded_at was stored in epoch-seconds but displayed via
 * new Date(seconds) (treating it as ms). Fixed by the documents read-flip —
 * the admin grid now reads created_at from the documents table and multiplies
 * by 1000 inside mediaDocToFile().
 */
test.describe('Media upload date display (#889)', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('media library page loads without 1970 dates', async ({ page }) => {
    await page.goto('/admin/media')
    await page.waitForLoadState('networkidle')

    // Collect all date text visible on the page
    const dateTexts = await page.locator('.text-xs.text-gray-500').allTextContents()
    for (const text of dateTexts) {
      // None of the visible date strings should mention 1970
      if (text.match(/\d{1,2}\/\d{1,2}\/\d{4}/) || text.match(/\d{4}-\d{2}-\d{2}/)) {
        expect(text).not.toContain('1970')
      }
    }
  })

  test('newly uploaded file appears at the top of the media grid with a valid date', async ({ page }) => {
    await page.goto('/admin/media')
    await page.waitForLoadState('networkidle')

    // Open upload modal
    const uploadButton = page.getByRole('button', { name: /upload/i }).first()
    await uploadButton.click()

    // Create a minimal test file
    const fileContent = Buffer.from('test-content-for-e2e')
    await page.setInputFiles('input[type="file"]', {
      name: 'e2e-test-upload.txt',
      mimeType: 'text/plain',
      buffer: fileContent,
    })

    // Wait for upload to complete and page to reload
    await page.waitForURL(/\/admin\/media/, { timeout: 10000 })
    await page.waitForLoadState('networkidle')

    // The grid should list the newly uploaded file
    const firstFile = page.locator('[data-file-id]').first()
    await expect(firstFile).toBeVisible()

    // Check that no date text on the page shows 1970
    const allText = await page.content()
    expect(allText).not.toMatch(/1\/\d+\/1970/)
    expect(allText).not.toMatch(/1970-01-01/)
  })
})
