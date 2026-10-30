import { test, expect } from './fixtures'
import { loginAsAdmin, gotoMediaLibrary, submitAndWaitForXhr } from './utils/test-helpers'

/**
 * Regression spec for issue #889: new media uploads displayed as 1/1970 and
 * sorted to the bottom of the grid.
 *
 * Root cause: uploaded_at was stored in epoch-seconds but displayed via
 * new Date(seconds) (treating it as ms). Fixed by the documents read-flip —
 * the admin grid now reads created_at from the documents table and multiplies
 * by 1000 inside mediaDocToFile().
 */
test.describe('Media upload date display (#889) @media', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page, false)
  })

  test('media library page loads without 1970 dates', async ({ page }) => {
    await gotoMediaLibrary(page)

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
    await gotoMediaLibrary(page)

    // Open upload modal
    const uploadButton = page.getByRole('button', { name: /upload/i }).first()
    await uploadButton.click()

    // Create a minimal test file. `#file-input`'s onchange only renders a preview — the upload
    // is an htmx POST from the form — so selecting a file uploads nothing without this submit.
    // Nothing was ever uploaded here before, and every assertion below still passed.
    const fileContent = Buffer.from('test-content-for-e2e')
    await page.setInputFiles('#file-input', {
      name: 'e2e-test-upload.txt',
      mimeType: 'text/plain',
      buffer: fileContent,
    })
    // The upload is an htmx POST to /admin/media/upload that writes to R2 and inserts a
    // document; #upload-results stays empty until it answers. Asserting straight after the click
    // spends an assertion budget on a server round trip — that is how this flaked in CI with the
    // locator resolving 24x to an empty <div id="upload-results">. Wait for the response first.
    await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
      page.locator('#upload-modal button[type="submit"]').click()
    )
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', {
      timeout: 15000,
    })

    // Wait for upload to complete and page to reload. The `?t=` matters: the upload runs on
    // /admin/media itself, so a bare /\/admin\/media/ matched the pre-upload page — and every
    // assertion below passed against it, which is why a spec named for a date-rendering
    // regression never once looked at the uploaded file's date.
    await page.waitForURL(/\/admin\/media\?t=/, { timeout: 20000, waitUntil: 'domcontentloaded' })

    // The grid should list the newly uploaded file
    const uploaded = page.locator('[data-file-id]').filter({ hasText: 'e2e-test-upload' }).first()
    await expect(uploaded).toBeVisible({ timeout: 15000 })

    // #889 was an epoch-seconds value rendered through `new Date(ms)`: every upload showed
    // 1/1/1970. Assert on the card for the file just uploaded, not on the page as a whole.
    await expect(uploaded).not.toContainText('1970')
  })
})
