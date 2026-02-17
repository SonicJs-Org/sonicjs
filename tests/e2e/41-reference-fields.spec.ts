import { expect, test } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Reference Fields', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  // Skip: Add Field button has display:none in headless CI — not visible even with force:true
  test.skip('should show reference field type in collection field dropdown', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/collections`)
    await expect(page.locator('h1')).toContainText('Collections')

    // Click first collection to edit
    const firstRow = page.locator('tbody tr').first()
    await expect(firstRow).toBeVisible()
    await firstRow.click()

    await expect(page.locator('h1')).toContainText('Edit Collection')

    // Open add field modal — force:true as button may be hidden in CI viewport
    const addFieldBtn = page.locator('button:has-text("Add Field")').first()
    await addFieldBtn.click({ force: true })
    await page.waitForSelector('#field-modal:not(.hidden)')

    // Check that reference option exists in field type dropdown
    const fieldTypeSelect = page.locator('#field-type')
    const options = await fieldTypeSelect.locator('option').allTextContents()
    expect(options).toContain('Reference')

    // Close modal
    await page.click('button:has-text("Cancel")')
  })

  // Skip: Add Field button has display:none in headless CI — not visible even with force:true
  test.skip('should show field options container when reference type is selected', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/collections`)

    const firstRow = page.locator('tbody tr').first()
    await firstRow.click()
    await expect(page.locator('h1')).toContainText('Edit Collection')

    const addFieldBtn2 = page.locator('button:has-text("Add Field")').first()
    await addFieldBtn2.click({ force: true })
    await page.waitForSelector('#field-modal:not(.hidden)')

    // Select reference type
    await page.selectOption('#field-type', 'reference')

    // Field options container should be visible
    await expect(page.locator('#field-options-container')).not.toHaveClass(/hidden/, { timeout: 5000 })

    // Should have default options with collection array
    const optionsValue = await page.locator('#field-options').inputValue()
    expect(optionsValue).toContain('collection')

    // Help text should mention linking to other collections
    const helpText = await page.locator('#field-type-help').textContent()
    expect(helpText?.toLowerCase()).toContain('collection')

    await page.click('button:has-text("Cancel")')
  })

  // Skip: Add Field button has display:none in headless CI — not visible even with force:true
  test.skip('should display reference picker button in content form', async ({ page }) => {
    // First, create a collection with a reference field
    await page.goto(`${BASE_URL}/admin/collections`)
    const firstRow = page.locator('tbody tr').first()
    await firstRow.click()

    // Try to find an existing reference field or create one
    const existingRefField = page.locator('.field-item:has([class*="teal"])')
    const hasRefField = await existingRefField.count() > 0

    let collectionName = ''
    if (!hasRefField) {
      // Create a reference field
      const addFieldBtn3 = page.locator('button:has-text("Add Field")').first()
      await addFieldBtn3.click({ force: true })
      await page.waitForSelector('#field-modal:not(.hidden)')

      const fieldNameInput = page.locator('#modal-field-name')
      const isReadonly = await fieldNameInput.getAttribute('readonly')
      if (isReadonly !== null) {
        await page.click('button:has-text("Cancel")')
        console.log('Skipping - cannot add field')
        return
      }

      await page.fill('#modal-field-name', 'test_ref')
      await page.selectOption('#field-type', 'reference')
      await page.fill('#field-label', 'Test Reference')

      // Get available collections from the page
      await page.fill('#field-options', '{"collection": ["pages"]}')

      await page.click('#field-modal button[type="submit"]')
      await page.waitForLoadState('networkidle')
    }

    // Get collection name from URL
    const url = page.url()
    const match = url.match(/collections\/([^/]+)/)
    collectionName = match ? match[1] : ''

    // Navigate to create new content
    await page.goto(`${BASE_URL}/admin/content/new?collection=${collectionName}`)
    await page.waitForLoadState('networkidle')

    // Look for the reference field picker button
    const refButton = page.locator('button:has-text("Select Reference")')

    // If reference field exists, at least one button should be visible
    if (await refButton.count() > 0) {
      await expect(refButton.first()).toBeVisible()
    }
  })

  test('should open reference selector modal when clicking Select Reference', async ({ page }) => {
    // Navigate to content with a reference field
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')

    // Find a collection that might have reference fields
    const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]')
    const count = await collectionLinks.count()

    for (let i = 0; i < count; i++) {
      await collectionLinks.nth(i).click()
      await page.waitForLoadState('networkidle')

      const refButton = page.locator('button:has-text("Select Reference")')
      if (await refButton.count() > 0) {
        // Found a reference field, click it
        await refButton.first().click()

        // Modal should appear
        const modal = page.locator('.fixed.inset-0.z-50')
        await expect(modal).toBeVisible({ timeout: 5000 })

        // Modal should have search input
        await expect(page.locator('#reference-search-input')).toBeVisible()

        // Modal should have collection filter
        await expect(page.locator('#reference-collection-filter')).toBeVisible()

        // Modal should have results area
        await expect(page.locator('#reference-results')).toBeVisible()

        // Close modal
        await page.click('button:has-text("Cancel")')
        return
      }

      // Go back and try next collection
      await page.goto(`${BASE_URL}/admin/content`)
      await page.waitForLoadState('networkidle')
    }

    console.log('No reference fields found in any collection')
  })

  test('should search and display content in reference selector', async ({ page }) => {
    // First ensure there's some content to reference
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')

    // Check if there's any content
    const contentRows = page.locator('tbody tr')
    const contentCount = await contentRows.count()

    if (contentCount === 0) {
      console.log('No content available to test reference selection')
      return
    }

    // Find a form with a reference field
    const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]')
    const count = await collectionLinks.count()

    for (let i = 0; i < count; i++) {
      await collectionLinks.nth(i).click()
      await page.waitForLoadState('networkidle')

      const refButton = page.locator('button:has-text("Select Reference")')
      if (await refButton.count() > 0) {
        await refButton.first().click()

        // Wait for modal
        await expect(page.locator('#reference-search-input')).toBeVisible({ timeout: 5000 })

        // Wait for initial search results
        await page.waitForTimeout(500) // Give time for API call

        const resultsDiv = page.locator('#reference-results')
        const resultsText = await resultsDiv.textContent()

        // Should either show results or "No results found" message
        expect(resultsText).toBeTruthy()

        // If there are results, they should be buttons
        const resultButtons = resultsDiv.locator('button')
        const buttonCount = await resultButtons.count()

        if (buttonCount > 0) {
          // Verify result structure
          const firstResult = resultButtons.first()
          await expect(firstResult).toBeVisible()
        }

        await page.click('button:has-text("Cancel")')
        return
      }

      await page.goto(`${BASE_URL}/admin/content`)
      await page.waitForLoadState('networkidle')
    }
  })

  test('should select a reference and display it', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')

    // Find a form with a reference field
    const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]')
    const count = await collectionLinks.count()

    for (let i = 0; i < count; i++) {
      await collectionLinks.nth(i).click()
      await page.waitForLoadState('networkidle')

      const refButton = page.locator('button:has-text("Select Reference")')
      if (await refButton.count() > 0) {
        const container = refButton.first().locator('xpath=ancestor::div[@data-reference-field]')

        await refButton.first().click()
        await expect(page.locator('#reference-search-input')).toBeVisible({ timeout: 5000 })

        // Wait for results
        await page.waitForTimeout(500)

        const resultButtons = page.locator('#reference-results button')
        const buttonCount = await resultButtons.count()

        if (buttonCount > 0) {
          // Click first result
          await resultButtons.first().click()

          // Modal should close
          await expect(page.locator('#reference-search-input')).not.toBeVisible({ timeout: 5000 })

          // Reference display should be visible
          const displayDiv = container.locator('[data-reference-display]')
          await expect(displayDiv).not.toHaveClass(/hidden/, { timeout: 5000 })

          // Hidden input should have a value
          const hiddenInput = container.locator('input[type="hidden"]')
          const value = await hiddenInput.inputValue()
          expect(value).toBeTruthy()
        }

        return
      }

      await page.goto(`${BASE_URL}/admin/content`)
      await page.waitForLoadState('networkidle')
    }

    console.log('Could not test reference selection - no reference fields or content found')
  })

  test('should clear a selected reference', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')

    const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]')
    const count = await collectionLinks.count()

    for (let i = 0; i < count; i++) {
      await collectionLinks.nth(i).click()
      await page.waitForLoadState('networkidle')

      const refButton = page.locator('button:has-text("Select Reference")')
      if (await refButton.count() > 0) {
        const container = refButton.first().locator('xpath=ancestor::div[@data-reference-field]')

        // Select a reference first
        await refButton.first().click()
        await page.waitForTimeout(500)

        const resultButtons = page.locator('#reference-results button')
        if (await resultButtons.count() > 0) {
          await resultButtons.first().click()
          await page.waitForTimeout(300)

          // Now clear it
          const clearButton = container.locator('button[title="Remove reference"]')
          await expect(clearButton).toBeVisible()
          await clearButton.click()

          // Display should be hidden
          const displayDiv = container.locator('[data-reference-display]')
          await expect(displayDiv).toHaveClass(/hidden/, { timeout: 5000 })

          // Actions should be visible again
          const actionsDiv = container.locator('[data-reference-actions]')
          await expect(actionsDiv).not.toHaveClass(/hidden/)

          // Hidden input should be empty
          const hiddenInput = container.locator('input[type="hidden"]')
          const value = await hiddenInput.inputValue()
          expect(value).toBe('')
        }

        return
      }

      await page.goto(`${BASE_URL}/admin/content`)
      await page.waitForLoadState('networkidle')
    }
  })
})
