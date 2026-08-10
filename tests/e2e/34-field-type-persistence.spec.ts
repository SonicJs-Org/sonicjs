import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * E2E Test: Field Type Persistence
 *
 * Tests that when editing a collection field and changing the field type,
 * required, and searchable properties, all values persist after saving and reopening the modal.
 */

test.describe.skip('Field Properties Persistence @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should persist all field properties when editing a field', async ({ page }) => {
    // Navigate to an existing collection
    await page.goto('http://localhost:8787/admin/collections/news-collection')
    await page.waitForLoadState('networkidle')

    // Find the first field's edit button and click it
    const firstEditButton = page.locator('.field-item button:has-text("Edit")').first()
    await firstEditButton.waitFor({ state: 'visible', timeout: 10000 })
    await firstEditButton.click()
    await page.waitForTimeout(500)

    // Wait for the modal to be visible
    await page.waitForSelector('#field-type', { state: 'visible', timeout: 10000 })

    // Log current values
    const currentType = await page.locator('#field-type').inputValue()
    const currentRequired = await page.locator('#field-required').isChecked()
    const currentSearchable = await page.locator('#field-searchable').isChecked()

    console.log('Current values:', {
      field_type: currentType,
      is_required: currentRequired,
      is_searchable: currentSearchable
    })

    // Change ALL properties to different values
    // Change field type to text (a standard field type that always exists)
    await page.selectOption('#field-type', 'text')

    // Toggle required checkbox
    const requiredCheckbox = page.locator('#field-required')
    if (currentRequired) {
      await requiredCheckbox.uncheck()
    } else {
      await requiredCheckbox.check()
    }

    // Toggle searchable checkbox
    const searchableCheckbox = page.locator('#field-searchable')
    if (currentSearchable) {
      await searchableCheckbox.uncheck()
    } else {
      await searchableCheckbox.check()
    }

    // Verify the new values are set
    const newType = await page.locator('#field-type').inputValue()
    const newRequired = await requiredCheckbox.isChecked()
    const newSearchable = await searchableCheckbox.isChecked()

    console.log('New values before save:', {
      field_type: newType,
      is_required: newRequired,
      is_searchable: newSearchable
    })

    expect(newType).toBe('text')
    expect(newRequired).not.toBe(currentRequired)
    expect(newSearchable).not.toBe(currentSearchable)

    // Click save button (which says "Update Field" in edit mode)
    const saveButton = page.locator('button:has-text("Update Field")').first()
    await saveButton.click()

    // Wait for save to complete (look for page reload)
    await page.waitForLoadState('networkidle')
    await page.waitForTimeout(1000)

    // Reopen the edit modal for the same field
    await firstEditButton.waitFor({ state: 'visible', timeout: 10000 })
    await firstEditButton.click()
    await page.waitForTimeout(500)

    // Wait for modal
    await page.waitForSelector('#field-type', { state: 'visible', timeout: 10000 })

    // Check if ALL properties persisted
    const persistedType = await page.locator('#field-type').inputValue()
    const persistedRequired = await page.locator('#field-required').isChecked()
    const persistedSearchable = await page.locator('#field-searchable').isChecked()

    console.log('Persisted values after reopen:', {
      field_type: persistedType,
      is_required: persistedRequired,
      is_searchable: persistedSearchable
    })

    // CRITICAL ASSERTIONS - All properties must persist
    expect(persistedType).toBe('text')
    expect(persistedRequired).toBe(newRequired)
    expect(persistedSearchable).toBe(newSearchable)
  })

  test('should show all field properties in PUT request data', async ({ page }) => {
    // Listen for console messages
    page.on('console', msg => console.log('Browser console:', msg.text()))

    // Set up request interception to see what's being sent
    const putRequests: any[] = []
    const allRequests: any[] = []
    page.on('request', request => {
      allRequests.push({
        url: request.url(),
        method: request.method()
      })
      if (request.url().includes('/fields/') && request.method() === 'PUT') {
        const postData = request.postData()
        putRequests.push({
          url: request.url(),
          method: request.method(),
          postData: postData
        })
      }
    })

    // Navigate to an existing collection
    await page.goto('http://localhost:8787/admin/collections/news-collection')
    await page.waitForLoadState('networkidle')

    // Find the first field's edit button and click it
    const firstEditButton = page.locator('.field-item button:has-text("Edit")').first()
    await firstEditButton.waitFor({ state: 'visible', timeout: 10000 })
    await firstEditButton.click()
    await page.waitForTimeout(500)

    // Wait for the modal to be visible
    await page.waitForSelector('#field-type', { state: 'visible', timeout: 10000 })

    // Change properties
    await page.selectOption('#field-type', 'text')
    await page.locator('#field-required').check()
    await page.locator('#field-searchable').check()

    // Click save button (which says "Update Field" in edit mode)
    const saveButton = page.locator('button:has-text("Update Field")').first()
    await saveButton.click()

    // Wait for request to complete
    await page.waitForTimeout(2000)

    // Check if all properties were in the request
    console.log('All requests:', JSON.stringify(allRequests, null, 2))
    console.log('Captured PUT requests:', JSON.stringify(putRequests, null, 2))

    const putRequest = putRequests.find(r => r.method === 'PUT')
    expect(putRequest).toBeDefined()

    if (putRequest && putRequest.postData) {
      console.log('PUT request data:', putRequest.postData)

      // Verify all three critical fields are in the request
      expect(putRequest.postData).toContain('field_type')
      expect(putRequest.postData).toContain('is_required')
      expect(putRequest.postData).toContain('is_searchable')
    }
  })
})
