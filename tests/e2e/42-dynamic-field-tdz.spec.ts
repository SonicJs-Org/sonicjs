import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Test for TDZ (Temporal Dead Zone) bug in renderDynamicField.
 *
 * Bug: The `select` case in renderDynamicField declares `const options = opts.options || []`
 * which shadows the function parameter `options: FieldRenderOptions`. Because const declarations
 * in switch cases are scoped to the entire switch block, this creates a TDZ error when
 * other cases (object, array) try to access the `options` parameter.
 *
 * Fix: Rename `options` to `selectOptions` in the select case.
 *
 * Related: GitHub Issue #555, PR #556
 */
test.describe('Dynamic Field TDZ Bug Fix @content', () => {
  /**
   * Helper to find and navigate to E2E Test collection
   * Returns true if collection was found and navigated to, false otherwise
   */
  async function navigateToE2eTestCollection(page: any): Promise<boolean> {
    // Navigate to the new content page to see available collections
    await page.goto('/admin/content/new')
    await page.waitForLoadState('networkidle')

    // Look for E2E Test collection which has object and array fields
    // The collection might be named "e2e_test" or listed as "E2E Test"
    const e2eTestLink = page.locator('a[href*="collection=e2e_test"]')
    const hasE2eTest = await e2eTestLink.count() > 0

    if (!hasE2eTest) {
      // Collection not found in content new page
      // Try triggering collection sync by visiting collections page
      await page.goto('/admin/collections')
      await page.waitForLoadState('networkidle')

      // Check if e2e_test appears in the collections list
      const hasE2eTestInList = await page.locator('text=E2E Test').count() > 0
      if (!hasE2eTestInList) {
        return false
      }

      // Navigate back to content/new
      await page.goto('/admin/content/new')
      await page.waitForLoadState('networkidle')

      // Try again
      const e2eTestLinkRetry = page.locator('a[href*="collection=e2e_test"]')
      if (await e2eTestLinkRetry.count() === 0) {
        return false
      }

      await e2eTestLinkRetry.click()
    } else {
      await e2eTestLink.click()
    }

    await page.waitForLoadState('networkidle')
    return true
  }

  test('should render content form with object fields without TDZ crash', async ({ page }) => {
    await loginAsAdmin(page)

    // Navigate to E2E Test collection
    const found = await navigateToE2eTestCollection(page)

    if (!found) {
      // If E2E Test collection doesn't exist, skip the test
      test.skip(true, 'E2E Test collection not available - code-based collection required')
      return
    }

    // The bug would cause a crash here: "ReferenceError: Cannot access 'options' before initialization"
    // If we can see the form, the bug is fixed

    // Check if collection was found or if there's an error
    const collectionNotFound = page.locator('text=Collection not found')
    if (await collectionNotFound.isVisible({ timeout: 2000 }).catch(() => false)) {
      test.skip(true, 'E2E Test collection not synced to database')
      return
    }

    // Wait for the form to render - if there's a TDZ error, the page will show an error
    const form = page.locator('form#content-form')

    // Verify the form is visible (not crashed)
    await expect(form).toBeVisible({ timeout: 10000 })

    // Verify the SEO object field rendered (this would crash with the TDZ bug)
    const seoField = page.locator('[data-structured-object][data-field-name="seo"]')
    await expect(seoField).toBeVisible()

    // Verify the blocks array field rendered (this would also crash with the TDZ bug)
    const blocksField = page.locator('.blocks-field[data-field-name="body"]')
    await expect(blocksField).toBeVisible()

    // Verify we can interact with the object field subfields (skip hidden storage input)
    const seoTitleInput = seoField.locator('input:not([type="hidden"])').first()
    await expect(seoTitleInput).toBeVisible()

    // Verify the add block button is visible (array field rendered correctly)
    const addBlockButton = blocksField.locator('[data-action="add-block"]')
    await expect(addBlockButton).toBeVisible()

    // Fill in required fields to verify form is functional
    await page.fill('input[name="title"]', 'TDZ Test Page')
    await page.fill('input[name="slug"]', 'tdz-test-page')

    // Verify hidden inputs for structured fields exist (they store JSON data)
    const seoHiddenInput = seoField.locator('input[type="hidden"][name="seo"]')
    await expect(seoHiddenInput).toHaveCount(1)

    const blocksHiddenInput = blocksField.locator('input[type="hidden"][name="body"]')
    await expect(blocksHiddenInput).toHaveCount(1)
  })

  test('should allow adding blocks to array field without errors', async ({ page }) => {
    await loginAsAdmin(page)

    // Navigate to E2E Test collection
    const found = await navigateToE2eTestCollection(page)

    if (!found) {
      test.skip(true, 'E2E Test collection not available')
      return
    }

    // Check for collection not found error
    const collectionNotFound = page.locator('text=Collection not found')
    if (await collectionNotFound.isVisible({ timeout: 2000 }).catch(() => false)) {
      test.skip(true, 'E2E Test collection not synced to database')
      return
    }

    // Check if page loaded correctly (no TDZ crash)
    const form = page.locator('form#content-form')
    const isFormVisible = await form.isVisible({ timeout: 5000 }).catch(() => false)

    if (!isFormVisible) {
      // Check for error message that would indicate TDZ bug
      const pageContent = await page.content()
      const hasTdzError = pageContent.includes('Cannot access') && pageContent.includes('before initialization')

      if (hasTdzError) {
        throw new Error('TDZ bug detected: "Cannot access \'options\' before initialization"')
      }

      // If form not visible but no TDZ error, collection might not exist
      test.skip(true, 'E2E Test collection form not available')
      return
    }

    // Fill required fields
    await page.fill('input[name="title"]', 'Block Test Page')
    await page.fill('input[name="slug"]', 'block-test-page')

    // Get the blocks field
    const blocksField = page.locator('.blocks-field[data-field-name="body"]')

    // Select a block type and add it
    await blocksField.locator('[data-role="block-type-select"]').selectOption('text')
    await blocksField.locator('[data-action="add-block"]').click()

    // Verify block was added
    const blockItem = blocksField.locator('.blocks-item')
    await expect(blockItem).toBeVisible()

    // Fill in block fields
    const headingInput = blockItem.locator('[data-block-field="heading"] input')
    await headingInput.fill('Test Heading')

    const bodyTextarea = blockItem.locator('[data-block-field="body"] textarea')
    await bodyTextarea.fill('Test body content')

    // Verify the hidden input has the block data
    const hiddenInput = blocksField.locator('input[type="hidden"][name="body"]')
    const hiddenValue = await hiddenInput.inputValue()
    const parsed = JSON.parse(hiddenValue)

    expect(parsed).toHaveLength(1)
    expect(parsed[0].blockType).toBe('text')
    expect(parsed[0].heading).toBe('Test Heading')
    expect(parsed[0].body).toBe('Test body content')
  })
})
