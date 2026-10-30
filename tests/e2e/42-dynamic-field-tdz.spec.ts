import { test, expect } from './fixtures'
import type { Page } from '@playwright/test'
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
 *
 * Both tests used to reach the form by loading `/admin/content/new`, waiting for `networkidle`,
 * hunting for an `a[href*="collection=e2e_test"]` in the collection picker, falling back to
 * `/admin/collections` to "trigger a sync", and giving up into `test.skip(true, 'E2E Test
 * collection not available')` at five separate points. `e2e_test` is a code-registered collection
 * — `registerCollections()` at bootstrap, no DB sync to wait for — so the form has a direct URL
 * and the picker is not part of what this spec tests. Every one of those skips was a way for a
 * slow or failed page load to report itself as "feature absent".
 */

const NEW_E2E_TEST_FORM = '/admin/content/new?collection=e2e_test'

/**
 * Open the E2E Test collection's new-content form.
 *
 * The TDZ bug surfaces as a server-rendered error page, not as a missing element, so check for it
 * by name first — otherwise the failure is a 15s timeout on `form#content-form` that says nothing
 * about the cause.
 */
async function openE2eTestForm(page: Page) {
  await page.goto(NEW_E2E_TEST_FORM)

  const body = await page.content()
  if (body.includes('Cannot access') && body.includes('before initialization')) {
    throw new Error(`TDZ bug detected: "Cannot access 'options' before initialization"`)
  }

  await expect(page.locator('form#content-form')).toBeVisible({ timeout: 15000 })
}

test.describe('Dynamic Field TDZ Bug Fix @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should render content form with object fields without TDZ crash', async ({ page }) => {
    await openE2eTestForm(page)

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
    await openE2eTestForm(page)

    // Fill required fields
    await page.fill('input[name="title"]', 'Block Test Page')
    await page.fill('input[name="slug"]', 'block-test-page')

    // Get the blocks field
    const blocksField = page.locator('.blocks-field[data-field-name="body"]')
    await expect(blocksField).toBeVisible()

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
