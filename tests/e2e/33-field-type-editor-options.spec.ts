import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateToAdminSection, waitForHTMX } from './utils/test-helpers'

/**
 * E2E Test: Field Type Editor Options
 *
 * Tests that the field type dropdown in the collection editor shows only
 * the editor options for plugins that are currently active:
 * - TinyMCE should be listed (active)
 * - Quill should be listed (active)
 * - MDXEditor should be listed (active)
 */

test.describe.skip('Field Type Editor Options @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should show all active editor options in field type dropdown', async ({ page }) => {
    // Navigate to collections page
    await page.goto('http://localhost:8787/admin/collections')
    await page.waitForLoadState('networkidle')

    // Click "New Collection" button
    await page.click('button:has-text("New Collection"), a:has-text("New Collection")')
    await page.waitForLoadState('networkidle')

    // Click "Add Field" button to open the modal
    await page.click('button:has-text("Add Field")')
    await page.waitForTimeout(500)

    // Wait for the modal and select to be visible
    await page.waitForSelector('select#field-type', { state: 'visible', timeout: 10000 })

    // Get all options in the field type dropdown
    const fieldTypeOptions = await page.locator('select#field-type option').allTextContents()

    console.log('Field type options found:', fieldTypeOptions)

    // Verify that all three editor options are present
    expect(fieldTypeOptions).toContain('Rich Text (TinyMCE)')
    expect(fieldTypeOptions).toContain('Rich Text (Quill)')
    expect(fieldTypeOptions).toContain('Rich Text (MDXEditor)')

    // Also verify the values are correct
    const tinymceOption = page.locator('select#field-type option[value="richtext"]')
    await expect(tinymceOption).toBeVisible()

    const quillOption = page.locator('select#field-type option[value="quill"]')
    await expect(quillOption).toBeVisible()

    const mdxeditorOption = page.locator('select#field-type option[value="mdxeditor"]')
    await expect(mdxeditorOption).toBeVisible()
  })

  test('should not show inactive editor options', async ({ page }) => {
    // First, deactivate TinyMCE
    await page.goto('http://localhost:8787/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Find and deactivate TinyMCE
    const tinymceCard = page.locator('[data-plugin-id="tinymce-plugin"]')
    const deactivateButton = tinymceCard.locator('button:has-text("Deactivate")')

    if (await deactivateButton.isVisible()) {
      await deactivateButton.click()
      await page.waitForLoadState('networkidle')
      await page.waitForTimeout(1000) // Give it a moment to update
    }

    // Navigate to collections page
    await page.goto('http://localhost:8787/admin/collections')
    await page.waitForLoadState('networkidle')

    // Click "New Collection" button
    await page.click('button:has-text("New Collection"), a:has-text("New Collection")')
    await page.waitForLoadState('networkidle')

    // Click "Add Field" button to open the modal
    await page.click('button:has-text("Add Field")')
    await page.waitForTimeout(500)

    // Wait for the modal and select to be visible
    await page.waitForSelector('select#field-type', { state: 'visible', timeout: 10000 })

    // Get all options in the field type dropdown
    const fieldTypeOptions = await page.locator('select#field-type option').allTextContents()

    console.log('Field type options after deactivating TinyMCE:', fieldTypeOptions)

    // Verify that TinyMCE is NOT in the list
    expect(fieldTypeOptions).not.toContain('Rich Text (TinyMCE)')

    // But Quill and MDXEditor should still be there
    expect(fieldTypeOptions).toContain('Rich Text (Quill)')
    expect(fieldTypeOptions).toContain('Rich Text (MDXEditor)')

    // Re-activate TinyMCE for other tests
    await page.goto('http://localhost:8787/admin/plugins')
    await page.waitForLoadState('networkidle')

    const tinymceCardAgain = page.locator('[data-plugin-id="tinymce-plugin"]')
    const activateButton = tinymceCardAgain.locator('button:has-text("Activate")')

    if (await activateButton.isVisible()) {
      await activateButton.click()
      await page.waitForLoadState('networkidle')
    }
  })

  test('should be able to select each editor type', async ({ page }) => {
    // Navigate to collections page
    await page.goto('http://localhost:8787/admin/collections')
    await page.waitForLoadState('networkidle')

    // Click "New Collection" button
    await page.click('button:has-text("New Collection"), a:has-text("New Collection")')
    await page.waitForLoadState('networkidle')

    // Click "Add Field" button to open the modal
    await page.click('button:has-text("Add Field")')
    await page.waitForTimeout(500)

    // Wait for the modal and select to be visible
    await page.waitForSelector('select#field-type', { state: 'visible', timeout: 10000 })

    // Test selecting TinyMCE
    await page.selectOption('select#field-type', 'richtext')
    let selectedValue = await page.locator('select#field-type').inputValue()
    expect(selectedValue).toBe('richtext')

    // Test selecting Quill
    await page.selectOption('select#field-type', 'quill')
    selectedValue = await page.locator('select#field-type').inputValue()
    expect(selectedValue).toBe('quill')

    // Test selecting MDXEditor
    await page.selectOption('select#field-type', 'mdxeditor')
    selectedValue = await page.locator('select#field-type').inputValue()
    expect(selectedValue).toBe('mdxeditor')
  })
})
