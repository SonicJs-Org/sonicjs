import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

test.describe('Slug Generation', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('should auto-generate slug from title when creating new content', async ({ page }) => {
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    
    // Fill the title field and manually dispatch input event
    await titleField.fill('My Awesome New Page 2024')
    await titleField.evaluate((el) => {
      el.dispatchEvent(new Event('input', { bubbles: true }));
    })
    
    // Wait for slug to auto-generate (account for 500ms debounce + API call)
    await expect(slugField).toHaveValue('my-awesome-new-page-2024', { timeout: 15000 })
    
    // Should show available status
    const statusDiv = page.locator('#field-slug-status')
    await expect(statusDiv).toContainText('Available', { timeout: 5000 })
  })

  test('should auto-generate slug for pages collection', async ({ page }) => {
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    
    // Fill the title field and manually dispatch input event
    await titleField.fill('My Second Test Page 2024')
    await titleField.evaluate((el) => {
      el.dispatchEvent(new Event('input', { bubbles: true }));
    })
    
    // Wait for slug to auto-generate (account for 500ms debounce + API call)
    await expect(slugField).toHaveValue('my-second-test-page-2024', { timeout: 15000 })
    
    // Should show available status
    const statusDiv = page.locator('#field-slug-status')
    await expect(statusDiv).toContainText('Available', { timeout: 5000 })
  })

  test('should handle special characters in slug generation', async ({ page }) => {
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    
    // Type title with special characters
    await titleField.fill('Hello World! @#$% Test 2024')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    
    // Wait for auto-generation (debounce + API call)
    await page.waitForTimeout(1500)
    
    // Slug should clean special chars
    await expect(slugField).toHaveValue('hello-world-test-2024', { timeout: 15000 })
  })

  test('should stop auto-generating after manual edit', async ({ page }) => {
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    
    // Auto-generate first
    await titleField.fill('Initial Title')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    await page.waitForTimeout(1500)
    await expect(slugField).toHaveValue('initial-title', { timeout: 15000 })
    
    // Manually edit slug
    await slugField.fill('my-custom-slug')
    await page.waitForTimeout(1000)
    
    // Change title again
    await titleField.fill('Changed Title')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    await page.waitForTimeout(1500)
    
    // Slug should NOT auto-update
    await expect(slugField).toHaveValue('my-custom-slug')
  })

  test('should regenerate slug when button clicked', async ({ page }) => {
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    const regenerateBtn = page.locator('button:has-text("Regenerate from title")')
    
    // Set title and manually edit slug
    await titleField.fill('Original Title')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    await page.waitForTimeout(1500)
    await slugField.fill('custom-slug')
    
    // Update title
    await titleField.fill('Brand New Title 2024')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    await page.waitForTimeout(1500)
    
    // Slug still custom (auto-generation stopped)
    await expect(slugField).toHaveValue('custom-slug')
    
    // Click regenerate
    await regenerateBtn.click()
    await page.waitForTimeout(1000)
    
    // Slug should update from current title
    await expect(slugField).toHaveValue('brand-new-title-2024')
  })

  test('should detect duplicate slugs within same collection', async ({ page }) => {
    // First, create content with a specific slug
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Test Duplicate Page')
    await page.waitForTimeout(1000)
    
    const slugField = page.locator('input[name="slug"]')
    await expect(slugField).toHaveValue('test-duplicate-page')
    
    // Save the content
    await page.click('button[name="action"][value="save_and_publish"]')
    await page.waitForTimeout(2000)
    
    // Now try to create another with same slug
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Different Title')
    await page.waitForTimeout(500)
    
    // Manually set duplicate slug
    await page.fill('input[name="slug"]', 'test-duplicate-page')
    await page.waitForTimeout(1500) // Wait for debounced check
    
    // Should show as unavailable
    const statusDiv = page.locator('#field-slug-status')
    await expect(statusDiv).toContainText('already in use')
    
    // Form should have validation error
    const isInvalid = await slugField.evaluate((el: HTMLInputElement) => !el.validity.valid)
    expect(isInvalid).toBe(true)
  })

  test.skip('should allow same slug in different collections', async ({ page }) => {
    // NOTE: Skipping because news-collection doesn't have a slug field in the database
    // Only pages-collection has a slug field defined in migration 003
    // This test would need another collection with a slug field to work properly
    
    // Create in pages collection
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Test Cross Collection')
    await page.waitForTimeout(1000)
    
    const slugValue = 'test-cross-collection'
    await expect(page.locator('input[name="slug"]')).toHaveValue(slugValue)
    
    await page.click('button[name="action"][value="save_and_publish"]')
    await page.waitForTimeout(2000)
    
    // Try to use same slug in news collection
    await page.goto('/admin/content/new?collection=news-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    
    // Wait for the form to load
    const titleField = page.locator('input[name="title"]')
    await expect(titleField).toBeVisible({ timeout: 10000 })
    
    await titleField.fill('Different Content Same Slug')
    await page.waitForTimeout(500)
    
    // Use same slug
    const slugField = page.locator('input[name="slug"]')
    await slugField.fill(slugValue)
    await page.waitForTimeout(1500)
    
    // Should show as available (different collection)
    const statusDiv = page.locator('#field-slug-status')
    await expect(statusDiv).toContainText('Available', { timeout: 5000 })
  })

  test('should not auto-change slug when editing existing content', async ({ page }) => {
    // Create content first
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Edit Mode Test Page')
    await page.waitForTimeout(1000)
    
    const originalSlug = 'edit-mode-test-page'
    await expect(page.locator('input[name="slug"]')).toHaveValue(originalSlug)
    
    await page.click('button[name="action"][value="save_and_publish"]')
    await page.waitForTimeout(2000)
    
    // Navigate to content list and find the item
    await page.goto('/admin/content?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    
    // Wait for the content to appear in the list (CI can be slow)
    const contentLink = page.locator(`a:has-text("Edit Mode Test Page")`).first()
    await contentLink.waitFor({ state: 'visible', timeout: 10000 })
    await contentLink.click()
    await page.waitForTimeout(1000)
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    
    // Verify slug is unchanged
    await expect(slugField).toHaveValue(originalSlug)
    
    // Change title
    await titleField.fill('Completely Different Title')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    await page.waitForTimeout(1500)
    
    // Slug should NOT auto-change in edit mode
    await expect(slugField).toHaveValue(originalSlug)
  })

  test('should allow manual regeneration in edit mode', async ({ page }) => {
    // Create content first
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Regen Test Page')
    await page.waitForTimeout(1000)
    
    await page.click('button[name="action"][value="save_and_publish"]')
    await page.waitForTimeout(2000)
    
    // Navigate to edit
    await page.goto('/admin/content?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    
    // Wait for the content to appear in the list (CI can be slow)
    const contentLink = page.locator(`a:has-text("Regen Test Page")`).first()
    await contentLink.waitFor({ state: 'visible', timeout: 10000 })
    await contentLink.click()
    await page.waitForTimeout(1000)
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    const regenerateBtn = page.locator('button:has-text("Regenerate from title")')
    
    // Change title
    await titleField.fill('Brand New Page Name')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    await page.waitForTimeout(1500)
    
    // Slug still shows old value
    await expect(slugField).toHaveValue('regen-test-page')
    
    // Click regenerate
    await regenerateBtn.click()
    await page.waitForTimeout(1000)
    
    // Slug should update
    await expect(slugField).toHaveValue('brand-new-page-name')
  })

  test('should show checking status during duplicate validation', async ({ page }) => {
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    const titleField = page.locator('input[name="title"]')
    const slugField = page.locator('input[name="slug"]')
    const statusDiv = page.locator('#field-slug-status')
    
    // Type title
    await titleField.fill('Checking Status Test')
    await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
    
    // Immediately check status (before debounce completes)
    await page.waitForTimeout(200)
    
    // Should show checking or empty (debouncing)
    const statusText = await statusDiv.textContent()
    expect(statusText === '' || statusText?.includes('Checking')).toBe(true)
    
    // Wait for check to complete
    await page.waitForTimeout(1500)
    
    // Should show available
    await expect(statusDiv).toContainText('Available')
  })

  test('should prevent form submission with duplicate slug', async ({ page }) => {
    // Create first content
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Submission Test Original')
    await page.waitForTimeout(1000)
    await page.click('button[name="action"][value="save_and_publish"]')
    await page.waitForTimeout(2000)
    
    // Try to create duplicate
    await page.goto('/admin/content/new?collection=pages-collection')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="title"]', { timeout: 10000 })
    
    await page.fill('input[name="title"]', 'Different Title')
    await page.waitForTimeout(500)
    
    // Set duplicate slug
    await page.fill('input[name="slug"]', 'submission-test-original')
    await page.waitForTimeout(1500)
    
    // Should show error
    await expect(page.locator('#field-slug-status')).toContainText('already in use')
    
    // Try to submit
    await page.click('button[name="action"][value="save_and_publish"]')
    
    // Should still be on form (not navigate away)
    await page.waitForTimeout(1000)
    await expect(page).toHaveURL(/\/admin\/content\/new/)
  })
})
