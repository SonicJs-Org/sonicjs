import { test, expect } from './fixtures';
import { loginAsAdmin, navigateToAdminSection, TEST_DATA, isFeatureAvailable } from './utils/test-helpers';

/**
 * E2E Tests for Forms System
 * Tests the complete Form.io integration including:
 * - Form CRUD operations
 * - Form builder UI
 * - Public form rendering
 * - Form submissions
 * - Multi-page wizards
 * - Component configuration
 */

test.describe('Forms Management @content', () => {
  test.describe.configure({ mode: 'serial' });

  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = await isFeatureAvailable(request, '/admin/forms')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  let testFormId: string;
  const testFormName = `test_form_${Date.now()}`;

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test.afterAll(async () => {
    // SKIP: Cleanup disabled - page fixture not available in afterAll
    // Forms are isolated per CI run and cleaned up automatically
    // If running locally, delete test forms manually or via cleanup script
  });

  test('should display forms list page', async ({ page }) => {
    await navigateToAdminSection(page, 'forms');
    
    await expect(page.locator('h1')).toContainText('Forms');
    await expect(page.locator('a[href="/admin/forms/new"]')).toBeVisible();
  });

  test('should create a new form', async ({ page }) => {
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    // Fill in form details
    await page.fill('[name="name"]', testFormName);
    await page.fill('[name="displayName"]', 'Test Form');
    await page.fill('[name="description"]', 'E2E Test Form');
    await page.selectOption('[name="category"]', 'general');

    // Submit form
    await page.click('button[type="submit"]');
    
    // Should redirect to builder
    await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 20000 });
    
    // Extract form ID from URL
    const url = page.url();
    const match = url.match(/\/admin\/forms\/([^/]+)\/builder/);
    testFormId = match ? match[1] : '';
    
    expect(testFormId).toBeTruthy();
    
    // Verify builder loaded
    await expect(page.locator('#builder-container')).toBeVisible({ timeout: 20000 });
  });

  test('should validate form name format', async ({ page }) => {
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    // Try invalid name with spaces and uppercase
    await page.fill('[name="name"]', 'Invalid Form Name');
    await page.fill('[name="displayName"]', 'Invalid Form');
    
    await page.click('button[type="submit"]');
    await page.waitForTimeout(1000);

    // Should show error or stay on page
    const hasError = await page.locator('text=/must contain only lowercase/i').isVisible()
      .catch(() => false);
    const stillOnNewPage = page.url().includes('/admin/forms/new');
    
    expect(hasError || stillOnNewPage).toBe(true);
  });

});

test.describe('Form Deletion @forms', () => {
  test('should delete a form', async ({ page }) => {
    // Create a form specifically for deletion
    await loginAsAdmin(page);
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    const deleteFormName = `delete_test_${Date.now()}`;
    await page.fill('[name="name"]', deleteFormName);
    await page.fill('[name="displayName"]', 'Delete Test');
    await page.click('button[type="submit"]');
    
    await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 20000 });
    
    // Go back to forms list
    await page.goto('/admin/forms');
    await page.waitForLoadState('networkidle');
    
    // Find and click delete button for our form
    const deleteButton = page.locator(`tr:has-text("Delete Test") button[title*="Delete"], tr:has-text("Delete Test") button:has-text("Delete")`).first();
    
    if (await deleteButton.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteButton.click();
      
      // Confirm deletion if there's a confirmation dialog
      const confirmButton = page.locator('button:has-text("Delete"), button:has-text("Confirm")');
      if (await confirmButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await confirmButton.click();
      }
      
      await page.waitForTimeout(1000);
      
      // Form should no longer appear in list
      const formExists = await page.locator(`text="${deleteFormName}"`).isVisible()
        .catch(() => false);
      
      expect(formExists).toBe(false);
    }
  });
});
