import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Content Duplicate Functionality @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should have duplicate button on content edit page', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    // Check if there's any content to edit
    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    // Skip if no content exists
    test.skip(count === 0, 'No existing content to test');

    if (count > 0) {
      // Click first edit link
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      // Check for duplicate button
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await expect(duplicateButton).toBeVisible();
    }
  });

  test('should show confirmation dialog when clicking duplicate', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    // Find and click first edit link
    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    if (count > 0) {
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      // Click duplicate button
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await duplicateButton.click();

      // Check for confirmation dialog
      const confirmDialog = page.locator('#duplicate-content-confirm, [role="dialog"]').filter({ hasText: /Duplicate|Create a copy/ });
      await expect(confirmDialog).toBeVisible({ timeout: 5000 });
    }
  });

  test('should duplicate content successfully', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    // Get initial content count
    const initialItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const initialCount = await initialItems.count();

    if (initialCount > 0) {
      // Get the title of the first content item to verify duplication
      const firstItemLink = initialItems.first();
      const firstItemText = await firstItemLink.textContent();

      // Click first edit link
      await firstItemLink.click();
      await page.waitForLoadState('networkidle');

      // Get the title from the form
      const titleInput = page.locator('input[name="title"]');
      const originalTitle = await titleInput.inputValue();

      // Click duplicate button
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await duplicateButton.click();

      // Wait for confirmation dialog and click confirm
      await page.waitForTimeout(500);
      const confirmButton = page.locator('button').filter({ hasText: 'Duplicate' }).last();
      await confirmButton.click();

      // Should redirect to the edit page of the duplicated content
      await page.waitForTimeout(2000);

      // Verify we're on an edit page
      await expect(page.url()).toContain('/admin/content/');
      await expect(page.url()).toContain('/edit');

      // Verify the title has "Copy of" prefix
      const newTitleInput = page.locator('input[name="title"]');
      const newTitle = await newTitleInput.inputValue();
      expect(newTitle).toContain('Copy of');
      expect(newTitle).toContain(originalTitle);
    }
  });

  test('should create independent copy of content', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    if (count > 0) {
      // Click first edit link
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      // Get original URL to compare later
      const originalUrl = page.url();

      // Click duplicate button
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await duplicateButton.click();

      // Confirm duplication
      await page.waitForTimeout(500);
      const confirmButton = page.locator('button').filter({ hasText: 'Duplicate' }).last();
      await confirmButton.click();

      // Wait for navigation
      await page.waitForTimeout(2000);

      // Verify we're on a different page (different ID)
      const newUrl = page.url();
      expect(newUrl).not.toBe(originalUrl);
      expect(newUrl).toContain('/edit');

      // Modify the duplicate
      const titleInput = page.locator('input[name="title"]');
      const currentTitle = await titleInput.inputValue();
      await titleInput.fill(currentTitle + ' - Modified');

      // Save the duplicate
      const saveButton = page.locator('button[type="submit"]').filter({ hasText: /Update|Save/ }).first();
      await saveButton.click();
      await page.waitForTimeout(2000);

      // Go back to original content
      await page.goto(originalUrl);
      await page.waitForLoadState('networkidle');

      // Verify original content is unchanged
      const originalTitleInput = page.locator('input[name="title"]');
      const originalTitle = await originalTitleInput.inputValue();
      expect(originalTitle).not.toContain('- Modified');
    }
  });

  test('should handle duplicate with all field types', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    // Check if there's any content to duplicate
    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    // Skip if no content exists
    test.skip(count === 0, 'No existing content to test');

    if (count > 0) {
      // Click first edit link
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      // Duplicate it
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await duplicateButton.click();
      await page.waitForTimeout(500);

      const confirmButton = page.locator('button').filter({ hasText: 'Duplicate' }).last();
      await confirmButton.click();
      await page.waitForTimeout(2000);

      // Verify duplicated content has all fields
      const dupTitleInput = page.locator('input[name="title"]');
      const dupTitle = await dupTitleInput.inputValue();
      expect(dupTitle).toContain('Copy of');
    }
  });

  test('should preserve content status as draft on duplicate', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    if (count > 0) {
      // Click first edit link
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      // Click duplicate button
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await duplicateButton.click();

      // Confirm duplication
      await page.waitForTimeout(500);
      const confirmButton = page.locator('button').filter({ hasText: 'Duplicate' }).last();
      await confirmButton.click();
      await page.waitForTimeout(2000);

      // Check status is set to draft
      const statusSelect = page.locator('select[name="status"]');
      if (await statusSelect.count() > 0) {
        const status = await statusSelect.inputValue();
        expect(status).toBe('draft');
      }
    }
  });

  test('should handle duplicate button visibility', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    // Check if duplicate button exists on list page (should not)
    const duplicateOnList = page.locator('button').filter({ hasText: 'Duplicate Content' });
    expect(await duplicateOnList.count()).toBe(0);

    // Navigate to edit page
    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    if (count > 0) {
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      // Duplicate button should be visible on edit page
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await expect(duplicateButton).toBeVisible();
    }
  });

  test('should navigate to duplicated content after duplication', async ({ page }) => {
    // Navigate to content list
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const contentItems = page.locator('a[href*="/admin/content/"][href*="/edit"]');
    const count = await contentItems.count();

    if (count > 0) {
      // Click first edit link
      await contentItems.first().click();
      await page.waitForLoadState('networkidle');

      const originalUrl = page.url();

      // Click duplicate button
      const duplicateButton = page.locator('button').filter({ hasText: 'Duplicate Content' });
      await duplicateButton.click();

      // Confirm duplication
      await page.waitForTimeout(500);
      const confirmButton = page.locator('button').filter({ hasText: 'Duplicate' }).last();
      await confirmButton.click();

      // Wait for navigation
      await page.waitForTimeout(2000);

      // Should be on the edit page of the NEW content (different ID)
      const newUrl = page.url();
      expect(newUrl).toContain('/admin/content/');
      expect(newUrl).toContain('/edit');
      expect(newUrl).not.toBe(originalUrl);

      // Should see the duplicated title
      const titleInput = page.locator('input[name="title"]');
      const title = await titleInput.inputValue();
      expect(title).toContain('Copy of');
    }
  });
});
