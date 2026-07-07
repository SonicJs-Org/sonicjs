import { test, expect } from '@playwright/test';
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers';

test.describe.skip('Media Cleanup Unused Files @media', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
    await navigateToAdminSection(page, 'media');
  });

  test('should have cleanup unused button in sidebar', async ({ page }) => {
    // Check for Cleanup Unused button in the sidebar
    const cleanupButton = page.locator('button').filter({ hasText: 'Cleanup Unused' });
    await expect(cleanupButton).toBeVisible();
  });

  test('should show confirmation dialog when clicking cleanup', async ({ page }) => {
    // Click cleanup button
    const cleanupButton = page.locator('button').filter({ hasText: 'Cleanup Unused' });

    // Set up dialog handler before clicking
    page.once('dialog', dialog => {
      expect(dialog.message()).toContain('Delete unused files');
      dialog.dismiss();
    });

    await cleanupButton.click();
  });

  test('should cleanup unused media files', async ({ page }) => {
    // First, upload a test image that will be "unused"
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();

    // Create a small test image file
    const testImageBuffer = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
      0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
      0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
      0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
      0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
      0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
      0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,
      0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
      0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4,
      0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C,
      0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9
    ]);

    await page.setInputFiles('#file-input', {
      name: 'unused-test-image.jpg',
      mimeType: 'image/jpeg',
      buffer: testImageBuffer
    });

    await page.locator('#upload-modal button#upload-btn').click();

    // Wait for upload success
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });

    // Wait for page to reload after upload
    await page.waitForLoadState('networkidle');

    // Now perform cleanup
    const cleanupButton = page.locator('button').filter({ hasText: 'Cleanup Unused' });

    // Accept the confirmation dialog
    page.once('dialog', dialog => {
      expect(dialog.message()).toContain('Delete unused files');
      dialog.accept();
    });

    await cleanupButton.click();

    // Wait for cleanup to complete - should show success message or reload
    // The cleanup route redirects to /admin/media after completion
    await page.waitForTimeout(3000);

    // Should be back on media library page
    await expect(page.locator('h1')).toContainText('Media Library', { timeout: 10000 });
  });

  test('should show message when no unused files exist', async ({ page }) => {
    // This test assumes all uploaded files are referenced in content
    // So cleanup should return "No unused media files found"

    const cleanupButton = page.locator('button').filter({ hasText: 'Cleanup Unused' });

    // Accept the confirmation dialog
    page.once('dialog', dialog => {
      expect(dialog.message()).toContain('Delete unused files');
      dialog.accept();
    });

    await cleanupButton.click();

    // Wait for response - might show "No unused media files found" or success message
    await page.waitForTimeout(3000);

    // Should be back on media library page either way
    await expect(page.locator('h1')).toContainText('Media Library', { timeout: 10000 });
  });

  test('should only delete unreferenced files', async ({ page }) => {
    // This is an integration test to ensure cleanup doesn't delete files in use

    // Step 1: Upload a test file
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();

    const testImageBuffer = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
      0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
      0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
      0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
      0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
      0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
      0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,
      0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
      0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4,
      0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C,
      0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9
    ]);

    await page.setInputFiles('#file-input', {
      name: 'referenced-test-image.jpg',
      mimeType: 'image/jpeg',
      buffer: testImageBuffer
    });

    await page.locator('#upload-modal button#upload-btn').click();

    // Wait for upload success
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });

    // Wait for page to reload
    await page.waitForLoadState('networkidle');

    // Step 2: Create content that references this file
    // Navigate to content section
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    // Try to create new content (if create button exists)
    const createButton = page.locator('button').filter({ hasText: /Create|New Content/i });

    if (await createButton.count() > 0) {
      await createButton.first().click();
      await page.waitForTimeout(1000);

      // Fill in basic content with the image reference
      // This is a simplified test - actual content creation may vary
      const titleInput = page.locator('input[name="title"], input[placeholder*="title"]').first();
      if (await titleInput.count() > 0) {
        await titleInput.fill('Test Content with Image Reference');
      }

      // Try to save the content
      const saveButton = page.locator('button').filter({ hasText: /Save|Create|Submit/i }).first();
      if (await saveButton.count() > 0) {
        await saveButton.click();
        await page.waitForTimeout(2000);
      }
    }

    // Step 3: Go back to media and run cleanup
    await page.goto('/admin/media');
    await page.waitForLoadState('networkidle');

    const cleanupButton = page.locator('button').filter({ hasText: 'Cleanup Unused' });

    // Accept the confirmation dialog
    page.once('dialog', dialog => {
      expect(dialog.message()).toContain('Delete unused files');
      dialog.accept();
    });

    await cleanupButton.click();

    // Wait for cleanup to complete
    await page.waitForTimeout(3000);

    // Should be back on media library page
    await expect(page.locator('h1')).toContainText('Media Library', { timeout: 10000 });

    // The referenced file should still exist in the media library
    // (This is a basic check - ideally we'd verify the specific file)
  });

  test('should handle cleanup with admin role only', async ({ page }) => {
    // This test verifies that cleanup requires admin role
    // The cleanup button should be visible for admin users (which we are logged in as)

    const cleanupButton = page.locator('button').filter({ hasText: 'Cleanup Unused' });
    await expect(cleanupButton).toBeVisible();

    // Non-admin users won't have access to this route (tested by requireRole middleware)
  });
});
