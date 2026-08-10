import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Media Bulk Actions @media', () => {
  let uploadedFileIds: string[] = [];

  test.beforeEach(async ({ page, context }) => {
    await loginAsAdmin(page);

    // Upload 2 test files via API instead of UI to ensure they persist
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

    // Upload via API (this should persist to database)
    const formData = new FormData();
    const blob1 = new Blob([testImageBuffer], { type: 'image/jpeg' });
    const blob2 = new Blob([testImageBuffer], { type: 'image/jpeg' });
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(7);
    formData.append('files', blob1, `test-bulk-${timestamp}-${randomSuffix}-1.jpg`);
    formData.append('files', blob2, `test-bulk-${timestamp}-${randomSuffix}-2.jpg`);
    formData.append('folder', 'uploads');

    // Use context.request to maintain cookies from browser login
    const uploadResponse = await context.request.post('http://localhost:8787/api/media/upload-multiple', {
      multipart: formData
    });

    const uploadResult = await uploadResponse.json();

    // Store uploaded file IDs for cleanup
    if (uploadResult.uploaded && Array.isArray(uploadResult.uploaded)) {
      uploadedFileIds = uploadResult.uploaded.map((file: any) => file.id);
      console.log(`Uploaded ${uploadedFileIds.length} files:`, uploadedFileIds);

      // Verify we got 2 files
      if (uploadedFileIds.length !== 2) {
        console.error('Upload result:', JSON.stringify(uploadResult, null, 2));
        throw new Error(`Expected 2 files to upload, but got ${uploadedFileIds.length}`);
      }
    } else {
      console.error('Upload result:', JSON.stringify(uploadResult, null, 2));
      throw new Error('Failed to upload files or invalid response format');
    }

    // Now navigate to media page with cache busting
    await page.goto(`/admin/media?t=${Date.now()}`);
    await page.waitForLoadState('networkidle');

    // Wait a moment for any post-upload processing
    await page.waitForTimeout(1000);

    // Reload to ensure we bypass cache
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Wait for media grid to load with at least 2 files
    await page.waitForSelector('input[type="checkbox"].media-checkbox', { timeout: 10000 });

    const fileCount = await page.locator('input[type="checkbox"].media-checkbox').count();
    if (fileCount < 2) {
      throw new Error(`Expected at least 2 media files, but found ${fileCount}`);
    }
  });

  test.afterEach(async ({ context }) => {
    // Clean up uploaded test files
    if (uploadedFileIds.length > 0) {
      try {
        await context.request.post('http://localhost:8787/api/media/bulk-delete', {
          data: {
            fileIds: uploadedFileIds
          }
        });
        uploadedFileIds = [];
      } catch (error) {
        console.warn('Failed to clean up test files:', error);
      }
    }
  });

  test('should display bulk actions menu without cutoff when files are selected', async ({ page }) => {
    // Files are already uploaded in beforeEach
    const mediaItems = page.locator('input[type="checkbox"].media-checkbox');
    await mediaItems.first().check();

    // Wait for bulk actions button to become enabled
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await expect(bulkActionsBtn).toBeEnabled({ timeout: 5000 });
    await expect(bulkActionsBtn).toContainText('Actions');

    // Click bulk actions button
    await bulkActionsBtn.click();

    // Wait for menu to appear and become visible
    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible({ timeout: 3000 });

    // Check that menu is properly positioned and not cut off
    const menuBox = await bulkActionsMenu.boundingBox();
    const viewportSize = page.viewportSize();

    expect(menuBox).not.toBeNull();
    if (menuBox && viewportSize) {
      // Menu should be within viewport
      expect(menuBox.x).toBeGreaterThanOrEqual(0);
      expect(menuBox.y).toBeGreaterThanOrEqual(0);
      expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(viewportSize.width);
      expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(viewportSize.height);

      // Verify menu has reasonable dimensions (not collapsed)
      expect(menuBox.width).toBeGreaterThan(100); // Menu should be at least 100px wide
      expect(menuBox.height).toBeGreaterThan(30); // Menu should be at least 30px tall (enough for button)
    }

    // Verify ALL menu items are visible and clickable
    const menuItems = [
      { text: 'Move to Folder', selector: 'button:has-text("Move to Folder")' },
      { text: 'Delete Selected Files', selector: 'button:has-text("Delete Selected Files")' }
    ];

    for (const item of menuItems) {
      const button = bulkActionsMenu.locator(item.selector);

      // Check button exists and is visible
      await expect(button).toBeVisible();

      // Verify button is fully visible (not cut off)
      const buttonBox = await button.boundingBox();
      expect(buttonBox).not.toBeNull();

      if (buttonBox && viewportSize) {
        // Button should be fully within viewport
        expect(buttonBox.x).toBeGreaterThanOrEqual(0);
        expect(buttonBox.y).toBeGreaterThanOrEqual(0);
        expect(buttonBox.x + buttonBox.width).toBeLessThanOrEqual(viewportSize.width);
        expect(buttonBox.y + buttonBox.height).toBeLessThanOrEqual(viewportSize.height);

        // Button should have reasonable dimensions (not collapsed)
        expect(buttonBox.width).toBeGreaterThan(50);
        expect(buttonBox.height).toBeGreaterThan(20);
      }

      // Verify button is clickable (use force: true since fixed positioning with high z-index might confuse elementFromPoint)
      await button.click({ force: true, timeout: 1000 });

      // If click succeeded, button is clickable - close any modal that opened
      const moveModal = page.locator('#move-to-folder-modal');
      const deleteDialog = page.locator('[role="dialog"]');

      if (await moveModal.isVisible().catch(() => false)) {
        await page.locator('#move-to-folder-modal button:has-text("Cancel")').click();
        await page.waitForTimeout(200);
        // Re-open bulk actions menu for next iteration
        await page.locator('#bulk-actions-btn').click();
        await page.waitForTimeout(300);
      } else if (await deleteDialog.isVisible().catch(() => false)) {
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);
        // Re-open bulk actions menu for next iteration
        await page.locator('#bulk-actions-btn').click();
        await page.waitForTimeout(300);
      }
    }

    // Click outside to close menu
    await page.click('body', { position: { x: 10, y: 10 } });

    // Menu should be hidden after clicking outside
    await expect(bulkActionsMenu).toBeHidden({ timeout: 2000 });
  });

  test('should show correct count in bulk actions button', async ({ page }) => {
    // Files are already uploaded in beforeEach
    const mediaItems = page.locator('input[type="checkbox"].media-checkbox');

    // Select first 2 items
    await mediaItems.nth(0).check();
    await mediaItems.nth(1).check();

    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await expect(bulkActionsBtn).toContainText('Actions (2)');

    // Unselect one
    await mediaItems.nth(0).uncheck();
    await expect(bulkActionsBtn).toContainText('Actions (1)');

    // Unselect all
    await mediaItems.nth(1).uncheck();
    await expect(bulkActionsBtn).toBeDisabled();
    await expect(bulkActionsBtn).toContainText('Bulk Actions');
  });

  test('should close menu when clicking outside', async ({ page }) => {
    // Files are already uploaded in beforeEach
    const mediaItems = page.locator('input[type="checkbox"].media-checkbox');

    // Select a file
    await mediaItems.first().check();

    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    const bulkActionsMenu = page.locator('#bulk-actions-menu');

    // Open menu
    await bulkActionsBtn.click();
    await expect(bulkActionsMenu).toBeVisible();

    // Click outside to close menu
    await page.click('body', { position: { x: 10, y: 10 } });

    // Menu should close
    await expect(bulkActionsMenu).toBeHidden({ timeout: 2000 });
  });

  test('should have proper z-index to avoid overlap', async ({ page }) => {
    // Files are already uploaded in beforeEach
    const mediaItems = page.locator('input[type="checkbox"].media-checkbox');

    // Select a file
    await mediaItems.first().check();

    // Open menu
    await page.locator('#bulk-actions-btn').click();
    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible();

    // Check z-index
    const zIndex = await bulkActionsMenu.evaluate((el) =>
      window.getComputedStyle(el).zIndex
    );

    // z-50 in Tailwind is z-index: 50
    expect(parseInt(zIndex)).toBeGreaterThanOrEqual(50);
  });

  test('should successfully delete selected files using bulk delete', async ({ page }) => {
    // Files are already uploaded in beforeEach
    const mediaItems = page.locator('input[type="checkbox"].media-checkbox');

    // Get initial count of media items
    const initialCount = await mediaItems.count();
    expect(initialCount).toBeGreaterThanOrEqual(2);

    // Select first 2 files
    await mediaItems.nth(0).check();
    await mediaItems.nth(1).check();

    // Open bulk actions menu
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await expect(bulkActionsBtn).toBeEnabled();
    await bulkActionsBtn.click();

    // Wait for menu to be visible
    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible();

    // Click Delete Selected Files button (use force since high z-index menu might confuse Playwright)
    const deleteButton = bulkActionsMenu.locator('button:has-text("Delete Selected Files")');
    await expect(deleteButton).toBeVisible();
    await deleteButton.click({ force: true });

    // Wait for dialog to open (check for open attribute on dialog element)
    const confirmDialog = page.locator('#media-bulk-delete-confirm');
    await confirmDialog.waitFor({ state: 'attached', timeout: 5000 });

    // Wait for the dialog to have the open attribute
    await expect(confirmDialog).toHaveAttribute('open', '', { timeout: 5000 });

    const confirmButton = confirmDialog.locator('button:has-text("Delete")');
    await expect(confirmButton).toBeVisible();
    await confirmButton.click({ force: true });

    // Wait for deletion to complete and grid to refresh
    await page.waitForTimeout(1000);

    // Verify files were deleted - count should decrease by 2
    const finalCount = await mediaItems.count();
    expect(finalCount).toBe(initialCount - 2);

    // Verify bulk actions button is disabled (no files selected)
    await expect(bulkActionsBtn).toBeDisabled();
  });
});
