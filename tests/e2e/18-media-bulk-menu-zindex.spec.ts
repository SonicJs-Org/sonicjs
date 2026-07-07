import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Media Bulk Actions Menu Z-Index @media', () => {
  let uploadedFileIds: string[] = [];

  test.beforeEach(async ({ page, context }) => {
    await loginAsAdmin(page);

    // Upload 2 test files to ensure we have media items
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

    const formData = new FormData();
    const blob1 = new Blob([testImageBuffer], { type: 'image/jpeg' });
    const blob2 = new Blob([testImageBuffer], { type: 'image/jpeg' });
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(7);
    formData.append('files', blob1, `test-zindex-${timestamp}-${randomSuffix}-1.jpg`);
    formData.append('files', blob2, `test-zindex-${timestamp}-${randomSuffix}-2.jpg`);
    formData.append('folder', 'uploads');

    const uploadResponse = await context.request.post('http://localhost:8787/api/media/upload-multiple', {
      multipart: formData
    });

    const uploadResult = await uploadResponse.json();
    if (uploadResult.uploaded && Array.isArray(uploadResult.uploaded)) {
      uploadedFileIds = uploadResult.uploaded.map((file: any) => file.id);
    }

    // Navigate to media page
    await page.goto('/admin/media');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    await page.reload();
    await page.waitForLoadState('networkidle');
  });

  test.afterEach(async ({ context }) => {
    if (uploadedFileIds.length > 0) {
      try {
        await context.request.post('http://localhost:8787/api/media/bulk-delete', {
          data: { fileIds: uploadedFileIds }
        });
        uploadedFileIds = [];
      } catch (error) {
        console.warn('Failed to clean up test files:', error);
      }
    }
  });

  test('bulk actions menu should have higher z-index than media items', async ({ page }) => {
    // Wait for media items to be visible
    await page.waitForSelector('[data-file-id]', { timeout: 10000 });

    // Select first file to enable bulk actions
    const firstCheckbox = page.locator('input[type="checkbox"].media-checkbox').first();
    await firstCheckbox.check();

    // Open bulk actions menu
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await expect(bulkActionsBtn).toBeEnabled();
    await bulkActionsBtn.click();

    // Wait for menu to be visible
    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible();

    // Get z-index of bulk actions menu
    const menuZIndex = await bulkActionsMenu.evaluate((el) => {
      return window.getComputedStyle(el).zIndex;
    });

    // Get z-index of first media item
    const firstMediaItem = page.locator('[data-file-id]').first();
    const mediaItemZIndex = await firstMediaItem.evaluate((el) => {
      return window.getComputedStyle(el).zIndex;
    });

    console.log('Bulk Actions Menu z-index:', menuZIndex);
    console.log('Media Item z-index:', mediaItemZIndex);

    // Menu should have higher z-index
    expect(parseInt(menuZIndex)).toBeGreaterThan(parseInt(mediaItemZIndex) || 0);
    expect(parseInt(menuZIndex)).toBeGreaterThanOrEqual(50);
  });

  test('bulk actions menu buttons should be clickable and not obscured', async ({ page }) => {
    // Wait for media items to be visible
    await page.waitForSelector('[data-file-id]', { timeout: 10000 });

    // Select first file
    const firstCheckbox = page.locator('input[type="checkbox"].media-checkbox').first();
    await firstCheckbox.check();

    // Open bulk actions menu
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await bulkActionsBtn.click();

    // Wait for menu to be visible
    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible();

    // Try to click "Move to Folder" button - this should work without being obscured
    const moveButton = bulkActionsMenu.locator('button:has-text("Move to Folder")');
    await expect(moveButton).toBeVisible();

    // Check if button is actually clickable by verifying it's not covered
    const isClickable = await moveButton.evaluate((button) => {
      const rect = button.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const elementAtPoint = document.elementFromPoint(centerX, centerY);

      // The element at the center point should be the button itself or a child of it
      return button.contains(elementAtPoint);
    });

    expect(isClickable).toBe(true);

    // Actually click the button to verify it works
    await moveButton.click();

    // Verify the modal opens (confirming the click worked)
    const moveModal = page.locator('#move-to-folder-modal');
    await expect(moveModal).toBeVisible({ timeout: 2000 });
  });

  test('bulk actions menu should remain on top when hovering over media items', async ({ page }) => {
    // Wait for media items to be visible
    await page.waitForSelector('[data-file-id]', { timeout: 10000 });

    // Select first file
    const firstCheckbox = page.locator('input[type="checkbox"].media-checkbox').first();
    await firstCheckbox.check();

    // Open bulk actions menu
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await bulkActionsBtn.click();

    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible();

    // Hover over a media item (which might trigger hover effects that change z-index)
    const secondMediaItem = page.locator('[data-file-id]').nth(1);
    await secondMediaItem.hover();

    // Menu should still be visible and clickable
    await expect(bulkActionsMenu).toBeVisible();

    // Verify delete button is still clickable after hover
    const deleteButton = bulkActionsMenu.locator('button:has-text("Delete Selected Files")');
    const isStillClickable = await deleteButton.evaluate((button) => {
      const rect = button.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const elementAtPoint = document.elementFromPoint(centerX, centerY);
      return button.contains(elementAtPoint);
    });

    expect(isStillClickable).toBe(true);
  });

  test('bulk actions menu positioning should be correct relative to button', async ({ page }) => {
    // Wait for media items to be visible
    await page.waitForSelector('[data-file-id]', { timeout: 10000 });

    // Select first file
    const firstCheckbox = page.locator('input[type="checkbox"].media-checkbox').first();
    await firstCheckbox.check();

    // Open bulk actions menu
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    await bulkActionsBtn.click();

    const bulkActionsMenu = page.locator('#bulk-actions-menu');
    await expect(bulkActionsMenu).toBeVisible();

    // Get positions
    const buttonBox = await bulkActionsBtn.boundingBox();
    const menuBox = await bulkActionsMenu.boundingBox();

    expect(buttonBox).not.toBeNull();
    expect(menuBox).not.toBeNull();

    if (buttonBox && menuBox) {
      // Menu should be positioned below and to the right of button
      expect(menuBox.y).toBeGreaterThan(buttonBox.y);

      // Menu should be aligned to the right edge of the button (approximately)
      const rightEdgeButton = buttonBox.x + buttonBox.width;
      const rightEdgeMenu = menuBox.x + menuBox.width;
      expect(Math.abs(rightEdgeButton - rightEdgeMenu)).toBeLessThan(50);

      // Menu should be fully within viewport
      const viewportSize = page.viewportSize();
      if (viewportSize) {
        expect(menuBox.x).toBeGreaterThanOrEqual(0);
        expect(menuBox.y).toBeGreaterThanOrEqual(0);
        expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(viewportSize.width);
        expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(viewportSize.height);
      }
    }
  });
});
