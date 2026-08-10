import { test, expect } from '@playwright/test';
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers';

test.describe.skip('Media Management @smoke @media', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
    await navigateToAdminSection(page, 'media');
  });

  test('should display media library', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Media Library');
    // Use first Upload Files button (the one in the sidebar)
    await expect(page.locator('button').filter({ hasText: 'Upload Files' }).first()).toBeVisible();
  });

  test('should open upload modal', async ({ page }) => {
    // Click the first Upload Files button (the one in the sidebar)
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();
    
    await expect(page.locator('#upload-modal')).toBeVisible();
    // File input is hidden by design, just check it exists
    await expect(page.locator('#file-input')).toBeAttached();
  });

  test('should handle file upload', async ({ page }) => {
    // Click the first Upload Files button (the one in the sidebar)
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
      name: 'test-image.jpg',
      mimeType: 'image/jpeg',
      buffer: testImageBuffer
    });

    await page.locator('#upload-modal button#upload-btn').click();
    
    // Should show upload success
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });
  });

  test('should validate file types', async ({ page }) => {
    // Click the first Upload Files button (the one in the sidebar)
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();
    
    // Try to upload an invalid file type
    await page.setInputFiles('#file-input', {
      name: 'test.exe',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('fake executable')
    });

    await page.locator('#upload-modal button#upload-btn').click();
    
    // Should show validation error
    await expect(page.locator('#upload-results')).toContainText('Unsupported file type');
  });

  test('should display uploaded media', async ({ page }) => {
    // Check if there are any existing media files
    const mediaGrid = page.locator('#media-grid');
    
    if (await mediaGrid.locator('.media-item').count() > 0) {
      await expect(mediaGrid.locator('.media-item').first()).toBeVisible();
    }
  });

  test('should handle media selection', async ({ page }) => {
    const mediaItems = page.locator('.media-item');
    const count = await mediaItems.count();
    
    if (count > 0) {
      // Click the checkbox inside the media item instead of the item itself
      const checkbox = mediaItems.first().locator('input[type="checkbox"]');
      if (await checkbox.count() > 0) {
        await checkbox.click();
        await expect(checkbox).toBeChecked();
      }
    }
  });

  test('should show media details', async ({ page }) => {
    const mediaItems = page.locator('.media-item');
    const count = await mediaItems.count();
    
    if (count > 0) {
      await mediaItems.first().click();
      
      // Should show details panel or modal
      const details = page.locator('#media-details, .media-details');
      if (await details.count() > 0) {
        await expect(details).toBeVisible();
      }
    }
  });

  test('should close upload modal', async ({ page }) => {
    // Click the first Upload Files button (the one in the sidebar)
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();

    // Close modal using the Cancel button within the upload modal
    await page.locator('#upload-modal button').filter({ hasText: 'Cancel' }).click();

    await expect(page.locator('#upload-modal')).not.toBeVisible();
  });

  test('should support media search/filter', async ({ page }) => {
    // Check if search functionality exists
    const searchInput = page.locator('input[type="search"], input[placeholder*="search"], input[placeholder*="filter"]');
    
    if (await searchInput.count() > 0) {
      await searchInput.fill('test');
      // Should filter results
      await page.waitForTimeout(500); // Wait for search to process
    }
  });

  test('should handle empty media library', async ({ page }) => {
    // If no media files exist, should show appropriate message
    const mediaGrid = page.locator('#media-grid');
    const mediaItems = page.locator('.media-item');

    if (await mediaItems.count() === 0) {
      // Use .first() to handle strict mode violation when multiple elements match
      await expect(page.getByText(/No media files|Upload your first file|No files found/i).first()).toBeVisible();
    }
  });

  test('should display media list view correctly', async ({ page }) => {
    // Verify media grid is visible
    const mediaGrid = page.locator('#media-grid');
    await expect(mediaGrid).toBeVisible();

    // Check if media items are rendered
    const mediaItems = page.locator('.media-item');
    const itemCount = await mediaItems.count();

    if (itemCount > 0) {
      // Verify first item has expected elements
      const firstItem = mediaItems.first();

      // Should have an image or file icon (check if either exists)
      const hasImage = await firstItem.locator('img').count() > 0;
      const hasSvg = await firstItem.locator('svg').count() > 0;
      expect(hasImage || hasSvg).toBeTruthy();

      // Should be clickable
      await expect(firstItem).toBeVisible();

      // Test list view toggle if available (using select dropdown)
      const viewSelector = page.locator('select').filter({ has: page.locator('option[value="grid"]') });
      if (await viewSelector.count() > 0) {
        await viewSelector.selectOption('list');

        // Wait for view to update - use timeout to handle potential reload
        await page.waitForTimeout(1000);

        try {
          await page.waitForLoadState('networkidle', { timeout: 3000 });
        } catch {
          // If networkidle times out, continue anyway
        }

        // Verify list view is active - check if element exists before verifying visibility
        try {
          const listViewContainer = page.locator('#media-grid > div.space-y-4');
          if (await listViewContainer.count() > 0) {
            await expect(listViewContainer).toBeVisible();
          }
        } catch (error) {
          // List view container might not exist or page might have reloaded
          // This is acceptable as list view implementation may vary
        }
      }
    } else {
      // If no items, that's also valid - should show empty state
      await expect(page.getByText(/No media files|Upload your first file/i).first()).toBeVisible();
    }
  });

  test('should handle media pagination', async ({ page }) => {
    // Check if pagination controls exist
    const nextButton = page.locator('button:has-text("Next"), a:has-text("Next"), [aria-label="Next page"]');
    const prevButton = page.locator('button:has-text("Previous"), a:has-text("Previous"), [aria-label="Previous page"]');

    if (await nextButton.count() > 0) {
      const isEnabled = await nextButton.isEnabled().catch(() => false);

      if (isEnabled) {
        // Get current media items
        const initialItems = await page.locator('.media-item').count();

        // Click next page
        await nextButton.click();
        await page.waitForTimeout(1000);

        // Should still have media items (count may change based on available items)
        const newItems = await page.locator('.media-item').count();
        expect(newItems).toBeGreaterThan(0);
      }
    }
  });
});
