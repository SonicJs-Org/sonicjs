import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Content Media Selector @content @media', () => {
  const testCollectionId = 'blog-posts-collection'; // Use existing collection
  let uploadedFileId: string;
  let uploadedFileName: string;

  test.beforeEach(async ({ page, context }) => {
    await loginAsAdmin(page);

    // Upload a test image via API
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
    const blob = new Blob([testImageBuffer], { type: 'image/jpeg' });
    const timestamp = Date.now();
    uploadedFileName = `test-selector-${timestamp}.jpg`;
    formData.append('files', blob, uploadedFileName);
    formData.append('folder', 'uploads');

    const uploadResponse = await context.request.post('http://localhost:8787/api/media/upload-multiple', {
      multipart: formData
    });

    const uploadResult = await uploadResponse.json();
    expect(uploadResult.uploaded).toBeDefined();
    expect(uploadResult.uploaded.length).toBe(1);
    uploadedFileId = uploadResult.uploaded[0].id;

    console.log(`Uploaded test file: ${uploadedFileName} with ID: ${uploadedFileId}`);
  });

  test.afterEach(async ({ context }) => {
    // Clean up: delete uploaded file
    if (uploadedFileId) {
      await context.request.post('http://localhost:8787/api/media/bulk-delete', {
        data: { fileIds: [uploadedFileId] }
      }).catch(() => {});
    }
  });

  test('should open media selector modal when Select Media button is clicked', async ({ page }) => {
    // Navigate to new content page for our test collection
    await page.goto(`/admin/content/new?collection=${testCollectionId}`);
    await page.waitForLoadState('networkidle');

    // Find and click the "Select Media" button
    const selectMediaButton = page.locator('button:has-text("Select Media")');
    await expect(selectMediaButton).toBeVisible({ timeout: 10000 });
    await selectMediaButton.click();

    // Verify media selector modal appears
    const modal = page.locator('#media-selector-modal');
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Verify modal has title "Select Media"
    await expect(page.locator('h3:has-text("Select Media")')).toBeVisible();
  });

  test('should display media files in the selector modal', async ({ page }) => {
    // Navigate to new content page
    await page.goto(`/admin/content/new?collection=${testCollectionId}`);
    await page.waitForLoadState('networkidle');

    // Open media selector
    await page.locator('button:has-text("Select Media")').click();

    // Wait for modal to load media
    await page.waitForTimeout(1000);

    // Verify our uploaded file appears in the selector
    const mediaItem = page.locator(`[data-media-id="${uploadedFileId}"]`).or(
      page.locator(`text=${uploadedFileName}`)
    );

    await expect(mediaItem.first()).toBeVisible({ timeout: 10000 });
  });

  test('should allow searching for media files', async ({ page }) => {
    // Navigate to new content page
    await page.goto(`/admin/content/new?collection=${testCollectionId}`);
    await page.waitForLoadState('networkidle');

    // Open media selector
    await page.locator('button:has-text("Select Media")').click();

    // Find search input
    const searchInput = page.locator('#media-selector-search').or(
      page.locator('input[type="search"]').or(
        page.locator('input[placeholder*="Search"]')
      )
    );

    await expect(searchInput.first()).toBeVisible({ timeout: 5000 });

    // Search for our uploaded file
    await searchInput.first().fill(uploadedFileName.substring(0, 10));
    await page.waitForTimeout(500);

    // Verify search results show our file
    const mediaItem = page.locator(`text=${uploadedFileName}`);
    await expect(mediaItem.first()).toBeVisible({ timeout: 5000 });
  });

  test('should select media file and populate the form field', async ({ page }) => {
    // Navigate to new content page
    await page.goto(`/admin/content/new?collection=${testCollectionId}`);
    await page.waitForLoadState('networkidle');

    // Open media selector
    await page.locator('button:has-text("Select Media")').click();
    await page.waitForTimeout(2000);

    // Select the first available file (just click the first Select button)
    const selectButton = page.locator('#media-selector-grid button:has-text("Select")').first();
    await expect(selectButton).toBeVisible({ timeout: 10000 });
    await selectButton.click();

    // Wait a moment for the selection to be processed
    await page.waitForTimeout(500);

    // Now click the OK button to close the modal
    const okButton = page.locator('#media-selector-modal button:has-text("OK")');
    await expect(okButton).toBeVisible({ timeout: 2000 });
    await okButton.click();

    // Verify modal closes
    const modal = page.locator('#media-selector-modal');
    await expect(modal).toBeHidden({ timeout: 5000 });

    // Verify the hidden input field is populated with a URL
    const hiddenInput = page.locator('input#featured_image');
    await expect(hiddenInput).toBeVisible({ timeout: 1000 });
    const hiddenInputValue = await hiddenInput.inputValue();
    expect(hiddenInputValue).toBeTruthy();
    expect(hiddenInputValue).toContain('http'); // Should be a URL

    // Verify image preview is displayed
    const preview = page.locator('.media-preview img');
    await expect(preview).toBeVisible({ timeout: 5000 });
  });

  test('should close media selector when Cancel button is clicked', async ({ page }) => {
    // Navigate to new content page
    await page.goto(`/admin/content/new?collection=${testCollectionId}`);
    await page.waitForLoadState('networkidle');

    // Open media selector
    await page.locator('button:has-text("Select Media")').click();

    // Wait for modal
    const modal = page.locator('#media-selector-modal');
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Click cancel button
    const cancelButton = modal.locator('button:has-text("Cancel")');
    await cancelButton.click();

    // Verify modal closes
    await expect(modal).toBeHidden({ timeout: 3000 });
  });

  test('should clear selected media when Remove button is clicked', async ({ page }) => {
    // Navigate to new content page
    await page.goto(`/admin/content/new?collection=${testCollectionId}`);
    await page.waitForLoadState('networkidle');

    // Open media selector and select a file
    await page.locator('button:has-text("Select Media")').click();
    await page.waitForTimeout(2000);

    const selectButton = page.locator('#media-selector-grid button:has-text("Select")').first();
    await expect(selectButton).toBeVisible({ timeout: 10000 });
    await selectButton.click();

    // Wait a moment for the selection to be processed
    await page.waitForTimeout(500);

    // Click OK button to close the modal
    const okButton = page.locator('#media-selector-modal button:has-text("OK")');
    await expect(okButton).toBeVisible({ timeout: 2000 });
    await okButton.click();

    // Wait for modal to close and verify selection
    await page.waitForTimeout(1000);

    // Verify file is selected (preview is visible)
    const preview = page.locator('.media-preview img');
    await expect(preview).toBeVisible({ timeout: 5000 });

    // Click Remove button
    const removeButton = page.locator('button:has-text("Remove")');
    await expect(removeButton).toBeVisible({ timeout: 5000 });
    await removeButton.click();

    // Verify hidden input is cleared
    const hiddenInput = page.locator('input#featured_image');
    const hiddenInputValue = await hiddenInput.inputValue();
    expect(hiddenInputValue).toBe('');

    // Verify preview is hidden
    await expect(preview).toBeHidden({ timeout: 3000 });
  });
});
