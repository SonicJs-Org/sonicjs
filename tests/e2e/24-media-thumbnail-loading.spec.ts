import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Media Thumbnail Loading @media', () => {
  test('uploaded image should display thumbnail without broken image', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/media');
    await page.waitForLoadState('networkidle');

    // Open upload modal
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();
    await expect(page.locator('#upload-modal')).toBeVisible();

    // Create test image buffer - a valid 1x1 red JPEG
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

    const uniqueFilename = `thumbnail-test-${Date.now()}.jpg`;

    // Upload file
    await page.setInputFiles('#file-input', {
      name: uniqueFilename,
      mimeType: 'image/jpeg',
      buffer: testImageBuffer
    });

    // Submit upload
    await page.locator('#upload-modal button[type="submit"]').click();

    // Wait for success message
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });

    // Wait for page to redirect with cache-busting parameter
    await page.waitForURL(/\/admin\/media\?t=/, { timeout: 5000 });

    // Page should be fully loaded after refresh
    await page.waitForLoadState('networkidle', { timeout: 10000 });

    // Find the media item we just uploaded
    const mediaGrid = page.locator('#media-grid');
    await expect(mediaGrid).toContainText(uniqueFilename, { timeout: 10000 });

    // Find all images in the media grid
    const images = mediaGrid.locator('img');
    const imageCount = await images.count();

    expect(imageCount).toBeGreaterThan(0);

    // Check the first image (our newly uploaded one should be first since sorted by date DESC)
    const firstImage = images.first();
    await expect(firstImage).toBeVisible();

    // Get the image src
    const imageSrc = await firstImage.getAttribute('src');
    console.log('Image src:', imageSrc);

    expect(imageSrc).toBeTruthy();
    expect(imageSrc).toContain('/files/');

    // Verify the image actually loads (not broken)
    // We'll check naturalWidth which is 0 for broken images
    const naturalWidth = await firstImage.evaluate((img: HTMLImageElement) => {
      return new Promise((resolve) => {
        if (img.complete) {
          resolve(img.naturalWidth);
        } else {
          img.onload = () => resolve(img.naturalWidth);
          img.onerror = () => resolve(0);
          // Timeout after 5 seconds
          setTimeout(() => resolve(0), 5000);
        }
      });
    });

    console.log('Image naturalWidth:', naturalWidth);

    // Also verify we can fetch the image URL directly - do this FIRST for better debugging
    console.log('Fetching image URL directly:', imageSrc);
    const response = await page.request.get(imageSrc!);
    console.log('Response status:', response.status());
    console.log('Response headers:', JSON.stringify(response.headers(), null, 2));

    if (response.status() !== 200) {
      const body = await response.text();
      console.log('Response body:', body);
    }

    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('image');

    // If the fetch works, then check naturalWidth
    expect(naturalWidth).toBeGreaterThan(0);
  });

  test('should display all uploaded images without broken thumbnails', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/media');
    await page.waitForLoadState('networkidle');

    // Check all existing images in the grid
    const mediaGrid = page.locator('#media-grid');
    const images = mediaGrid.locator('img');
    const imageCount = await images.count();

    if (imageCount === 0) {
      console.log('No images in media library - skipping test');
      return;
    }

    console.log(`Found ${imageCount} images to check`);

    // Check each image
    for (let i = 0; i < Math.min(imageCount, 5); i++) {
      const image = images.nth(i);
      await expect(image).toBeVisible();

      const src = await image.getAttribute('src');
      console.log(`Image ${i} src:`, src);

      // Check naturalWidth
      const naturalWidth = await image.evaluate((img: HTMLImageElement) => {
        return new Promise<number>((resolve) => {
          if (img.complete) {
            resolve(img.naturalWidth);
          } else {
            img.onload = () => resolve(img.naturalWidth);
            img.onerror = () => resolve(0);
            setTimeout(() => resolve(0), 5000);
          }
        });
      });

      console.log(`Image ${i} naturalWidth:`, naturalWidth);
      expect(naturalWidth).toBeGreaterThan(0);
    }
  });
});
