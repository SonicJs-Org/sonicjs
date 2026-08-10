import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Profile Picture Upload @media @auth', () => {
  test('should update profile picture and display it immediately', async ({ page }) => {
    // Login as admin
    await loginAsAdmin(page);

    // Navigate to profile page
    await page.goto('/admin/profile');
    await page.waitForLoadState('networkidle');

    // Verify profile page loaded
    await expect(page.locator('h1')).toContainText('User Profile');

    // Get initial avatar state (check if there's an image or initials)
    const avatarContainer = page.locator('#avatar-image-container');
    await expect(avatarContainer).toBeVisible();

    // Create a test image buffer (1x1 pixel JPEG)
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

    const uniqueFilename = `profile-avatar-${Date.now()}.jpg`;

    // Upload avatar by setting the file input
    // The form will auto-submit on file selection
    await page.setInputFiles('#avatar-input', {
      name: uniqueFilename,
      mimeType: 'image/jpeg',
      buffer: testImageBuffer
    });

    // Wait for HTMX to complete the upload and update the DOM
    await page.waitForTimeout(2000);

    // Verify success message appears
    await expect(page.locator('#avatar-messages')).toContainText('Profile picture updated successfully', { timeout: 5000 });

    // Verify the avatar image was updated
    // The avatar should now contain an img tag instead of initials
    const avatarImage = avatarContainer.locator('img');
    await expect(avatarImage).toBeVisible({ timeout: 5000 });

    // Verify the image src contains the avatar URL pattern
    const imgSrc = await avatarImage.getAttribute('src');
    expect(imgSrc).toBeTruthy();
    expect(imgSrc).toContain('/uploads/avatars/');

    // Verify the image src has a cache-busting timestamp parameter
    expect(imgSrc).toMatch(/\?t=\d+/);
  });

  test('should validate file type on upload', async ({ page }) => {
    // Login as admin
    await loginAsAdmin(page);

    // Navigate to profile page
    await page.goto('/admin/profile');
    await page.waitForLoadState('networkidle');

    // Try to upload a text file instead of an image
    const textBuffer = Buffer.from('This is not an image file');

    await page.setInputFiles('#avatar-input', {
      name: 'invalid-file.txt',
      mimeType: 'text/plain',
      buffer: textBuffer
    });

    // Wait for response
    await page.waitForTimeout(2000);

    // Verify error message appears
    await expect(page.locator('#avatar-messages')).toContainText('valid image file', { timeout: 5000 });
  });

  test('should handle large file size validation', async ({ page }) => {
    // Login as admin
    await loginAsAdmin(page);

    // Navigate to profile page
    await page.goto('/admin/profile');
    await page.waitForLoadState('networkidle');

    // Create a buffer larger than 5MB (5 * 1024 * 1024 bytes)
    const largeBuffer = Buffer.alloc(6 * 1024 * 1024, 0xFF);

    await page.setInputFiles('#avatar-input', {
      name: 'large-image.jpg',
      mimeType: 'image/jpeg',
      buffer: largeBuffer
    });

    // Wait for response
    await page.waitForTimeout(2000);

    // Verify error message appears about file size
    await expect(page.locator('#avatar-messages')).toContainText('smaller than 5MB', { timeout: 5000 });
  });
});
