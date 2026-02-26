import { test, expect } from '@playwright/test';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

test.describe('Block Media Persistence', () => {
  let uploadedFileId: string | undefined;

  test.beforeEach(async ({ page, context }) => {
    await ensureAdminUserExists(page);
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
    const uploadedFileName = `block-media-${timestamp}.jpg`;
    formData.append('files', blob, uploadedFileName);
    formData.append('folder', 'uploads');

    const uploadResponse = await context.request.post('http://localhost:8787/api/media/upload-multiple', {
      multipart: formData
    });

    const uploadResult = await uploadResponse.json();
    expect(uploadResult.uploaded).toBeDefined();
    expect(uploadResult.uploaded.length).toBe(1);
    uploadedFileId = uploadResult.uploaded[0].id;
  });

  test.afterEach(async ({ context }) => {
    if (uploadedFileId) {
      await context.request.post('http://localhost:8787/api/media/bulk-delete', {
        data: { fileIds: [uploadedFileId] }
      }).catch(() => {});
    }
  });

  test('should persist media selection in blocks', async ({ page }) => {
    let createdContentId: string | null = null;
    const title = `Block Media ${Date.now()}`;
    const slug = `block-media-${Date.now()}`;
    await page.goto('/admin/content/new');
    const pageBlocksLink = page.locator('a[href^="/admin/content/new?collection="]').filter({ hasText: 'Page Blocks' });
    const hasPageBlocks = await pageBlocksLink.isVisible().catch(() => false);
    if (!hasPageBlocks) {
      test.skip(true, 'Page Blocks collection not available');
      return;
    }

    await pageBlocksLink.click();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('form#content-form')).toBeVisible();

    await page.fill('input[name="title"]', title);
    await page.fill('input[name="slug"]', slug);

    const blocksField = page.locator('[data-field-name="body"]');
    await expect(blocksField).toBeVisible();

    await blocksField.locator('[data-role="block-type-select"]').selectOption('hero');
    await blocksField.locator('[data-action="add-block"]').click();

    const firstBlock = blocksField.locator('.blocks-item').first();
    await firstBlock.locator('[data-block-field="heading"] input').fill('Media persistence hero');
    await firstBlock.locator('[data-block-field="ctaPrimary"] input[name$="__label"]').fill('Primary CTA');

    const imageField = firstBlock.locator('[data-block-field="image"]');
    const selectMediaButton = imageField.locator('button:has-text("Select Media")');
    await expect(selectMediaButton).toBeVisible();
    await selectMediaButton.click();

    const selectButton = page.locator('#media-selector-grid button:has-text("Select")').first();
    await expect(selectButton).toBeVisible({ timeout: 10000 });
    await selectButton.click();
    await page.locator('#media-selector-modal button:has-text("OK")').click();

    const hiddenInput = imageField.locator('input[type="hidden"]');
    await expect(hiddenInput).not.toHaveValue('');

    await page.click('button[name="action"][value="save_and_publish"]');
    await page.waitForURL(/\/admin\/content\/[^/]+\/edit|\/admin\/content\?/, { timeout: 15000 });

    try {
      // Prefer grabbing content ID from redirect URL if we're on edit page already
      const editUrlMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/);
      if (editUrlMatch?.[1]) {
        createdContentId = editUrlMatch[1];
      } else {
        await page.goto('/admin/content?collection=page_blocks');
        const contentLink = page.locator(`a:has-text("${title}")`).first();
        await expect(contentLink).toBeVisible({ timeout: 10000 });
        const href = await contentLink.getAttribute('href');
        const match = href?.match(/\/admin\/content\/([^/]+)\/edit/);
        createdContentId = match?.[1] || null;
        await contentLink.click();
      }

      const reloadedBlock = page.locator('[data-field-name="body"] .blocks-item').first();
      const reloadedHiddenInput = reloadedBlock.locator('[data-block-field="image"] input[type="hidden"]');
      await expect(reloadedHiddenInput).not.toHaveValue('');
    } finally {
      if (!createdContentId) {
        try {
          await page.goto('/admin/content?collection=page_blocks');
          const fallbackLink = page.locator(`a:has-text("${title}")`).first();
          if (await fallbackLink.isVisible({ timeout: 3000 }).catch(() => false)) {
            const href = await fallbackLink.getAttribute('href');
            const match = href?.match(/\/admin\/content\/([^/]+)\/edit/);
            createdContentId = match?.[1] || null;
          }
        } catch {
          // Best-effort fallback only; don't fail test due to cleanup lookup issues.
        }
      }

      if (createdContentId) {
        const deleteResponse = await page.request.delete(`/admin/content/${createdContentId}`);
        expect(deleteResponse.ok()).toBeTruthy();
      }
    }
  });
});
