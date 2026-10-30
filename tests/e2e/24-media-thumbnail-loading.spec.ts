import { test, expect, type Locator } from './fixtures';
import { loginAsAdmin, gotoMediaLibrary, submitAndWaitForXhr } from './utils/test-helpers';

/**
 * A real, decodable 1x1 PNG.
 *
 * This spec previously used a hand-written JPEG byte array. The server accepts it, but the
 * entropy-coded scan is truncated, so Chromium decodes it to naturalWidth 0 — every thumbnail
 * assertion failed on a broken fixture rather than on a broken product.
 */
const ONE_PX_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
);

/**
 * Decoded width of an <img>; 0 means the browser could not render it (broken thumbnail).
 *
 * Scrolls first: grid thumbnails are `loading="lazy"`, so one below the fold has not been
 * requested yet and would read as a broken image rather than an undisplayed one.
 */
async function decodedWidth(image: Locator): Promise<number> {
  await image.scrollIntoViewIfNeeded();
  return image.evaluate((img: HTMLImageElement) => {
    return new Promise<number>((resolve) => {
      if (img.complete) {
        resolve(img.naturalWidth);
      } else {
        img.onload = () => resolve(img.naturalWidth);
        img.onerror = () => resolve(0);
        // A broken image reports through `onerror` within the round trip, so this cap is only
        // reached when the fetch is still queued. Thumbnails come from the worker (~0.8s idle,
        // far worse with four Playwright workers on one preview isolate), and 5s here failed as
        // "broken thumbnail" when the image was merely late.
        setTimeout(() => resolve(0), 20000);
      }
    });
  });
}

test.describe('Media Thumbnail Loading @media', () => {
  // Files uploaded by the test, removed afterwards so the library does not grow run over run.
  let uploadedIds: string[] = [];

  test.beforeEach(async ({ page }) => {
    uploadedIds = [];
    await loginAsAdmin(page, false);
  });

  test.afterEach(async ({ context }) => {
    if (uploadedIds.length > 0) {
      await context.request
        .post('/api/media/bulk-delete', { data: { fileIds: uploadedIds } })
        .catch(() => {});
    }
  });

  test('uploaded image should display thumbnail without broken image', async ({ page }) => {
    await gotoMediaLibrary(page);

    // Open upload modal
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();
    await expect(page.locator('#upload-modal')).toBeVisible();

    const uniqueFilename = `thumbnail-test-${Date.now()}.png`;

    // Upload file
    await page.setInputFiles('#file-input', {
      name: uniqueFilename,
      mimeType: 'image/png',
      buffer: ONE_PX_PNG
    });

    // Submit upload
    // The upload is an htmx POST to /admin/media/upload that writes to R2 and inserts a
    // document; #upload-results stays empty until it answers. Asserting straight after the click
    // spends an assertion budget on a server round trip — that is how this flaked in CI with the
    // locator resolving 24x to an empty <div id="upload-results">. Wait for the response first.
    await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
      page.locator('#upload-modal button[type="submit"]').click()
    );

    // Wait for success message
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });

    // Wait for page to redirect with cache-busting parameter
    await page.waitForURL(/\/admin\/media\?t=/, { timeout: 20000, waitUntil: 'domcontentloaded' });

    // Find the media item we just uploaded
    const mediaGrid = page.locator('#media-grid');
    await expect(mediaGrid).toContainText(uniqueFilename, { timeout: 10000 });

    // Scope to our own upload rather than trusting grid ordering
    const uploadedItem = mediaGrid.locator('.media-item').filter({ hasText: uniqueFilename }).first();
    const fileId = await uploadedItem.getAttribute('data-file-id');
    expect(fileId).toBeTruthy();
    uploadedIds.push(fileId!);

    const image = uploadedItem.locator('img').first();
    await expect(image).toBeVisible();

    const imageSrc = await image.getAttribute('src');
    console.log('Image src:', imageSrc);

    expect(imageSrc).toBeTruthy();
    expect(imageSrc).toContain('/files/');

    const naturalWidth = await decodedWidth(image);
    console.log('Image naturalWidth:', naturalWidth);

    // Fetch the image URL directly first — a non-200 here pins the failure on serving, not decoding
    const response = await page.request.get(imageSrc!);
    if (response.status() !== 200) {
      console.log('Response body:', await response.text());
    }
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('image');

    // Serving works, so a zero width means the browser could not render the thumbnail
    expect(naturalWidth).toBeGreaterThan(0);
  });

  test('should display all uploaded images without broken thumbnails', async ({ page, context }) => {
    // Seed our own images. Checking whatever happens to be in the library makes this test a
    // referendum on other specs' fixtures, so upload a known set and assert on exactly those.
    const stamp = Date.now();
    for (let i = 0; i < 3; i++) {
      const form = new FormData();
      form.append('files', new Blob([ONE_PX_PNG], { type: 'image/png' }), `grid-check-${stamp}-${i}.png`);
      form.append('folder', 'uploads');

      const upload = await context.request.post('/api/media/upload-multiple', { multipart: form });
      expect(upload.ok()).toBeTruthy();
      const result = await upload.json();
      expect(result.uploaded).toHaveLength(1);
      uploadedIds.push(result.uploaded[0].id);
    }

    await gotoMediaLibrary(page);
    await page.waitForLoadState('domcontentloaded');

    const mediaGrid = page.locator('#media-grid');
    await expect(mediaGrid.locator('.media-item').first()).toBeVisible({ timeout: 10000 });

    for (const fileId of uploadedIds) {
      const image = mediaGrid.locator(`[data-file-id="${fileId}"] img`).first();
      await expect(image).toBeVisible({ timeout: 10000 });

      const src = await image.getAttribute('src');
      expect(src).toContain('/files/');

      const naturalWidth = await decodedWidth(image);
      console.log(`Image ${fileId} (${src}) naturalWidth:`, naturalWidth);
      expect(naturalWidth).toBeGreaterThan(0);
    }
  });
});
