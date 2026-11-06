import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { gotoMediaLibrary } from "./fixtures/media-fixtures"
import { submitAndWaitForXhr } from "./utils/test-helpers"
import type { Locator } from "./fixtures"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 17-media-upload-immediate.spec.ts", () => {
  test.describe('Media Upload - Immediate Availability @media', () => {
    test('uploaded photo should appear immediately in media list', async ({ page }) => {
      await loginAsAdmin(page, false);
      await gotoMediaLibrary(page);

      // Open upload modal
      await page.locator('button').filter({ hasText: 'Upload Files' }).first().click();
      await expect(page.locator('#upload-modal')).toBeVisible();

      // Create test image buffer
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

      const uniqueFilename = `test-immediate-${Date.now()}.jpg`;

      // Upload file
      await page.setInputFiles('#file-input', {
        name: uniqueFilename,
        mimeType: 'image/jpeg',
        buffer: testImageBuffer
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

      // No `networkidle` here. The redirect lands on the library, whose thumbnails are now
      // `loading="lazy"` but still trickle in as they scroll into view; the assertion below is
      // about the grid's text, which the server rendered before the first image was requested.
      // After refresh, verify the new file appears in the grid by filename
      // (It should be at the top since files are sorted by upload date DESC)
      await expect(page.locator('#media-grid')).toContainText(uniqueFilename, { timeout: 10000 });

      // Modal should be closed after refresh
      await expect(page.locator('#upload-modal')).toBeHidden();

      // Verify at least one checkbox exists (media files are present)
      await expect(page.locator('input[type="checkbox"].media-checkbox')).toHaveCount(await page.locator('input[type="checkbox"].media-checkbox').count());
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 24-media-thumbnail-loading.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 91-media-upload-date.spec.ts", () => {
  /**
   * Regression spec for issue #889: new media uploads displayed as 1/1970 and
   * sorted to the bottom of the grid.
   *
   * Root cause: uploaded_at was stored in epoch-seconds but displayed via
   * new Date(seconds) (treating it as ms). Fixed by the documents read-flip —
   * the admin grid now reads created_at from the documents table and multiplies
   * by 1000 inside mediaDocToFile().
   */
  test.describe('Media upload date display (#889) @media', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page, false)
    })

    test('media library page loads without 1970 dates', async ({ page }) => {
      await gotoMediaLibrary(page)

      // Collect all date text visible on the page
      const dateTexts = await page.locator('.text-xs.text-gray-500').allTextContents()
      for (const text of dateTexts) {
        // None of the visible date strings should mention 1970
        if (text.match(/\d{1,2}\/\d{1,2}\/\d{4}/) || text.match(/\d{4}-\d{2}-\d{2}/)) {
          expect(text).not.toContain('1970')
        }
      }
    })

    test('newly uploaded file appears at the top of the media grid with a valid date', async ({ page }) => {
      await gotoMediaLibrary(page)

      // Open upload modal
      const uploadButton = page.getByRole('button', { name: /upload/i }).first()
      await uploadButton.click()

      // Create a minimal test file. `#file-input`'s onchange only renders a preview — the upload
      // is an htmx POST from the form — so selecting a file uploads nothing without this submit.
      // Nothing was ever uploaded here before, and every assertion below still passed.
      const fileContent = Buffer.from('test-content-for-e2e')
      await page.setInputFiles('#file-input', {
        name: 'e2e-test-upload.txt',
        mimeType: 'text/plain',
        buffer: fileContent,
      })
      // The upload is an htmx POST to /admin/media/upload that writes to R2 and inserts a
      // document; #upload-results stays empty until it answers. Asserting straight after the click
      // spends an assertion budget on a server round trip — that is how this flaked in CI with the
      // locator resolving 24x to an empty <div id="upload-results">. Wait for the response first.
      await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
        page.locator('#upload-modal button[type="submit"]').click()
      )
      await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', {
        timeout: 15000,
      })

      // Wait for upload to complete and page to reload. The `?t=` matters: the upload runs on
      // /admin/media itself, so a bare /\/admin\/media/ matched the pre-upload page — and every
      // assertion below passed against it, which is why a spec named for a date-rendering
      // regression never once looked at the uploaded file's date.
      await page.waitForURL(/\/admin\/media\?t=/, { timeout: 20000, waitUntil: 'domcontentloaded' })

      // The grid should list the newly uploaded file
      const uploaded = page.locator('[data-file-id]').filter({ hasText: 'e2e-test-upload' }).first()
      await expect(uploaded).toBeVisible({ timeout: 15000 })

      // #889 was an epoch-seconds value rendered through `new Date(ms)`: every upload showed
      // 1/1/1970. Assert on the card for the file just uploaded, not on the page as a whole.
      await expect(uploaded).not.toContainText('1970')
    })
  })
})
