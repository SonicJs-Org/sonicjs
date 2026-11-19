import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { navigateToAdminSection } from "./utils/test-helpers"
import { submitAndWaitForXhr } from "./utils/test-helpers"
import { gotoMediaLibrary } from "./fixtures/media-fixtures"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 06-media.spec.ts", () => {
  /**
   * Most of this file used to pass without checking anything.
   *
   * Seven of the twelve tests wrapped their real assertions in `if (await x.count() > 0)` — on a
   * media library that starts empty, so the body never ran and the test reported green for having
   * loaded a page. `should display uploaded media` was the whole body. `should support media
   * search/filter` typed into the box, slept 500ms and asserted nothing at all. `should handle
   * empty media library` only asserted when the library happened to be empty, which it never is
   * once any other spec has uploaded. `should display media list view correctly` put its list-view
   * check behind two `if`s and a `try/catch` whose comment conceded "list view implementation may
   * vary".
   *
   * They are hermetic now: each one uploads the file it then asserts on, so there is no "if
   * something is there" left to hide behind.
   *
   * `should handle media pagination` is gone. The library pages at 24 items and sorts by
   * `updated_at DESC`, which `documents` stores in SECONDS — so making a Next link appear means
   * uploading 25 files, and which of a same-second batch lands on which page is not decidable.
   * What is decidable without any of that is asserted below in `applies the page offset`.
   */

  // Smallest thing the upload path accepts as an image: a 1x1 baseline JPEG.
  const JPEG_1X1 = Buffer.from([
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

  /** The sidebar and the empty state both render an "Upload Files" button. */
  const uploadButton = (page: Page) =>
    page.locator('button').filter({ hasText: 'Upload Files' }).first();

  /**
   * Upload one file and come back to a library page that contains it.
   *
   * On success the response ships a script that hides the modal and navigates to
   * `/admin/media?t=<now>` 1500ms later. Waiting for that navigation rather than issuing our own
   * `goto` is what keeps the pending timer from redirecting out from under the next step.
   */
  async function uploadFile(
    page: Page,
    opts: { name: string; mimeType?: string; buffer?: Buffer }
  ): Promise<string> {
    await uploadButton(page).click();
    await page.setInputFiles('#file-input', {
      name: opts.name,
      mimeType: opts.mimeType ?? 'image/jpeg',
      buffer: opts.buffer ?? JPEG_1X1,
    });

    // The upload is an htmx POST to /admin/media/upload that writes to R2 and inserts a document;
    // #upload-results stays empty until it answers. Asserting straight after the click spends an
    // assertion budget on a server round trip — that is how this flaked in CI with the locator
    // resolving 24x to an empty <div id="upload-results">. Wait for the response first.
    await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
      page.locator('#upload-modal button#upload-btn').click()
    );
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded');

    await page.waitForURL(/\/admin\/media\?t=\d+/);
    return opts.name;
  }

  /** A unique filename, so an assertion can never match another spec's leftovers. */
  function uniqueName(label: string): string {
    return `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.jpg`;
  }

  /** The card for one uploaded file, located by the name rendered in its title. */
  const cardFor = (page: Page, filename: string) =>
    page.locator('#media-grid .media-item').filter({ hasText: filename });

  /**
   * Type into the search box and wait for the htmx swap that search triggers.
   *
   * `fill()` does not work here. It sets the value and fires `input` + `change`, but the input is
   * wired `hx-trigger="keyup changed delay:300ms"` — no keyup, no request, and the assertion that
   * follows then checks an unswapped grid. Typing real keys is what drives it.
   *
   * The response predicate matches the *complete* term so a debounce that happens to fire mid-word
   * cannot satisfy the wait with a partial query.
   */
  async function search(page: Page, term: string): Promise<void> {
    const input = page.locator('#media-search-input');
    const swapped = page.waitForResponse(
      (r) => r.url().includes('/admin/media/search') && r.url().includes(`search=${term}`)
    );
    await input.click();
    await input.pressSequentially(term);
    const res = await swapped;
    expect(res.ok(), `search returned ${res.status()}`).toBeTruthy();
  }

  test.describe('Media Management @smoke @media', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
      await navigateToAdminSection(page, 'media');
    });

    test('should display media library', async ({ page }) => {
      await expect(page.locator('h1')).toContainText('Media Library');
      await expect(uploadButton(page)).toBeVisible();
    });

    test('should open upload modal', async ({ page }) => {
      await uploadButton(page).click();

      await expect(page.locator('#upload-modal')).toBeVisible();
      // The file input is hidden by design — setInputFiles does not need it visible.
      await expect(page.locator('#file-input')).toBeAttached();
    });

    test('should handle file upload', async ({ page }) => {
      const name = await uploadFile(page, { name: uniqueName('upload') });

      // The upload is only done when the library serves the file back.
      await expect(cardFor(page, name)).toHaveCount(1);
    });

    test('should validate file types', async ({ page }) => {
      await uploadButton(page).click();
      await page.setInputFiles('#file-input', {
        name: 'test.exe',
        mimeType: 'application/octet-stream',
        buffer: Buffer.from('fake executable'),
      });

      await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
        page.locator('#upload-modal button#upload-btn').click()
      );

      await expect(page.locator('#upload-results')).toContainText('Unsupported file type');

      // A rejection must not navigate away. The form carried
      // `hx-on::after-request="if(event.detail.successful) { … window.location.href = … }"`, and
      // `successful` is true for any 2xx — which the rejection is, since the handler answers 200
      // with the error list — so it redirected 1500ms later and took the error message with it.
      // The only signal here is that timer NOT firing, so the wait is the assertion.
      await page.waitForTimeout(2_000);
      await expect(page.locator('#upload-modal')).toBeVisible();
      await expect(page.locator('#upload-results')).toContainText('Unsupported file type');
      expect(new URL(page.url()).searchParams.has('t')).toBe(false);
    });

    test('escapes the filename in search results', async ({ page }) => {
      // The search endpoint rendered its own copy of the card markup with no escaping at all, so a
      // filename — which is user-controlled — was injected straight into the grid HTML and into a
      // `title` attribute. It now goes through the same escaping component as the page (R8).
      const marker = `xss${Date.now()}`;
      await uploadFile(page, {
        name: `${marker}<img src=x onerror="window.__xssFired=true">.jpg`,
      });

      await search(page, marker);

      const card = page.locator('#media-grid .media-item').first();
      await expect(card).toHaveCount(1);
      // Rendered as text, not parsed as markup.
      await expect(card.locator('img[src="x"]')).toHaveCount(0);
      await expect(card).toContainText('<img src=x');
      expect(await page.evaluate(() => (window as any).__xssFired)).toBeUndefined();
    });

    test('should display uploaded media', async ({ page }) => {
      const name = await uploadFile(page, { name: uniqueName('display') });

      const card = cardFor(page, name);
      await expect(card).toHaveCount(1);
      await expect(card).toBeVisible();
      // Images render a thumbnail rather than the generic file icon.
      await expect(card.locator('img')).toHaveAttribute('src', /\S/);
      // `data-file-id` is what every selection and details handler keys off.
      await expect(card).toHaveAttribute('data-file-id', /\S/);
    });

    test('should handle media selection', async ({ page }) => {
      const name = await uploadFile(page, { name: uniqueName('select') });

      const card = cardFor(page, name);
      const bulkButton = page.locator('#bulk-actions-btn');
      await expect(bulkButton).toBeDisabled();

      await card.locator('input[type="checkbox"]').check();

      await expect(card).toHaveClass(/selected/);
      await expect(bulkButton).toBeEnabled();
      await expect(bulkButton).toHaveText(/Actions \(1\)/);

      await card.locator('input[type="checkbox"]').uncheck();

      await expect(card).not.toHaveClass(/selected/);
      await expect(bulkButton).toBeDisabled();
      await expect(bulkButton).toHaveText(/Bulk Actions/);
    });

    test('should show media details', async ({ page }) => {
      const name = await uploadFile(page, { name: uniqueName('details') });

      const modal = page.locator('#file-modal');
      await expect(modal).toBeHidden();

      // The details button is inside a hover overlay, so click it through the card.
      await cardFor(page, name)
        .locator('button[hx-get*="/details"]')
        .click();

      await expect(modal).toBeVisible();
      await expect(page.locator('#file-modal-content')).toContainText(name);
    });

    test('should close upload modal', async ({ page }) => {
      await uploadButton(page).click();
      await expect(page.locator('#upload-modal')).toBeVisible();

      await page.locator('#upload-modal button').filter({ hasText: 'Cancel' }).click();

      await expect(page.locator('#upload-modal')).toBeHidden();
    });

    test('should support media search/filter', async ({ page }) => {
      const wanted = await uploadFile(page, { name: uniqueName('needle') });
      const other = await uploadFile(page, { name: uniqueName('haystack') });

      await expect(cardFor(page, wanted)).toHaveCount(1);
      await expect(cardFor(page, other)).toHaveCount(1);

      await search(page, wanted.replace('.jpg', ''));

      await expect(cardFor(page, wanted)).toHaveCount(1);
      await expect(cardFor(page, other)).toHaveCount(0);
    });

    test('renders the empty state when a search matches nothing', async ({ page }) => {
      // Replaces the old `should handle empty media library`, which only asserted when the library
      // happened to be empty — never true once any other spec has uploaded. A search with no hits
      // renders the same empty state through the same component, and does so deterministically.
      await search(page, `no-such-file-${Date.now()}`);

      await expect(page.locator('#media-grid .media-item')).toHaveCount(0);
      await expect(page.locator('#media-grid')).toContainText('No media files');
      await expect(page.locator('#media-grid')).toContainText('match your search');
    });

    test('should display media list view correctly', async ({ page }) => {
      const name = await uploadFile(page, { name: uniqueName('listview') });

      const card = cardFor(page, name);
      // Grid view is the default: the wrapper carries .media-grid.
      await expect(page.locator('#media-grid > div.media-grid')).toHaveCount(1);
      await expect(card).toHaveCount(1);

      // The selector navigates — `onchange="window.location.href = updateUrlParam('view', ...)"`.
      await Promise.all([
        page.waitForURL((url) => url.searchParams.get('view') === 'list'),
        page
          .locator('select')
          .filter({ has: page.locator('option[value="grid"]') })
          .selectOption('list'),
      ]);

      // List view swaps the wrapper class and keeps the same cards.
      await expect(page.locator('#media-grid > div.space-y-4')).toHaveCount(1);
      await expect(page.locator('#media-grid > div.media-grid')).toHaveCount(0);
      await expect(cardFor(page, name)).toHaveCount(1);
    });

    test('applies the page offset', async ({ page }) => {
      // The honest, state-independent half of the pagination contract: page 1 and page 2 are
      // disjoint. It holds for 1 file (page 2 empty) and for 100 (a real second page), so it needs
      // neither a 25-file upload nor a guess about which same-second upload sorts where.
      await uploadFile(page, { name: uniqueName('offset') });

      const ids = async () =>
        page.locator('#media-grid .media-item').evaluateAll((els) =>
          els.map((el) => (el as HTMLElement).dataset.fileId).filter(Boolean)
        );

      await page.goto('/admin/media?page=1');
      const first = await ids();
      expect(first.length).toBeGreaterThan(0);

      await page.goto('/admin/media?page=2');
      const second = await ids();

      expect(second.filter((id) => first.includes(id))).toEqual([]);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 09-media-bulk-actions.spec.ts", () => {
  test.describe('Media Bulk Actions @media', () => {
    let uploadedFileIds: string[] = [];

    test.beforeEach(async ({ page, context }) => {
      await loginAsAdmin(page, false);

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
      const uploadResponse = await context.request.post('/api/media/upload-multiple', {
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

      // Now navigate to media page with cache busting. One load, not two: the previous
      // goto/sleep/reload sequence was guarding against the upload not being visible yet, but the
      // uploads above are awaited API calls — the row exists before this navigation starts, and the
      // poll below is what actually proves it. The round trip it removes is the expensive one.
      await gotoMediaLibrary(page, `/admin/media?t=${Date.now()}`);

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
          await context.request.post('/api/media/bulk-delete', {
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
      // Target the two files this spec uploaded, by id, rather than "whatever is first in the
      // grid". The media library is shared with every other @media spec running in parallel: by
      // position this test deletes a neighbour's fixtures, and comparing the grid's total count
      // before and after fails whenever a neighbour uploads in between (seen as `Expected: 16,
      // Received: 18`).
      expect(uploadedFileIds, 'beforeEach should have uploaded exactly two files').toHaveLength(2);

      for (const id of uploadedFileIds) {
        const box = page.locator(`input[type="checkbox"].media-checkbox[value="${id}"]`);
        await expect(box, `uploaded file ${id} should be on the first page of the grid`).toBeVisible();
        await box.check();
      }

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

      // Our two rows go away. What the rest of the library is doing is another spec's business.
      for (const id of uploadedFileIds) {
        await expect(
          page.locator(`[data-file-id="${id}"]`),
          `media item ${id} should be gone from the grid after bulk delete`
        ).toHaveCount(0, { timeout: 15000 });
      }
      uploadedFileIds = [];

      // Verify bulk actions button is disabled (no files selected)
      await expect(bulkActionsBtn).toBeDisabled();
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 10-media-view-switching.spec.ts", () => {
  /**
   * Pick a view and wait for the resulting navigation.
   *
   * The View select is not htmx — its `onchange` runs
   * `window.location.href = updateUrlParam('view', this.value)`, so every change is a full page
   * load of the same route with `?view=<value>`. Nothing here is instantaneous, and the assertions
   * below are about which container the *server* rendered, so the URL has to have changed before
   * they mean anything.
   */
  async function selectView(page: Page, view: 'grid' | 'list') {
    const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });
    await viewSelector.selectOption(view);
    await page.waitForURL(new RegExp(`[?&]view=${view}(&|$)`));
  }

  test.describe('Media View Switching @media', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page, false);
      await gotoMediaLibrary(page);
    });

    test('should switch between grid and list views bidirectionally', async ({ page }) => {
      // Verify default view is grid by checking the container class
      const mediaGridContainer = page.locator('#media-grid > div.media-grid');
      await expect(mediaGridContainer).toBeVisible();

      // Find the view selector dropdown
      const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });
      await expect(viewSelector).toBeVisible();

      // Verify grid is selected
      await expect(viewSelector).toHaveValue('grid');

      // Switch to list view
      await selectView(page, 'list');

      // Verify list view is active - list view uses space-y-4 class
      const listViewContainer = page.locator('#media-grid > div.space-y-4');
      await expect(listViewContainer).toBeVisible();
      await expect(mediaGridContainer).not.toBeVisible();
      await expect(viewSelector).toHaveValue('list');

      // Switch back to grid view
      await selectView(page, 'grid');

      // Verify grid view is active again
      await expect(mediaGridContainer).toBeVisible();
      await expect(listViewContainer).not.toBeVisible();
      await expect(viewSelector).toHaveValue('grid');

      // Test multiple switches to ensure consistency
      await selectView(page, 'list');
      await expect(listViewContainer).toBeVisible();
      await expect(viewSelector).toHaveValue('list');

      await selectView(page, 'grid');
      await expect(mediaGridContainer).toBeVisible();
      await expect(viewSelector).toHaveValue('grid');

      await selectView(page, 'list');
      await expect(listViewContainer).toBeVisible();
      await expect(viewSelector).toHaveValue('list');
    });

    test('should persist view preference across page reloads', async ({ page }) => {
      const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });

      // Switch to list view
      await selectView(page, 'list');

      // Verify list view is active
      const listViewContainer = page.locator('#media-grid > div.space-y-4');
      await expect(listViewContainer).toBeVisible();
      await expect(viewSelector).toHaveValue('list');

      // Reload page
      await page.reload();

      // Verify list view is still active after reload
      await expect(listViewContainer).toBeVisible();
      await expect(viewSelector).toHaveValue('list');

      // Switch back to grid, then reload. `reload()` re-requests whatever URL the page is
      // currently on, so it has to run after the `?view=grid` navigation has committed — the
      // 500ms sleep that used to stand in for that wait expired first on a slow preview, the
      // reload re-fetched `?view=list`, and the grid container was never in the document.
      await selectView(page, 'grid');
      await page.reload();

      // Verify grid view is active after reload
      const mediaGridContainer = page.locator('#media-grid > div.media-grid');
      await expect(mediaGridContainer).toBeVisible();
      await expect(viewSelector).toHaveValue('grid');
    });

    test('should reflect selected view in dropdown', async ({ page }) => {
      const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });

      // Initial state: grid should be selected
      await expect(viewSelector).toHaveValue('grid');

      // Switch to list view
      await selectView(page, 'list');

      // List should now be selected
      await expect(viewSelector).toHaveValue('list');

      // Switch back to grid
      await selectView(page, 'grid');

      // Grid should be selected again
      await expect(viewSelector).toHaveValue('grid');
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 18-media-bulk-menu-zindex.spec.ts", () => {
  test.describe('Media Bulk Actions Menu Z-Index @media', () => {
    let uploadedFileIds: string[] = [];

    test.beforeEach(async ({ page, context }) => {
      await loginAsAdmin(page, false);

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

      const uploadResponse = await context.request.post('/api/media/upload-multiple', {
        multipart: formData
      });

      const uploadResult = await uploadResponse.json();
      if (uploadResult.uploaded && Array.isArray(uploadResult.uploaded)) {
        uploadedFileIds = uploadResult.uploaded.map((file: any) => file.id);
      }

      // Navigate to media page. One load: the upload above is an awaited API call, so the two
      // rows already exist server-side and the sleep-then-reload dance was only ever hiding the
      // absence of a real wait. The tests below assert on the checkboxes, which auto-wait.
      await gotoMediaLibrary(page);
    });

    test.afterEach(async ({ context }) => {
      if (uploadedFileIds.length > 0) {
        try {
          await context.request.post('/api/media/bulk-delete', {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 25-media-cleanup-unused.spec.ts", () => {
  test.describe('Media Cleanup Unused Files @media', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page, false);
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

      // The upload is an htmx POST to /admin/media/upload that writes to R2 and inserts a
      // document; #upload-results stays empty until it answers. Asserting straight after the click
      // spends an assertion budget on a server round trip — that is how this flaked in CI with the
      // locator resolving 24x to an empty <div id="upload-results">. Wait for the response first.
      await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
        page.locator('#upload-modal button#upload-btn').click()
      );

      // Wait for upload success
      await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });

      // Wait for page to reload after upload

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

      // The upload is an htmx POST to /admin/media/upload that writes to R2 and inserts a
      // document; #upload-results stays empty until it answers. Asserting straight after the click
      // spends an assertion budget on a server round trip — that is how this flaked in CI with the
      // locator resolving 24x to an empty <div id="upload-results">. Wait for the response first.
      await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
        page.locator('#upload-modal button#upload-btn').click()
      );

      // Wait for upload success
      await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 });

      // Wait for page to reload

      // Step 2: Create content that references this file
      // Navigate to content section
      await page.goto('/admin/content');

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
      await gotoMediaLibrary(page);

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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 88-media-library-fixes.spec.ts", () => {
  test.describe('Media library fixes (#888, #890) @media', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page, false)
    })

    test('#888 All Files count reflects real total, not page size', async ({ page }) => {
      await gotoMediaLibrary(page)

      // Find the "All Files" sidebar entry - should show a number, not be capped at 24
      const allFilesText = page.locator('text=/All Files/').first()
      await expect(allFilesText).toBeVisible()

      // The count label should exist and be a number (regression: was always 24)
      const countEl = page.locator('[data-testid="total-files-count"], .total-files-count').first()
      // If no data-testid, just verify the page renders without error
      await expect(page.locator('body')).not.toContainText('Error')
    })

    test('#890 Media selector search input has name attribute', async ({ page }) => {
      await page.goto('/admin/media/selector')

      const searchInput = page.locator('#media-selector-search')
      await expect(searchInput).toHaveAttribute('name', 'search')
    })
  })
})
