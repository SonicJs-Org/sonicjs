import { test, expect, type Page } from './fixtures';
import { loginAsAdmin, navigateToAdminSection, submitAndWaitForXhr } from './utils/test-helpers';

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
