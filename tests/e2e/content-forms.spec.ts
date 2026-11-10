import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { fillHiddenEditorFields } from "./utils/test-helpers"
import { loginAsAdmin } from "./utils/test-helpers"
import { waitForHTMX } from "./utils/test-helpers"
import { saveNewContent } from "./fixtures/content-fixtures"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { uniqueTestId } from "./utils/test-runtime"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 117-content-form-no-htmx.spec.ts", () => {
  /**
   * The content form has to survive a submit that htmx did not intercept.
   *
   * htmx is loaded from a CDN, so there is a window after the markup is interactive in which
   * `hx-post` / `hx-put` are not wired up yet — and if the CDN is unreachable the window never
   * closes. The form carried no `method` or `action`, so a submit in that state fell back to the
   * browser default: a GET of the current URL with every field in the query string. For a create
   * that landed back on the "pick a collection" page and silently dropped the content; for an
   * edit it reloaded the editor with the changes gone. The form now declares `method="post"`
   * plus an `action`, and the update handler answers POST as well as PUT because a plain form
   * cannot send PUT.
   *
   * Blocking the htmx script reproduces that state exactly.
   */
  test.describe('Content form submits without htmx @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      await page.route('**/htmx*', (route) => route.abort())
    })

    test('creates and updates content with htmx unavailable', async ({ page }) => {
      // Use whichever collection the install lists first — the fallback is not collection
      // specific, and hard-coding one breaks as soon as the demo app changes.
      await page.goto('/admin/content/new')
      const collectionLink = page.locator('a[href*="/admin/content/new?collection="]').first()
      await expect(collectionLink).toBeVisible({ timeout: 15000 })
      const href = await collectionLink.getAttribute('href')
      const collectionId = new URL(`http://x${href}`).searchParams.get('collection')
      expect(collectionId).toBeTruthy()

      const timestamp = Date.now()
      const title = `E2E no-htmx ${timestamp}`

      await page.goto(`/admin/content/new?collection=${collectionId}`)
      await expect(page.locator('form#content-form')).toHaveAttribute('action', '/admin/content')
      await expect(page.locator('form#content-form')).toHaveAttribute('method', /post/i)

      await page.locator('input[name="title"]').first().fill(title)
      await page.locator('input[name="slug"]').first().fill(`e2e-no-htmx-${timestamp}`)
      await fillRequiredFields(page, timestamp)

      // Without htmx this is a plain browser submit, so it navigates.
      await Promise.all([
        page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 20000 }),
        page.locator('button[name="action"][value="save"]').first().click(),
      ])

      const rootId = page.url().match(/\/admin\/content\/([^/?]+)\/edit/)?.[1]
      expect(rootId).toBeTruthy()
      await expect(page.locator('input[name="title"]').first()).toHaveValue(title)

      // The edit form points its native action at the POST alias for the update handler.
      await expect(page.locator('form#content-form')).toHaveAttribute(
        'action',
        `/admin/content/${rootId}`
      )

      const updatedTitle = `E2E no-htmx updated ${timestamp}`
      await page.locator('input[name="title"]').first().fill(updatedTitle)
      await Promise.all([
        page.waitForURL(/\/admin\/content\/[^/]+\/edit\?success=/, { timeout: 20000 }),
        page.locator('button[name="action"][value="save"]').first().click(),
      ])

      await page.goto(`/admin/content/${rootId}/edit`)
      await expect(page.locator('input[name="title"]').first()).toHaveValue(updatedTitle)
    })
  })

  /**
   * Fill whatever else the collection declares required. Which fields those are is a per-
   * collection decision, so they are discovered from the rendered form rather than listed here.
   */
  async function fillRequiredFields(page: Page, timestamp: number) {
    const controls = page.locator('form#content-form [required]:not([type="hidden"]):not([disabled])')

    for (let i = 0; i < (await controls.count()); i++) {
      const control = controls.nth(i)
      if (!(await control.isVisible())) continue

      const tag = (await control.evaluate((node) => node.tagName)).toLowerCase()
      if (tag === 'select') {
        const values = await control
          .locator('option')
          .evaluateAll((options) => options.map((o) => (o as HTMLOptionElement).value).filter(Boolean))
        if (values.length > 0) await control.selectOption(values[0])
        continue
      }

      if (await control.inputValue()) continue
      await control.fill(`E2E ${timestamp}`)
    }

    // Lexical — the default richtext editor on a fresh install — edits a contenteditable surface
    // and mirrors into a hidden input, so `[required]:not([type="hidden"])` never sees it. The
    // browser raises no constraint error either, and the save fails server-side instead
    // ("Content is required"), which looks like a broken form rather than an unfilled field.
    await fillHiddenEditorFields(page, `E2E no-htmx body ${timestamp}`)
  }
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 118-content-save-and-close.spec.ts", () => {
  test.describe('Content save-and-close redirects to unfiltered list @smoke @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('save-and-close returns to unfiltered content list with updated title @content', async ({ page }) => {
      const unique = Math.random().toString(36).slice(2, 8)
      const originalTitle = `SaveClose Original ${unique}`
      const updatedTitle = `SaveClose Updated ${unique}`
      const slug = `saveclose-${unique}`

      const createRes = await page.request.post('/admin/documents', {
        headers: { 'Content-Type': 'application/json' },
        data: {
          typeId: 'blog_post',
          title: originalTitle,
          slug,
          data: { author: 'E2E', difficulty: 'beginner', content: '<p>test</p>', excerpt: 'x' },
          publishOnCreate: true,
        },
      })
      expect(createRes.ok()).toBeTruthy()
      const created = await createRes.json()
      const rootId = created.data?.rootId ?? created.rootId ?? created.id

      await page.goto(`/admin/content/${rootId}/edit`)
      await waitForHTMX(page)

      const titleInput = page.locator('input[name="title"]')
      await titleInput.fill(updatedTitle)

      const saveCloseBtn = page.locator('button[value="save_and_close"]')
      await saveCloseBtn.click()
      await page.waitForURL(url => url.pathname === '/admin/content', { timeout: 10000 })

      // Verify redirected to unfiltered list (no collection= or model= param)
      const url = new URL(page.url())
      expect(url.pathname).toBe('/admin/content')
      expect(url.searchParams.has('collection')).toBe(false)
      expect(url.searchParams.has('model')).toBe(false)

      await waitForHTMX(page)
      await expect(page.locator('body')).toContainText(updatedTitle)
    })

    test('name-field update reflects as title on content list @content', async ({ page }) => {
      const unique = Math.random().toString(36).slice(2, 8)
      const originalName = `NameTest Original ${unique}`
      const updatedName = `NameTest Updated ${unique}`

      const createRes = await page.request.post('/admin/documents', {
        headers: { 'Content-Type': 'application/json' },
        data: {
          typeId: 'example',
          title: originalName,
          data: { name: originalName, emoji: '😈', description: 'test' },
          publishOnCreate: true,
        },
      })
      expect(createRes.ok(), 'create example doc').toBeTruthy()
      const created = await createRes.json()
      const rootId = created.data?.rootId ?? created.rootId ?? created.id

      await page.goto(`/admin/content/${rootId}/edit`)
      await waitForHTMX(page)

      const nameInput = page.locator('input[name="name"]')
      await nameInput.fill(updatedName)

      const saveCloseBtn = page.locator('button[value="save_and_close"]')
      await saveCloseBtn.click()
      await page.waitForURL(url => url.pathname === '/admin/content', { timeout: 10000 })

      await waitForHTMX(page)
      await expect(page.locator('body')).toContainText(updatedName)
    })

    test('save-and-close preserves referrer params when present @content', async ({ page }) => {
      const unique = Math.random().toString(36).slice(2, 8)
      const title = `Referrer Test ${unique}`
      const slug = `referrer-${unique}`

      const createRes = await page.request.post('/admin/documents', {
        headers: { 'Content-Type': 'application/json' },
        data: {
          typeId: 'blog_post',
          title,
          slug,
          data: { author: 'E2E', difficulty: 'beginner', content: '<p>test</p>', excerpt: 'x' },
          publishOnCreate: true,
        },
      })
      expect(createRes.ok()).toBeTruthy()
      const created = await createRes.json()
      const rootId = created.data?.rootId ?? created.rootId ?? created.id

      await page.goto(`/admin/content/${rootId}/edit?ref=${encodeURIComponent('model=blog_post')}`)
      await waitForHTMX(page)

      const saveCloseBtn = page.locator('button[value="save_and_close"]')
      await saveCloseBtn.click()
      await page.waitForURL(url => url.pathname === '/admin/content', { timeout: 10000 })

      const url = new URL(page.url())
      expect(url.searchParams.get('model')).toBe('blog_post')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 122-content-form-no-background-write.spec.ts", () => {
  /**
   * The content form used to arm a 30s autosave timer on every `input` and `change` event, then
   * `fetch(form.action, { method: 'POST', body: formData })` with `action=autosave` appended.
   *
   * Two things were wrong with it. `HTMLFormElement` is [LegacyOverrideBuiltIns], so the two
   * submit buttons named "action" shadowed the built-in `form.action` property: the fetch read a
   * RadioNodeList, stringified it to "[object RadioNodeList]" and posted to
   * /admin/content/[object%20RadioNodeList]. And nothing server-side has ever handled
   * `action=autosave`, so repairing the URL would have made the timer create a new document every
   * 30 seconds instead of 404ing. The timer was also re-armed on every keystroke and outlived the
   * page that set it, so it fired from whatever the editor had navigated to next.
   *
   * `/admin/content/new` is a page CI opens constantly, which made this a steady source of
   * unanswered worker requests during E2E runs. Guard the shape of the fix rather than the dead
   * code: the form writes when the operator asks it to, and never on a timer.
   *
   * `e2e_test` is code-registered and needs only title + slug.
   */
  const NEW_RECORD_FORM = '/admin/content/new?collection=e2e_test'

  /** Nothing on this page has a legitimate reason to schedule a write this far out. */
  const LONG_TIMER_MS = 10_000

  test.describe('Content form background writes @smoke @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('typing in the form arms no long-running timer and sends no write', async ({ page }) => {
      // Recorded from an init script so the wrapper is in place before any page script runs --
      // the old timer was armed by the form's own DOMContentLoaded handler.
      await page.addInitScript(() => {
        ;(window as any).__longTimers = []
        const original = window.setTimeout
        ;(window as any).setTimeout = function (handler: TimerHandler, delay?: number, ...args: any[]) {
          if (typeof delay === 'number' && delay >= 10_000) {
            ;(window as any).__longTimers.push(delay)
          }
          return original(handler, delay as any, ...args)
        }
      })

      const writes: string[] = []
      page.on('request', (req) => {
        if (req.method() !== 'GET' && req.method() !== 'HEAD') writes.push(`${req.method()} ${req.url()}`)
      })

      await page.goto(NEW_RECORD_FORM)
      await expect(page.locator('#content-form')).toBeVisible()

      const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
      await page.fill('input[name="title"]', `No autosave ${stamp}`)
      await page.fill('input[name="slug"]', `no-autosave-${stamp}`)
      // `change` as well as `input`: the old handler bound both.
      await page.selectOption('select[name="status"]', 'draft')
      await page.locator('input[name="title"]').blur()

      // Long enough for the slug-availability debounce (500ms) and any immediate writer to show up.
      await page.waitForTimeout(2000)

      const timers = await page.evaluate(() => (window as any).__longTimers as number[])
      expect(timers, `the form scheduled a timer >= ${LONG_TIMER_MS}ms: ${timers.join(', ')}`).toEqual([])

      // The form itself must not have written anything yet -- nobody has pressed Save.
      expect(writes, `the form wrote without being asked: ${writes.join(', ')}`).toEqual([])
    })

    test('the explicit save posts to the collection endpoint, not to a stringified node list', async ({
      page,
    }) => {
      const seen: string[] = []
      page.on('request', (req) => {
        if (req.method() === 'POST') seen.push(new URL(req.url()).pathname)
      })

      await page.goto(NEW_RECORD_FORM)
      const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
      await page.fill('input[name="title"]', `Explicit save ${stamp}`)
      await page.fill('input[name="slug"]', `explicit-save-${stamp}`)
      await page.selectOption('select[name="status"]', 'draft')

      const editPath = await saveNewContent(page, () =>
        page
          .locator('button[type="submit"]')
          .filter({ hasText: /Save|Create/ })
          .first()
          .click()
      )
      expect(editPath).toMatch(/^\/admin\/content\/[^/]+\/edit$/)

      expect(seen).toContain('/admin/content')
      // The property `form.action` resolves to the two buttons named "action" on this form, so any
      // code that reads it instead of the attribute ends up here.
      for (const path of seen) {
        expect(path, `posted to a stringified DOM node: ${path}`).not.toContain('[object')
      }
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 19-content-media-selector.spec.ts", () => {
  test.describe('Content Media Selector @content @media', () => {
    const testCollectionId = 'e2e_test'; // Code-defined collection carrying media fields
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

      const uploadResponse = await context.request.post('/api/media/upload-multiple', {
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
        await context.request.post('/api/media/bulk-delete', {
          data: { fileIds: [uploadedFileId] }
        }).catch(() => {});
      }
    });

    test('should open media selector modal when Select Media button is clicked', async ({ page }) => {
      // Navigate to new content page for our test collection
      await page.goto(`/admin/content/new?collection=${testCollectionId}`);
      await page.waitForLoadState('domcontentloaded');

      // Find and click the "Select Media" button
      const selectMediaButton = page.locator('button:has-text("Select Media")').first();
      await expect(selectMediaButton).toBeVisible({ timeout: 10000 });
      await selectMediaButton.click();

      // Verify media selector modal appears
      const modal = page.locator('#media-selector-modal');
      await expect(modal).toBeVisible({ timeout: 5000 });

      // Verify modal has title "Select Media"
      await expect(page.locator('h3:has-text("Select Media")').first()).toBeVisible();
    });

    test('should display media files in the selector modal', async ({ page }) => {
      // Navigate to new content page
      await page.goto(`/admin/content/new?collection=${testCollectionId}`);
      await page.waitForLoadState('domcontentloaded');

      // Open media selector
      await page.locator('button:has-text("Select Media")').first().click();

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
      await page.waitForLoadState('domcontentloaded');

      // Open media selector
      await page.locator('button:has-text("Select Media")').first().click();

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
      await page.waitForLoadState('domcontentloaded');

      // Open media selector
      await page.locator('button:has-text("Select Media")').first().click();
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

      // Verify the backing input is populated with a URL. It is type="hidden", so assert it is
      // attached rather than visible.
      const hiddenInput = page.locator('input#field-featuredImage');
      await expect(hiddenInput).toBeAttached({ timeout: 1000 });
      const hiddenInputValue = await hiddenInput.inputValue();
      expect(hiddenInputValue).toBeTruthy();
      // Media URLs are served relative (/files/<folder>/<name>); absolute URLs are also valid
      // when an R2 public bucket is configured.
      expect(hiddenInputValue).toMatch(/^(https?:\/\/\S+|\/[^\s?]+)\.(jpe?g|png|gif|webp|svg|avif)$/i);

      // Verify image preview is displayed. The collection has several media fields, so scope the
      // preview to the one we populated.
      const preview = page.locator('#field-featuredImage-preview img');
      await expect(preview).toBeVisible({ timeout: 5000 });
    });

    test('should close media selector when Cancel button is clicked', async ({ page }) => {
      // Navigate to new content page
      await page.goto(`/admin/content/new?collection=${testCollectionId}`);
      await page.waitForLoadState('domcontentloaded');

      // Open media selector
      await page.locator('button:has-text("Select Media")').first().click();

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
      await page.waitForLoadState('domcontentloaded');

      // Open media selector and select a file
      await page.locator('button:has-text("Select Media")').first().click();
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

      // Verify file is selected (preview is visible). Scope to the field we populated — the
      // collection renders several media fields.
      const preview = page.locator('#field-featuredImage-preview img');
      await expect(preview).toBeVisible({ timeout: 5000 });

      // Click Remove button — it is injected on selection with data-media-remove="true"
      const removeButton = page.locator('button[data-media-remove="true"]').first();
      await expect(removeButton).toBeVisible({ timeout: 5000 });
      await removeButton.click();

      // Verify the backing input is cleared
      const hiddenInput = page.locator('input#field-featuredImage');
      const hiddenInputValue = await hiddenInput.inputValue();
      expect(hiddenInputValue).toBe('');

      // Verify preview is hidden
      await expect(preview).toBeHidden({ timeout: 3000 });
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 39-slug-generation.spec.ts", () => {
  // Tests below that actually save content need a name no earlier run has already used: a
  // repeated slug is rejected by the duplicate check and the form never submits. The `Test `
  // prefix is what the cleanup endpoint matches on, so these rows do not pile up either.
  // Slug availability is checked by a 500ms-debounced request to the worker, so these
  // assertions wait on a cold HTTP round trip rather than on local DOM work. Playwright's
  // 5s expect default does not cover that against a preview deployment: it is what failed
  // two of these tests in CI, both attempts, with the status stuck on
  // "⏳ Checking availability..." -- the request in flight, not a product defect.
  const SLUG_CHECK_TIMEOUT = 20_000

  const RUN = uniqueTestId()

  /**
   * No `waitForLoadState('networkidle')` in this file.
   *
   * Every test used to open a form page and then wait up to 15s for the network to go idle before
   * its real `waitForSelector`. Admin pages poll, so idle need never arrive, and the selector wait
   * that follows is the one that actually gates the fills — the idle wait only ever added up to 15s
   * of dead time per test to a suite whose failures are all budget exhaustion.
   */

  test.describe('Slug Generation @content', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('should auto-generate slug from title when creating new content', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')

      // Fill the title field and manually dispatch input event
      await titleField.fill('My Awesome New Page 2024')
      await titleField.evaluate((el) => {
        el.dispatchEvent(new Event('input', { bubbles: true }));
      })

      // Wait for slug to auto-generate (account for 500ms debounce + API call)
      await expect(slugField).toHaveValue('my-awesome-new-page-2024', { timeout: 15000 })

      // Should show available status
      const statusDiv = page.locator('#field-slug-status')
      await expect(statusDiv).toContainText('Available', { timeout: SLUG_CHECK_TIMEOUT })
    })

    test('should auto-generate slug for blog_post collection', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')

      // Fill the title field and manually dispatch input event
      await titleField.fill('My Second Test Page 2024')
      await titleField.evaluate((el) => {
        el.dispatchEvent(new Event('input', { bubbles: true }));
      })

      // Wait for slug to auto-generate (account for 500ms debounce + API call)
      await expect(slugField).toHaveValue('my-second-test-page-2024', { timeout: 15000 })

      // Should show available status
      const statusDiv = page.locator('#field-slug-status')
      await expect(statusDiv).toContainText('Available', { timeout: SLUG_CHECK_TIMEOUT })
    })

    test('should handle special characters in slug generation', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')

      // Type title with special characters
      await titleField.fill('Hello World! @#$% Test 2024')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))

      // Wait for auto-generation (debounce + API call)
      await page.waitForTimeout(1500)

      // Slug should clean special chars
      await expect(slugField).toHaveValue('hello-world-test-2024', { timeout: 15000 })
    })

    test('should stop auto-generating after manual edit', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')

      // Auto-generate first
      await titleField.fill('Initial Title')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
      await page.waitForTimeout(1500)
      await expect(slugField).toHaveValue('initial-title', { timeout: 15000 })

      // Manually edit slug
      await slugField.fill('my-custom-slug')
      await page.waitForTimeout(1000)

      // Change title again
      await titleField.fill('Changed Title')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
      await page.waitForTimeout(1500)

      // Slug should NOT auto-update
      await expect(slugField).toHaveValue('my-custom-slug')
    })

    test('should regenerate slug when button clicked', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')
      const regenerateBtn = page.locator('button:has-text("Regenerate from title")')

      // Set title and manually edit slug
      await titleField.fill('Original Title')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
      await page.waitForTimeout(1500)
      await slugField.fill('custom-slug')

      // Update title
      await titleField.fill('Brand New Title 2024')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
      await page.waitForTimeout(1500)

      // Slug still custom (auto-generation stopped)
      await expect(slugField).toHaveValue('custom-slug')

      // Click regenerate
      await regenerateBtn.click()
      await page.waitForTimeout(1000)

      // Slug should update from current title
      await expect(slugField).toHaveValue('brand-new-title-2024')
    })

    test('should detect duplicate slugs within same collection', async ({ page, resourceId }) => {
      // Creating content is prerequisite here; the behavior under test is the duplicate check.
      const slug = `test-duplicate-${resourceId}`
      const created = await page.request.post('/api/content', {
        data: { collectionId: 'blog_post', title: `Test Duplicate ${resourceId}`, slug,
          data: { author: 'Test Author', content: 'Test content' } },
      })
      expect(created.ok(), `Duplicate-slug prerequisite failed: HTTP ${created.status()}`).toBeTruthy()
      const body = await created.json()
      const id = body.data?.id || body.id
      expect(id).toBeTruthy()
      try {
        await page.goto('/admin/content/new?collection=blog_post')
        await page.locator('input[name="title"]').fill('Different Title')
        const slugField = page.locator('input[name="slug"]')
        await slugField.fill(slug)
        await expect(page.locator('#field-slug-status')).toContainText('already in use', {
          timeout: SLUG_CHECK_TIMEOUT,
        })
        await expect.poll(() => slugField.evaluate((el: HTMLInputElement) => !el.validity.valid)).toBe(true)
      } finally {
        const deleted = await page.request.delete(`/api/content/${id}`)
        expect(deleted.ok(), `Duplicate-slug cleanup failed: HTTP ${deleted.status()}`).toBeTruthy()
      }
    })

    test('should not auto-change slug when editing existing content', async ({ page }) => {
      // Create content first
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      await page.fill('input[name="title"]', `Test Edit Mode ${RUN}`)
      await page.waitForTimeout(1000)

      const originalSlug = `test-edit-mode-${RUN}`
      await expect(page.locator('input[name="slug"]')).toHaveValue(originalSlug)

      // Fill required fields before saving
      // Fill the user-picker author field. Setting the hidden input alone is not enough:
      // the field's submit handler overwrites the hidden value from the visible search box
      // unless the display value matches dataset.linkedName. Set all three so it sticks.
      await page.evaluate(() => {
        const container = document.querySelector('.user-search-field-container')
        if (container) {
          const display = container.querySelector('input[type="text"]') as HTMLInputElement | null
          const hidden = container.querySelector('input[type="hidden"]') as HTMLInputElement | null
          if (display) { display.value = 'Test Author'; display.dataset.linkedName = 'Test Author' }
          if (hidden) { hidden.value = 'Test Author' }
        } else {
          const el = document.querySelector('input[name="author"]') as HTMLInputElement | null
          if (el) { el.value = 'Test Author'; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })) }
        }
      })
      await page.evaluate(() => {
        const el = document.querySelector('input[name="content"], textarea[name="content"]') as HTMLInputElement | HTMLTextAreaElement
        if (el) el.value = 'Test content'
      })

      await saveNewContent(page, () => page.click('button[name="action"][value="save_and_publish"]'))

      // Publishing navigated to this record's freshly server-rendered edit form, so the slug below
      // is the stored one. The list round trip this replaces hunted for the row by title on a
      // paginated page four workers write to concurrently — the same race that burned a full 120s
      // budget in CI two tests down.
      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')

      // Verify slug is unchanged
      await expect(slugField).toHaveValue(originalSlug)

      // Change title
      await titleField.fill('Completely Different Title')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
      await page.waitForTimeout(1500)

      // Slug should NOT auto-change in edit mode
      await expect(slugField).toHaveValue(originalSlug)
    })

    test('should allow manual regeneration in edit mode', async ({ page }) => {
      // Create content first
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      await page.fill('input[name="title"]', `Test Regen Page ${RUN}`)
      await page.waitForTimeout(1000)

      // Fill required fields before saving
      // Fill the user-picker author field. Setting the hidden input alone is not enough:
      // the field's submit handler overwrites the hidden value from the visible search box
      // unless the display value matches dataset.linkedName. Set all three so it sticks.
      await page.evaluate(() => {
        const container = document.querySelector('.user-search-field-container')
        if (container) {
          const display = container.querySelector('input[type="text"]') as HTMLInputElement | null
          const hidden = container.querySelector('input[type="hidden"]') as HTMLInputElement | null
          if (display) { display.value = 'Test Author'; display.dataset.linkedName = 'Test Author' }
          if (hidden) { hidden.value = 'Test Author' }
        } else {
          const el = document.querySelector('input[name="author"]') as HTMLInputElement | null
          if (el) { el.value = 'Test Author'; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })) }
        }
      })
      await page.evaluate(() => {
        const el = document.querySelector('input[name="content"], textarea[name="content"]') as HTMLInputElement | HTMLTextAreaElement
        if (el) el.value = 'Test content'
      })

      await saveNewContent(page, () => page.click('button[name="action"][value="save_and_publish"]'))

      // Publishing already landed on this record's edit form, which is where the rest of the test
      // runs. The round trip this replaces went back out to /admin/content and hunted for the row
      // by title, which is a race on a paginated list that four workers are writing to: in CI the
      // link never appeared and the click burned the whole 120s budget. The edit URL is in hand.
      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')
      const regenerateBtn = page.locator('button:has-text("Regenerate from title")')

      // Change title
      await titleField.fill('Brand New Page Name')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))
      await page.waitForTimeout(1500)

      // Slug still shows old value
      await expect(slugField).toHaveValue(`test-regen-page-${RUN}`)

      // Click regenerate
      await regenerateBtn.click()
      await page.waitForTimeout(1000)

      // Slug should update
      await expect(slugField).toHaveValue('brand-new-page-name')
    })

    test('should show checking status during duplicate validation', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      const titleField = page.locator('input[name="title"]')
      const slugField = page.locator('input[name="slug"]')
      const statusDiv = page.locator('#field-slug-status')

      // Type title
      await titleField.fill('Checking Status Test')
      await titleField.evaluate((el) => el.dispatchEvent(new Event('input', { bubbles: true })))

      // Immediately check status (before debounce completes)
      await page.waitForTimeout(200)

      // Should show checking or empty (debouncing)
      const statusText = await statusDiv.textContent()
      expect(statusText === '' || statusText?.includes('Checking')).toBe(true)

      // Wait for check to complete
      await page.waitForTimeout(1500)

      // Should show available
      await expect(statusDiv).toContainText('Available', { timeout: SLUG_CHECK_TIMEOUT })
    })

    test('should prevent form submission with duplicate slug', async ({ page }) => {
      // Create first content
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      await page.fill('input[name="title"]', `Test Submission ${RUN}`)
      await page.waitForTimeout(1000)

      // Fill required fields before saving
      // Fill the user-picker author field. Setting the hidden input alone is not enough:
      // the field's submit handler overwrites the hidden value from the visible search box
      // unless the display value matches dataset.linkedName. Set all three so it sticks.
      await page.evaluate(() => {
        const container = document.querySelector('.user-search-field-container')
        if (container) {
          const display = container.querySelector('input[type="text"]') as HTMLInputElement | null
          const hidden = container.querySelector('input[type="hidden"]') as HTMLInputElement | null
          if (display) { display.value = 'Test Author'; display.dataset.linkedName = 'Test Author' }
          if (hidden) { hidden.value = 'Test Author' }
        } else {
          const el = document.querySelector('input[name="author"]') as HTMLInputElement | null
          if (el) { el.value = 'Test Author'; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })) }
        }
      })
      await page.evaluate(() => {
        const el = document.querySelector('input[name="content"], textarea[name="content"]') as HTMLInputElement | HTMLTextAreaElement
        if (el) el.value = 'Test content'
      })

      await saveNewContent(page, () => page.click('button[name="action"][value="save_and_publish"]'))

      // Try to create duplicate
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForSelector('input[name="title"]', { timeout: 10000 })

      await page.fill('input[name="title"]', 'Different Title')
      await page.waitForTimeout(500)

      // Set duplicate slug
      await page.fill('input[name="slug"]', `test-submission-${RUN}`)
      await page.waitForTimeout(1500)

      // Should show error
      await expect(page.locator('#field-slug-status')).toContainText('already in use', {
        timeout: SLUG_CHECK_TIMEOUT,
      })

      // Try to submit
      await page.click('button[name="action"][value="save_and_publish"]')

      // Should still be on form (not navigate away)
      await page.waitForTimeout(1000)
      await expect(page).toHaveURL(/\/admin\/content\/new/)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 54-hero-cta-style-persistence.spec.ts", () => {
  test.describe('Hero CTA Style Persistence @content', () => {
    test('should keep CTA styles after unrelated second save', async ({ page }) => {
      // Seven full page loads (login, /admin/content/new, the collection pick, two saves and
      // their redirects, the final reload) plus the cleanup round trip. The 60s this replaces was
      // *below* the suite default, so the test had opted itself out of the CI budget it needed:
      // against a cold preview one admin page load has been measured at ~10s p90.
      test.setTimeout(180000)
      let contentId: string | null = null
      const title = `Hero CTA Persist ${Date.now()}`
      const updatedTitle = `${title} updated`
      const tryExtractContentIdFromHref = (href: string | null) => {
        const match = href?.match(/\/admin\/content\/([^/]+)\/edit/)
        return match?.[1] || null
      }
      try {
        await ensureAdminUserExists(page)
        await loginAsAdmin(page)

        await page.goto('/admin/content/new')
        const e2eTestLink = page.locator('a[href^="/admin/content/new?collection="]').filter({ hasText: 'E2E Test' })
        await expect(e2eTestLink).toBeVisible()
        await e2eTestLink.click()

        await page.waitForLoadState('networkidle')
        await expect(page.locator('form#content-form')).toBeVisible()

        await page.fill('input[name="title"]', title)
        await page.fill('input[name="slug"]', `hero-cta-persist-${Date.now()}`)

        const blocksField = page.locator('[data-field-name="body"]')
        await blocksField.locator('[data-role="block-type-select"]').selectOption('hero')
        await blocksField.locator('[data-action="add-block"]').click()

        const firstBlock = blocksField.locator('.blocks-item').first()
        await firstBlock.locator('[data-block-field="heading"] input').fill('Hero heading')

        const ctaPrimary = firstBlock.locator('[data-block-field="ctaPrimary"]')
        const ctaPrimaryLabel = ctaPrimary.locator('input[name$="__label"]')
        if (!(await ctaPrimaryLabel.isVisible())) {
          await ctaPrimary.locator('.field-group-header').first().click()
          await expect(ctaPrimaryLabel).toBeVisible()
        }
        const ctaPrimaryMode = ctaPrimary.locator('select[name$="__mode"]')
        if (!(await ctaPrimaryMode.isVisible())) {
          const ctaPrimaryLinkHeader = ctaPrimary.locator('[data-field-name$="__link"] .field-group-header').first()
          if (await ctaPrimaryLinkHeader.count()) {
            await ctaPrimaryLinkHeader.click()
          }
          await expect(ctaPrimaryMode).toBeVisible()
        }
        await ctaPrimary.locator('input[name$="__label"]').fill('Primary CTA')
        await ctaPrimaryMode.selectOption('external')
        await ctaPrimary.locator('input[name$="__url"]').fill('https://example.com/primary')
        await ctaPrimary.locator('select[name$="__style"]').selectOption('secondary')

        const ctaSecondary = firstBlock.locator('[data-block-field="ctaSecondary"]')
        const ctaSecondaryLabel = ctaSecondary.locator('input[name$="__label"]')
        if (!(await ctaSecondaryLabel.isVisible())) {
          await ctaSecondary.locator('.field-group-header').first().click()
          await expect(ctaSecondaryLabel).toBeVisible()
        }
        await ctaSecondary.locator('input[name$="__label"]').fill('Secondary CTA')
        await ctaSecondary.locator('select[name$="__style"]').selectOption('secondary')

        // A new-document save answers the HTMX request with `HX-Redirect:
        // /admin/content/<id>/edit`, and htmx only sets location once that response lands. The
        // fixed 2s raced it: on a cold preview the POST had not returned, so the `goto` below
        // cancelled the save in flight. Waiting for the redirect also hands us the id and a fresh
        // server render of the edit page — which is all the trip through the content list was
        // for — and drops a title match that leftover rows from earlier runs could satisfy.
        await page.click('button[name="action"][value="save"]')
        await page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 30000 })
        contentId = page.url().match(/\/admin\/content\/([^/]+)\/edit/)?.[1] || null
        await expect(page.locator('form#content-form')).toBeVisible()

        const reloadedBlocksField = page.locator('[data-field-name="body"]')
        const reloadedFirstBlock = reloadedBlocksField.locator('.blocks-item').first()
        const reloadedBlockContent = reloadedFirstBlock.locator('[data-block-content]')
        const reloadedBlockClass = (await reloadedBlockContent.getAttribute('class')) || ''
        if (reloadedBlockClass.includes('hidden')) {
          await reloadedFirstBlock.locator('button[data-action="toggle-block"]').first().click()
          await expect(reloadedBlockContent).not.toHaveClass(/hidden/)
        }

        const reloadedCtaPrimary = reloadedFirstBlock.locator('[data-block-field="ctaPrimary"]')
        const reloadedPrimaryStyle = reloadedCtaPrimary.locator('select[name$="__style"]')
        if (!(await reloadedPrimaryStyle.isVisible())) {
          await reloadedCtaPrimary.locator('.field-group-header').first().click()
          await expect(reloadedPrimaryStyle).toBeVisible()
        }

        const reloadedCtaSecondary = reloadedFirstBlock.locator('[data-block-field="ctaSecondary"]')
        const reloadedSecondaryStyle = reloadedCtaSecondary.locator('select[name$="__style"]')
        if (!(await reloadedSecondaryStyle.isVisible())) {
          await reloadedCtaSecondary.locator('.field-group-header').first().click()
          await expect(reloadedSecondaryStyle).toBeVisible()
        }

        await expect(reloadedPrimaryStyle).toHaveValue('secondary')
        await expect(reloadedSecondaryStyle).toHaveValue('secondary')

        // Unlike the create above, an edit-page `save` does not navigate: the document-model
        // update path answers the PUT with an inline `#form-messages` banner and stays put
        // (admin-content.ts, "save / save_and_publish: stay on page"). So wait on the PUT itself.
        // That is what the fixed 2s stood in for, and it is the thing that matters here — once the
        // response is in, the write is committed and the reload below cannot cancel it. Keying on
        // banner text instead would be fragile in a different way: the create redirect already put
        // a success message on this page.
        await page.fill('input[name="title"]', updatedTitle)
        const secondSaveResponse = page.waitForResponse(
          (response) =>
            response.request().method() === 'PUT' &&
            /^\/admin\/content\/[^/]+$/.test(new URL(response.url()).pathname),
          { timeout: 30000 }
        )
        await page.click('button[name="action"][value="save"]')
        expect((await secondSaveResponse).ok()).toBeTruthy()

        if (contentId) {
          await page.goto(`/admin/content/${contentId}/edit`)
        } else {
          await page.reload()
        }

        const secondBlocksField = page.locator('[data-field-name="body"]')
        const secondFirstBlock = secondBlocksField.locator('.blocks-item').first()
        const secondBlockContent = secondFirstBlock.locator('[data-block-content]')
        const secondBlockClass = (await secondBlockContent.getAttribute('class')) || ''
        if (secondBlockClass.includes('hidden')) {
          await secondFirstBlock.locator('button[data-action="toggle-block"]').first().click()
          await expect(secondBlockContent).not.toHaveClass(/hidden/)
        }

        const secondCtaPrimary = secondFirstBlock.locator('[data-block-field="ctaPrimary"]')
        const secondPrimaryStyle = secondCtaPrimary.locator('select[name$="__style"]')
        if (!(await secondPrimaryStyle.isVisible())) {
          await secondCtaPrimary.locator('.field-group-header').first().click()
          await expect(secondPrimaryStyle).toBeVisible()
        }

        const secondCtaSecondary = secondFirstBlock.locator('[data-block-field="ctaSecondary"]')
        const secondSecondaryStyle = secondCtaSecondary.locator('select[name$="__style"]')
        if (!(await secondSecondaryStyle.isVisible())) {
          await secondCtaSecondary.locator('.field-group-header').first().click()
          await expect(secondSecondaryStyle).toBeVisible()
        }

        await expect(secondPrimaryStyle).toHaveValue('secondary')
        await expect(secondSecondaryStyle).toHaveValue('secondary')
      } finally {
        try {
          if (page.isClosed()) {
            return
          }

          if (!contentId) {
            await page.goto('/admin/content?collection=e2e_test')
            const updatedLink = page.locator(`a:has-text("${updatedTitle}")`).first()
            if (await updatedLink.count()) {
              contentId = tryExtractContentIdFromHref(await updatedLink.getAttribute('href'))
            }
            if (!contentId) {
              const originalLink = page.locator(`a:has-text("${title}")`).first()
              if (await originalLink.count()) {
                contentId = tryExtractContentIdFromHref(await originalLink.getAttribute('href'))
              }
            }
          }

          if (contentId) {
            const apiDelete = await page.request.delete(`/api/content/${contentId}`)
            if (!apiDelete.ok()) {
              await page.request.delete(`/admin/content/${contentId}`)
            }
          }
        } catch {
          // Best-effort cleanup; don't mask the actual test failure.
        }
      }
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 55-collapsible-state-persistence.spec.ts", () => {
  async function resolvePageBlocksCollectionKey(page: Page): Promise<string> {
    await page.goto('/admin/content/new')
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const e2eTestLink = page
      .locator('a[href^="/admin/content/new?collection="]')
      .filter({ hasText: 'E2E Test' })
      .first()

    await expect(e2eTestLink).toBeVisible({ timeout: 10000 })
    const href = await e2eTestLink.getAttribute('href')
    const match = href?.match(/[?&]collection=([^&]+)/)
    return match?.[1] || 'e2e_test'
  }

  async function gotoPageBlocksNewForm(page: Page) {
    const collectionKey = await resolvePageBlocksCollectionKey(page)
    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    const titleField = page.locator('input[name="title"]').first()
    if (await titleField.count()) {
      await expect(titleField).toBeVisible({ timeout: 10000 })
      return collectionKey
    }

    const e2eTestLink = page
      .locator('a[href^="/admin/content/new?collection="]')
      .filter({ hasText: 'E2E Test' })
      .first()
    if (await e2eTestLink.count()) {
      await e2eTestLink.click()
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('input[name="title"]').first()).toBeVisible({ timeout: 10000 })
      return collectionKey
    }

    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })
    return collectionKey
  }

  /**
   * Save the open new-content form and return the created record's edit URL.
   *
   * The shared helper does the work; this adds the title to the error and proves the edit form
   * rendered, because everything below reads structured fields off it.
   *
   * What the version this replaces got wrong: it swallowed its `waitForURL` with `.catch(() => {})`
   * and fell through to a "fallback for environments that may not auto-redirect" that took
   * `a[href*="/edit"]` `.first()` on the page it never left. On the form page that is nothing, so a
   * create that failed server-side was reported as "edit link not found" with the real error
   * discarded — which is what CI run 39582792718 reported.
   */
  async function saveAndCaptureEditUrl(page: Page, title: string): Promise<string> {
    const editPath = await saveNewContent(page, () =>
      page.click('button[name="action"][value="save"]')
    ).catch((error: Error) => {
      throw new Error(`Saving "${title}": ${error.message}`)
    })

    await expect(page.locator('form#content-form')).toBeVisible()
    // The pathname, not the landed URL: the collapse-state key is
    // `window.location.pathname + ':' + collectionId`, so `?success=...` is noise.
    return editPath
  }

  test.describe('Collapsible State Persistence @content', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    // Structured arrays and blocks each ship an inert <template> holding a prototype item, and
    // Playwright's selector engine looks inside template content. Every item/control locator below
    // is therefore anchored with `:scope >` (or `.first()` inside an item) so it cannot match the
    // prototype — an unanchored `.structured-array-item` counts the template copy too.
    test('should persist object/repeater/block collapsed state per document in session', async ({
      page,
    }) => {
      const docATitle = `Test Collapse State A ${Date.now()}`
      const docASlug = `test-collapse-state-a-${Date.now()}`
      const docBTitle = `Test Collapse State B ${Date.now()}`
      const docBSlug = `test-collapse-state-b-${Date.now()}`

      const collectionKey = await resolvePageBlocksCollectionKey(page)

      // Create document A with blocks and repeater items.
      await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      const formTitle = page.locator('input[name="title"]').first()
      if (!(await formTitle.count())) {
        await gotoPageBlocksNewForm(page)
      }
      await page.fill('input[name="title"]', docATitle)
      await page.fill('input[name="slug"]', docASlug)

      const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
      const teamContent = teamGroup.locator(':scope > .field-group-content')
      await expect(teamContent).toHaveClass(/hidden/)
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).not.toHaveClass(/hidden/)

      const membersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
      await expect(membersField).toBeVisible()
      const addMember = membersField.locator(':scope > div > [data-action="add-item"]')
      await addMember.click()
      await addMember.click()

      const memberItems = membersField.locator(
        ':scope > [data-structured-array-list] > .structured-array-item'
      )
      await expect(memberItems).toHaveCount(2)
      const memberFields = (index: number) =>
        memberItems.nth(index).locator('[data-array-item-fields]').first()
      await expect(memberFields(0)).not.toHaveClass(/hidden/)
      await expect(memberFields(1)).not.toHaveClass(/hidden/)
      await memberFields(0).locator('input[type="text"]').first().fill('Member One')
      await memberFields(1).locator('input[type="text"]').first().fill('Member Two')
      await memberItems.nth(0).locator('[data-action="toggle-item"]').first().click()
      await expect(memberFields(0)).toHaveClass(/hidden/)
      await expect(memberFields(1)).not.toHaveClass(/hidden/)

      const blocksField = page.locator('[data-blocks-discriminator][data-field-name="body"]')
      await expect(blocksField).toBeVisible()
      const blockTypeSelect = blocksField.locator('[data-role="block-type-select"]').first()
      const addBlock = blocksField.locator('[data-action="add-block"]').first()
      await blockTypeSelect.selectOption('hero')
      await addBlock.click()
      await blockTypeSelect.selectOption('text')
      await addBlock.click()

      const blockItems = blocksField.locator(':scope > [data-blocks-list] > .blocks-item')
      const blockContent = (index: number) =>
        blockItems.nth(index).locator('[data-block-content]').first()
      await expect(blockItems).toHaveCount(2)
      await expect(blockContent(0)).not.toHaveClass(/hidden/)
      await expect(blockContent(1)).not.toHaveClass(/hidden/)
      await blockContent(0).locator('input[type="text"]').first().fill('Hero Heading')
      await blockContent(1).locator('input[type="text"]').first().fill('Text Heading')
      await blockContent(1).locator('textarea').first().fill('Text body content')

      const docAEditUrl = await saveAndCaptureEditUrl(page, docATitle)

      // Set UI collapse state on the saved edit page (same document path/key).
      await page.goto(docAEditUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()

      const editTeamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
      const editTeamContent = editTeamGroup.locator(':scope > .field-group-content')
      await expect(editTeamContent).toHaveClass(/hidden/)
      await editTeamGroup.locator(':scope > .field-group-header').click()
      await expect(editTeamContent).not.toHaveClass(/hidden/)

      const editMembersField = page
        .locator('[data-structured-array][data-field-name="team__members"]')
        .first()
      const editMemberItems = editMembersField.locator(
        ':scope > [data-structured-array-list] > .structured-array-item'
      )
      const editMemberFields = (index: number) =>
        editMemberItems.nth(index).locator('[data-array-item-fields]').first()
      await expect(editMemberItems).toHaveCount(2)
      await expect(editMemberFields(0)).toHaveClass(/hidden/)
      await expect(editMemberFields(1)).toHaveClass(/hidden/)
      await editMemberItems.nth(1).locator('[data-action="toggle-item"]').first().click()
      await expect(editMemberFields(1)).not.toHaveClass(/hidden/)

      const editBlocksField = page.locator('[data-blocks-discriminator][data-field-name="body"]')
      const editBlockItems = editBlocksField.locator(':scope > [data-blocks-list] > .blocks-item')
      const editBlockContent = (index: number) =>
        editBlockItems.nth(index).locator('[data-block-content]').first()
      await expect(editBlockItems).toHaveCount(2)
      await expect(editBlockContent(0)).toHaveClass(/hidden/)
      await expect(editBlockContent(1)).toHaveClass(/hidden/)
      await editBlockItems.nth(1).locator('[data-action="toggle-block"]').first().click()
      await expect(editBlockContent(1)).not.toHaveClass(/hidden/)
      await expect(editBlockContent(0)).toHaveClass(/hidden/)
      await expect(editBlockContent(1)).not.toHaveClass(/hidden/)

      // Create document B without toggling grouped fields so defaults are used.
      await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      const formTitleB = page.locator('input[name="title"]').first()
      if (!(await formTitleB.count())) {
        await gotoPageBlocksNewForm(page)
      }
      await page.fill('input[name="title"]', docBTitle)
      await page.fill('input[name="slug"]', docBSlug)
      const docBEditUrl = await saveAndCaptureEditUrl(page, docBTitle)

      // Return to document A and verify state restoration.
      await page.goto(docAEditUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()
      const restoredTeamGroup = page
        .locator('[data-structured-object][data-field-name="team"]')
        .first()
      const restoredTeamContent = restoredTeamGroup.locator(':scope > .field-group-content')
      await expect(restoredTeamContent).not.toHaveClass(/hidden/)

      const restoredMembers = page.locator(
        '[data-structured-array][data-field-name="team__members"] > [data-structured-array-list] > .structured-array-item'
      )
      const restoredMemberFields = (index: number) =>
        restoredMembers.nth(index).locator('[data-array-item-fields]').first()
      await expect(restoredMembers).toHaveCount(2)
      await expect(restoredMemberFields(0)).toHaveClass(/hidden/)
      await expect(restoredMemberFields(1)).not.toHaveClass(/hidden/)

      const restoredBlocks = page.locator(
        '[data-blocks-discriminator][data-field-name="body"] > [data-blocks-list] > .blocks-item'
      )
      const restoredBlockContent = (index: number) =>
        restoredBlocks.nth(index).locator('[data-block-content]').first()
      await expect(restoredBlocks).toHaveCount(2)
      await expect(restoredBlockContent(0)).toHaveClass(/hidden/)
      await expect(restoredBlockContent(1)).not.toHaveClass(/hidden/)

      // Reorder should keep each item's expanded/collapsed state.
      await restoredMembers.nth(0).locator('[data-action="move-down"]').first().click()
      await expect(restoredMemberFields(0)).not.toHaveClass(/hidden/)
      await expect(restoredMemberFields(1)).toHaveClass(/hidden/)

      await restoredBlocks.nth(0).locator('[data-action="move-down"]').first().click()
      await expect(restoredBlockContent(0)).not.toHaveClass(/hidden/)
      await expect(restoredBlockContent(1)).toHaveClass(/hidden/)

      // Open different document and confirm defaults still apply there.
      await page.goto(docBEditUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()
      const docBTeamGroup = page
        .locator('[data-structured-object][data-field-name="team"]')
        .first()
      await expect(docBTeamGroup.locator(':scope > .field-group-content')).toHaveClass(/hidden/)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 56-collapsible-validation-visibility.spec.ts", () => {
  /**
   * `#content-form` is rendered with `novalidate` and validates server-side — see
   * `admin-content-form.template.ts` and the banner contract guarded by
   * `68-blog-post-validation-no-nesting.spec.ts`. So a required field left empty inside a group the
   * user collapsed must still be reported, and the failed submit must not navigate away or discard
   * the data the user did enter.
   *
   * Structured arrays ship an inert <template> holding a prototype item and Playwright's selector
   * engine looks inside template content, so item locators are anchored with `:scope >`.
   */
  const ADD_MEMBER =
    ':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]'
  const MEMBER_ITEM = ':scope > [data-structured-array-list] > .structured-array-item'

  test.describe('Collapsible Validation Visibility @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/content/new?collection=e2e_test')
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()
    })

    test('should surface a validation error without navigating away or losing collapse state', async ({
      page,
    }) => {
      // Only structured-object groups are collapsible — `renderFieldGroup` is called with
      // collapsible=false for Basic Information / Content Details — so the required `title` lives in
      // a static group while `team` and `openingHoursWeek` are the ones the user can collapse.
      await page.fill('input[name="slug"]', `test-validation-visibility-${Date.now()}`)

      const collapsible = ['team', 'openingHoursWeek'].map((name) =>
        page.locator(`[data-structured-object][data-field-name="${name}"]`).first(),
      )
      for (const group of collapsible) {
        const content = group.locator(':scope > .field-group-content')
        if (!((await content.getAttribute('class')) || '').includes('hidden')) {
          await group.locator(':scope > .field-group-header').click()
        }
        await expect(content).toHaveClass(/hidden/)
      }

      // Title is required and has no fallback source, so leaving it empty is the error we want.
      await page.click('button[name="action"][value="save"]')

      const messages = page.locator('#form-messages')
      await expect(messages).toContainText('Please fix the validation errors below', {
        timeout: 10000,
      })
      await expect(messages).toContainText('title')

      // A rejected save must not navigate, must not drop what the user already typed, and must not
      // reset the collapse state (only #form-messages is swapped).
      expect(page.url()).toContain('/admin/content/new')
      await expect(page.locator('input[name="slug"]')).not.toHaveValue('')
      for (const group of collapsible) {
        await expect(group.locator(':scope > .field-group-content')).toHaveClass(/hidden/)
      }

      const titleField = page.locator('input[name="title"]')
      await expect(titleField).toBeVisible()
      await expect(titleField).toHaveValue('')
      await expect(titleField).toHaveAttribute('required', '')
    })

    test('should keep a collapsed nested repeater item editable after a rejected save', async ({
      page,
    }) => {
      await page.fill('input[name="slug"]', `test-validation-nested-${Date.now()}`)

      const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
      const teamContent = teamGroup.locator(':scope > .field-group-content')
      await expect(teamContent).toHaveClass(/hidden/)
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).not.toHaveClass(/hidden/)

      const membersField = page
        .locator('[data-structured-array][data-field-name="team__members"]')
        .first()
      await membersField.locator(ADD_MEMBER).click()

      const firstMember = membersField.locator(MEMBER_ITEM).first()
      const firstMemberContent = firstMember.locator('[data-array-item-fields]').first()
      await expect(firstMemberContent).not.toHaveClass(/hidden/)
      await firstMember.locator('input[name$="__name"]').first().fill('Collapsed Member')

      // Collapse the item and its parent group, then submit with title still empty.
      await firstMember.locator('[data-action="toggle-item"]').first().click()
      await expect(firstMemberContent).toHaveClass(/hidden/)
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).toHaveClass(/hidden/)

      await page.click('button[name="action"][value="save"]')
      await expect(page.locator('#form-messages')).toContainText(
        'Please fix the validation errors below',
        { timeout: 10000 },
      )

      // The nested item the user entered survives the rejected save and is still reachable.
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).not.toHaveClass(/hidden/)
      await expect(membersField.locator(MEMBER_ITEM)).toHaveCount(1)
      await firstMember.locator('[data-action="toggle-item"]').first().click()
      await expect(firstMemberContent).not.toHaveClass(/hidden/)
      await expect(firstMember.locator('input[name$="__name"]').first()).toHaveValue(
        'Collapsed Member',
      )
    })
  })
})
