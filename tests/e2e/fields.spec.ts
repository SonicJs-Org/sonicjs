import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { TEST_ORIGIN } from "./utils/test-helpers"
import type { Page as source6_Page } from "@playwright/test"
import { test as base } from "./fixtures"
import { submitAndWaitForXhr } from "./utils/test-helpers"
import { saveNewContent } from "./fixtures/content-fixtures"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 41-reference-fields.spec.ts", () => {
  /**
   * Reference fields.
   *
   * Collections are code-only (CollectionRegistry, no DB table) and every shipped
   * collection is `managed: true`, so `/admin/collections/<slug>` renders the
   * read-only "Collection Fields" list instead of the editable list + "Add Field"
   * trigger button. The Add/Edit Field modal itself is still rendered on the page,
   * so the field-type assertions below open it through the same entry point the
   * button used (`showAddFieldModal()`).
   *
   * `employees` is the code-defined collection that declares reference fields
   * (`department` → departments, `region` → regions), so it is the fixture used
   * for the content-form picker tests.
   */

  const REFERENCE_COLLECTION = 'employees'
  const REFERENCE_TARGET_COLLECTION = 'departments'
  const COLLECTION_EDIT_URL = `/admin/collections/${REFERENCE_COLLECTION}`
  const CONTENT_FORM_URL = `/admin/content/new?collection=${REFERENCE_COLLECTION}`

  // Deliberately does NOT match /test-cleanup's title patterns ("Test %", "%E2E%",
  // "%Playwright%", "%Sample%") so a concurrent suite's global cleanup cannot delete
  // the fixture mid-run; afterAll removes it explicitly.
  const REF_TARGET_STAMP = Date.now()
  const REF_TARGET_TITLE = `Ref Target Dept ${REF_TARGET_STAMP}`
  const REF_TARGET_SLUG = `ref-target-dept-${REF_TARGET_STAMP}`

  let referenceTargetId: string | null = null

  async function openFieldModal(page: Page) {
    // Managed (code-defined) collections do not render the "Add Field" trigger,
    // but the modal and its handlers are still shipped on the page.
    await page.waitForFunction(() => typeof (window as any).showAddFieldModal === 'function')
    await page.evaluate(() => (window as any).showAddFieldModal())
    await page.waitForSelector('#field-modal:not(.hidden)')
  }

  async function openReferencePicker(page: Page) {
    const container = page.locator('[data-reference-field][data-field-name="department"]')
    await expect(container).toBeVisible()

    const refButton = container.locator('button:has-text("Select reference")')
    await expect(refButton).toBeVisible()

    // The modal paints empty and `loadResults()` fills it from /admin/api/references. Waiting on
    // that response rather than giving the first result button a fixed timeout is what lets this
    // survive a slow deployment — the fetch is the only thing between the click and a populated
    // list, and on a cold preview it alone can outlast the 10s the assertions used to allow.
    await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes('/admin/api/references') && r.request().method() === 'GET'
      ),
      refButton.click(),
    ])

    const modal = page.locator('#reference-selector-modal')
    await expect(modal).toBeVisible({ timeout: 5000 })
    // A failed fetch renders this instead of buttons; without the check the failure surfaces as a
    // bare "element(s) not found" on the result list.
    await expect(page.locator('#reference-results')).not.toContainText('Failed to load references.')
    return { container, modal }
  }

  test.describe('Reference Fields @content', () => {
    test.beforeAll(async ({ browser }) => {
      // The reference picker only lists published documents, so seed one target.
      const context = await browser.newContext({ baseURL: TEST_ORIGIN })
      const page = await context.newPage()
      await ensureAdminUserExists(page)
      // API-only session: these hooks never touch the DOM, and rendering /admin inside them is
      // what blew the afterAll budget on a cold preview.
      await loginAsAdmin(page, false)
      const res = await page.request.post('/api/content', {
        data: {
          collectionId: REFERENCE_TARGET_COLLECTION,
          title: REF_TARGET_TITLE,
          slug: REF_TARGET_SLUG,
          status: 'published',
          data: { name: REF_TARGET_TITLE },
        },
      })
      expect(res.ok()).toBeTruthy()
      const body = await res.json()
      referenceTargetId = body.data?.id ?? body.id ?? null
      expect(referenceTargetId).toBeTruthy()
      await context.close()
    })

    test.afterAll(async ({ browser }) => {
      if (!referenceTargetId) return
      const context = await browser.newContext({ baseURL: TEST_ORIGIN })
      const page = await context.newPage()
      await loginAsAdmin(page, false)
      await page.request.delete(`/api/content/${referenceTargetId}`)
      await context.close()
    })

    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('should show reference field type in collection field dropdown', async ({ page }) => {
      await page.goto('/admin/collections')
      await expect(page.locator('h1')).toContainText('Collections')

      // Open the collection that uses reference fields.
      const row = page.locator(`tr[onclick*="/admin/collections/${REFERENCE_COLLECTION}"]`).first()
      await expect(row).toBeVisible()
      await row.click()

      await expect(page.locator('h1')).toContainText('Edit Collection')

      // The read-only field list must advertise the reference field type.
      await expect(
        page.locator('span', { hasText: /^Reference$/ }).first(),
      ).toBeVisible()

      // Open add field modal
      await openFieldModal(page)

      // Check that reference option exists in field type dropdown
      const fieldTypeSelect = page.locator('#field-type')
      const options = await fieldTypeSelect.locator('option').allTextContents()
      expect(options).toContain('Reference')

      // Close modal
      await page.click('#field-modal button:has-text("Cancel")')
      await expect(page.locator('#field-modal')).toHaveClass(/hidden/)
    })

    test('should show field options container when reference type is selected', async ({ page }) => {
      await page.goto(COLLECTION_EDIT_URL)
      await expect(page.locator('h1')).toContainText('Edit Collection')

      await openFieldModal(page)

      // Select reference type
      await page.selectOption('#field-type', 'reference')

      // Field options container should be visible
      await expect(page.locator('#field-options-container')).not.toHaveClass(/hidden/, { timeout: 5000 })

      // Should have default options with collection array
      const optionsValue = await page.locator('#field-options').inputValue()
      expect(optionsValue).toContain('collection')

      // Help text should mention linking to other collections
      const helpText = await page.locator('#field-type-help').textContent()
      expect(helpText?.toLowerCase()).toContain('collection')

      await page.click('#field-modal button:has-text("Cancel")')
      await expect(page.locator('#field-modal')).toHaveClass(/hidden/)
    })

    test('should display reference picker button in content form', async ({ page }) => {
      await page.goto(CONTENT_FORM_URL)
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('form#content-form')).toBeVisible()

      // Both declared reference fields render a picker button.
      const refButtons = page.locator('[data-reference-field] button:has-text("Select reference")')
      await expect(refButtons.first()).toBeVisible()
      expect(await refButtons.count()).toBeGreaterThanOrEqual(2)

      const departmentField = page.locator('[data-reference-field][data-field-name="department"]')
      await expect(departmentField).toHaveAttribute(
        'data-reference-collection',
        REFERENCE_TARGET_COLLECTION,
      )
    })

    test('should open reference selector modal when clicking Select Reference', async ({ page }) => {
      await page.goto(CONTENT_FORM_URL)
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('form#content-form')).toBeVisible()

      const { modal } = await openReferencePicker(page)

      // Modal is a full-screen overlay
      await expect(page.locator('#reference-selector-modal.fixed.inset-0.z-50')).toBeVisible()

      // Modal should have search input
      await expect(page.locator('#reference-search-input')).toBeVisible()

      // Modal should have results area
      await expect(page.locator('#reference-results')).toBeVisible()

      // Results are scoped to the field's target collection (the standalone
      // collection-filter dropdown was replaced by per-field scoping).
      const firstResult = page.locator('#reference-results button').first()
      await expect(firstResult).toBeVisible({ timeout: 10000 })
      await expect(firstResult).toContainText(/Departments/i)

      // Close modal
      await modal.locator('button:has-text("Close")').click()
      await expect(modal).toBeHidden()
    })

    test('should search and display content in reference selector', async ({ page }) => {
      await page.goto(CONTENT_FORM_URL)
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('form#content-form')).toBeVisible()

      const { modal } = await openReferencePicker(page)

      await expect(page.locator('#reference-search-input')).toBeVisible({ timeout: 5000 })

      const resultsDiv = page.locator('#reference-results')
      const resultButtons = resultsDiv.locator('button')

      // Initial (unfiltered) load must render at least the seeded target.
      await expect(resultButtons.first()).toBeVisible({ timeout: 10000 })
      expect(await resultsDiv.textContent()).toBeTruthy()

      // Searching narrows the list to matching titles.
      await page.fill('#reference-search-input', REF_TARGET_TITLE)
      await expect(resultButtons).toHaveCount(1, { timeout: 10000 })
      await expect(resultButtons.first()).toContainText(REF_TARGET_TITLE)

      // A non-matching search renders the empty state.
      await page.fill('#reference-search-input', 'zzz-no-such-reference-zzz')
      await expect(resultsDiv).toContainText('No items found.', { timeout: 10000 })

      await modal.locator('button:has-text("Close")').click()
      await expect(modal).toBeHidden()
    })

    test('should select a reference and display it', async ({ page }) => {
      await page.goto(CONTENT_FORM_URL)
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('form#content-form')).toBeVisible()

      const { container, modal } = await openReferencePicker(page)

      const resultButtons = page.locator('#reference-results button')
      await expect(resultButtons.first()).toBeVisible({ timeout: 10000 })

      // Click first result
      await resultButtons.first().click()

      // Modal should close
      await expect(modal).toBeHidden({ timeout: 5000 })

      // Reference display should show the selected item
      const displayDiv = container.locator('[data-reference-display]')
      await expect(displayDiv).toBeVisible()
      await expect(displayDiv).not.toContainText('No reference selected.')

      // Hidden input should have a value
      const hiddenInput = container.locator('input[type="hidden"]')
      const value = await hiddenInput.inputValue()
      expect(value).toBeTruthy()
    })

    test('should clear a selected reference', async ({ page }) => {
      await page.goto(CONTENT_FORM_URL)
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('form#content-form')).toBeVisible()

      const { container, modal } = await openReferencePicker(page)

      const resultButtons = page.locator('#reference-results button')
      await expect(resultButtons.first()).toBeVisible({ timeout: 10000 })
      await resultButtons.first().click()
      await expect(modal).toBeHidden({ timeout: 5000 })

      const hiddenInput = container.locator('input[type="hidden"]')
      await expect(hiddenInput).not.toHaveValue('')

      // Now clear it
      const clearButton = container.locator('[data-reference-clear]')
      await expect(clearButton).toBeVisible()
      await expect(clearButton).toBeEnabled()
      await clearButton.click()

      // Display falls back to the empty-state message
      const displayDiv = container.locator('[data-reference-display]')
      await expect(displayDiv).toContainText('No reference selected.', { timeout: 5000 })

      // Clear button is disabled again once nothing is selected
      await expect(clearButton).toBeDisabled()

      // Hidden input should be empty
      await expect(hiddenInput).toHaveValue('')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 42-dynamic-field-tdz.spec.ts", () => {
  type Page = source6_Page;
  /**
   * Test for TDZ (Temporal Dead Zone) bug in renderDynamicField.
   *
   * Bug: The `select` case in renderDynamicField declares `const options = opts.options || []`
   * which shadows the function parameter `options: FieldRenderOptions`. Because const declarations
   * in switch cases are scoped to the entire switch block, this creates a TDZ error when
   * other cases (object, array) try to access the `options` parameter.
   *
   * Fix: Rename `options` to `selectOptions` in the select case.
   *
   * Related: GitHub Issue #555, PR #556
   *
   * Both tests used to reach the form by loading `/admin/content/new`, waiting for `networkidle`,
   * hunting for an `a[href*="collection=e2e_test"]` in the collection picker, falling back to
   * `/admin/collections` to "trigger a sync", and giving up into `test.skip(true, 'E2E Test
   * collection not available')` at five separate points. `e2e_test` is a code-registered collection
   * — `registerCollections()` at bootstrap, no DB sync to wait for — so the form has a direct URL
   * and the picker is not part of what this spec tests. Every one of those skips was a way for a
   * slow or failed page load to report itself as "feature absent".
   */

  const NEW_E2E_TEST_FORM = '/admin/content/new?collection=e2e_test'

  /**
   * Open the E2E Test collection's new-content form.
   *
   * The TDZ bug surfaces as a server-rendered error page, not as a missing element, so check for it
   * by name first — otherwise the failure is a 15s timeout on `form#content-form` that says nothing
   * about the cause.
   */
  async function openE2eTestForm(page: Page) {
    await page.goto(NEW_E2E_TEST_FORM)

    const body = await page.content()
    if (body.includes('Cannot access') && body.includes('before initialization')) {
      throw new Error(`TDZ bug detected: "Cannot access 'options' before initialization"`)
    }

    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 15000 })
  }

  test.describe('Dynamic Field TDZ Bug Fix @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('should render content form with object fields without TDZ crash', async ({ page }) => {
      await openE2eTestForm(page)

      // Verify the SEO object field rendered (this would crash with the TDZ bug)
      const seoField = page.locator('[data-structured-object][data-field-name="seo"]')
      await expect(seoField).toBeVisible()

      // Verify the blocks array field rendered (this would also crash with the TDZ bug)
      const blocksField = page.locator('.blocks-field[data-field-name="body"]')
      await expect(blocksField).toBeVisible()

      // Verify we can interact with the object field subfields (skip hidden storage input)
      const seoTitleInput = seoField.locator('input:not([type="hidden"])').first()
      await expect(seoTitleInput).toBeVisible()

      // Verify the add block button is visible (array field rendered correctly)
      const addBlockButton = blocksField.locator('[data-action="add-block"]')
      await expect(addBlockButton).toBeVisible()

      // Fill in required fields to verify form is functional
      await page.fill('input[name="title"]', 'TDZ Test Page')
      await page.fill('input[name="slug"]', 'tdz-test-page')

      // Verify hidden inputs for structured fields exist (they store JSON data)
      const seoHiddenInput = seoField.locator('input[type="hidden"][name="seo"]')
      await expect(seoHiddenInput).toHaveCount(1)

      const blocksHiddenInput = blocksField.locator('input[type="hidden"][name="body"]')
      await expect(blocksHiddenInput).toHaveCount(1)
    })

    test('should allow adding blocks to array field without errors', async ({ page }) => {
      await openE2eTestForm(page)

      // Fill required fields
      await page.fill('input[name="title"]', 'Block Test Page')
      await page.fill('input[name="slug"]', 'block-test-page')

      // Get the blocks field
      const blocksField = page.locator('.blocks-field[data-field-name="body"]')
      await expect(blocksField).toBeVisible()

      // Select a block type and add it
      await blocksField.locator('[data-role="block-type-select"]').selectOption('text')
      await blocksField.locator('[data-action="add-block"]').click()

      // Verify block was added
      const blockItem = blocksField.locator('.blocks-item')
      await expect(blockItem).toBeVisible()

      // Fill in block fields
      const headingInput = blockItem.locator('[data-block-field="heading"] input')
      await headingInput.fill('Test Heading')

      const bodyTextarea = blockItem.locator('[data-block-field="body"] textarea')
      await bodyTextarea.fill('Test body content')

      // Verify the hidden input has the block data
      const hiddenInput = blocksField.locator('input[type="hidden"][name="body"]')
      const hiddenValue = await hiddenInput.inputValue()
      const parsed = JSON.parse(hiddenValue)

      expect(parsed).toHaveLength(1)
      expect(parsed[0].blockType).toBe('text')
      expect(parsed[0].heading).toBe('Test Heading')
      expect(parsed[0].body).toBe('Test body content')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 53-block-media-persist.spec.ts", () => {
  test.describe('Block Media Persistence @content @media', () => {
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

      const uploadResponse = await context.request.post('/api/media/upload-multiple', {
        multipart: formData
      });

      const uploadResult = await uploadResponse.json();
      expect(uploadResult.uploaded).toBeDefined();
      expect(uploadResult.uploaded.length).toBe(1);
      uploadedFileId = uploadResult.uploaded[0].id;
    });

    test.afterEach(async ({ context }) => {
      if (uploadedFileId) {
        await context.request.post('/api/media/bulk-delete', {
          data: { fileIds: [uploadedFileId] }
        }).catch(() => {});
      }
    });

    test('should persist media selection in blocks', async ({ page }) => {
      let createdContentId: string | null = null;
      const title = `Block Media ${Date.now()}`;
      const slug = `block-media-${Date.now()}`;
      // `e2e_test` is registered in code at bootstrap (`registerCollections`), so the form has a
      // direct URL. Going through the collection picker meant a missing or slow-to-render link
      // reported itself as `test.skip(true, 'E2E Test collection not available')` — a green run for
      // a page that never loaded.
      await page.goto('/admin/content/new?collection=e2e_test');
      await expect(page.locator('form#content-form')).toBeVisible();

      await page.fill('input[name="title"]', title);
      await page.fill('input[name="slug"]', slug);

      const blocksField = page.locator('[data-field-name="body"]');
      await expect(blocksField).toBeVisible();

      await blocksField.locator('[data-role="block-type-select"]').selectOption('hero');
      await blocksField.locator('[data-action="add-block"]').click();

      const firstBlock = blocksField.locator('.blocks-item').first();
      await firstBlock.locator('[data-block-field="heading"] input').fill('Media persistence hero');
      const ctaPrimaryField = firstBlock.locator('[data-block-field="ctaPrimary"]');
      const ctaPrimaryLabelInput = ctaPrimaryField.locator('input[name$="__label"]');
      if (!(await ctaPrimaryLabelInput.isVisible())) {
        await ctaPrimaryField.locator('.field-group-header').first().click();
        await expect(ctaPrimaryLabelInput).toBeVisible();
      }
      await ctaPrimaryLabelInput.fill('Primary CTA');

      const imageField = firstBlock.locator('[data-block-field="backgroundImage"]');
      const selectMediaButton = imageField.locator('button:has-text("Select Media")');
      await expect(selectMediaButton).toBeVisible();
      await selectMediaButton.click();

      const selectButton = page.locator('#media-selector-grid button:has-text("Select")').first();
      await expect(selectButton).toBeVisible({ timeout: 10000 });
      await selectButton.click();
      await page.locator('#media-selector-modal button:has-text("OK")').click();

      const hiddenInput = imageField.locator('input[type="hidden"]');
      await expect(hiddenInput).not.toHaveValue('');

      await page.click('button[name="action"][value="save"]');
      await page.waitForURL(/\/admin\/content\/[^/]+\/edit|\/admin\/content\?/, { timeout: 15000 });

      try {
        // Prefer grabbing content ID from redirect URL if we're on edit page already
        const editUrlMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/);
        if (editUrlMatch?.[1]) {
          createdContentId = editUrlMatch[1];
        } else {
          await page.goto('/admin/content?collection=e2e_test');
          const contentLink = page.locator(`a:has-text("${title}")`).first();
          await expect(contentLink).toBeVisible({ timeout: 10000 });
          const href = await contentLink.getAttribute('href');
          const match = href?.match(/\/admin\/content\/([^/]+)\/edit/);
          createdContentId = match?.[1] || null;
          await contentLink.click();
        }

        const reloadedBlock = page.locator('[data-field-name="body"] .blocks-item').first();
        const reloadedHiddenInput = reloadedBlock.locator('[data-block-field="backgroundImage"] input[type="hidden"]');
        await expect(reloadedHiddenInput).not.toHaveValue('');
      } finally {
        if (!createdContentId) {
          try {
            await page.goto('/admin/content?collection=e2e_test');
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 53-object-layout.spec.ts", () => {
  test.describe('Object Layout @content', () => {
    test('should render flat objects expanded and nested objects collapsed by default', async ({ page }) => {
      await loginAsAdmin(page)

      await page.goto('/admin/content/new')
      const e2eTestLink = page
        .locator('a[href^="/admin/content/new?collection="]')
        .filter({ hasText: 'E2E Test' })
      await expect(e2eTestLink).toBeVisible()
      await e2eTestLink.click()
      await page.waitForLoadState('networkidle')
      await expect(page.locator('form#content-form')).toBeVisible()

      // Top-level flat object should render without collapsible header and stay visible.
      const flatSeoObject = page.locator('[data-structured-object][data-field-name="seo"]')
      await expect(flatSeoObject).toBeVisible()
      await expect(flatSeoObject.locator('.field-group-header')).toHaveCount(0)
      await expect(flatSeoObject.locator('input[name="seo__title"]')).toBeVisible()

      const blocksField = page.locator('[data-field-name="body"]')
      await expect(blocksField).toBeVisible()
      await blocksField.locator('[data-role="block-type-select"]').selectOption('hero')
      await blocksField.locator('[data-action="add-block"]').click()

      const heroBlock = blocksField.locator('.blocks-item').first()
      await expect(heroBlock).toBeVisible()

      const blockContent = heroBlock.locator('[data-block-content]')
      if (await blockContent.isHidden()) {
        await heroBlock.locator('[data-action="toggle-block"]').first().click()
        await expect(blockContent).toBeVisible()
      }

      // Nested object inside block should render as collapsible and start collapsed.
      const nestedCtaObject = heroBlock
        .locator('[data-block-field="ctaPrimary"] .field-group')
        .filter({ has: page.getByRole('heading', { name: 'Primary CTA' }) })
        .first()
      await expect(nestedCtaObject).toBeVisible()

      const nestedHeader = nestedCtaObject.locator(':scope > .field-group-header')
      const nestedContent = nestedCtaObject.locator(':scope > .field-group-content')
      const nestedIcon = nestedCtaObject.locator(':scope > .field-group-header svg[id$="-icon"]')

      await expect(nestedHeader).toHaveCount(1)
      await expect(nestedContent).toHaveClass(/hidden/)
      await expect(nestedIcon).toHaveClass(/-rotate-90/)

      await nestedHeader.click()
      await expect(nestedContent).not.toHaveClass(/hidden/)
      await expect(nestedIcon).not.toHaveClass(/-rotate-90/)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 83-json-field-viewer.spec.ts", () => {
  // `e2e_test` is the only collection with a `json`-typed field (`metadata`), which is the field
  // this spec is about — `blog_post` has no json field, so its edit form renders no viewer at all.
  const COLLECTION = 'e2e_test'
  const SAMPLE_JSON = { version: 1, tags: ['a', 'b'], nested: { active: true } }

  const test = base.extend<{ contentId: string }>({
    contentId: async ({ page, resourceId }, use) => {
      await loginAsAdmin(page, false)
      const res = await page.request.post(`${TEST_ORIGIN}/api/content`, {
        data: {
          collectionId: COLLECTION,
          title: `Test JSON Viewer ${resourceId}`,
          slug: `json-viewer-${resourceId}`,
          data: { metadata: SAMPLE_JSON },
        },
      })
      expect(res.ok(), `JSON fixture create failed: ${res.status()}`).toBeTruthy()
      const body = await res.json()
      const contentId = body.data?.id || body.id
      expect(contentId).toBeTruthy()
      try {
        await use(contentId)
      } finally {
        const deleted = await page.request.delete(`${TEST_ORIGIN}/api/content/${contentId}`)
        expect(deleted.ok(), `JSON fixture cleanup failed: ${deleted.status()}`).toBeTruthy()
      }
    },
  })

  test.describe('JSON field viewer @database', () => {

    test('edit form shows JSON viewer, not [object Object]', async ({ page, contentId }) => {
      await page.goto(`${TEST_ORIGIN}/admin/content/${contentId}/edit`)
      await page.waitForLoadState('domcontentloaded')

      // Must not render [object Object]
      const bodyText = await page.textContent('body')
      expect(bodyText).not.toContain('[object Object]')

      // JSON viewer host must exist
      const viewer = page.locator('[data-json-viewer]').first()
      await expect(viewer).toBeVisible()

      // Toggle button must exist
      const toggleBtn = page.locator('[data-json-toggle]').first()
      await expect(toggleBtn).toBeVisible()
      await expect(toggleBtn).toHaveText('Edit JSON')
    })

    test('toggle switches to textarea and back to viewer', async ({ page, contentId }) => {
      await page.goto(`${TEST_ORIGIN}/admin/content/${contentId}/edit`)
      await page.waitForLoadState('domcontentloaded')

      const toggleBtn = page.locator('[data-json-toggle]').first()
      await expect(toggleBtn).toBeVisible()

      // Switch to edit mode
      await toggleBtn.click()
      await expect(toggleBtn).toHaveText('Preview')

      const textarea = page.locator('[data-json-edit-area]').first()
      await expect(textarea).toBeVisible()

      // Textarea must contain valid JSON with our sample data
      const raw = await textarea.inputValue()
      expect(() => JSON.parse(raw)).not.toThrow()
      const parsed = JSON.parse(raw)
      expect(parsed.version).toBe(1)
      expect(parsed.tags).toEqual(['a', 'b'])

      // Switch back to viewer
      await toggleBtn.click()
      await expect(toggleBtn).toHaveText('Edit JSON')
      await expect(textarea).toBeHidden()
      await expect(page.locator('[data-json-viewer]').first()).toBeVisible()
    })

    test('invalid JSON shows inline error and blocks switch back to viewer', async ({ page, contentId }) => {
      await page.goto(`${TEST_ORIGIN}/admin/content/${contentId}/edit`)
      await page.waitForLoadState('domcontentloaded')

      const toggleBtn = page.locator('[data-json-toggle]').first()
      await toggleBtn.click()
      await expect(toggleBtn).toHaveText('Preview')

      const textarea = page.locator('[data-json-edit-area]').first()
      await textarea.fill('{ invalid json }')

      // Try switching back — should be blocked
      await toggleBtn.click()

      const errorEl = page.locator('[id$="-json-error"]').first()
      await expect(errorEl).toBeVisible()
      await expect(errorEl).toContainText('Invalid JSON')

      // Textarea still visible (not switched back)
      await expect(textarea).toBeVisible()
    })

    test('edited JSON saves correctly on form submit', async ({ page, contentId }) => {
      await page.goto(`${TEST_ORIGIN}/admin/content/${contentId}/edit`)
      await page.waitForLoadState('domcontentloaded')

      const toggleBtn = page.locator('[data-json-toggle]').first()
      await toggleBtn.click()
      await expect(toggleBtn).toHaveText('Preview')

      const textarea = page.locator('[data-json-edit-area]').first()
      const newJson = JSON.stringify({ version: 2, updated: true }, null, 2)
      await textarea.fill(newJson)

      // Switch to preview (validates + updates hidden input)
      await toggleBtn.click()
      await expect(toggleBtn).toHaveText('Edit JSON')

      // Submit the form (content form action buttons are Save / Save & close / Publish)
      await submitAndWaitForXhr(page, 'PUT', `/admin/content/${contentId}`, () =>
        page.locator('button[name="action"][value="save"]').click())
      await expect(page.getByText('Content saved successfully!', { exact: true })).toBeVisible()

      // Re-open and verify persisted
      await page.goto(`${TEST_ORIGIN}/admin/content/${contentId}/edit`)
      await page.waitForLoadState('domcontentloaded')

      await page.locator('[data-json-toggle]').first().click()
      const savedRaw = await page.locator('[data-json-edit-area]').first().inputValue()
      const saved = JSON.parse(savedRaw)
      expect(saved.version).toBe(2)
      expect(saved.updated).toBe(true)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 96-block-stable-ids.spec.ts", () => {
  /**
   * Issue #931: block array items need stable persisted IDs.
   * blockId must be generated on create and preserved on reorder/edit.
   *
   * This test could not fail. It opened /admin/collections, took the first collection link, and
   * then gave itself six ways out before reaching an assertion: `test.skip()` on a missing href,
   * `test.skip()` on a missing id, a bare `return` when that collection had no blocks field,
   * another when the URL did not look like an edit page, another when the API answered non-OK, and
   * finally a loop that fell off its end — passing — when no field held block items.
   *
   * The API call was the giveaway: it fetched `/api/v1/content/<id>`, and there is no `/api/v1`
   * mount. Content lives at `/api/content/:id`. So every run 404'd, took the `!response.ok()`
   * return, and reported a pass having checked nothing.
   *
   * `e2e_test` is a code-registered collection with a blocks array field (`body`), so the record,
   * the block and the fetch are all deterministic.
   */
  test.describe('Block stable IDs @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('saved blocks include blockId in fetched JSON', async ({ page }) => {
      const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

      await page.goto('/admin/content/new?collection=e2e_test')
      await page.fill('input[name="title"]', `Block ID Test ${stamp}`)
      await page.fill('input[name="slug"]', `block-id-test-${stamp}`)

      const blocksField = page.locator('.blocks-field[data-field-name="body"]')
      await expect(blocksField).toBeVisible()

      await blocksField.locator('[data-role="block-type-select"]').selectOption('text')
      await blocksField.locator('[data-action="add-block"]').click()
      await expect(blocksField.locator('.blocks-item')).toHaveCount(1)
      await blocksField.locator('[data-block-field="heading"] input').fill('Stable ID heading')

      // The editor serialises the array into this hidden input, and that is what the POST carries.
      // `parseBlocksValue` (utils/blocks.ts) is what stamps the id, server-side, on save — so the
      // value here has no blockId yet and the fetched document must.
      const editPath = await saveNewContent(page, () =>
        page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
      )
      const docId = editPath.split('/')[3]

      // `page.request` carries the browser context's session cookie, so this reads as the admin and
      // a draft is visible.
      const response = await page.request.get(`/api/content/${docId}`)
      expect(response.ok(), `GET /api/content/${docId} returned ${response.status()}`).toBeTruthy()

      const json = await response.json()
      const blocks = json.data?.data?.body
      expect(Array.isArray(blocks), `body was not an array: ${JSON.stringify(json.data?.data)}`).toBe(
        true
      )
      expect(blocks).toHaveLength(1)
      expect(blocks[0].blockType).toBe('text')
      expect(blocks[0].blockId).toMatch(/^blk_[0-9a-f]{12}$/)
    })
  })
})
