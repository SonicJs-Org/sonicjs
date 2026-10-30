import { expect, test, type Page } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists, TEST_ORIGIN } from './utils/test-helpers'

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
