import { test, expect } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists, saveNewContent } from './utils/test-helpers'
import { uniqueTestId } from './utils/test-runtime'

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
