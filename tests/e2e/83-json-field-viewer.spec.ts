import { test as base, expect } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN, submitAndWaitForXhr } from './utils/test-helpers'

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
