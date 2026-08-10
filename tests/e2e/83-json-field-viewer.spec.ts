import { test, expect } from '@playwright/test'
import { loginAsAdmin, TEST_ORIGIN } from './utils/test-helpers'

const COLLECTION = 'e2e_test'
const SAMPLE_JSON = { version: 1, tags: ['a', 'b'], nested: { active: true } }

test.describe('JSON field viewer @database', () => {
  let contentId: string

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext({ baseURL: TEST_ORIGIN })
    const page = await ctx.newPage()
    await page.goto(TEST_ORIGIN)
    await loginAsAdmin(page)

    const slug = `json-viewer-test-${Date.now()}`
    const res = await page.request.post(`${TEST_ORIGIN}/api/content`, {
      data: {
        collectionId: COLLECTION,
        title: 'JSON Viewer Test',
        slug,
        data: { metadata: SAMPLE_JSON },
      },
    })
    const body = await res.json()
    contentId = body.data?.id || body.id
    expect(contentId).toBeTruthy()
    await ctx.close()
  })

  test.afterAll(async ({ browser }) => {
    if (!contentId) return
    const ctx = await browser.newContext({ baseURL: TEST_ORIGIN })
    const page = await ctx.newPage()
    await page.goto(TEST_ORIGIN)
    await loginAsAdmin(page)
    await page.request.delete(`${TEST_ORIGIN}/api/content/${contentId}`)
    await ctx.close()
  })

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('edit form shows JSON viewer, not [object Object]', async ({ page }) => {
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

  test('toggle switches to textarea and back to viewer', async ({ page }) => {
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

  test('invalid JSON shows inline error and blocks switch back to viewer', async ({ page }) => {
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

  test('edited JSON saves correctly on form submit', async ({ page }) => {
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

    // Submit the form
    await page.getByRole('button', { name: /update/i }).click()
    await page.waitForLoadState('networkidle')

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
