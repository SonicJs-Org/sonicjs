import { test, expect } from './fixtures'
import { loginAsAdmin, saveNewContent } from './utils/test-helpers'

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
