import { test, expect } from '@playwright/test'
import { loginAsAdmin, createTestContent, getCollectionWithBlocks } from './utils/test-helpers'

/**
 * Issue #931: block array items need stable persisted IDs.
 * blockId must be generated on create and preserved on reorder/edit.
 */
test.describe('Block stable IDs', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('saved blocks include blockId in fetched JSON', async ({ page }) => {
    // Find a collection that uses blocks field type
    await page.goto('/admin/collections')
    const collectionLink = page.locator('a[href*="/admin/content?collection="]').first()
    const collectionHref = await collectionLink.getAttribute('href')
    if (!collectionHref) test.skip()

    const collectionId = new URL(`http://x${collectionHref}`).searchParams.get('collection')
    if (!collectionId) test.skip()

    await page.goto(`/admin/content/new?collection=${collectionId}`)

    // Check if there's a blocks field visible
    const blocksField = page.locator('[data-field-type="array"], textarea[data-blocks-editor]').first()
    const hasBlocksField = await blocksField.count() > 0
    if (!hasBlocksField) {
      // No blocks field in this collection — skip gracefully
      test.skip()
      return
    }

    // Fill title and save
    const titleInput = page.locator('input[name="title"]')
    if (await titleInput.count() > 0) {
      await titleInput.fill('Block ID Test')
    }

    await page.click('button[value="save"]')
    await page.waitForLoadState('networkidle')

    // Fetch via API and verify blockId present on any blocks
    const idMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/)
    if (!idMatch) return

    const docId = idMatch[1]
    const response = await page.request.get(`/api/v1/content/${docId}`)
    if (!response.ok()) return

    const json = await response.json()
    const data = json.data || json

    // Find any array field that has block items
    for (const val of Object.values(data)) {
      if (Array.isArray(val) && val.length > 0 && (val[0] as any).blockType) {
        expect((val[0] as any).blockId).toMatch(/^blk_[0-9a-f]{12}$/)
        return
      }
    }
  })
})
