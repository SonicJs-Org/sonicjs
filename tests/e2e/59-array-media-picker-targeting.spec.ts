import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import { ensureAdminUserExists, loginAsAdmin } from './utils/test-helpers'

type UploadedMedia = {
  id: string
  filename: string
}

async function uploadTestImage(
  request: APIRequestContext,
  filenamePrefix: string,
): Promise<UploadedMedia> {
  const testImageBuffer = Buffer.from([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
    0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0a, 0x0c, 0x14, 0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12,
    0x13, 0x0f, 0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a, 0x1c, 0x1c, 0x20,
    0x24, 0x2e, 0x27, 0x20, 0x22, 0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29,
    0x2c, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39, 0x3d, 0x38, 0x32,
    0x3c, 0x2e, 0x33, 0x34, 0x32, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
    0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xff, 0xc4,
    0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x0c,
    0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00, 0x80, 0xff, 0xd9,
  ])

  const formData = new FormData()
  const blob = new Blob([testImageBuffer], { type: 'image/jpeg' })
  const timestamp = Date.now()
  const uploadedFileName = `${filenamePrefix}-${timestamp}.jpg`
  formData.append('files', blob, uploadedFileName)
  formData.append('folder', 'uploads')

  const uploadResponse = await request.post('/api/media/upload-multiple', {
    multipart: formData,
  })

  expect(uploadResponse.ok()).toBeTruthy()
  const uploadResult = await uploadResponse.json()
  expect(uploadResult.uploaded).toBeDefined()
  expect(uploadResult.uploaded.length).toBe(1)

  return uploadResult.uploaded[0] as UploadedMedia
}

async function resolvePageBlocksCollectionKey(page: Page): Promise<string | null> {
  await page.goto('/admin/content/new')
  await page.waitForLoadState('networkidle', { timeout: 15000 })

  const pageBlocksLink = page
    .locator('a[href^="/admin/content/new?collection="]')
    .filter({ hasText: 'Page Blocks' })
    .first()

  if (!(await pageBlocksLink.isVisible({ timeout: 5000 }).catch(() => false))) {
    return null
  }

  const href = await pageBlocksLink.getAttribute('href')
  const match = href?.match(/[?&]collection=([^&]+)/)
  return match?.[1] || null
}

async function ensureExpandedArrayItem(item: ReturnType<Page['locator']>) {
  const itemFields = item.locator('[data-array-item-fields]').first()
  const itemClasses = (await itemFields.getAttribute('class')) || ''
  if (itemClasses.includes('hidden')) {
    await item.locator('[data-action="toggle-item"]').first().click()
    await expect(itemFields).not.toHaveClass(/hidden/)
  }
}

async function selectMediaForField(
  page: Page,
  field: ReturnType<Page['locator']>,
  uploadedMediaId: string,
) {
  const selectMediaButton = field.locator('button:has-text("Select Media")').first()
  await expect(selectMediaButton).toBeVisible()
  await selectMediaButton.click()

  const modal = page.locator('#media-selector-modal')
  await expect(modal).toBeVisible({ timeout: 10000 })

  const selectButton = page
    .locator(`[data-media-id="${uploadedMediaId}"] button:has-text("Select")`)
    .first()
  await expect(selectButton).toBeVisible({ timeout: 10000 })
  await selectButton.click()

  await modal.locator('button:has-text("OK")').click()
  await expect(modal).toBeHidden({ timeout: 5000 })
}

test.describe('Array Media Picker Targeting', () => {
  let uploadedMediaA: UploadedMedia | null = null
  let uploadedMediaB: UploadedMedia | null = null

  test.beforeEach(async ({ page, context }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)

    uploadedMediaA = await uploadTestImage(context.request, 'array-media-a')
    uploadedMediaB = await uploadTestImage(context.request, 'array-media-b')
  })

  test.afterEach(async ({ context }) => {
    const fileIds = [uploadedMediaA?.id, uploadedMediaB?.id].filter(Boolean)
    if (fileIds.length > 0) {
      await context.request.post('/api/media/bulk-delete', {
        data: { fileIds },
      }).catch(() => {})
    }
  })

  test('should target the correct structured-array row when selecting media', async ({ page }) => {
    let createdContentId: string | null = null
    const title = `Gallery Media Targeting ${Date.now()}`
    const slug = `gallery-media-targeting-${Date.now()}`

    const collectionKey = await resolvePageBlocksCollectionKey(page)
    test.skip(!collectionKey, 'Page Blocks collection not available')

    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey!))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible()

    await page.fill('input[name="title"]', title)
    await page.fill('input[name="slug"]', slug)

    const blocksField = page.locator('[data-field-name="body"]').first()
    await expect(blocksField).toBeVisible()

    await blocksField.locator('[data-role="block-type-select"]').selectOption('gallery')
    await blocksField.locator('[data-action="add-block"]').click()

    const galleryBlock = blocksField.locator('.blocks-item').first()
    await expect(galleryBlock).toBeVisible()
    const galleryBlockContent = galleryBlock.locator('[data-block-content]')
    const galleryBlockContentClasses = (await galleryBlockContent.getAttribute('class')) || ''
    if (galleryBlockContentClasses.includes('hidden')) {
      await galleryBlock.locator('[data-action="toggle-block"]').first().click()
      await expect(galleryBlockContent).not.toHaveClass(/hidden/)
    }

    await galleryBlock.locator('[data-block-field="heading"] input').fill('Targeted gallery')

    const imagesField = galleryBlock.locator('[data-block-field="images"] [data-structured-array]').first()
    const topLevelRows = imagesField.locator(':scope > [data-structured-array-list] > .structured-array-item')

    await imagesField.locator(':scope > .flex.items-center.justify-between.gap-3 [data-action="add-item"]').click()
    await expect(topLevelRows).toHaveCount(1)

    const firstRow = topLevelRows.first()
    await ensureExpandedArrayItem(firstRow)
    const firstImageField = firstRow.locator('[data-structured-field="image"]').first()
    await selectMediaForField(page, firstImageField, uploadedMediaA!.id)

    const firstHiddenInput = firstImageField.locator('input[type="hidden"]').first()
    await expect(firstHiddenInput).not.toHaveValue('')
    const firstSelectedValue = await firstHiddenInput.inputValue()

    await imagesField.locator(':scope > .flex.items-center.justify-between.gap-3 [data-action="add-item"]').click()
    await expect(topLevelRows).toHaveCount(2)

    const secondRow = topLevelRows.nth(1)
    await ensureExpandedArrayItem(secondRow)
    const secondImageField = secondRow.locator('[data-structured-field="image"]').first()
    await selectMediaForField(page, secondImageField, uploadedMediaB!.id)

    const secondHiddenInput = secondImageField.locator('input[type="hidden"]').first()
    await expect(secondHiddenInput).not.toHaveValue('')
    const secondSelectedValue = await secondHiddenInput.inputValue()
    expect(secondSelectedValue).not.toBe(firstSelectedValue)
    await expect(firstHiddenInput).toHaveValue(firstSelectedValue)

    await page.click('button[name="action"][value="save_and_publish"]')
    await page.waitForURL(/\/admin\/content\/[^/]+\/edit|\/admin\/content\?/, { timeout: 15000 })

    try {
      const editUrlMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/)
      if (editUrlMatch?.[1]) {
        createdContentId = editUrlMatch[1]
      } else {
        await page.goto('/admin/content?collection=' + encodeURIComponent(collectionKey!))
        await page.waitForLoadState('networkidle', { timeout: 15000 })
        const contentLink = page.locator(`a:has-text("${title}")`).first()
        await expect(contentLink).toBeVisible({ timeout: 10000 })
        const href = await contentLink.getAttribute('href')
        const match = href?.match(/\/admin\/content\/([^/]+)\/edit/)
        createdContentId = match?.[1] || null
        await contentLink.click()
      }

      const reloadedGalleryBlock = page.locator('[data-field-name="body"] .blocks-item').first()
      const reloadedGalleryContent = reloadedGalleryBlock.locator('[data-block-content]')
      if (((await reloadedGalleryContent.getAttribute('class')) || '').includes('hidden')) {
        await reloadedGalleryBlock.locator('button[data-action="toggle-block"]').first().click()
        await expect(reloadedGalleryContent).not.toHaveClass(/hidden/)
      }

      const reloadedImagesField = reloadedGalleryBlock
        .locator('[data-block-field="images"] [data-structured-array]')
        .first()
      const reloadedRows = reloadedImagesField.locator(
        ':scope > [data-structured-array-list] > .structured-array-item',
      )
      await expect(reloadedRows).toHaveCount(2)

      const reloadedFirstRow = reloadedRows.first()
      const reloadedSecondRow = reloadedRows.nth(1)
      await ensureExpandedArrayItem(reloadedFirstRow)
      await ensureExpandedArrayItem(reloadedSecondRow)

      const reloadedFirstHiddenInput = reloadedFirstRow
        .locator('[data-structured-field="image"] input[type="hidden"]')
        .first()
      const reloadedSecondHiddenInput = reloadedSecondRow
        .locator('[data-structured-field="image"] input[type="hidden"]')
        .first()

      await expect(reloadedFirstHiddenInput).toHaveValue(firstSelectedValue)
      await expect(reloadedSecondHiddenInput).toHaveValue(secondSelectedValue)
    } finally {
      if (createdContentId) {
        const deleteResponse = await page.request.delete(`/admin/content/${createdContentId}`)
        expect(deleteResponse.ok()).toBeTruthy()
      }
    }
  })
})
