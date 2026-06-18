import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

const minimalJpeg = Buffer.from([
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
  0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9,
])

test.describe('Media — document model (slice 3)', () => {
  test('API upload returns document rootId and file is listed from documents', async ({ context }) => {
    const fd = new FormData()
    fd.append('file', new Blob([minimalJpeg], { type: 'image/jpeg' }), 'doc-model-test.jpg')
    fd.append('folder', 'uploads')

    const uploadRes = await context.request.post('/api/media/upload', { multipart: fd })
    expect(uploadRes.ok()).toBeTruthy()
    const body = await uploadRes.json()
    expect(body.success).toBe(true)
    expect(body.file.id).toBeTruthy()

    const fileId = body.file.id

    // Cleanup
    const del = await context.request.delete(`/api/media/${fileId}`)
    expect(del.ok()).toBeTruthy()
  })

  test('API upload-multiple creates document-backed files; bulk-delete removes them', async ({ context }) => {
    const fd = new FormData()
    fd.append('files', new Blob([minimalJpeg], { type: 'image/jpeg' }), 'bulk-1.jpg')
    fd.append('files', new Blob([minimalJpeg], { type: 'image/jpeg' }), 'bulk-2.jpg')
    fd.append('folder', 'test')

    const uploadRes = await context.request.post('/api/media/upload-multiple', { multipart: fd })
    expect(uploadRes.ok()).toBeTruthy()
    const body = await uploadRes.json()
    expect(body.uploaded).toHaveLength(2)

    const ids = body.uploaded.map((f: { id: string }) => f.id)

    const delRes = await context.request.post('/api/media/bulk-delete', { data: { fileIds: ids } })
    expect(delRes.ok()).toBeTruthy()
    const delBody = await delRes.json()
    expect(delBody.deleted).toHaveLength(2)
  })

  test('API PATCH updates metadata on the document', async ({ context }) => {
    const fd = new FormData()
    fd.append('file', new Blob([minimalJpeg], { type: 'image/jpeg' }), 'patch-test.jpg')
    fd.append('folder', 'uploads')

    const uploadRes = await context.request.post('/api/media/upload', { multipart: fd })
    const { file } = await uploadRes.json()
    const fileId = file.id

    const patchRes = await context.request.patch(`/api/media/${fileId}`, {
      data: { alt: 'updated alt text', tags: ['tag1', 'tag2'] },
    })
    expect(patchRes.ok()).toBeTruthy()
    const patchBody = await patchRes.json()
    expect(patchBody.success).toBe(true)

    // Cleanup
    await context.request.delete(`/api/media/${fileId}`)
  })

  test('Admin media library page loads without error', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/media')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('h1')).toContainText('Media Library')
  })

  test('Admin upload creates document-backed file visible in media library', async ({ page, context }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/media')
    await page.waitForLoadState('networkidle')

    const uniqueName = `e2e-doc-${Date.now()}.jpg`

    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click()
    await expect(page.locator('#upload-modal')).toBeVisible()

    await page.setInputFiles('#file-input', {
      name: uniqueName,
      mimeType: 'image/jpeg',
      buffer: minimalJpeg,
    })

    await page.locator('#upload-modal button[type="submit"]').click()
    await expect(page.locator('#upload-results')).toContainText('Successfully uploaded', { timeout: 10000 })

    // Page auto-redirects; wait for media library to reload
    await page.waitForURL(/\/admin\/media/, { timeout: 8000 })
    await page.waitForLoadState('networkidle', { timeout: 10000 })

    // File should appear in the grid (sourced from documents now)
    await expect(page.locator('#media-grid')).toContainText(uniqueName, { timeout: 10000 })
  })
})
