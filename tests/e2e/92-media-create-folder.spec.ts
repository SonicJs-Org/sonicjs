import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Media create folder (#929)', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('POST /api/media/create-folder succeeds without legacy media table', async ({ page }) => {
    const folderName = `test-folder-${Date.now()}`
    const res = await page.request.post('/api/media/create-folder', {
      data: { folderName },
      headers: { 'Content-Type': 'application/json' },
    })
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body.success).toBe(true)
    expect(body.folder).toBe(folderName)
  })

  test('rejects invalid folder name characters', async ({ page }) => {
    const res = await page.request.post('/api/media/create-folder', {
      data: { folderName: 'My Folder!' },
      headers: { 'Content-Type': 'application/json' },
    })
    expect(res.status()).toBe(400)
    const body = await res.json()
    expect(body.success).toBe(false)
  })

  test('rejects missing folder name', async ({ page }) => {
    const res = await page.request.post('/api/media/create-folder', {
      data: {},
      headers: { 'Content-Type': 'application/json' },
    })
    expect(res.status()).toBe(400)
    const body = await res.json()
    expect(body.success).toBe(false)
  })
})
