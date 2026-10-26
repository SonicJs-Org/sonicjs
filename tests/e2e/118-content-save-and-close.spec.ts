import { test, expect } from './fixtures'
import { loginAsAdmin, waitForHTMX } from './utils/test-helpers'

test.describe('Content save-and-close redirects to unfiltered list @smoke @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('save-and-close returns to unfiltered content list with updated title @content', async ({ page }) => {
    const unique = Math.random().toString(36).slice(2, 8)
    const originalTitle = `SaveClose Original ${unique}`
    const updatedTitle = `SaveClose Updated ${unique}`
    const slug = `saveclose-${unique}`

    const createRes = await page.request.post('/admin/documents', {
      headers: { 'Content-Type': 'application/json' },
      data: {
        typeId: 'blog_post',
        title: originalTitle,
        slug,
        data: { author: 'E2E', difficulty: 'beginner', content: '<p>test</p>', excerpt: 'x' },
        publishOnCreate: true,
      },
    })
    expect(createRes.ok()).toBeTruthy()
    const created = await createRes.json()
    const rootId = created.data?.rootId ?? created.rootId ?? created.id

    await page.goto(`/admin/content/${rootId}/edit`)
    await waitForHTMX(page)

    const titleInput = page.locator('input[name="title"]')
    await titleInput.fill(updatedTitle)

    const saveCloseBtn = page.locator('button[value="save_and_close"]')
    await saveCloseBtn.click()
    await page.waitForURL(url => url.pathname === '/admin/content', { timeout: 10000 })

    // Verify redirected to unfiltered list (no collection= or model= param)
    const url = new URL(page.url())
    expect(url.pathname).toBe('/admin/content')
    expect(url.searchParams.has('collection')).toBe(false)
    expect(url.searchParams.has('model')).toBe(false)

    await waitForHTMX(page)
    await expect(page.locator('body')).toContainText(updatedTitle)
  })

  test('name-field update reflects as title on content list @content', async ({ page }) => {
    const unique = Math.random().toString(36).slice(2, 8)
    const originalName = `NameTest Original ${unique}`
    const updatedName = `NameTest Updated ${unique}`

    const createRes = await page.request.post('/admin/documents', {
      headers: { 'Content-Type': 'application/json' },
      data: {
        typeId: 'example',
        title: originalName,
        data: { name: originalName, emoji: '😈', description: 'test' },
        publishOnCreate: true,
      },
    })
    expect(createRes.ok(), 'create example doc').toBeTruthy()
    const created = await createRes.json()
    const rootId = created.data?.rootId ?? created.rootId ?? created.id

    await page.goto(`/admin/content/${rootId}/edit`)
    await waitForHTMX(page)

    const nameInput = page.locator('input[name="name"]')
    await nameInput.fill(updatedName)

    const saveCloseBtn = page.locator('button[value="save_and_close"]')
    await saveCloseBtn.click()
    await page.waitForURL(url => url.pathname === '/admin/content', { timeout: 10000 })

    await waitForHTMX(page)
    await expect(page.locator('body')).toContainText(updatedName)
  })

  test('save-and-close preserves referrer params when present @content', async ({ page }) => {
    const unique = Math.random().toString(36).slice(2, 8)
    const title = `Referrer Test ${unique}`
    const slug = `referrer-${unique}`

    const createRes = await page.request.post('/admin/documents', {
      headers: { 'Content-Type': 'application/json' },
      data: {
        typeId: 'blog_post',
        title,
        slug,
        data: { author: 'E2E', difficulty: 'beginner', content: '<p>test</p>', excerpt: 'x' },
        publishOnCreate: true,
      },
    })
    expect(createRes.ok()).toBeTruthy()
    const created = await createRes.json()
    const rootId = created.data?.rootId ?? created.rootId ?? created.id

    await page.goto(`/admin/content/${rootId}/edit?ref=${encodeURIComponent('model=blog_post')}`)
    await waitForHTMX(page)

    const saveCloseBtn = page.locator('button[value="save_and_close"]')
    await saveCloseBtn.click()
    await page.waitForURL(url => url.pathname === '/admin/content', { timeout: 10000 })

    const url = new URL(page.url())
    expect(url.searchParams.get('model')).toBe('blog_post')
  })
})
