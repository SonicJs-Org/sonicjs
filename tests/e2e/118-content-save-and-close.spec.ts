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
    const rootId = created.rootId || created.id

    await page.goto(`/admin/content/${rootId}/edit`)
    await waitForHTMX(page)

    const titleInput = page.locator('input[name="title"]')
    await titleInput.fill(updatedTitle)

    const saveCloseBtn = page.locator('button[value="save_and_close"]')
    await saveCloseBtn.click()
    await page.waitForURL('**/admin/content**', { timeout: 10000 })

    // Verify redirected to unfiltered list (no collection= or model= param)
    const url = new URL(page.url())
    expect(url.pathname).toBe('/admin/content')
    expect(url.searchParams.has('collection')).toBe(false)
    expect(url.searchParams.has('model')).toBe(false)

    await waitForHTMX(page)
    await expect(page.locator('body')).toContainText(updatedTitle)
  })

  test('name-field update reflects as title on content list @content', async ({ page }) => {
    // Collections like "example" use a 'name' field instead of 'title'.
    // The content list derives the displayed title from data.name when no title field exists.
    // Regression: previously, updating name didn't update the list title because the stale
    // DB title took precedence over the current form data.name.

    // Find an example collection item (seeded by default content)
    await page.goto('/admin/content')
    await waitForHTMX(page)

    // Look for an example-type row in the content list
    const exampleLink = page.locator('table tbody tr').filter({ hasText: 'Example' }).first().locator('a').first()
    const hasExample = await exampleLink.count() > 0
    if (!hasExample) {
      // Create an example document if none exist (via API or form)
      const createRes = await page.request.post('/admin/documents', {
        headers: { 'Content-Type': 'application/json' },
        data: {
          typeId: 'example',
          title: 'Original Name',
          data: { name: 'Original Name', emoji: '😈', description: 'test' },
          publishOnCreate: true,
        },
      })
      expect(createRes.ok(), 'create example doc').toBeTruthy()
      await page.goto('/admin/content')
      await waitForHTMX(page)
    }

    // Click into the first example item
    const editLink = page.locator('table tbody tr').filter({ hasText: 'Example' }).first().locator('a').first()
    const editHref = await editLink.getAttribute('href')
    expect(editHref).toBeTruthy()
    await page.goto(editHref!)
    await waitForHTMX(page)

    // Read the current name, change it
    const unique = Math.random().toString(36).slice(2, 8)
    const newName = `Updated Name ${unique}`
    const nameInput = page.locator('input[name="name"]')
    await nameInput.fill(newName)

    // Save and close
    const saveCloseBtn = page.locator('button[value="save_and_close"]')
    await saveCloseBtn.click()
    await page.waitForURL('**/admin/content**', { timeout: 10000 })

    // The content list must show the new name as the title
    await waitForHTMX(page)
    await expect(page.locator('body')).toContainText(newName)
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
    const rootId = created.rootId || created.id

    await page.goto(`/admin/content/${rootId}/edit?ref=${encodeURIComponent('model=blog_post')}`)
    await waitForHTMX(page)

    const saveCloseBtn = page.locator('button[value="save_and_close"]')
    await saveCloseBtn.click()
    await page.waitForURL('**/admin/content**', { timeout: 10000 })

    const url = new URL(page.url())
    expect(url.searchParams.get('model')).toBe('blog_post')
  })
})
