/**
 * Document-model blog posts (Option B) — E2E regression guard.
 *
 * Verifies the blog_post collection is document-backed end to end:
 *  - the admin "Blog Posts" content list renders (doc-backed list branch is wired + mounted),
 *  - the authenticated admin document API creates a blog_post document,
 *  - the public document API returns it once published, and hides drafts.
 *
 * The reliable assertions use the JSON API contracts (stable); the admin list check guards the
 * route wiring. Run locally: `npm run e2e` (needs the dev server + seeded admin + migrations 043/044).
 */
import { test, expect } from '@playwright/test'
import { loginAsAdmin, waitForHTMX } from './utils/test-helpers'

test.describe('Blog posts on the document model (Option B)', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('admin Blog Posts list renders (doc-backed list branch)', async ({ page }) => {
    await page.goto('/admin/content?model=blog_post')
    await waitForHTMX(page)
    await expect(page).toHaveURL(/model=blog_post/)
    // Should not 404 / error — the content list shell is present.
    await expect(page.locator('body')).toContainText(/Blog Posts|Content|New/i)
  })

  test('create via admin document API → readable on public API once published; draft hidden', async ({ page }) => {
    const unique = await page.evaluate(() => Math.random().toString(36).slice(2, 8))
    const title = `E2E Doc Blog ${unique}`
    const slug = `e2e-doc-blog-${unique}`

    // Create a published blog_post document through the authenticated admin API (same store the UI uses).
    const createRes = await page.request.post('/admin/documents', {
      headers: { 'Content-Type': 'application/json' },
      data: {
        typeId: 'blog_post',
        title,
        slug,
        data: { author: 'E2E', difficulty: 'advanced', content: '<p>hello</p>', excerpt: 'x' },
        publishOnCreate: true,
      },
    })
    expect(createRes.ok()).toBeTruthy()

    // Public document API returns the published post.
    const pubRes = await page.request.get('/api/documents?type=blog_post&limit=100')
    expect(pubRes.ok()).toBeTruthy()
    const pub = await pubRes.json()
    const found = (pub.data ?? []).find((d: any) => d.slug === slug)
    expect(found, 'published blog doc should appear on the public API').toBeTruthy()

    // A draft (publishOnCreate omitted) must NOT appear on the public API.
    const draftSlug = `${slug}-draft`
    const draftRes = await page.request.post('/admin/documents', {
      headers: { 'Content-Type': 'application/json' },
      data: { typeId: 'blog_post', title: `${title} Draft`, slug: draftSlug, data: { author: 'E2E', difficulty: 'beginner', content: '<p>draft</p>' } },
    })
    expect(draftRes.ok()).toBeTruthy()
    const pub2 = await (await page.request.get('/api/documents?type=blog_post&limit=100')).json()
    const draftFound = (pub2.data ?? []).find((d: any) => d.slug === draftSlug)
    expect(draftFound, 'unpublished draft must be hidden from the public API').toBeFalsy()
  })

  test('Option B: creating a blog post through the content collection route stores a document', async ({ page }) => {
    // The blog editor posts to /admin/content with the collection_id; for the doc-backed blog_post
    // collection that create handler routes to the document model. Drive it via an authenticated form
    // POST to the REAL route (no fragile field selectors / Quill interaction).
    await page.goto('/admin/content/new?collection=blog_post')
    await waitForHTMX(page)
    const collectionId = await page.locator('input[name="collection_id"]').first().inputValue()
    expect(collectionId, 'blog editor should carry a collection_id').toBeTruthy()

    const unique = await page.evaluate(() => Math.random().toString(36).slice(2, 8))
    const slug = `e2e-formblog-${unique}`
    const res = await page.request.post('/admin/content', {
      multipart: {
        collection_id: collectionId,
        title: `E2E Form Blog ${unique}`,
        slug,
        author: 'E2E',
        difficulty: 'advanced',
        content: '<p>body</p>',
        excerpt: 'x',
        status: 'published',
        action: 'save_and_publish',
      },
    })
    expect([200, 302]).toContain(res.status())

    // It must now be a published blog_post DOCUMENT on the public API.
    const pub = await (await page.request.get('/api/documents?type=blog_post&limit=200')).json()
    expect((pub.data ?? []).some((d: any) => d.slug === slug), 'form-created blog post should be a published document').toBeTruthy()
  })
})
