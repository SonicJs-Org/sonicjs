import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Versioning is OFF by default (Phase 1) and the version-history / restore UI ships as the
 * versioning-plugin (Phase 2). A document type opts in via `settings.versioning: true`.
 *
 * blog_post → versioning OFF (edits in place, no history rows)
 * faq       → versioning ON  (via CollectionConfig.versioning: true)
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' }

async function createFaq(request: import('@playwright/test').APIRequestContext, suffix: string) {
  const res = await request.post('/admin/documents', {
    headers: JSON_HEADERS,
    data: {
      typeId: 'faq',
      title: `FAQ Spec ${suffix}`,
      slug: `faq-spec-${suffix}`,
      data: { question: `Q ${suffix}`, answer: 'A1', category: 'general' },
    },
  })
  expect(res.ok(), `faq create failed: ${res.status()} ${await res.text()}`).toBeTruthy()
  return (await res.json()).data.rootId as string
}

async function createBlogPost(request: import('@playwright/test').APIRequestContext, suffix: string) {
  const res = await request.post('/admin/documents', {
    headers: JSON_HEADERS,
    data: {
      typeId: 'blog_post',
      title: `Blog Spec ${suffix}`,
      slug: `blog-spec-${suffix}`,
      data: {
        title: `Blog Spec ${suffix}`,
        content: 'v1 body',
        author: 'admin',
        difficulty: 'beginner',
      },
    },
  })
  expect(res.ok(), `blog create failed: ${res.status()} ${await res.text()}`).toBeTruthy()
  return (await res.json()).data.rootId as string
}

test.describe('Versioning (optional, plugin-backed)', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  // ── Collections page ──────────────────────────────────────────────────────

  test('collections page shows Versioning column — faq On, blog_post Off', async ({ page }) => {
    await page.goto('/admin/collections')
    await page.waitForLoadState('networkidle', { timeout: 20000 })
    const html = await page.content()
    // Versioning column header present
    expect(html).toContain('Versioning')
    // FAQ opted in → "On" badge
    expect(html).toContain('faq')
    expect(html).toContain('On')
    // Source and Created columns removed
    expect(html).not.toContain('>Source<')
    expect(html).not.toContain('>Created<')
  })

  // ── FAQ (versioning ON) ───────────────────────────────────────────────────

  test('faq accumulates history and restore creates a new version', async ({ page }) => {
    const suffix = `${Date.now()}-a`
    const rootId = await createFaq(page.request, suffix)

    // Two edits → v2 and v3
    for (const answer of ['A2', 'A3']) {
      const put = await page.request.put(`/admin/documents/${rootId}`, {
        headers: JSON_HEADERS,
        data: { data: { answer } },
      })
      expect(put.ok(), `edit failed: ${put.status()} ${await put.text()}`).toBeTruthy()
    }

    // History panel lists all three versions
    const histRes = await page.request.get(`/admin/versioning/${rootId}`)
    expect(histRes.ok()).toBeTruthy()
    const html = await histRes.text()
    expect(html).toContain('Version History')
    expect(html).toContain('v3')
    expect(html).toContain('v2')
    expect(html).toContain('v1')
    expect(html).toContain('Restore')

    // Restore v1 → creates v4
    const restoreRes = await page.request.post(`/admin/versioning/${rootId}/restore/1`)
    expect(restoreRes.ok(), `restore failed: ${restoreRes.status()} ${await restoreRes.text()}`).toBeTruthy()
    expect((await restoreRes.json()).success).toBe(true)

    const afterHtml = await (await page.request.get(`/admin/versioning/${rootId}`)).text()
    expect(afterHtml).toContain('v4')
  })

  test('faq edit form shows Version history section and Save Draft button', async ({ page }) => {
    const suffix = `${Date.now()}-b`
    const rootId = await createFaq(page.request, suffix)

    await page.goto(`/admin/content/documents/faq/${rootId}/edit`)
    await page.waitForLoadState('networkidle', { timeout: 20000 })
    // Versioning ON → "Save Draft" not "Update"
    await expect(page.getByRole('button', { name: 'Save Draft' })).toBeVisible()
    // Version history section present (the <details> summary)
    await expect(page.getByText('Version history').first()).toBeVisible()
  })

  test('history route returns 404 for unknown root', async ({ page }) => {
    const res = await page.request.get('/admin/versioning/does-not-exist-root')
    expect(res.status()).toBe(404)
  })

  // ── Blog post (versioning OFF) ────────────────────────────────────────────

  test('blog_post edits in place — no extra version rows', async ({ page }) => {
    const suffix = `${Date.now()}-bp`
    const rootId = await createBlogPost(page.request, suffix)

    // Three edits — with versioning OFF each saveDraft updates the single row
    for (const content of ['edit1', 'edit2', 'edit3']) {
      const put = await page.request.put(`/admin/documents/${rootId}`, {
        headers: JSON_HEADERS,
        data: { data: { content } },
      })
      expect(put.ok(), `blog edit failed: ${put.status()} ${await put.text()}`).toBeTruthy()
    }

    // History route should 404 (versioning not opted in for blog_post)
    const histRes = await page.request.get(`/admin/versioning/${rootId}`)
    expect(histRes.status()).toBe(404)
  })

  test('blog_post edit form shows Update button — no Save Draft or Publish', async ({ page }) => {
    const suffix = `${Date.now()}-c`
    const rootId = await createBlogPost(page.request, suffix)

    await page.goto(`/admin/content/${rootId}/edit`)
    await page.waitForLoadState('networkidle', { timeout: 20000 })
    // Versioning OFF → single "Update" button
    await expect(page.getByRole('button', { name: 'Update' })).toBeVisible()
    // No "Save Draft" or "Update & Publish" pair
    await expect(page.getByRole('button', { name: 'Update & Publish' })).not.toBeVisible()
    // No "View Version History" link
    await expect(page.getByText('View Version History')).not.toBeVisible()
  })
})
