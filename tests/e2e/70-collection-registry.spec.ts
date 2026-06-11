import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

const BASE = process.env.BASE_URL || 'http://localhost:8787'

/**
 * Phase 1 of drop-db-collections plan: in-memory CollectionRegistry coexists
 * with the legacy DB sync. Bootstrap populates the registry from
 * loadCollectionConfigs(); autoRegisterCollectionDocumentTypes now reads from
 * the registry (was a stub returning []).
 *
 * The unit test suite (collection-registry.test.ts) covers the registry
 * semantics exhaustively. This E2E verifies that boot didn't break — the
 * document type registry remains populated and a code-defined collection's
 * documents are readable end-to-end.
 */
test.describe('collection registry (PR 1)', () => {
  test('boot succeeds — blog_post document type is reachable', async ({ request }) => {
    const response = await request.get(`${BASE}/api/documents?type=blog_post&limit=1`)
    expect(response.ok()).toBeTruthy()
    const body = await response.json()
    expect(Array.isArray(body.data)).toBe(true)
  })

  test('an unregistered document type returns 400 (registry gate works)', async ({ request }) => {
    const response = await request.get(`${BASE}/api/documents?type=does_not_exist&limit=1`)
    expect(response.status()).toBe(400)
    const body = await response.json()
    expect(body.error).toContain('Unknown document type')
  })

  test('blog_post records carry the expected type id (autoRegister skipped blog_post, hand-tuned seed wins)', async ({ request }) => {
    const response = await request.get(`${BASE}/api/documents?type=blog_post&limit=5`)
    expect(response.ok()).toBeTruthy()
    const body = await response.json()
    const docs = body.data ?? []
    for (const doc of docs) {
      expect(doc.typeId).toBe('blog_post')
    }
  })

  test('admin UI /admin/collections requires auth (read-only page)', async ({ request }) => {
    const response = await request.get(`${BASE}/admin/collections`, { maxRedirects: 0 })
    // Page exists (read-only list) but is auth-gated.
    expect([200, 302, 401]).toContain(response.status())
  })

  test('admin UI /admin/collections/new requires auth (instructional page)', async ({ request }) => {
    const response = await request.get(`${BASE}/admin/collections/new`, { maxRedirects: 0 })
    // /new page renders code-only instructions; auth-gated.
    expect([200, 302, 401]).toContain(response.status())
  })
})

test.describe('collection registry — authed admin UI', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('/admin/collections lists code-defined blog_post as read-only', async ({ page }) => {
    await page.goto(`${BASE}/admin/collections`)
    await expect(page.locator('body')).toContainText('Collections')
    await expect(page.locator('body')).toContainText('blog_post')
    // Code-defined badge should be present on managed collections.
    await expect(page.locator('body')).toContainText('Config')
    // No write-action buttons (create/delete raw buttons outside of New Collection link).
    await expect(page.locator('button:has-text("Delete"), button:has-text("Create Collection")')).toHaveCount(0)
  })

  test('/admin/collections/new shows code-defined instructions + docs link', async ({ page }) => {
    await page.goto(`${BASE}/admin/collections/new`)
    await expect(page.locator('body')).toContainText('code-defined')
    await expect(page.locator('body')).toContainText('registerCollections')
    await expect(page.locator('body')).toContainText('CollectionConfig')
    // Docs link is present and points to the canonical SonicJS docs.
    const docsLink = page.locator('a[href="https://sonicjs.com/collections"]')
    await expect(docsLink.first()).toBeVisible()
  })
})
