import { test, expect } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN } from './utils/test-helpers'

// /admin/content/documents/:typeId/* must not reach internal types. The editor/author matrix and the
// type-mismatch guard are covered by admin-content-write-acl.integration.test.ts.
test.describe('Admin content write policy @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('internal document types cannot be created from the admin documents form', async ({ page, resourceId }) => {
    for (const typeId of ['rbac_user_roles', 'site_settings']) {
      const res = await page.request.post(`/admin/content/documents/${typeId}/new`, {
        form: { title: 'e2e', slug: `e2e-${resourceId}` },
        headers: { Origin: TEST_ORIGIN },
        maxRedirects: 0,
      })
      expect(res.status(), typeId).toBe(404)
    }
  })

  test('admin can still create a blog post from the admin documents form', async ({ page, resourceId }) => {
    let createdRootId: string | null = null
    try {
      const res = await page.request.post('/admin/content/documents/blog_post/new', {
        form: { title: resourceId, slug: resourceId },
        headers: { Origin: TEST_ORIGIN },
        maxRedirects: 0,
      })
      expect(res.status()).toBe(302)
      const location = res.headers()['location']
      expect(location).toContain('/admin/content/documents/blog_post/')
      // Extract root ID from redirect: /admin/content/documents/blog_post/<rootId>
      const match = location?.match(/\/admin\/content\/documents\/blog_post\/([^/?]+)/)
      createdRootId = match?.[1] ?? null
    } finally {
      // Cleanup created content to avoid accumulating test records
      if (createdRootId) {
        await page.request.delete(`${TEST_ORIGIN}/api/content/${createdRootId}`, {
          headers: { Origin: TEST_ORIGIN },
        }).catch(() => {})
      }
    }
  })
})
