import { test, expect } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN } from './utils/test-helpers'

// /admin/content/documents/:typeId/* must not reach internal types. The editor/author matrix and the
// type-mismatch guard are covered by admin-content-write-acl.integration.test.ts.
test.describe('Admin content write policy @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('internal document types cannot be created from the admin documents form', async ({ page }) => {
    for (const typeId of ['rbac_user_roles', 'site_settings']) {
      const res = await page.request.post(`/admin/content/documents/${typeId}/new`, {
        form: { title: 'e2e', slug: `e2e-${Date.now()}` },
        headers: { Origin: TEST_ORIGIN },
        maxRedirects: 0,
      })
      expect(res.status(), typeId).toBe(404)
    }
  })

  test('admin can still create a blog post from the admin documents form', async ({ page }) => {
    const slug = `e2e-admin-docs-${Date.now()}`
    const res = await page.request.post('/admin/content/documents/blog_post/new', {
      form: { title: slug, slug },
      headers: { Origin: TEST_ORIGIN },
      maxRedirects: 0,
    })
    expect(res.status()).toBe(302)
    expect(res.headers()['location']).toContain('/admin/content/documents/blog_post/')
  })
})
