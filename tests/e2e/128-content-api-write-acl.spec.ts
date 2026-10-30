import { test, expect } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN } from './utils/test-helpers'

// Content-API writes go through the document ACL and never reach internal types such as site_settings.
// The role matrix (author/editor/deny overrides) is covered by api-content-write-acl.integration.test.ts.
test.describe('Content API write ACL @api', () => {
  let cookie = ''

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()
    await loginAsAdmin(page)
    cookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join('; ')
    await context.close()
  })

  const headers = () => ({ 'Content-Type': 'application/json', Cookie: cookie, Origin: TEST_ORIGIN })

  test('admin can still create and delete ordinary content', async ({ request }) => {
    const slug = `write-acl-${Date.now()}`
    const created = await request.post(`${TEST_ORIGIN}/api/content`, {
      data: { collectionId: 'blog_post', title: slug, slug, status: 'draft', data: {} },
      headers: headers(),
    })
    expect(created.status()).toBe(201)
    const id = (await created.json()).data.id

    const deleted = await request.delete(`${TEST_ORIGIN}/api/content/${id}`, { headers: headers() })
    expect(deleted.status()).toBe(200)
  })

  test('site_settings is not writable through the content API, even by admin', async ({ request }) => {
    const body = { title: 'security', slug: `security-${Date.now()}`, data: { jwtExpiresIn: '3650d' } }
    const viaCollection = await request.post(`${TEST_ORIGIN}/api/site_settings`, { data: body, headers: headers() })
    expect(viaCollection.status()).toBe(404)
    const viaContent = await request.post(`${TEST_ORIGIN}/api/content`, {
      data: { collectionId: 'site_settings', ...body },
      headers: headers(),
    })
    expect(viaContent.status()).toBe(404)
  })

  test('anonymous writes are rejected', async ({ request }) => {
    const res = await request.post(`${TEST_ORIGIN}/api/blog_post`, {
      data: { title: 'anon', slug: `anon-${Date.now()}` },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(res.status()).toBe(401)
  })
})
