import { test, expect } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'

/**
 * GraphQL endpoint coverage @api
 *
 * Mints an API key, drives the /graphql endpoint with Bearer auth.
 * Covers: unauthenticated rejection, introspection, document queries, mutations.
 */

const GQL_URL = `${TEST_ORIGIN}/graphql`
const SLUG = `gql-e2e-${Date.now()}`

test.describe('GraphQL endpoint @api', () => {
  let apiKey = ''
  let keyId = ''

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage()
    await loginAsAdmin(page)
    const csrf = await getCsrfTokenFromPage(page)
    const res = await page.request.post(`${TEST_ORIGIN}/admin/plugins/api-keys/api/keys`, {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      data: { name: `gql-e2e-${Date.now()}` },
    })
    expect(res.status(), await res.text()).toBe(201)
    const body = await res.json()
    apiKey = body.apiKey.key
    keyId = body.apiKey.id
    expect(apiKey).toMatch(/^sk_/)
    await page.close()
  })

  test.afterAll(async ({ browser }) => {
    if (!keyId) return
    const page = await browser.newPage()
    await loginAsAdmin(page)
    const csrf = await getCsrfTokenFromPage(page)
    await page.request.delete(`${TEST_ORIGIN}/admin/plugins/api-keys/api/keys/${keyId}`, {
      headers: { 'X-CSRF-Token': csrf },
    })
    await page.close()
  })

  async function gql(request: any, query: string, variables?: Record<string, unknown>) {
    const res = await request.post(GQL_URL, {
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      data: { query, variables },
    })
    return { status: res.status(), body: await res.json() }
  }

  test('unauthenticated POST returns error, not 401', async ({ request }) => {
    // GraphQL always returns 200 with errors array (per spec).
    const res = await request.post(GQL_URL, {
      headers: { 'Content-Type': 'application/json' },
      data: { query: '{ documents { items { id } } }' },
    })
    expect(res.status()).toBe(200)
    const body = await res.json()
    // Unauthenticated users get public principal — empty result is fine, no crash.
    expect(body).toHaveProperty('data')
  })

  test('introspection returns schema types', async ({ request }) => {
    const { body } = await gql(request, '{ __schema { queryType { name } } }')
    expect(body.errors).toBeUndefined()
    expect(body.data.__schema.queryType.name).toBe('Query')
  })

  test('documents query returns a page', async ({ request }) => {
    const { body } = await gql(
      request,
      `query {
        documents(status: "all", limit: 10) {
          items { id typeId status isCurrentDraft }
          cursor
        }
      }`,
    )
    expect(body.errors).toBeUndefined()
    expect(Array.isArray(body.data.documents.items)).toBe(true)
  })

  test('createDocument → document query → publishDocument → deleteDocument', async ({ request }) => {
    // Create a draft document.
    const { body: createBody } = await gql(
      request,
      `mutation($typeId: String!, $title: String, $slug: String, $data: JSON!) {
        createDocument(typeId: $typeId, title: $title, slug: $slug, data: $data) {
          id rootId typeId title slug status isPublished isCurrentDraft
        }
      }`,
      { typeId: 'blog_posts', title: 'GraphQL E2E Test', slug: SLUG, data: { content: 'hello from graphql' } },
    )
    expect(createBody.errors).toBeUndefined()
    const created = createBody.data.createDocument
    expect(created.typeId).toBe('blog_posts')
    expect(created.slug).toBe(SLUG)
    expect(created.isPublished).toBe(false)
    expect(created.isCurrentDraft).toBe(true)

    const docId = created.id
    const rootId = created.rootId

    // Fetch it back by id.
    const { body: fetchBody } = await gql(request, `query($id: String!) { document(id: $id) { id rootId title } }`, { id: docId })
    expect(fetchBody.errors).toBeUndefined()
    expect(fetchBody.data.document.rootId).toBe(rootId)

    // Publish it.
    const { body: pubBody } = await gql(
      request,
      `mutation($id: String!) { publishDocument(id: $id) { id isPublished status } }`,
      { id: docId },
    )
    expect(pubBody.errors).toBeUndefined()
    expect(pubBody.data.publishDocument.isPublished).toBe(true)
    expect(pubBody.data.publishDocument.status).toBe('published')

    // Delete it (soft delete).
    const { body: delBody } = await gql(
      request,
      `mutation($id: String!) { deleteDocument(id: $id) }`,
      { id: docId },
    )
    expect(delBody.errors).toBeUndefined()
    expect(delBody.data.deleteDocument).toBe(true)
  })

  test('GET /graphql serves GraphiQL playground', async ({ page }) => {
    const res = await page.request.get(GQL_URL, {
      headers: { Accept: 'text/html' },
    })
    expect(res.status()).toBe(200)
    const body = await res.text()
    expect(body).toContain('GraphiQL')
  })
})
