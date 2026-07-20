import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * FTS5 lexical search (T2.1).
 *
 * Content written through the document model is indexed into `documents_fts` on write (the projection
 * seam), and the ai-search-plugin's `keyword` mode serves bm25-ranked, published-only results via
 * POST /api/search. This spec drives the full HTTP path: create → publish → search, and the
 * deindex paths (draft excluded, unpublish, delete).
 *
 * Prereq: the local D1 must have migration 0003 applied — `cd my-sonicjs-app && npm run setup:db`.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' }

async function createBlogPost(request: import('@playwright/test').APIRequestContext, marker: string) {
  const res = await request.post('/admin/documents', {
    headers: JSON_HEADERS,
    data: {
      typeId: 'blog_post',
      title: `Searchable ${marker} Post`,
      slug: `searchable-${marker}`,
      data: { title: `Searchable ${marker} Post`, content: `body about ${marker}`, author: 'admin', difficulty: 'beginner' },
    },
  })
  expect(res.ok(), `create failed: ${res.status()} ${await res.text()}`).toBeTruthy()
  const body = await res.json()
  return { rootId: body.data.rootId as string, id: (body.data.id ?? body.data.rootId) as string }
}

async function publish(request: import('@playwright/test').APIRequestContext, id: string) {
  const res = await request.post(`/admin/documents/${id}/publish`, { headers: JSON_HEADERS, data: {} })
  expect(res.ok(), `publish failed: ${res.status()} ${await res.text()}`).toBeTruthy()
}

async function search(request: import('@playwright/test').APIRequestContext, query: string) {
  const res = await request.post('/api/search', { headers: JSON_HEADERS, data: { query, mode: 'keyword' } })
  expect(res.ok(), `search failed: ${res.status()} ${await res.text()}`).toBeTruthy()
  return (await res.json()).data as {
    results: Array<{ id: string; title: string; slug: string; relevance_score?: number; snippet?: string }>
    total: number
    mode: string
  }
}

test.describe('FTS5 lexical search @api', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('published content is searchable by title via /api/search keyword mode', async ({ page }) => {
    const marker = `quokka${Date.now()}`
    const { id } = await createBlogPost(page.request, marker)
    await publish(page.request, id)

    const data = await search(page.request, marker)
    expect(data.mode).toBe('keyword')
    expect(data.total).toBeGreaterThanOrEqual(1)
    const hit = data.results.find((r) => r.id === id)
    expect(hit, 'published doc should appear in keyword search').toBeTruthy()
    expect(hit!.title).toContain('<mark>') // FTS highlight wraps the matched term
    expect(typeof hit!.relevance_score).toBe('number')
  })

  test('post body text is searchable with a highlighted snippet (fulltext content field)', async ({ page }) => {
    // Marker appears ONLY in data.content — title/slug stay generic so a hit proves body indexing.
    // (FTS MATCH spans all columns, so a marker in the slug would false-positive this test.)
    const marker = `capybara${Date.now()}`
    const res = await page.request.post('/admin/documents', {
      headers: JSON_HEADERS,
      data: {
        typeId: 'blog_post',
        title: 'Plain Title Only',
        slug: `plain-${Date.now()}`,
        data: {
          title: 'Plain Title Only',
          content: `<h2>Field Notes</h2><p>A deep dive about ${marker} habitats along the river.</p>`,
          author: 'admin',
          difficulty: 'beginner',
        },
      },
    })
    expect(res.ok(), `create failed: ${res.status()} ${await res.text()}`).toBeTruthy()
    const created = await res.json()
    const id = (created.data.id ?? created.data.rootId) as string
    await publish(page.request, id)

    const data = await search(page.request, marker)
    const hit = data.results.find((r) => r.id === id)
    expect(hit, 'doc should be found by body-only text').toBeTruthy()
    expect(hit!.snippet ?? '').toContain('<mark>') // snippet() highlights the body match
    expect(hit!.snippet ?? '').not.toContain('<h2>') // HTML stripped before indexing
  })

  test('a draft (unpublished) is NOT returned by public search', async ({ page }) => {
    const marker = `wombat${Date.now()}`
    await createBlogPost(page.request, marker) // left as a draft
    const data = await search(page.request, marker)
    expect(data.results.some((r) => r.title?.toLowerCase().includes(marker))).toBeFalsy()
  })

  test('unpublish removes a doc from public search', async ({ page }) => {
    const marker = `badger${Date.now()}`
    const { id } = await createBlogPost(page.request, marker)
    await publish(page.request, id)
    expect((await search(page.request, marker)).total).toBeGreaterThanOrEqual(1)

    const res = await page.request.post(`/admin/documents/${id}/unpublish`, { headers: JSON_HEADERS, data: {} })
    expect(res.ok(), `unpublish failed: ${res.status()}`).toBeTruthy()
    expect((await search(page.request, marker)).results.some((r) => r.id === id)).toBeFalsy()
  })

  test('delete removes a doc from public search', async ({ page }) => {
    const marker = `otter${Date.now()}`
    const { id } = await createBlogPost(page.request, marker)
    await publish(page.request, id)
    expect((await search(page.request, marker)).total).toBeGreaterThanOrEqual(1)

    const res = await page.request.delete(`/admin/documents/${id}`)
    expect(res.ok(), `delete failed: ${res.status()}`).toBeTruthy()
    expect((await search(page.request, marker)).results.some((r) => r.id === id)).toBeFalsy()
  })
})
