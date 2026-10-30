import { test, expect, type APIRequestContext, type Page } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists, isFeatureAvailable, saveNewContent } from './utils/test-helpers'

/**
 * This file used to be twelve tests that mostly printed to the console: `console.log('Found status
 * indicators:', count)`, `console.log('Vectorize info present in UI:', hasVectorizeInfo)`,
 * `console.log('Re-index feedback visible:', …)`. Four more wrapped their only assertion in
 * `if (await locator.count() > 0)`, and an `afterAll` hunted for content the file never created and
 * logged that it had found it. The whole file passed in 32 seconds without ever checking that search
 * returns anything.
 *
 * It was hiding a dead feature. `searchKeyword` read
 * `FROM content c JOIN collections col ON c.collection_id = col.id`; the `collections` table was
 * dropped when collections became code-only, so the query threw on every call, the service's catch
 * turned that into `{ results: [], total: 0 }`, and `/api/search` answered 200 forever. The only
 * assertions the old tests made of the search endpoints — status 200 and a `success` property —
 * are exactly the two things a swallowed exception still satisfies.
 *
 * Deleted outright:
 * - `should have Custom RAG initialized` registered its console listener after the navigation it
 *   meant to capture, then logged the empty array.
 * - `should show Vectorize binding status` logged whether the page mentions "vector". It does not;
 *   the settings page has no binding-status surface to assert on.
 * - `should handle plugin settings save` was `should be able to select collections for indexing`
 *   with the same nested `if`s and no assertion about what was saved.
 */

const SEARCH_API = '/api/search'
const SETTINGS_API = '/admin/plugins/ai-search/api/settings'
const STATUS_API = '/admin/plugins/ai-search/api/status'
const REINDEX_API = '/admin/plugins/ai-search/api/reindex'

/** Seeded by global setup: a published blog_post, and blog_post grants `public: ['read']`. */
const SEEDED = { title: 'Welcome to SonicJS', slug: 'welcome-to-sonicjs', collection: 'blog_post' }

type SearchBody = {
  success: boolean
  data: {
    results: Array<{
      id: string
      title: string
      slug: string
      collection_id: string
      collection_name: string
      snippet?: string
      status: string
      created_at: number
      updated_at: number
    }>
    total: number
    mode: string
    query_time_ms: number
  }
}

async function search(
  api: APIRequestContext,
  body: Record<string, unknown>
): Promise<SearchBody['data']> {
  const res = await api.post(SEARCH_API, { data: body })
  expect(res.status(), `${SEARCH_API} answered ${res.status()}`).toBe(200)
  const json = (await res.json()) as SearchBody
  expect(json.success).toBe(true)
  return json.data
}

test.describe('AI Search Plugin @plugins', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = await isFeatureAvailable(request, '/admin/plugins/ai-search')
  })
  test.beforeEach(() => {
    test.skip(!featureAvailable, 'Plugin/feature not available in this deployment')
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('lists the plugin on the plugins page', async ({ page }) => {
    await page.goto('/admin/plugins')

    // data-name is the manifest name, which is what the card renders.
    const card = page.locator('.plugin-card[data-name="AI Search"]')
    await expect(card).toHaveCount(1)
    await expect(card.locator('.status-badge')).not.toBeEmpty()
  })

  test('renders every control the save handler reads', async ({ page }) => {
    await page.goto('/admin/plugins/ai-search')
    await expect(page.locator('h1')).toContainText(/AI Search/i)

    await expect(page.locator('#settingsForm')).toBeVisible()

    // The submit handler calls getElementById for each of these and would throw on a missing one,
    // which it catches and reports as "Error saving settings" — so their presence IS the save path.
    for (const id of ['enabled', 'ai_mode_enabled', 'autocomplete_enabled', 'index_media']) {
      await expect(page.locator(`#${id}`), `#${id} is missing`).toHaveAttribute('type', 'checkbox')
    }
    expect(Number(await page.locator('#cache_duration').inputValue())).toBeGreaterThanOrEqual(0)
    expect(Number(await page.locator('#results_limit').inputValue())).toBeGreaterThan(0)
    await expect(page.locator('#settingsForm button[type="submit"]')).toBeVisible()

    // One checkbox per code-defined collection, each labelled — the label is the only thing
    // identifying a row, since the value is the collection id.
    const boxes = page.locator('#collections-list input[name="selected_collections"]')
    const count = await boxes.count()
    expect(count, 'no collections offered for indexing').toBeGreaterThan(0)
    await expect(page.locator(`#collection_${SEEDED.collection}`)).toHaveCount(1)
    for (let i = 0; i < count; i++) {
      const id = await boxes.nth(i).getAttribute('id')
      await expect(page.locator(`label[for="${id}"]`)).not.toBeEmpty()
    }
  })

  test('saves the selected collections and keeps them after a reload', async ({ page }) => {
    const before = await page.request.get(SETTINGS_API)
    expect(before.ok()).toBeTruthy()
    const original = (await before.json()).data as { selected_collections?: string[] }
    const originalSelection = original.selected_collections ?? []

    try {
      await page.goto('/admin/plugins/ai-search')
      const box = page.locator(`#collection_${SEEDED.collection}`)
      const wasChecked = await box.isChecked()
      if (!wasChecked) await box.check()
      else await box.uncheck()
      const expected = !wasChecked

      const [saved] = await Promise.all([
        page.waitForResponse(
          (r) =>
            r.request().method() === 'POST' &&
            new URL(r.url()).pathname === '/admin/plugins/ai-search'
        ),
        page.locator('#settingsForm button[type="submit"]').click(),
      ])
      expect(saved.status(), 'settings POST failed').toBe(200)
      await expect(page.locator('#msg')).toBeVisible()

      // The page reloads itself two seconds after a save; read the state back from a fresh load so
      // the assertion is about what was persisted, not about the checkbox this test just clicked.
      await page.goto('/admin/plugins/ai-search')
      await expect(page.locator(`#collection_${SEEDED.collection}`)).toBeChecked({
        checked: expected,
      })
    } finally {
      // Settings are global to the deployment, so put the original selection back whatever happened.
      await page.request.post('/admin/plugins/ai-search', {
        data: { selected_collections: originalSelection },
      })
    }
  })

  test('refuses a reindex request that names no collection', async ({ page }) => {
    const res = await page.request.post(REINDEX_API, { data: {} })
    expect(res.status()).toBe(400)
    expect((await res.json()).error).toContain('collection_id')
  })

  test('records index status for a collection after a reindex', async ({ page }) => {
    const res = await page.request.post(REINDEX_API, { data: { collection_id: SEEDED.collection } })
    expect(res.status()).toBe(200)
    expect((await res.json()).success).toBe(true)

    // Indexing runs in waitUntil, so the status row lands shortly after the response. Without
    // Vectorize bound it records the keyword-only fallback — still a real row, which is the point:
    // the old test only logged `Object.keys(status).length`.
    const row = await expect
      .poll(
        async () => {
          const status = await page.request.get(STATUS_API)
          if (!status.ok()) return null
          return ((await status.json()).data ?? {})[SEEDED.collection] ?? null
        },
        { message: `no index status recorded for ${SEEDED.collection}`, timeout: 20_000 }
      )
      .not.toBeNull()
      .then(async () => {
        const status = await page.request.get(STATUS_API)
        return (await status.json()).data[SEEDED.collection]
      })

    expect(row.collection_id).toBe(SEEDED.collection)
    expect(['indexing', 'completed', 'error']).toContain(row.status)
    expect(typeof row.total_items).toBe('number')
    expect(typeof row.indexed_items).toBe('number')
  })

  test('keyword search finds published content', async ({ request }) => {
    const data = await search(request, { query: SEEDED.title, mode: 'keyword', limit: 10 })

    expect(data.mode).toBe('keyword')
    expect(data.total).toBeGreaterThan(0)

    const hit = data.results.find((r) => r.slug === SEEDED.slug)
    expect(hit, `"${SEEDED.title}" was not returned`).toBeTruthy()
    expect(hit!.title).toBe(SEEDED.title)
    expect(hit!.collection_id).toBe(SEEDED.collection)
    // Resolved from the collection registry now that there is no collections table to join.
    expect(hit!.collection_name).toBe('Blog Post')
    expect(hit!.status).toBe('published')

    // documents stores seconds; the response boundary converts to ms. A raw second-value here
    // renders as January 1970 in any consumer that does `new Date(updated_at)`.
    expect(hit!.created_at).toBeGreaterThan(1_600_000_000_000)
    expect(hit!.updated_at).toBeGreaterThan(1_600_000_000_000)

    // The snippet is prose pulled from the document's string values — not its JSON envelope.
    expect(hit!.snippet).toContain(SEEDED.title)
    expect(hit!.snippet).not.toContain('{"')
  })

  test('keyword search honors the collection filter', async ({ request }) => {
    const inCollection = await search(request, {
      query: SEEDED.title,
      mode: 'keyword',
      filters: { collections: [SEEDED.collection] },
    })
    expect(inCollection.total).toBeGreaterThan(0)

    const elsewhere = await search(request, {
      query: SEEDED.title,
      mode: 'keyword',
      filters: { collections: ['no_such_collection'] },
    })
    expect(elsewhere.total).toBe(0)
    expect(elsewhere.results).toEqual([])
  })

  test('ai mode falls back to keyword results when no vector index is bound', async ({ request }) => {
    // Documented behavior of the settings page: "If AI binding unavailable, will fallback to keyword
    // search". The reported mode stays 'ai' so the caller knows what it asked for.
    const data = await search(request, { query: SEEDED.title, mode: 'ai', limit: 10 })

    expect(data.mode).toBe('ai')
    expect(data.results.some((r) => r.slug === SEEDED.slug)).toBe(true)
    for (const result of data.results) {
      expect(typeof result.title).toBe('string')
      expect(typeof result.collection_id).toBe('string')
    }
  })

  test('search suggestions come from logged queries', async ({ request }) => {
    const marker = `sonicjs-suggest-${Date.now()}`
    await search(request, { query: marker, mode: 'keyword' })

    // Every keyword search is written to ai_search_history, which is what autocomplete reads when
    // there is no vector index to ask.
    await expect
      .poll(
        async () => {
          const res = await request.get(`${SEARCH_API}/suggest?q=${encodeURIComponent(marker)}`)
          if (!res.ok()) return []
          return (await res.json()).data as string[]
        },
        { message: 'the logged query never showed up in suggestions', timeout: 10_000 }
      )
      .toContain(marker)
  })

  test('public search never returns unpublished content', async ({ page, playwright }) => {
    const marker = `ai-search-draft-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

    // e2e_test needs only a title and a slug, and grants `public: ['read']` — so if this draft
    // showed up in anonymous search results it could only be the publish axis leaking, not a
    // missing grant.
    await page.goto('/admin/content/new?collection=e2e_test')
    await page.fill('input[name="title"]', marker)
    await page.fill('input[name="slug"]', marker)
    const editPath = await saveNewContent(page, () =>
      page.locator('button[type="submit"]').first().click()
    )
    const contentId = editPath.split('/')[3]!

    // A context of its own: the worker-scoped `request` fixture has signed in (isFeatureAvailable
    // does that deliberately), and a signed-in caller is not the public principal.
    const anon = await playwright.request.newContext({
      baseURL: process.env.BASE_URL || 'http://localhost:8787',
    })
    try {
      const data = await search(anon, { query: marker, mode: 'keyword', limit: 10 })
      expect(data.total, 'an unpublished document was returned to an anonymous caller').toBe(0)
      expect(data.results).toEqual([])

      // Same search as an admin — still nothing, because search reads the published axis for every
      // caller. Drafts belong to /admin/content, which is where this one is.
      const asAdmin = await search(page.request, { query: marker, mode: 'keyword', limit: 10 })
      expect(asAdmin.total).toBe(0)
      await page.goto('/admin/content?collection=e2e_test&status=all')
      await expect(page.locator('body')).toContainText(marker)
    } finally {
      await anon.dispose()
      await page.request.delete(`/admin/content/${contentId}`).catch(() => {})
    }
  })
})
