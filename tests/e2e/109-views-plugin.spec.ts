/**
 * Views plugin — saved queries over document collections, admin builder, public JSON API.
 *
 * Spec 109 (@views — selected by the CI tag mapping when views-plugin files change).
 * Covers (port-correctness regressions + deep-review 2026-07-04 findings):
 *  - admin list + editor pages render (UI state)
 *  - create view → public /api/views/:name serves PUBLISHED rows only (persistence + the
 *    forced-published invariant)
 *  - MUST-FIX 1 regression: a `created_at _gte <ISO date>` filter binds epoch SECONDS —
 *    the substrate's timestamp unit. The pre-fix code bound MILLISECONDS, so a past-date
 *    _gte matched NOTHING (0 rows). Both partition arms asserted (past → rows, future → 0).
 *  - save-time serveability: an op the document model can't serve is a 400 at SAVE
 *  - name validation error path
 */
import { test, expect, type Page } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'

const VIEW_NAME = 'e2e-views-109'
const VIEW_ID = `${VIEW_NAME}-view`
const CONTENT_SLUG = 'e2e-views-109-post'

async function csrfHeaders(page: Page): Promise<Record<string, string>> {
  const csrf = await getCsrfTokenFromPage(page)
  return { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }
}

/** Best-effort cleanup so re-runs on a persistent dev DB stay green. */
async function deleteView(page: Page, id: string): Promise<void> {
  const headers = await csrfHeaders(page)
  await page.request.delete(`${TEST_ORIGIN}/admin/views/api/${id}`, { headers })
}

test.describe.configure({ mode: 'serial' })

test.describe('Views plugin @views', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('admin list and editor pages render', async ({ page }) => {
    await page.goto('/admin/views')
    await expect(page.locator('h1')).toContainText(/views/i)

    await page.goto('/admin/views/new')
    await expect(page.locator('#view-name')).toBeVisible()
    // The collection dropdown is populated from document_types — blog_post is seeded.
    await expect(page.locator('#view-collection option[value="blog_post"]')).toHaveCount(1)
  })

  test('create view → public API serves published rows only', async ({ page }) => {
    const headers = await csrfHeaders(page)

    // Seed one PUBLISHED blog post (409 = leftover from a prior run; also fine).
    const contentRes = await page.request.post(`${TEST_ORIGIN}/api/content`, {
      headers,
      data: {
        collectionId: 'blog_post',
        title: 'E2E Views 109 Post',
        slug: CONTENT_SLUG,
        status: 'published',
        data: { content: 'views e2e body', author: 'e2e' },
      },
    })
    expect([200, 201, 409]).toContain(contentRes.status())

    await deleteView(page, VIEW_ID)
    const createRes = await page.request.post(`${TEST_ORIGIN}/admin/views/api/`, {
      headers,
      data: {
        name: VIEW_NAME,
        display_name: 'E2E Views 109',
        collection_id: 'blog_post',
        is_public: true,
        columns_config: { fields: ['title', 'slug', 'status'] },
        page_size: 10,
      },
    })
    expect(createRes.ok()).toBeTruthy()

    // Persisted: it shows up in the admin list.
    await page.goto('/admin/views')
    await expect(page.locator(`text=${VIEW_NAME}`).first()).toBeVisible()

    // Public read: forced published-only, whatever else exists in the DB.
    const pub = await page.request.get(`${TEST_ORIGIN}/api/views/${VIEW_NAME}`)
    expect(pub.status()).toBe(200)
    const json = await pub.json()
    expect(Array.isArray(json.data)).toBeTruthy()
    expect(json.data.length).toBeGreaterThanOrEqual(1)
    for (const row of json.data) expect(row.status).toBe('published')
    expect(json.data.some((r: { slug?: string }) => r.slug === CONTENT_SLUG)).toBeTruthy()
  })

  test('date filter binds epoch seconds — past _gte matches, future _gte excludes (MUST-FIX 1)', async ({ page }) => {
    const headers = await csrfHeaders(page)

    // Past-date _gte: every seeded row was created after 2020 → rows MUST come back.
    // Pre-fix, the ISO value was bound as epoch MILLISECONDS (1.577e12) against a SECONDS
    // column (~1.7e9): _gte matched nothing and this view served 0 rows.
    const putPast = await page.request.put(`${TEST_ORIGIN}/admin/views/api/${VIEW_ID}`, {
      headers,
      data: {
        display_name: 'E2E Views 109',
        filter_config: { rules: [{ field: 'created_at', operator: '_gte', value: '2020-01-01' }] },
        columns_config: { fields: ['title', 'slug', 'status'] },
        page_size: 10,
        is_public: true,
      },
    })
    expect(putPast.ok()).toBeTruthy()
    const past = await (await page.request.get(`${TEST_ORIGIN}/api/views/${VIEW_NAME}`)).json()
    expect(past.data.length).toBeGreaterThanOrEqual(1)

    // Future-date _gte: the same filter with a far-future bound → 0 rows. Together the two
    // arms prove the value actually partitions the rows (not ignored, not always-true).
    const putFuture = await page.request.put(`${TEST_ORIGIN}/admin/views/api/${VIEW_ID}`, {
      headers,
      data: {
        display_name: 'E2E Views 109',
        filter_config: { rules: [{ field: 'created_at', operator: '_gte', value: '2035-01-01' }] },
        columns_config: { fields: ['title', 'slug', 'status'] },
        page_size: 10,
        is_public: true,
      },
    })
    expect(putFuture.ok()).toBeTruthy()
    const future = await (await page.request.get(`${TEST_ORIGIN}/api/views/${VIEW_NAME}`)).json()
    expect(future.data.length).toBe(0)
  })

  test('a view is PRIVATE by default — public API 404s until is_public is set', async ({ page }) => {
    const headers = await csrfHeaders(page)
    const privName = 'e2e-views-109-private'
    const privId = `${privName}-view`
    await deleteView(page, privId)

    // Created WITHOUT is_public → private. Same collection as the public view above.
    const createRes = await page.request.post(`${TEST_ORIGIN}/admin/views/api/`, {
      headers,
      data: {
        name: privName,
        display_name: 'Private',
        collection_id: 'blog_post',
        columns_config: { fields: ['title', 'slug', 'status'] },
        page_size: 10,
      },
    })
    expect(createRes.ok()).toBeTruthy()

    // Anonymous public API must NOT serve a private view (no cookie on a fresh request).
    const priv = await page.request.get(`${TEST_ORIGIN}/api/views/${privName}`)
    expect(priv.status()).toBe(404)

    // Flip it public → now it serves.
    const put = await page.request.put(`${TEST_ORIGIN}/admin/views/api/${privId}`, {
      headers,
      data: { display_name: 'Private', is_public: true, columns_config: { fields: ['title', 'slug', 'status'] }, page_size: 10 },
    })
    expect(put.ok()).toBeTruthy()
    const nowPublic = await page.request.get(`${TEST_ORIGIN}/api/views/${privName}`)
    expect(nowPublic.status()).toBe(200)

    await page.request.delete(`${TEST_ORIGIN}/admin/views/api/${privId}`, { headers })
  })

  test('unserveable op is rejected at save time with a 400', async ({ page }) => {
    const headers = await csrfHeaders(page)
    const res = await page.request.post(`${TEST_ORIGIN}/admin/views/api/`, {
      headers,
      data: {
        name: 'e2e-views-109-bad',
        collection_id: 'blog_post',
        // _contains on a date-family column — family-invalid; the save gate must 400,
        // not store a config that 500s at read time.
        filter_config: { rules: [{ field: 'created_at', operator: '_contains', value: '2026' }] },
      },
    })
    expect(res.status()).toBe(400)
    const body = await res.json()
    expect(String(body.error)).toBeTruthy()
  })

  test('invalid view name is rejected', async ({ page }) => {
    const headers = await csrfHeaders(page)
    const res = await page.request.post(`${TEST_ORIGIN}/admin/views/api/`, {
      headers,
      data: { name: 'Bad Name!', collection_id: 'blog_post' },
    })
    expect(res.status()).toBe(400)
  })

  test('publish an embed from the display page → /v/:path serves; unpublish → 404', async ({ page }) => {
    const headers = await csrfHeaders(page)
    const embedName = 'e2e-views-109-embed'
    const embedId = `${embedName}-view`
    const embedPath = 'e2e109team'
    await page.request.delete(`${TEST_ORIGIN}/admin/views/api/${embedId}`, { headers })

    // A public view over a public collection, with an explicit column whitelist (publish safety bar).
    const create = await page.request.post(`${TEST_ORIGIN}/admin/views/api/`, {
      headers,
      data: { name: embedName, collection_id: 'blog_post', is_public: true, columns_config: { fields: ['title', 'slug', 'status'] } },
    })
    expect(create.ok()).toBeTruthy()

    // The display page exposes the publish control (UI is reachable — not backend-only).
    await page.goto(`/admin/views/${embedId}/display`)
    await expect(page.locator('#view-publish')).toBeVisible()

    // Publish (the control POSTs this) → the public embed serves.
    const publish = await page.request.post(`${TEST_ORIGIN}/admin/views/${embedId}/display/publish`, {
      headers, data: { path: embedPath },
    })
    expect(publish.ok()).toBeTruthy()
    expect((await page.request.get(`${TEST_ORIGIN}/v/${embedPath}`)).status()).toBe(200)

    // Unpublish → the embed 404s.
    const unpublish = await page.request.post(`${TEST_ORIGIN}/admin/views/${embedId}/display/unpublish`, {
      headers, data: {},
    })
    expect(unpublish.ok()).toBeTruthy()
    expect((await page.request.get(`${TEST_ORIGIN}/v/${embedPath}`)).status()).toBe(404)

    await page.request.delete(`${TEST_ORIGIN}/admin/views/api/${embedId}`, { headers })
  })

  test('cleanup', async ({ page }) => {
    await deleteView(page, VIEW_ID)
  })
})
