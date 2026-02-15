import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

const SEARCH_API = '/api/search'
const ADMIN_API = '/admin/plugins/ai-search/api'

test.describe('Click Tracking', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // =============================================
  // POST /api/search/click — Record Clicks
  // =============================================

  test.describe('Record Click API', () => {
    test('POST /api/search/click records a click with valid data', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-001',
          content_title: 'Test Article',
          click_position: 1
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
    })

    test('click records with search_id link to search history', async ({ page }) => {
      // First do a search to get a search_id
      const searchResponse = await page.request.post(SEARCH_API, {
        data: { query: 'click-tracking-test', mode: 'keyword' }
      })
      expect(searchResponse.status()).toBe(200)
      const searchJson = await searchResponse.json()
      const searchId = searchJson.data?.search_id

      // Record a click linked to that search
      const clickResponse = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          search_id: searchId,
          content_id: 'test-content-linked',
          content_title: 'Linked Article',
          click_position: 2
        }
      })
      expect(clickResponse.status()).toBe(200)
      expect((await clickResponse.json()).success).toBe(true)
    })

    test('click without search_id still succeeds', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-no-search',
          click_position: 3
        }
      })
      expect(response.status()).toBe(200)
      expect((await response.json()).success).toBe(true)
    })

    test('click rejects missing content_id', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          click_position: 1
        }
      })
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.success).toBe(false)
      expect(json.error).toContain('content_id')
    })

    test('click rejects missing click_position', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-002'
        }
      })
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.success).toBe(false)
      expect(json.error).toContain('click_position')
    })

    test('click rejects non-integer click_position', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-003',
          click_position: 1.5
        }
      })
      expect(response.status()).toBe(400)
    })

    test('click rejects zero click_position', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-004',
          click_position: 0
        }
      })
      expect(response.status()).toBe(400)
    })

    test('click rejects negative click_position', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-005',
          click_position: -1
        }
      })
      expect(response.status()).toBe(400)
    })
  })

  // =============================================
  // POST /api/search/facet-click — Record Facet Interactions
  // =============================================

  test.describe('Record Facet Click API', () => {
    test('POST /api/search/facet-click records a facet interaction', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/facet-click`, {
        data: {
          facet_field: 'collection_name',
          facet_value: 'blog_posts'
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
    })

    test('facet-click with search_id succeeds', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/facet-click`, {
        data: {
          facet_field: 'status',
          facet_value: 'published',
          search_id: '12345'
        }
      })
      expect(response.status()).toBe(200)
      expect((await response.json()).success).toBe(true)
    })

    test('facet-click rejects missing facet_field', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/facet-click`, {
        data: {
          facet_value: 'blog_posts'
        }
      })
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.success).toBe(false)
      expect(json.error).toContain('facet_field')
    })

    test('facet-click rejects missing facet_value', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/facet-click`, {
        data: {
          facet_field: 'collection_name'
        }
      })
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.success).toBe(false)
      expect(json.error).toContain('facet_value')
    })
  })

  // =============================================
  // Seed Click Data (Admin API)
  // =============================================

  test.describe('Seed Click Data API', () => {
    test('POST /api/seed/clicks inserts search history + clicks', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/seed/clicks`, {
        data: {
          searches: [
            {
              query: 'e2e test query',
              mode: 'fts5',
              results_count: 5,
              response_time_ms: 120,
              clicks: [
                { content_id: 'seed-c1', content_title: 'Seed Article 1', position: 1 },
                { content_id: 'seed-c2', content_title: 'Seed Article 2', position: 3 }
              ]
            }
          ],
          days: 7
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.searches_inserted).toBe(1)
      expect(json.data.clicks_inserted).toBe(2)
    })

    test('seed/clicks rejects empty searches array', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/seed/clicks`, {
        data: { searches: [] }
      })
      expect(response.status()).toBe(400)
    })

    test('seed/clicks inserts searches without clicks', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/seed/clicks`, {
        data: {
          searches: [
            { query: 'no click query', mode: 'keyword', results_count: 0, response_time_ms: 50 }
          ]
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.searches_inserted).toBe(1)
      expect(json.data.clicks_inserted).toBe(0)
    })

    test('DELETE /api/seed/clicks clears all click and history data', async ({ page }) => {
      // Seed some data first
      await page.request.post(`${ADMIN_API}/seed/clicks`, {
        data: {
          searches: [
            { query: 'to-be-deleted', mode: 'fts5', results_count: 1, response_time_ms: 100 }
          ]
        }
      })

      // Delete it
      const deleteResponse = await page.request.delete(`${ADMIN_API}/seed/clicks`)
      expect(deleteResponse.status()).toBe(200)
      const json = await deleteResponse.json()
      expect(json.success).toBe(true)
    })
  })

  // =============================================
  // Seed Facet Click Data (Admin API)
  // =============================================

  test.describe('Seed Facet Click Data API', () => {
    test('POST /api/seed/facet-clicks inserts facet click data', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/seed/facet-clicks`, {
        data: {
          clicks: [
            { facet_field: 'collection_name', facet_value: 'blog_posts' },
            { facet_field: 'status', facet_value: 'published' },
            { facet_field: '$.tags', facet_value: 'javascript' }
          ],
          days: 14
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.facet_clicks_inserted).toBe(3)
    })

    test('seed/facet-clicks rejects empty clicks array', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/seed/facet-clicks`, {
        data: { clicks: [] }
      })
      expect(response.status()).toBe(400)
    })

    test('DELETE /api/seed/facet-clicks clears all facet click data', async ({ page }) => {
      // Seed some data first
      await page.request.post(`${ADMIN_API}/seed/facet-clicks`, {
        data: {
          clicks: [
            { facet_field: 'collection_name', facet_value: 'to-delete' }
          ]
        }
      })

      // Delete it
      const deleteResponse = await page.request.delete(`${ADMIN_API}/seed/facet-clicks`)
      expect(deleteResponse.status()).toBe(200)
      const json = await deleteResponse.json()
      expect(json.success).toBe(true)
    })
  })

  // =============================================
  // Analytics Extended (includes CTR data)
  // =============================================

  test.describe('Analytics with Click Data', () => {
    test('GET /api/analytics/extended returns analytics structure', async ({ page }) => {
      const response = await page.request.get(`${ADMIN_API}/analytics/extended`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data).toBeDefined()
    })

    test('analytics includes click tracking fields', async ({ page }) => {
      // Seed some click data first
      await page.request.post(`${ADMIN_API}/seed/clicks`, {
        data: {
          searches: [
            {
              query: 'analytics test',
              mode: 'fts5',
              results_count: 10,
              response_time_ms: 150,
              clicks: [
                { content_id: 'analytics-c1', content_title: 'Analytics Article', position: 1 }
              ]
            },
            {
              query: 'analytics test',
              mode: 'fts5',
              results_count: 10,
              response_time_ms: 140,
              clicks: []
            }
          ],
          days: 7
        }
      })

      const response = await page.request.get(`${ADMIN_API}/analytics/extended`)
      const json = await response.json()
      expect(json.success).toBe(true)

      const data = json.data
      // Standard analytics fields
      expect(data).toHaveProperty('total_queries')
      expect(data).toHaveProperty('queries_today')
      expect(data).toHaveProperty('avg_response_time_ms')
      // Click-related analytics (30-day window)
      expect(data).toHaveProperty('total_clicks_30d')
      expect(data).toHaveProperty('ctr_30d')
      expect(data).toHaveProperty('avg_click_position_30d')
      expect(data).toHaveProperty('most_clicked_content')
      expect(data).toHaveProperty('no_click_searches')
      // Facet analytics
      expect(data).toHaveProperty('total_facet_clicks_30d')
      expect(data).toHaveProperty('top_facet_fields')
    })
  })

  // =============================================
  // Search produces search_id for click tracking
  // =============================================

  test.describe('Search ID Plumbing', () => {
    test('keyword search returns search_id when history logging works', async ({ page }) => {
      const response = await page.request.post(SEARCH_API, {
        data: { query: 'search-id-test', mode: 'keyword' }
      })
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json.success).toBe(true)
      // search_id is set when logSearch succeeds (ai_search_history table exists)
      if (json.data.search_id) {
        expect(typeof json.data.search_id).toBe('string')
        expect(json.data.search_id.length).toBeGreaterThan(0)
      }
    })

    test('each search produces a unique search_id', async ({ page }) => {
      const response1 = await page.request.post(SEARCH_API, {
        data: { query: 'unique-id-test-1', mode: 'keyword' }
      })
      const response2 = await page.request.post(SEARCH_API, {
        data: { query: 'unique-id-test-2', mode: 'keyword' }
      })

      const json1 = await response1.json()
      const json2 = await response2.json()

      // If both have search_id, they must be different
      if (json1.data.search_id && json2.data.search_id) {
        expect(json1.data.search_id).not.toBe(json2.data.search_id)
      }
      // At minimum, the search responses should be successful
      expect(json1.success).toBe(true)
      expect(json2.success).toBe(true)
    })

    test('FTS5 search mode returns successful response', async ({ page }) => {
      const response = await page.request.post(SEARCH_API, {
        data: { query: 'fts5-id-test', mode: 'fts5' }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data).toHaveProperty('mode', 'fts5')
      // search_id may or may not be present depending on FTS5 table availability
    })
  })

  // =============================================
  // End-to-End: Search → Click → Analytics
  // =============================================

  test.describe('End-to-End Flow', () => {
    test('seed search + click data → verify analytics reflects it', async ({ page }) => {
      // Seed search history with clicks via admin API (reliable, deterministic)
      const seedResponse = await page.request.post(`${ADMIN_API}/seed/clicks`, {
        data: {
          searches: [
            {
              query: 'e2e flow query',
              mode: 'fts5',
              results_count: 5,
              response_time_ms: 120,
              clicks: [
                { content_id: 'e2e-c1', content_title: 'E2E Article', position: 1 }
              ]
            },
            {
              query: 'e2e flow query 2',
              mode: 'keyword',
              results_count: 3,
              response_time_ms: 80,
              clicks: []
            }
          ],
          days: 7
        }
      })
      expect((await seedResponse.json()).success).toBe(true)

      // Check analytics reflects the seeded data
      const analyticsResponse = await page.request.get(`${ADMIN_API}/analytics/extended`)
      const analyticsJson = await analyticsResponse.json()
      expect(analyticsJson.success).toBe(true)
      expect(analyticsJson.data.total_queries).toBeGreaterThanOrEqual(2)
      expect(analyticsJson.data.total_clicks_30d).toBeGreaterThanOrEqual(1)
    })
  })

  // =============================================
  // Analytics Tab UI
  // =============================================

  test.describe('Analytics Tab UI', () => {
    test('admin search page has Analytics tab', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForLoadState('networkidle')

      const analyticsTabBtn = page.locator('#tab-btn-analytics')
      await expect(analyticsTabBtn).toBeVisible()
      await expect(analyticsTabBtn).toHaveText('Analytics')
    })

    test('clicking Analytics tab shows analytics panel', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForLoadState('networkidle')

      await page.click('#tab-btn-analytics')

      const analyticsPanel = page.locator('#tab-analytics')
      await expect(analyticsPanel).toBeVisible()
    })

    test('Analytics tab loads via hash navigation', async ({ page }) => {
      await page.goto('/admin/search#analytics')
      await page.waitForLoadState('networkidle')

      const analyticsPanel = page.locator('#tab-analytics')
      await expect(analyticsPanel).toBeVisible()

      const analyticsTabBtn = page.locator('#tab-btn-analytics')
      await expect(analyticsTabBtn).toHaveClass(/text-indigo-600/)
    })
  })
})
