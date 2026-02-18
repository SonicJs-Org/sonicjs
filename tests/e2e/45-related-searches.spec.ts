import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

const SEARCH_API = '/api/search'
const ADMIN_API = '/admin/plugins/ai-search/api'

test.describe('Related Searches', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // =============================================
  // CRUD API
  // =============================================

  test.describe('CRUD API', () => {
    test('POST creates a manual related search pair', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: {
          source_query: 'react hooks',
          related_query: 'state management'
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.source_query).toBe('react hooks')
      expect(json.data.related_query).toBe('state management')
      expect(json.data.source).toBe('manual')
      expect(json.data.enabled).toBe(true)

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${json.data.id}`)
    })

    test('GET lists all related search pairs', async ({ page }) => {
      // Create a pair first
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'list-test-source', related_query: 'list-test-target' }
      })
      const created = await createRes.json()

      const response = await page.request.get(`${ADMIN_API}/related-searches`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(Array.isArray(json.data)).toBe(true)

      // Should contain our pair
      const found = json.data.find((r: any) => r.source_query === 'list-test-source')
      expect(found).toBeDefined()

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })

    test('PUT updates a related search entry', async ({ page }) => {
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'update-test', related_query: 'original' }
      })
      const created = await createRes.json()

      const response = await page.request.put(`${ADMIN_API}/related-searches/${created.data.id}`, {
        data: { related_query: 'updated', position: 5 }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.related_query).toBe('updated')
      expect(json.data.position).toBe(5)

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })

    test('DELETE removes a related search entry', async ({ page }) => {
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'delete-test', related_query: 'to-be-removed' }
      })
      const created = await createRes.json()

      const response = await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)

      // Verify it's gone
      const getRes = await page.request.get(`${ADMIN_API}/related-searches`)
      const getJson = await getRes.json()
      const found = getJson.data.find((r: any) => r.id === created.data.id)
      expect(found).toBeUndefined()
    })

    test('POST bulk creates multiple pairs', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/related-searches/bulk`, {
        data: {
          entries: [
            { source_query: 'bulk-a', related_query: 'bulk-b' },
            { source_query: 'bulk-c', related_query: 'bulk-d' }
          ]
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.created).toBe(2)

      // Clean up
      const listRes = await page.request.get(`${ADMIN_API}/related-searches`)
      const listJson = await listRes.json()
      for (const r of listJson.data) {
        if (r.source_query.startsWith('bulk-')) {
          await page.request.delete(`${ADMIN_API}/related-searches/${r.id}`)
        }
      }
    })

    test('POST rejects duplicate pair (UNIQUE constraint)', async ({ page }) => {
      const res1 = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'dup-test', related_query: 'dup-target' }
      })
      const created = await res1.json()
      expect(created.success).toBe(true)

      // Try to create same pair again
      const res2 = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'dup-test', related_query: 'dup-target' }
      })
      expect(res2.status()).toBe(409)

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })
  })

  // =============================================
  // Bidirectional
  // =============================================

  test.describe('Bidirectional', () => {
    test('bidirectional=true creates both directions', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: {
          source_query: 'bidi-source',
          related_query: 'bidi-target',
          bidirectional: true
        }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.bidirectional).toBe(true)

      // Check both directions exist
      const listRes = await page.request.get(`${ADMIN_API}/related-searches`)
      const listJson = await listRes.json()

      const forward = listJson.data.find(
        (r: any) => r.source_query === 'bidi-source' && r.related_query === 'bidi-target'
      )
      const reverse = listJson.data.find(
        (r: any) => r.source_query === 'bidi-target' && r.related_query === 'bidi-source'
      )
      expect(forward).toBeDefined()
      expect(reverse).toBeDefined()

      // Clean up both
      if (forward) await page.request.delete(`${ADMIN_API}/related-searches/${forward.id}`)
      if (reverse) await page.request.delete(`${ADMIN_API}/related-searches/${reverse.id}`)
    })

    test('deleting one direction does not delete the other', async ({ page }) => {
      // Create bidirectional pair
      await page.request.post(`${ADMIN_API}/related-searches`, {
        data: {
          source_query: 'bidi-del-a',
          related_query: 'bidi-del-b',
          bidirectional: true
        }
      })

      // Find and delete forward direction only
      const listRes = await page.request.get(`${ADMIN_API}/related-searches`)
      const listJson = await listRes.json()
      const forward = listJson.data.find(
        (r: any) => r.source_query === 'bidi-del-a' && r.related_query === 'bidi-del-b'
      )
      expect(forward).toBeDefined()
      await page.request.delete(`${ADMIN_API}/related-searches/${forward.id}`)

      // Reverse should still exist
      const listRes2 = await page.request.get(`${ADMIN_API}/related-searches`)
      const listJson2 = await listRes2.json()
      const reverse = listJson2.data.find(
        (r: any) => r.source_query === 'bidi-del-b' && r.related_query === 'bidi-del-a'
      )
      expect(reverse).toBeDefined()

      // Clean up reverse
      if (reverse) await page.request.delete(`${ADMIN_API}/related-searches/${reverse.id}`)
    })
  })

  // =============================================
  // Public API
  // =============================================

  test.describe('Public API', () => {
    test('GET /api/search/related returns related searches', async ({ page }) => {
      // Create a pair
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'public-test', related_query: 'public-result' }
      })
      const created = await createRes.json()

      // Query public API
      const response = await page.request.get(`${SEARCH_API}/related?q=public-test`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.query).toBe('public-test')
      expect(json.data.related.length).toBeGreaterThanOrEqual(1)
      const found = json.data.related.find((r: any) => r.query === 'public-result')
      expect(found).toBeDefined()
      expect(found.source).toBe('manual')

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })

    test('GET /api/search/related respects limit', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/related?q=anything&limit=2`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.related.length).toBeLessThanOrEqual(2)
    })

    test('GET /api/search/related returns empty for unknown query', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/related?q=xyzzy-unknown-query-12345`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.related).toEqual([])
    })
  })

  // =============================================
  // Priority Ordering
  // =============================================

  test.describe('Priority Ordering', () => {
    test('manual entries appear before agent entries', async ({ page }) => {
      // Create manual pair
      const manualRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'priority-test', related_query: 'manual-result', position: 0 }
      })
      const manual = await manualRes.json()

      // Query the public API
      const response = await page.request.get(`${SEARCH_API}/related?q=priority-test`)
      const json = await response.json()
      expect(json.data.related.length).toBeGreaterThanOrEqual(1)
      // Manual should be first
      expect(json.data.related[0].query).toBe('manual-result')
      expect(json.data.related[0].source).toBe('manual')

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${manual.data.id}`)
    })

    test('position ordering works within same source', async ({ page }) => {
      const res1 = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'pos-test', related_query: 'second', position: 2 }
      })
      const res2 = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'pos-test', related_query: 'first', position: 1 }
      })
      const created1 = await res1.json()
      const created2 = await res2.json()

      const response = await page.request.get(`${SEARCH_API}/related?q=pos-test`)
      const json = await response.json()
      expect(json.data.related.length).toBeGreaterThanOrEqual(2)
      // Position 1 should come before position 2
      expect(json.data.related[0].query).toBe('first')
      expect(json.data.related[1].query).toBe('second')

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created1.data.id}`)
      await page.request.delete(`${ADMIN_API}/related-searches/${created2.data.id}`)
    })
  })

  // =============================================
  // Enable / Disable
  // =============================================

  test.describe('Enable / Disable', () => {
    test('disabled entries are excluded from results', async ({ page }) => {
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'disabled-test', related_query: 'should-hide' }
      })
      const created = await createRes.json()

      // Disable it
      await page.request.put(`${ADMIN_API}/related-searches/${created.data.id}`, {
        data: { enabled: false }
      })

      // Should not appear in public API
      const response = await page.request.get(`${SEARCH_API}/related?q=disabled-test`)
      const json = await response.json()
      const found = json.data.related.find((r: any) => r.query === 'should-hide')
      expect(found).toBeUndefined()

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })

    test('re-enabled entries appear again', async ({ page }) => {
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'reenable-test', related_query: 'should-return' }
      })
      const created = await createRes.json()

      // Disable then re-enable
      await page.request.put(`${ADMIN_API}/related-searches/${created.data.id}`, {
        data: { enabled: false }
      })
      await page.request.put(`${ADMIN_API}/related-searches/${created.data.id}`, {
        data: { enabled: true }
      })

      // Should appear again
      const response = await page.request.get(`${SEARCH_API}/related?q=reenable-test`)
      const json = await response.json()
      const found = json.data.related.find((r: any) => r.query === 'should-return')
      expect(found).toBeDefined()

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })
  })

  // =============================================
  // Search Response Integration
  // =============================================

  test.describe('Search Response Integration', () => {
    test('main search response includes related_searches field', async ({ page }) => {
      // Create a pair that matches a search term
      const createRes = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'test', related_query: 'testing guide' }
      })
      const created = await createRes.json()

      // Do a search for the source query
      const response = await page.request.post(SEARCH_API, {
        data: { query: 'test', mode: 'keyword' }
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)

      // Should have related_searches in the response
      if (json.data.related_searches) {
        expect(Array.isArray(json.data.related_searches)).toBe(true)
        const found = json.data.related_searches.find((r: any) => r.query === 'testing guide')
        expect(found).toBeDefined()
      }

      // Clean up
      await page.request.delete(`${ADMIN_API}/related-searches/${created.data.id}`)
    })
  })

  // =============================================
  // Validation
  // =============================================

  test.describe('Validation', () => {
    test('POST rejects missing source_query', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { related_query: 'something' }
      })
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.error).toContain('source_query')
    })

    test('POST rejects missing related_query', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/related-searches`, {
        data: { source_query: 'something' }
      })
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.error).toContain('related_query')
    })

    test('POST bulk rejects empty entries array', async ({ page }) => {
      const response = await page.request.post(`${ADMIN_API}/related-searches/bulk`, {
        data: { entries: [] }
      })
      expect(response.status()).toBe(400)
    })
  })

  // =============================================
  // Cache Invalidation
  // =============================================

  test.describe('Cache', () => {
    test('DELETE /related-searches/cache succeeds', async ({ page }) => {
      const response = await page.request.delete(`${ADMIN_API}/related-searches/cache`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
    })

    test('DELETE /related-searches/cache with query param succeeds', async ({ page }) => {
      const response = await page.request.delete(`${ADMIN_API}/related-searches/cache?query=test`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
    })
  })

  // =============================================
  // Relevance Tab UI
  // =============================================

  test.describe('Relevance Tab UI', () => {
    test('Relevance tab has Related Searches section', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search#relevance')
      await page.waitForLoadState('networkidle')

      // Click the relevance tab
      await page.click('#tab-btn-relevance')

      // Check for the Related Searches heading
      const heading = page.locator('text=Related Searches').first()
      await expect(heading).toBeVisible()
    })

    test('Related Searches section has Add button', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search#relevance')
      await page.waitForLoadState('networkidle')
      await page.click('#tab-btn-relevance')

      const addBtn = page.locator('#related-add-btn')
      await expect(addBtn).toBeVisible()
      await expect(addBtn).toHaveText(/Add Related Search/)
    })
  })

  test.describe('Agent Tab Integration', () => {
    test('Agent tab category filter includes related_search', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForLoadState('networkidle')

      // Verify the Agent tab's filter dropdown contains 'related_search' option in the DOM
      // (checking hidden elements since tab panel starts hidden)
      const option = page.locator('#agent-filter-category option[value="related_search"]')
      await expect(option).toHaveCount(1)
      await expect(option).toHaveText('Related Search')
    })
  })
})
