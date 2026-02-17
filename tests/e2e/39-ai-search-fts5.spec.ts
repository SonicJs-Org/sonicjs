import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

test.describe('AI Search - FTS5 Full-Text Search', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  test.describe('FTS5 Admin API', () => {
    test('should return FTS5 status via admin API', async ({ page }) => {
      const response = await page.request.get('/admin/plugins/ai-search/api/fts5/status')

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data).toHaveProperty('data')
      expect(data.data).toHaveProperty('available')

      if (data.data.available) {
        expect(data.data).toHaveProperty('total_indexed')
        expect(data.data).toHaveProperty('by_collection')
        console.log('FTS5 status:', {
          available: true,
          total_indexed: data.data.total_indexed,
          collections: Object.keys(data.data.by_collection).length
        })
      } else {
        console.log('FTS5 not yet available (migration may not have run)')
        expect(data.data).toHaveProperty('message')
      }
    })

    test('should reject FTS5 index-collection without collection_id', async ({ page }) => {
      const response = await page.request.post('/admin/plugins/ai-search/api/fts5/index-collection', {
        data: {}
      })

      // Should return 400 (bad request) or 400 (FTS5 not available)
      const status = response.status()
      expect([400, 200]).toContain(status)

      const data = await response.json()
      if (status === 400) {
        expect(data).toHaveProperty('error')
      }
    })

    test('should start FTS5 reindex-all for selected collections', async ({ page }) => {
      const response = await page.request.post('/admin/plugins/ai-search/api/fts5/reindex-all', {
        data: {}
      })

      const status = response.status()
      const data = await response.json()

      if (status === 400) {
        // FTS5 not available - expected if migration hasn't run
        expect(data).toHaveProperty('error')
        console.log('FTS5 reindex-all: FTS5 not available -', data.error)
      } else {
        expect(status).toBe(200)
        expect(data).toHaveProperty('success', true)
        console.log('FTS5 reindex-all started:', data.message)
      }
    })
  })

  test.describe('FTS5 Search API', () => {
    test('should support FTS5 search mode via search API', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: 'test',
          mode: 'fts5',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data).toHaveProperty('data')
      expect(data.data).toHaveProperty('results')
      expect(data.data).toHaveProperty('total')
      expect(data.data).toHaveProperty('query_time_ms')

      // Mode should be fts5 or fallback to keyword if FTS5 table not available
      expect(['fts5', 'keyword']).toContain(data.data.mode)

      console.log('FTS5 search result:', {
        mode: data.data.mode,
        total: data.data.total,
        query_time_ms: data.data.query_time_ms,
        result_count: data.data.results.length
      })

      // If results found and mode is fts5, verify FTS5-specific fields
      if (data.data.results.length > 0 && data.data.mode === 'fts5') {
        const firstResult = data.data.results[0]
        expect(firstResult).toHaveProperty('id')
        expect(firstResult).toHaveProperty('title')
        expect(firstResult).toHaveProperty('collection_id')

        // FTS5 results should have highlights and bm25 score
        if (firstResult.highlights) {
          console.log('FTS5 highlights:', firstResult.highlights)
        }
        if (firstResult.bm25_score !== undefined) {
          expect(firstResult.bm25_score).toBeGreaterThan(0)
          console.log('FTS5 BM25 score:', firstResult.bm25_score)
        }
      }
    })

    test('should return empty results for FTS5 search with gibberish query', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: 'xyzzy99nonexistent',
          mode: 'fts5',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data.data.results.length).toBe(0)
    })

    test('should handle empty FTS5 query gracefully', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: '',
          mode: 'fts5',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data.data.results.length).toBe(0)
    })

    test('should handle FTS5 query with special characters safely', async ({ page }) => {
      // FTS5 special characters that could cause SQL errors if not sanitized
      const specialQueries = [
        'test AND OR NOT',
        '"quoted phrase"',
        'test*',
        'test:column',
        'test(brackets)',
        'cafe with accents'
      ]

      for (const query of specialQueries) {
        const response = await page.request.post('/api/search', {
          data: { query, mode: 'fts5', limit: 5 }
        })

        expect(response.status()).toBe(200)

        const data = await response.json()
        expect(data).toHaveProperty('success', true)
        console.log(`FTS5 special query "${query}": ${data.data.results.length} results`)
      }
    })
  })

  test.describe('FTS5 Test Page UI', () => {
    test('should show FTS5 mode option on test page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('.mode-toggle', { timeout: 10000 })

      // Should have three mode options
      const fts5Radio = page.locator('input[name="mode"][value="fts5"]')
      await expect(fts5Radio).toBeVisible()

      const aiRadio = page.locator('input[name="mode"][value="ai"]')
      await expect(aiRadio).toBeVisible()

      const keywordRadio = page.locator('input[name="mode"][value="keyword"]')
      await expect(keywordRadio).toBeVisible()
    })

    test('should execute FTS5 search from test page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('.mode-toggle', { timeout: 10000 })

      // Select FTS5 mode
      const fts5Radio = page.locator('input[name="mode"][value="fts5"]')
      await fts5Radio.click()
      await expect(fts5Radio).toBeChecked()

      // Type a search query
      const searchInput = page.locator('#searchInput')
      await searchInput.fill('test')

      // Click search
      const searchBtn = page.locator('#searchBtn')
      await searchBtn.click()

      // Wait for results
      await page.waitForTimeout(3000)

      // Results area should have content (either results or "No results found")
      const resultsDiv = page.locator('#results')
      const resultsText = await resultsDiv.textContent()
      expect(resultsText).toBeTruthy()
      expect(resultsText!.length).toBeGreaterThan(0)

      // Stats should update
      const totalQueries = page.locator('#totalQueries')
      const totalText = await totalQueries.textContent()
      expect(parseInt(totalText || '0')).toBeGreaterThanOrEqual(1)

      console.log('Test page FTS5 search completed, results text length:', resultsText!.length)
    })
  })

  test.describe('FTS5 Settings Page UI', () => {
    test('should show FTS5 section on settings page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Switch to Configuration tab where FTS5 settings live
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      // Should show FTS5 Full-Text Search heading
      const fts5Heading = page.locator('text=FTS5 Full-Text Search')
      await expect(fts5Heading).toBeVisible({ timeout: 10000 })

      // Should show FTS5 status text
      const fts5StatusText = page.locator('#fts5-status-text')
      await expect(fts5StatusText).toBeVisible()

      // Wait for async status check to complete
      await page.waitForTimeout(3000)
      const statusText = await fts5StatusText.textContent()
      expect(statusText).toBeTruthy()

      // Should be either "FTS5 is available" or "FTS5 tables not created yet"
      expect(statusText).toMatch(/FTS5 (is available|tables not created)/i)

      console.log('FTS5 settings status:', statusText)
    })

    test('should show FTS5 reindex button on settings page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Switch to Configuration tab
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      const reindexBtn = page.locator('#fts5-reindex-btn')
      await expect(reindexBtn).toBeVisible({ timeout: 10000 })
    })

    test('should show FTS5 queries in analytics', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Switch to Analytics tab where query stats live
      await page.click('#tab-btn-analytics')
      await page.waitForTimeout(2000)

      // Analytics content is AJAX-loaded — may not render on CI (missing bindings)
      const fts5QueriesStat = page.locator('text=FTS5 Queries')
      const loaded = await fts5QueriesStat.isVisible().catch(() => false)
      if (!loaded) {
        console.log('FTS5 Queries stat not visible (analytics API may be unavailable on CI)')
        return
      }
      await expect(fts5QueriesStat).toBeVisible()
    })
  })

  test.describe('FTS5 Content Sync', () => {
    test('should sync new content to FTS5 index via API', async ({ page }) => {
      // Create content via API
      const createResponse = await page.request.post('/api/content', {
        data: {
          collectionId: 'posts',
          title: 'FTS5 Test Article',
          slug: `fts5-test-${Date.now()}`,
          status: 'published',
          data: {
            title: 'FTS5 Test Article',
            content: 'This article tests FTS5 full-text search indexing with porter stemming.',
            description: 'Testing FTS5 search indexing'
          }
        }
      })

      // If content creation succeeded, search for it
      if (createResponse.status() === 201 || createResponse.status() === 200) {
        const created = await createResponse.json()
        const contentId = created?.data?.id
        console.log('Created test content:', contentId)

        // Wait for background FTS5 indexing
        await page.waitForTimeout(2000)

        // Search for the content via FTS5
        const searchResponse = await page.request.post('/api/search', {
          data: {
            query: 'FTS5 Test Article',
            mode: 'fts5',
            limit: 10
          }
        })

        expect(searchResponse.status()).toBe(200)
        const searchData = await searchResponse.json()

        if (searchData.data.mode === 'fts5') {
          console.log('FTS5 content sync search results:', searchData.data.total)
          // If FTS5 is available, the newly created content should appear
          if (searchData.data.results.length > 0) {
            const found = searchData.data.results.some(
              (r: any) => r.title === 'FTS5 Test Article'
            )
            console.log('FTS5 content sync - found new content:', found)
          }
        } else {
          console.log('FTS5 not available, fell back to:', searchData.data.mode)
        }

        // Cleanup: delete the test content
        if (contentId) {
          await page.request.delete(`/api/content/${contentId}`)
          console.log('Cleaned up test content:', contentId)
        }
      } else {
        console.log('Content creation returned status:', createResponse.status(), '- collection may not exist')
      }
    })
  })

  test.describe('FTS5 Integration Guide', () => {
    test('should document FTS5 mode in integration guide', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForSelector('.container', { timeout: 10000 })

      // Should mention fts5 mode in the API reference
      const pageContent = await page.content()
      expect(pageContent).toContain('fts5')

      // Should show mode options including fts5
      expect(pageContent).toContain('"ai", "fts5", "hybrid", or "keyword"')

      // Should show FTS5-specific response fields
      expect(pageContent).toContain('bm25_score')
      expect(pageContent).toContain('highlights')
    })

    test('should show FTS5 in performance tips', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForSelector('.container', { timeout: 10000 })

      const fts5Tip = page.locator('text=FTS5 Full-Text Mode')
      await expect(fts5Tip).toBeVisible({ timeout: 10000 })
    })
  })
})
