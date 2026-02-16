import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

test.describe('AI Search - Phase 2: Hybrid Search', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  test.describe('Hybrid Search API', () => {
    test('should return valid response with mode: "hybrid"', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: 'test',
          mode: 'hybrid',
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

      // Mode should be hybrid (or keyword fallback if FTS5 not available)
      expect(['hybrid', 'keyword']).toContain(data.data.mode)

      console.log('Hybrid search result:', {
        mode: data.data.mode,
        total: data.data.total,
        query_time_ms: data.data.query_time_ms,
        result_count: data.data.results.length
      })
    })

    test('should return results with rrf_score when hybrid mode active', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: 'test',
          mode: 'hybrid',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)

      if (data.data.mode === 'hybrid' && data.data.results.length > 0) {
        const firstResult = data.data.results[0]
        expect(firstResult).toHaveProperty('rrf_score')
        expect(firstResult.rrf_score).toBeGreaterThan(0)
        console.log('First hybrid result:', {
          title: firstResult.title,
          rrf_score: firstResult.rrf_score,
          bm25_score: firstResult.bm25_score,
          relevance_score: firstResult.relevance_score
        })
      }
    })

    test('should handle empty hybrid query gracefully', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: '',
          mode: 'hybrid',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data.data.results.length).toBe(0)
    })

    test('should handle hybrid search with special characters safely', async ({ page }) => {
      const specialQueries = [
        'test AND OR NOT',
        '"quoted phrase"',
        'test*',
        'test:column',
        'test(brackets)',
        '<script>alert("xss")</script>'
      ]

      for (const query of specialQueries) {
        const response = await page.request.post('/api/search', {
          data: { query, mode: 'hybrid', limit: 5 }
        })

        expect(response.status()).toBe(200)

        const data = await response.json()
        expect(data).toHaveProperty('success', true)
        console.log(`Hybrid special query "${query}": ${data.data.results.length} results`)
      }
    })

    test('should respect limit parameter in hybrid mode', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: 'test',
          mode: 'hybrid',
          limit: 3
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data.data.results.length).toBeLessThanOrEqual(3)
    })

    test('should return empty results for gibberish hybrid query', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: {
          query: 'xyzzy99nonexistent_zqw',
          mode: 'hybrid',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)
      expect(data.data.results.length).toBe(0)
    })
  })

  test.describe('Graceful Degradation', () => {
    test('should work without Vectorize (FTS5 fallback)', async ({ page }) => {
      // In local dev, Vectorize is not available
      // Hybrid mode should still return results from FTS5
      const response = await page.request.post('/api/search', {
        data: {
          query: 'test',
          mode: 'hybrid',
          limit: 10
        }
      })

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success', true)

      // Should still report mode as hybrid (or keyword if FTS5 also unavailable)
      expect(['hybrid', 'keyword']).toContain(data.data.mode)

      console.log('Degradation test:', {
        mode: data.data.mode,
        results: data.data.results.length,
        query_time_ms: data.data.query_time_ms
      })
    })
  })

  test.describe('Test Page UI', () => {
    test('should show Hybrid mode option on test page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('.mode-toggle', { timeout: 10000 })

      // Should have four mode options including hybrid
      const hybridRadio = page.locator('input[name="mode"][value="hybrid"]')
      await expect(hybridRadio).toBeVisible()

      const aiRadio = page.locator('input[name="mode"][value="ai"]')
      await expect(aiRadio).toBeVisible()

      const fts5Radio = page.locator('input[name="mode"][value="fts5"]')
      await expect(fts5Radio).toBeVisible()

      const keywordRadio = page.locator('input[name="mode"][value="keyword"]')
      await expect(keywordRadio).toBeVisible()
    })

    test('should execute hybrid search from test page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('.mode-toggle', { timeout: 10000 })

      // Select Hybrid mode
      const hybridRadio = page.locator('input[name="mode"][value="hybrid"]')
      await hybridRadio.click()
      await expect(hybridRadio).toBeChecked()

      // Type a search query
      const searchInput = page.locator('#searchInput')
      await searchInput.fill('test')

      // Click search
      const searchBtn = page.locator('#searchBtn')
      await searchBtn.click()

      // Wait for results
      await page.waitForTimeout(3000)

      // Results area should have content
      const resultsDiv = page.locator('#results')
      const resultsText = await resultsDiv.textContent()
      expect(resultsText).toBeTruthy()
      expect(resultsText!.length).toBeGreaterThan(0)

      // Stats should update
      const totalQueries = page.locator('#totalQueries')
      const totalText = await totalQueries.textContent()
      expect(parseInt(totalText || '0')).toBeGreaterThanOrEqual(1)

      console.log('Test page hybrid search completed, results text length:', resultsText!.length)
    })
  })

  test.describe('Integration Guide', () => {
    test('should document hybrid mode in integration guide', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForSelector('.container', { timeout: 10000 })

      const pageContent = await page.content()

      // Should mention hybrid mode in the API reference
      expect(pageContent).toContain('hybrid')
      expect(pageContent).toContain('"ai", "fts5", "hybrid", or "keyword"')
    })

    test('should show Hybrid performance card', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForSelector('.container', { timeout: 10000 })

      const hybridCard = page.locator('text=Hybrid Mode')
      await expect(hybridCard).toBeVisible({ timeout: 10000 })
    })
  })

  test.describe('Settings Page', () => {
    test('should show Hybrid Queries in analytics', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForTimeout(2000)

      // Switch to Analytics tab
      await page.click('#tab-btn-analytics')
      await page.waitForTimeout(2000)

      const hybridQueriesStat = page.locator('text=Hybrid Queries')
      await expect(hybridQueriesStat).toBeVisible({ timeout: 10000 })
    })

    test('should show AI/Semantic Search settings section', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForTimeout(2000)

      // Switch to Configuration tab
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      const aiHeading = page.locator('text=AI / Semantic Search').or(page.locator('text=AI Reranking'))
      await expect(aiHeading.first()).toBeVisible({ timeout: 10000 })
    })

    test('should show AI Reranking toggle', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForTimeout(2000)

      // Switch to Configuration tab
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      const rerankingCheckbox = page.locator('#reranking_enabled')
      await expect(rerankingCheckbox).toBeVisible({ timeout: 10000 })
    })

    test('should show Query Rewriting toggle', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForTimeout(2000)

      // Switch to Configuration tab
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      const rewritingCheckbox = page.locator('#query_rewriting_enabled')
      await expect(rewritingCheckbox).toBeVisible({ timeout: 10000 })
    })
  })

  test.describe('Analytics', () => {
    test('should count hybrid queries in analytics', async ({ page }) => {
      // Execute a hybrid search first
      await page.request.post('/api/search', {
        data: {
          query: 'analytics test hybrid',
          mode: 'hybrid',
          limit: 5
        }
      })

      // Check analytics API
      const analyticsResponse = await page.request.get('/api/search/analytics')

      if (analyticsResponse.status() === 200) {
        const analytics = await analyticsResponse.json()
        if (analytics.data) {
          expect(analytics.data).toHaveProperty('hybrid_queries')
          expect(typeof analytics.data.hybrid_queries).toBe('number')
          console.log('Analytics after hybrid search:', {
            total: analytics.data.total_queries,
            hybrid: analytics.data.hybrid_queries,
            fts5: analytics.data.fts5_queries,
            ai: analytics.data.ai_queries
          })
        }
      }
    })
  })
})
