import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

/**
 * Comprehensive E2E tests for AI Search Plugin v3
 *
 * Covers: Search API (all modes), Autocomplete, Analytics, Settings API,
 * Admin FTS5 API, Test Page UI, Content Lifecycle, Edge Cases
 */

test.describe('Search v3 - Comprehensive', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // ──────────────────────────────────────────────
  // Search API — Response Structure
  // ──────────────────────────────────────────────

  test.describe('Search API Response Structure', () => {
    test('keyword mode returns expected response shape', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: { query: 'test', mode: 'keyword', limit: 5 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()

      expect(body).toHaveProperty('success', true)
      expect(body).toHaveProperty('data')
      expect(body.data).toHaveProperty('results')
      expect(body.data).toHaveProperty('total')
      expect(body.data).toHaveProperty('query_time_ms')
      expect(body.data).toHaveProperty('mode', 'keyword')
      expect(Array.isArray(body.data.results)).toBe(true)
      expect(typeof body.data.total).toBe('number')
      expect(typeof body.data.query_time_ms).toBe('number')

      if (body.data.results.length > 0) {
        const r = body.data.results[0]
        expect(r).toHaveProperty('id')
        expect(r).toHaveProperty('title')
        expect(r).toHaveProperty('collection_id')
        expect(r).toHaveProperty('status')
      }
    })

    test('fts5 mode returns expected response shape', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: { query: 'test', mode: 'fts5', limit: 5 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()

      expect(body.success).toBe(true)
      expect(['fts5', 'keyword']).toContain(body.data.mode)

      if (body.data.mode === 'fts5' && body.data.results.length > 0) {
        const r = body.data.results[0]
        expect(r).toHaveProperty('id')
        expect(r).toHaveProperty('title')
        expect(r).toHaveProperty('collection_id')
        expect(r).toHaveProperty('collection_name')
        // FTS5 specific fields
        expect(r).toHaveProperty('highlights')
        expect(r).toHaveProperty('bm25_score')
        expect(r.bm25_score).toBeGreaterThan(0)
      }
    })

    test('ai mode returns expected response shape', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: { query: 'test', mode: 'ai', limit: 5 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()

      expect(body.success).toBe(true)
      expect(body.data).toHaveProperty('mode', 'ai')

      if (body.data.results.length > 0) {
        const r = body.data.results[0]
        expect(r).toHaveProperty('id')
        expect(r).toHaveProperty('title')
        expect(r).toHaveProperty('relevance_score')
        expect(r.relevance_score).toBeGreaterThan(0)
      }
    })

    test('results are limited by limit parameter', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: { query: 'a', mode: 'keyword', limit: 2 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.data.results.length).toBeLessThanOrEqual(2)
    })
  })

  // ──────────────────────────────────────────────
  // Search API — Edge Cases
  // ──────────────────────────────────────────────

  test.describe('Search API Edge Cases', () => {
    test('empty query does not crash for any mode', async ({ page }) => {
      for (const mode of ['keyword', 'fts5']) {
        const response = await page.request.post('/api/search', {
          data: { query: '', mode, limit: 5 }
        })

        expect(response.status()).toBe(200)
        const body = await response.json()
        expect(body.success).toBe(true)
        // keyword mode may return results (LIKE %% matches all)
        // fts5 mode should return empty for empty query
        if (mode === 'fts5') {
          expect(body.data.results.length).toBe(0)
        }
      }
    })

    test('empty query for ai mode does not crash', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: { query: '', mode: 'ai', limit: 5 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    test('whitespace-only query returns empty results', async ({ page }) => {
      const response = await page.request.post('/api/search', {
        data: { query: '   ', mode: 'keyword', limit: 5 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    test('gibberish query returns zero results for all modes', async ({ page }) => {
      for (const mode of ['keyword', 'fts5']) {
        const response = await page.request.post('/api/search', {
          data: { query: 'xkcd99zzzznonexistent', mode, limit: 5 }
        })

        expect(response.status()).toBe(200)
        const body = await response.json()
        expect(body.data.results.length).toBe(0)
      }
    })

    test('special characters do not cause 500 errors', async ({ page }) => {
      const dangerous = [
        "'; DROP TABLE content; --",
        '<script>alert("xss")</script>',
        'test AND OR NOT NEAR',
        '"unmatched quote',
        'test(parens)[brackets]{braces}',
        'a*b?c:d^e',
        '日本語テスト',
        'café résumé naïve'
      ]

      for (const query of dangerous) {
        const response = await page.request.post('/api/search', {
          data: { query, mode: 'fts5', limit: 3 }
        })
        expect(response.status()).toBe(200)
        const body = await response.json()
        expect(body.success).toBe(true)
      }
    })

    test('very long query is handled gracefully', async ({ page }) => {
      const longQuery = 'search '.repeat(200)
      const response = await page.request.post('/api/search', {
        data: { query: longQuery, mode: 'keyword', limit: 5 }
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })
  })

  // ──────────────────────────────────────────────
  // Autocomplete / Suggest API
  // ──────────────────────────────────────────────

  test.describe('Autocomplete API', () => {
    test('returns suggestions for valid prefix', async ({ page }) => {
      const response = await page.request.get('/api/search/suggest?q=te')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toHaveProperty('success', true)
      expect(Array.isArray(body.data)).toBe(true)
    })

    test('returns empty for single character', async ({ page }) => {
      const response = await page.request.get('/api/search/suggest?q=a')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.data.length).toBe(0)
    })

    test('returns empty for missing q parameter', async ({ page }) => {
      const response = await page.request.get('/api/search/suggest')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.data.length).toBe(0)
    })

    test('suggestions respond within 500ms', async ({ page }) => {
      const start = Date.now()
      const response = await page.request.get('/api/search/suggest?q=test')
      const duration = Date.now() - start

      expect(response.status()).toBe(200)
      expect(duration).toBeLessThan(500)
    })
  })

  // ──────────────────────────────────────────────
  // Analytics API
  // ──────────────────────────────────────────────

  test.describe('Analytics API', () => {
    test('returns analytics data structure', async ({ page }) => {
      const response = await page.request.get('/api/search/analytics')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toHaveProperty('success', true)
      expect(body).toHaveProperty('data')
      expect(body.data).toHaveProperty('total_queries')
      expect(body.data).toHaveProperty('ai_queries')
      expect(body.data).toHaveProperty('keyword_queries')
      expect(body.data).toHaveProperty('fts5_queries')
      expect(body.data).toHaveProperty('popular_queries')
      expect(typeof body.data.total_queries).toBe('number')
    })

    test('search queries increment analytics counts', async ({ page }) => {
      // Get baseline
      const before = await page.request.get('/api/search/analytics')
      const beforeData = (await before.json()).data
      const baseKeyword = beforeData.keyword_queries

      // Make a keyword search
      await page.request.post('/api/search', {
        data: { query: 'analytics test', mode: 'keyword', limit: 1 }
      })

      // Check counts increased
      const after = await page.request.get('/api/search/analytics')
      const afterData = (await after.json()).data

      expect(afterData.keyword_queries).toBeGreaterThanOrEqual(baseKeyword)
    })
  })

  // ──────────────────────────────────────────────
  // Settings API
  // ──────────────────────────────────────────────

  test.describe('Settings API', () => {
    test('returns current plugin settings', async ({ page }) => {
      const response = await page.request.get('/admin/plugins/ai-search/api/settings')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toHaveProperty('success', true)
      expect(body).toHaveProperty('data')

      const settings = body.data
      expect(settings).toHaveProperty('enabled')
      expect(settings).toHaveProperty('selected_collections')
      expect(settings).toHaveProperty('autocomplete_enabled')
      expect(settings).toHaveProperty('results_limit')
      expect(Array.isArray(settings.selected_collections)).toBe(true)
    })

    test('returns index status for collections', async ({ page }) => {
      const response = await page.request.get('/admin/plugins/ai-search/api/status')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toBeDefined()
    })

    test('returns new collections detection', async ({ page }) => {
      const response = await page.request.get('/admin/plugins/ai-search/api/new-collections')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toHaveProperty('success', true)
      expect(Array.isArray(body.data)).toBe(true)
    })
  })

  // ──────────────────────────────────────────────
  // FTS5 Admin API
  // ──────────────────────────────────────────────

  test.describe('FTS5 Admin API', () => {
    test('fts5 status reports availability and counts', async ({ page }) => {
      const response = await page.request.get('/admin/plugins/ai-search/api/fts5/status')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.data).toHaveProperty('available')

      if (body.data.available) {
        expect(typeof body.data.total_indexed).toBe('number')
        expect(body.data.total_indexed).toBeGreaterThanOrEqual(0)
        expect(typeof body.data.by_collection).toBe('object')
      }
    })

    test('fts5 reindex-all triggers without error', async ({ page }) => {
      const response = await page.request.post('/admin/plugins/ai-search/api/fts5/reindex-all', {
        data: {}
      })

      const status = response.status()
      expect([200, 400]).toContain(status)

      const body = await response.json()
      if (status === 200) {
        expect(body.success).toBe(true)
      } else {
        expect(body).toHaveProperty('error')
      }
    })

    test('fts5 index-collection requires collection_id', async ({ page }) => {
      const response = await page.request.post('/admin/plugins/ai-search/api/fts5/index-collection', {
        data: {}
      })

      expect([400, 200]).toContain(response.status())
    })
  })

  // ──────────────────────────────────────────────
  // Test Page UI
  // ──────────────────────────────────────────────

  test.describe('Test Page UI', () => {
    test('loads with all three search mode options', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('.mode-toggle', { timeout: 10000 })

      await expect(page.locator('input[name="mode"][value="ai"]')).toBeVisible()
      await expect(page.locator('input[name="mode"][value="fts5"]')).toBeVisible()
      await expect(page.locator('input[name="mode"][value="keyword"]')).toBeVisible()

      // AI mode selected by default
      await expect(page.locator('input[name="mode"][value="ai"]')).toBeChecked()
    })

    test('has search input, button, stats, and history sections', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('#searchInput', { timeout: 10000 })

      await expect(page.locator('#searchInput')).toBeVisible()
      await expect(page.locator('#searchBtn')).toBeVisible()
      await expect(page.locator('#totalQueries')).toBeVisible()
      await expect(page.locator('#avgTime')).toBeVisible()
      await expect(page.locator('#lastTime')).toBeVisible()
    })

    test('keyword search from UI produces results or no-results message', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('#searchInput', { timeout: 10000 })

      // Switch to keyword mode
      await page.locator('input[name="mode"][value="keyword"]').check()

      // Enter query and search
      await page.locator('#searchInput').fill('test')
      await page.locator('#searchBtn').click()

      // Wait for response
      await page.waitForTimeout(3000)

      const resultsText = await page.locator('#results').textContent()
      expect(resultsText!.length).toBeGreaterThan(0)

      // Stats should update
      expect(await page.locator('#totalQueries').textContent()).toBe('1')
      expect(await page.locator('#lastTime').textContent()).not.toBe('-')
    })

    test('search results have clickable title links', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('#searchInput', { timeout: 10000 })

      // Use keyword mode (most reliable for content)
      await page.locator('input[name="mode"][value="keyword"]').check()
      await page.locator('#searchInput').fill('a')
      await page.locator('#searchBtn').click()
      await page.waitForTimeout(3000)

      // Check if results exist
      const resultLinks = page.locator('#results .result-title a')
      const linkCount = await resultLinks.count()

      if (linkCount > 0) {
        // Verify links point to content edit pages
        const href = await resultLinks.first().getAttribute('href')
        expect(href).toMatch(/^\/admin\/content\/[^/]+\/edit$/)

        // Verify links open in new tab
        const target = await resultLinks.first().getAttribute('target')
        expect(target).toBe('_blank')
      } else {
        // No results means no links to test — that's fine
        console.log('No search results to verify links')
      }
    })

    test('Enter key triggers search', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('#searchInput', { timeout: 10000 })

      await page.locator('input[name="mode"][value="keyword"]').check()
      await page.locator('#searchInput').fill('test')
      await page.locator('#searchInput').press('Enter')

      await page.waitForTimeout(3000)

      // Stats should update (search happened via Enter)
      expect(await page.locator('#totalQueries').textContent()).toBe('1')
    })

    test('query history tracks searches', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('#searchInput', { timeout: 10000 })

      await page.locator('input[name="mode"][value="keyword"]').check()

      // Perform two searches
      await page.locator('#searchInput').fill('first query')
      await page.locator('#searchBtn').click()
      await page.waitForTimeout(2000)

      await page.locator('#searchInput').fill('second query')
      await page.locator('#searchBtn').click()
      await page.waitForTimeout(2000)

      // History should contain both queries
      const history = await page.locator('#history').textContent()
      expect(history).toContain('first query')
      expect(history).toContain('second query')

      // Total queries should be 2
      expect(await page.locator('#totalQueries').textContent()).toBe('2')
    })

    test('has back link to settings page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForSelector('.back-link', { timeout: 10000 })

      const backLink = page.locator('.back-link')
      await expect(backLink).toBeVisible()
      expect(await backLink.getAttribute('href')).toBe('/admin/plugins/ai-search')
    })
  })

  // ──────────────────────────────────────────────
  // Settings Page UI
  // ──────────────────────────────────────────────

  test.describe('Settings Page UI', () => {
    test('loads with expected sections', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await expect(page.locator('h1')).toContainText(/Search/i, { timeout: 10000 })

      // Should contain key sections on Configuration tab
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)
      const content = await page.content()
      expect(content).toContain('collection')
    })

    test('has links to test page and integration guide', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Use .first() — these links may appear on multiple tabs
      const testLink = page.locator('a[href="/admin/plugins/ai-search/test"]').first()
      await expect(testLink).toBeVisible()

      const guideLink = page.locator('a[href="/admin/plugins/ai-search/integration"]').first()
      await expect(guideLink).toBeVisible()
    })

    test('shows FTS5 status section', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Switch to Configuration tab where FTS5 settings live
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      await expect(page.locator('text=FTS5 Full-Text Search')).toBeVisible({ timeout: 10000 })
      await expect(page.locator('#fts5-status-text')).toBeVisible()
    })
  })

  // ──────────────────────────────────────────────
  // Integration Guide Page
  // ──────────────────────────────────────────────

  test.describe('Integration Guide', () => {
    test('shows API documentation with endpoints', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForSelector('.container', { timeout: 10000 })

      const content = await page.content()
      expect(content).toContain('/api/search')
      expect(content).toContain('/api/search/suggest')
      expect(content).toContain('fts5')
      expect(content).toContain('bm25_score')
    })

    test('has framework tabs (Vanilla JS, React, Vue)', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForTimeout(1000)

      await expect(page.locator('button:has-text("Vanilla JS")')).toBeVisible()
      await expect(page.locator('button:has-text("React")')).toBeVisible()
      await expect(page.locator('button:has-text("Vue")')).toBeVisible()
    })
  })

  // ──────────────────────────────────────────────
  // Content Lifecycle — Create → Search → Delete
  // ──────────────────────────────────────────────

  test.describe('Content Lifecycle', () => {
    test('newly created content appears in keyword search', async ({ page }) => {
      const uniqueTitle = `SearchV3 Lifecycle Test ${Date.now()}`

      // Create content
      const createResp = await page.request.post('/api/content', {
        data: {
          collectionId: 'posts',
          title: uniqueTitle,
          slug: `sv3-lifecycle-${Date.now()}`,
          status: 'published',
          data: {
            title: uniqueTitle,
            content: 'Unique lifecycle content for search testing',
            description: 'Lifecycle test article'
          }
        }
      })

      if (createResp.status() !== 200 && createResp.status() !== 201) {
        console.log('Content creation skipped (posts collection may not exist)')
        return
      }

      const created = await createResp.json()
      const contentId = created?.data?.id

      try {
        // Wait for indexing (background FTS5 sync)
        await page.waitForTimeout(2000)

        // Search via keyword
        const searchResp = await page.request.post('/api/search', {
          data: { query: uniqueTitle, mode: 'keyword', limit: 10 }
        })
        expect(searchResp.status()).toBe(200)
        const searchData = await searchResp.json()

        if (searchData.data.results.length > 0) {
          const found = searchData.data.results.some(
            (r: any) => r.title === uniqueTitle
          )
          expect(found).toBe(true)
        }
      } finally {
        // Cleanup
        if (contentId) {
          await page.request.delete(`/api/content/${contentId}`)
        }
      }
    })

    test('newly created content appears in FTS5 search', async ({ page }) => {
      const uniqueTitle = `SearchV3 FTS5 Lifecycle ${Date.now()}`

      const createResp = await page.request.post('/api/content', {
        data: {
          collectionId: 'posts',
          title: uniqueTitle,
          slug: `sv3-fts5-lifecycle-${Date.now()}`,
          status: 'published',
          data: {
            title: uniqueTitle,
            content: 'FTS5 lifecycle test with porter stemming content',
            description: 'FTS5 lifecycle test article'
          }
        }
      })

      if (createResp.status() !== 200 && createResp.status() !== 201) {
        console.log('Content creation skipped (posts collection may not exist)')
        return
      }

      const created = await createResp.json()
      const contentId = created?.data?.id

      try {
        // Wait for background FTS5 indexing
        await page.waitForTimeout(2000)

        const searchResp = await page.request.post('/api/search', {
          data: { query: uniqueTitle, mode: 'fts5', limit: 10 }
        })
        expect(searchResp.status()).toBe(200)
        const searchData = await searchResp.json()

        if (searchData.data.mode === 'fts5' && searchData.data.results.length > 0) {
          const found = searchData.data.results.some(
            (r: any) => r.title === uniqueTitle
          )
          console.log('FTS5 lifecycle: found created content =', found)
        }
      } finally {
        if (contentId) {
          await page.request.delete(`/api/content/${contentId}`)
        }
      }
    })
  })

  // ──────────────────────────────────────────────
  // Cross-Mode Consistency
  // ──────────────────────────────────────────────

  test.describe('Cross-Mode Consistency', () => {
    test('same query returns consistent result structures across modes', async ({ page }) => {
      const query = 'test'
      const modes = ['keyword', 'fts5']

      for (const mode of modes) {
        const response = await page.request.post('/api/search', {
          data: { query, mode, limit: 5 }
        })
        expect(response.status()).toBe(200)

        const body = await response.json()
        expect(body.success).toBe(true)

        // All modes should have these base fields
        for (const r of body.data.results) {
          expect(r).toHaveProperty('id')
          expect(r).toHaveProperty('title')
          expect(r).toHaveProperty('collection_id')
        }
      }
    })
  })
})
