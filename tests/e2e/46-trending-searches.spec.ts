import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

const SEARCH_API = '/api/search'

test.describe('Trending Searches', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // =============================================
  // Trending API Endpoint
  // =============================================

  test.describe('GET /api/search/trending', () => {
    test('returns structured response with required fields', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/trending`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json).toHaveProperty('trending')
      expect(json).toHaveProperty('period_days')
      expect(json).toHaveProperty('generated_at')
      expect(json).toHaveProperty('cached')
      expect(Array.isArray(json.trending)).toBe(true)
      expect(typeof json.period_days).toBe('number')
      expect(typeof json.cached).toBe('boolean')
      expect(typeof json.generated_at).toBe('string')
    })

    test('trending items have correct shape', async ({ page }) => {
      // First do several searches to generate history
      for (let i = 0; i < 4; i++) {
        await page.request.post(`${SEARCH_API}`, {
          data: { query: 'trending test query', mode: 'fts5' }
        })
      }

      const response = await page.request.get(`${SEARCH_API}/trending?period=30`)
      expect(response.status()).toBe(200)
      const json = await response.json()

      // May or may not have items depending on results_count > 0 and count >= 3
      if (json.trending.length > 0) {
        const item = json.trending[0]
        expect(item).toHaveProperty('query')
        expect(item).toHaveProperty('trend_score')
        expect(item).toHaveProperty('search_count')
        expect(typeof item.query).toBe('string')
        expect(typeof item.trend_score).toBe('number')
        expect(typeof item.search_count).toBe('number')
        expect(item.trend_score).toBeGreaterThan(0)
        expect(item.search_count).toBeGreaterThanOrEqual(3)
      }
    })

    test('respects limit parameter', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/trending?limit=2`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.trending.length).toBeLessThanOrEqual(2)
    })

    test('respects period parameter', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/trending?period=1`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.period_days).toBe(1)
      expect(Array.isArray(json.trending)).toBe(true)
    })

    test('clamps limit to valid range (1-20)', async ({ page }) => {
      // Too high
      const resp1 = await page.request.get(`${SEARCH_API}/trending?limit=100`)
      expect(resp1.status()).toBe(200)
      const json1 = await resp1.json()
      expect(json1.trending.length).toBeLessThanOrEqual(20)

      // Too low — should still succeed
      const resp2 = await page.request.get(`${SEARCH_API}/trending?limit=0`)
      expect(resp2.status()).toBe(200)
    })

    test('clamps period to valid range (1-30)', async ({ page }) => {
      const resp = await page.request.get(`${SEARCH_API}/trending?period=0`)
      expect(resp.status()).toBe(200)
      const json = await resp.json()
      // Clamped to 1
      expect(json.period_days).toBeGreaterThanOrEqual(1)
    })

    test('default limit is 5 and default period is 7', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/trending`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.period_days).toBe(7)
      expect(json.trending.length).toBeLessThanOrEqual(5)
    })
  })

  // =============================================
  // Suggest Endpoint (Trending on Empty Query)
  // =============================================

  test.describe('GET /api/search/suggest', () => {
    test('returns trending on empty query', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/suggest?q=`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(Array.isArray(json.data)).toBe(true)
      // Suggest returns string[] (query names only, not TrendingSearch objects)
      if (json.data.length > 0) {
        expect(typeof json.data[0]).toBe('string')
      }
    })

    test('returns prefix matches on 2+ char query', async ({ page }) => {
      const response = await page.request.get(`${SEARCH_API}/suggest?q=test`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(Array.isArray(json.data)).toBe(true)
    })
  })
})
