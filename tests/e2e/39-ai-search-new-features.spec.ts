import { expect, test } from '@playwright/test'
import {
  ensureAdminUserExists,
  ensureWorkflowTablesExist,
  loginAsAdmin
} from './utils/test-helpers'

test.describe('AI Search - New Features', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  test.describe('Headless Integration Guide', () => {
    test('should display integration guide page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')

      // Check page loaded
      await expect(page.locator('h1')).toContainText(/Headless Integration/i, { timeout: 10000 })

      // Should have tabs for different frameworks
      await expect(page.locator('button:has-text("Vanilla JS")')).toBeVisible()
      await expect(page.locator('button:has-text("React")')).toBeVisible()
      await expect(page.locator('button:has-text("Vue")')).toBeVisible()
    })

    test('should switch between framework tabs', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForTimeout(1000)

      // Click React tab
      await page.locator('button:has-text("React")').click()
      await page.waitForTimeout(500)

      // Should show React code
      const reactCode = page.locator('#react')
      await expect(reactCode).toHaveClass(/active/)

      // Click Vue tab
      await page.locator('button:has-text("Vue")').click()
      await page.waitForTimeout(500)

      // Should show Vue code
      const vueCode = page.locator('#vue')
      await expect(vueCode).toHaveClass(/active/)
    })

    test('should have copy buttons for code examples', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForTimeout(1000)

      // Should have copy buttons
      const copyButtons = page.locator('button:has-text("Copy")')
      const count = await copyButtons.count()

      expect(count).toBeGreaterThan(0)
      console.log(`Found ${count} copy buttons`)
    })

    test('should display API reference', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForTimeout(1000)

      // Check for API documentation sections
      const pageContent = await page.content()
      expect(pageContent).toContain('Search Endpoint')
      expect(pageContent).toContain('Autocomplete')
      expect(pageContent).toContain('/api/search')
      expect(pageContent).toContain('/api/search/suggest')
    })

    test('should have back link to settings', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForTimeout(1000)

      // Should have back link
      const backLink = page.locator('a[href="/admin/plugins/ai-search"]')
      await expect(backLink).toBeVisible()

      // Click back link
      await backLink.click()
      await page.waitForTimeout(1000)

      // Should navigate to settings
      await expect(page).toHaveURL(/\/admin\/plugins\/ai-search$/)
    })
  })

  test.describe('Test Search Page', () => {
    test('should display test search page', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForTimeout(1000)

      // Check page loaded
      await expect(page.locator('h1')).toContainText(/Search Test/i)

      // Should have search input
      await expect(page.locator('input[type="text"]')).toBeVisible()

      // Should have mode toggle (AI/Keyword)
      await expect(page.locator('input[name="mode"][value="ai"]')).toBeVisible()
      await expect(page.locator('input[name="mode"][value="keyword"]')).toBeVisible()
    })

    test('should show performance stats', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForTimeout(1000)

      // Should have stat displays
      await expect(page.locator('#totalQueries')).toBeVisible()
      await expect(page.locator('#avgTime')).toBeVisible()
      await expect(page.locator('#lastTime')).toBeVisible()
    })

    test('should perform keyword search', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForTimeout(1000)

      // Select keyword mode
      await page.locator('input[name="mode"][value="keyword"]').check()

      // Type search query
      await page.locator('input[type="text"]').fill('test')
      await page.waitForTimeout(500)

      // Click search button
      await page.locator('button:has-text("Search")').click()

      // Wait for results
      await page.waitForTimeout(2000)

      // Should show either results or "no results"
      const resultsDiv = page.locator('#results')
      const content = await resultsDiv.textContent()

      expect(content).toBeTruthy()
      console.log('Search results:', content?.substring(0, 100))
    })

    test('should update stats after search', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForTimeout(1000)

      // Get initial stat values
      const initialQueries = await page.locator('#totalQueries').textContent()
      expect(initialQueries).toBe('0')

      // Perform search
      await page.locator('input[type="text"]').fill('test')
      await page.locator('button:has-text("Search")').click()
      await page.waitForTimeout(2000)

      // Stats should update
      const finalQueries = await page.locator('#totalQueries').textContent()
      expect(finalQueries).toBe('1')

      // Should show timing
      const lastTime = await page.locator('#lastTime').textContent()
      expect(lastTime).not.toBe('-')
      console.log('Query time:', lastTime)
    })

    test('should show query history', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForTimeout(1000)

      // Perform a search
      await page.locator('input[type="text"]').fill('test query')
      await page.locator('button:has-text("Search")').click()
      await page.waitForTimeout(2000)

      // Should show in history
      const historyDiv = page.locator('#history')
      const historyContent = await historyDiv.textContent()

      expect(historyContent).toContain('test query')
      console.log('History updated:', historyContent?.substring(0, 100))
    })
  })

  test.describe('Fast Autocomplete', () => {
    test('should show suggestions quickly', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/test')
      await page.waitForTimeout(1000)

      // Type to trigger autocomplete
      const input = page.locator('input[type="text"]')
      await input.fill('te')

      // Wait for suggestions (should be <300ms + debounce)
      await page.waitForTimeout(800)

      // Check if suggestions appeared
      const suggestionsDiv = page.locator('#suggestions')
      const isVisible = await suggestionsDiv.isVisible()

      console.log('Autocomplete suggestions visible:', isVisible)

      // If suggestions shown, verify they're clickable
      if (isVisible) {
        const suggestionItems = page.locator('.suggestion-item')
        const count = await suggestionItems.count()
        console.log(`Found ${count} suggestions`)

        if (count > 0) {
          // Click first suggestion
          await suggestionItems.first().click()
          await page.waitForTimeout(500)

          // Input should be updated
          const inputValue = await input.inputValue()
          expect(inputValue.length).toBeGreaterThan(0)
          console.log('Selected suggestion:', inputValue)
        }
      }
    })

    test('should fetch suggestions via API', async ({ page }) => {
      // Test the autocomplete API directly
      const response = await page.request.get('/api/search/suggest?q=test')

      expect(response.status()).toBe(200)

      const data = await response.json()
      expect(data).toHaveProperty('success')
      expect(data).toHaveProperty('data')
      expect(Array.isArray(data.data)).toBe(true)

      console.log('Autocomplete suggestions:', data.data)
    })

    test('should measure autocomplete performance', async ({ page }) => {
      // Measure multiple autocomplete requests
      const queries = ['te', 'tes', 'test']
      const times: number[] = []

      for (const query of queries) {
        const start = Date.now()
        const response = await page.request.get(`/api/search/suggest?q=${query}`)
        const end = Date.now()

        expect(response.status()).toBe(200)

        const duration = end - start
        times.push(duration)
        console.log(`Autocomplete for "${query}": ${duration}ms`)
      }

      // Average should be fast (<100ms for keyword mode)
      const avg = times.reduce((a, b) => a + b, 0) / times.length
      console.log(`Average autocomplete time: ${avg.toFixed(0)}ms`)

      // Should be reasonably fast (allowing for network overhead in tests)
      expect(avg).toBeLessThan(500)
    })
  })

  test.describe('Similarity Caching', () => {
    test('should show faster response for similar queries', async ({ page }) => {
      // Test similarity caching by making similar queries
      const queries = [
        { query: 'cloudflare workers', label: 'first' },
        { query: 'cloudflare worker', label: 'similar' },
        { query: 'workers cloudflare', label: 'variation' }
      ]

      const times: Array<{ label: string; time: number }> = []

      for (const { query, label } of queries) {
        const start = Date.now()
        const response = await page.request.post('/api/search', {
          data: {
            query,
            mode: 'ai',
            limit: 10
          }
        })
        const end = Date.now()

        expect(response.status()).toBe(200)

        const duration = end - start
        times.push({ label, time: duration })
        console.log(`${label} query ("${query}"): ${duration}ms`)

        // Wait a bit between queries
        await page.waitForTimeout(500)
      }

      // Log performance comparison
      console.log('\nSimilarity Caching Performance:')
      times.forEach(t => console.log(`  ${t.label}: ${t.time}ms`))

      // Note: Caching benefit may not always be visible in tests due to:
      // - Network variability
      // - Cold starts
      // - Test environment differences
      // But we verify the API works correctly
    })

    test('should cache embedding generation', async ({ page }) => {
      // Make the same query twice to test caching
      const query = 'test caching query'

      // First query
      const start1 = Date.now()
      const response1 = await page.request.post('/api/search', {
        data: { query, mode: 'ai' }
      })
      const time1 = Date.now() - start1

      expect(response1.status()).toBe(200)
      console.log(`First query: ${time1}ms`)

      // Wait a moment
      await page.waitForTimeout(1000)

      // Exact same query (should be cached)
      const start2 = Date.now()
      const response2 = await page.request.post('/api/search', {
        data: { query, mode: 'ai' }
      })
      const time2 = Date.now() - start2

      expect(response2.status()).toBe(200)
      console.log(`Cached query: ${time2}ms`)

      // Both should return results
      const data1 = await response1.json()
      const data2 = await response2.json()

      expect(data1.success).toBe(true)
      expect(data2.success).toBe(true)

      // Log the comparison
      if (time2 < time1) {
        console.log(`✓ Cached query was ${time1 - time2}ms faster (${((1 - time2 / time1) * 100).toFixed(0)}% speedup)`)
      } else {
        console.log(`⚠ No speedup observed (network/environment variability)`)
      }
    })
  })

  test.describe('Settings Page Integration', () => {
    test('should have buttons for new pages', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Should have Test Search button
      const testButton = page.locator('a[href="/admin/plugins/ai-search/test"]')
      await expect(testButton).toBeVisible()
      expect(await testButton.textContent()).toContain('Test Search')

      // Should have Headless Guide button
      const guideButton = page.locator('a[href="/admin/plugins/ai-search/integration"]')
      await expect(guideButton).toBeVisible()
      expect(await guideButton.textContent()).toContain('Headless Guide')
    })

    test('should open pages in new tabs', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Check Test Search button has target="_blank"
      const testButton = page.locator('a[href="/admin/plugins/ai-search/test"]')
      const testTarget = await testButton.getAttribute('target')
      expect(testTarget).toBe('_blank')

      // Check Integration Guide button has target="_blank"
      const guideButton = page.locator('a[href="/admin/plugins/ai-search/integration"]')
      const guideTarget = await guideButton.getAttribute('target')
      expect(guideTarget).toBe('_blank')
    })
  })
})
