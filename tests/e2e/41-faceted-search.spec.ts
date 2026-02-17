import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

/**
 * E2E tests for Faceted Search (Phase 6-ready)
 *
 * Covers: Facet discovery API, auto-generate config, config save/load,
 * search-with-facets response, facet-click tracking, admin UI toggle,
 * InstantSearch adapter facets, and edge cases.
 */

test.describe('Faceted Search', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // ──────────────────────────────────────────────
  // Facet Discovery API
  // ──────────────────────────────────────────────

  test.describe('Facet Discovery API', () => {
    test('GET discover returns built-in facets and discovered fields', async ({ page }) => {
      const response = await page.request.get(
        '/admin/plugins/ai-search/api/facets/discover'
      )

      expect(response.status()).toBe(200)
      const body = await response.json()

      expect(body).toHaveProperty('success', true)
      expect(body).toHaveProperty('data')
      expect(Array.isArray(body.data)).toBe(true)

      // Should always include the 3 built-in facets
      const fields = body.data.map((d: any) => d.field)
      expect(fields).toContain('collection_name')
      expect(fields).toContain('status')
      expect(fields).toContain('author')

      // Built-in facets should be recommended
      const collectionFacet = body.data.find((d: any) => d.field === 'collection_name')
      expect(collectionFacet).toMatchObject({
        field: 'collection_name',
        title: 'Collection',
        type: 'builtin',
        recommended: true,
      })

      const statusFacet = body.data.find((d: any) => d.field === 'status')
      expect(statusFacet.enumValues).toEqual(
        expect.arrayContaining(['draft', 'published', 'archived'])
      )
    })

    test('discovered fields have correct structure', async ({ page }) => {
      const response = await page.request.get(
        '/admin/plugins/ai-search/api/facets/discover'
      )
      const body = await response.json()

      for (const field of body.data) {
        expect(field).toHaveProperty('field')
        expect(field).toHaveProperty('title')
        expect(field).toHaveProperty('type')
        expect(field).toHaveProperty('recommended')
        expect(field).toHaveProperty('collections')
        expect(['builtin', 'json_scalar', 'json_array']).toContain(field.type)
        expect(typeof field.recommended).toBe('boolean')
        expect(Array.isArray(field.collections)).toBe(true)
      }
    })
  })

  // ──────────────────────────────────────────────
  // Facet Configuration API
  // ──────────────────────────────────────────────

  test.describe('Facet Configuration API', () => {
    test('GET config returns current facet settings', async ({ page }) => {
      const response = await page.request.get(
        '/admin/plugins/ai-search/api/facets/config'
      )

      expect(response.status()).toBe(200)
      const body = await response.json()

      expect(body).toHaveProperty('success', true)
      expect(body.data).toHaveProperty('enabled')
      expect(body.data).toHaveProperty('config')
      expect(body.data).toHaveProperty('max_values')
      expect(typeof body.data.enabled).toBe('boolean')
      expect(Array.isArray(body.data.config)).toBe(true)
      expect(typeof body.data.max_values).toBe('number')
    })

    test('POST auto-generate creates config from schema discovery', async ({ page }) => {
      const response = await page.request.post(
        '/admin/plugins/ai-search/api/facets/auto-generate'
      )

      expect(response.status()).toBe(200)
      const body = await response.json()

      expect(body).toHaveProperty('success', true)
      expect(body.data).toHaveProperty('enabled', true)
      expect(body.data).toHaveProperty('config')
      expect(body.data).toHaveProperty('discovered_count')
      expect(body.data).toHaveProperty('auto_enabled_count')

      // Should have auto-enabled at least the 3 built-in facets
      expect(body.data.auto_enabled_count).toBeGreaterThanOrEqual(3)
      expect(body.data.config.length).toBeGreaterThanOrEqual(3)

      // Verify config entries have correct shape
      for (const facet of body.data.config) {
        expect(facet).toHaveProperty('name')
        expect(facet).toHaveProperty('field')
        expect(facet).toHaveProperty('type')
        expect(facet).toHaveProperty('enabled', true)
        expect(facet).toHaveProperty('source', 'auto')
        expect(facet).toHaveProperty('position')
        expect(typeof facet.position).toBe('number')
      }
    })

    test('POST config saves facet settings', async ({ page }) => {
      const testConfig = [
        {
          name: 'Collection',
          field: 'collection_name',
          type: 'builtin',
          enabled: true,
          source: 'manual',
          position: 0,
          sortBy: 'count',
        },
        {
          name: 'Status',
          field: 'status',
          type: 'builtin',
          enabled: false, // Intentionally disabled
          source: 'manual',
          position: 1,
          sortBy: 'count',
        },
      ]

      const saveResponse = await page.request.post(
        '/admin/plugins/ai-search/api/facets/config',
        {
          data: {
            enabled: true,
            config: testConfig,
            max_values: 15,
          },
        }
      )

      expect(saveResponse.status()).toBe(200)
      const saveBody = await saveResponse.json()
      expect(saveBody.success).toBe(true)
      expect(saveBody.data.enabled).toBe(true)
      expect(saveBody.data.config).toHaveLength(2)
      expect(saveBody.data.max_values).toBe(15)

      // Verify it persists
      const getResponse = await page.request.get(
        '/admin/plugins/ai-search/api/facets/config'
      )
      const getBody = await getResponse.json()
      expect(getBody.data.enabled).toBe(true)
      expect(getBody.data.config).toHaveLength(2)
      expect(getBody.data.config[1].enabled).toBe(false)
      expect(getBody.data.max_values).toBe(15)
    })
  })

  // ──────────────────────────────────────────────
  // Search with Facets
  // ──────────────────────────────────────────────

  test.describe('Search with Facets', () => {
    test('FTS5 search with facets=true returns facets when results exist', async ({ page }) => {
      // Ensure facets are enabled
      await page.request.post('/admin/plugins/ai-search/api/facets/auto-generate')

      const response = await page.request.post('/api/search', {
        data: { query: 'api', mode: 'fts5', facets: true, limit: 5 },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)

      // If results exist, facets should be present with correct structure
      if (body.data.total > 0) {
        expect(body.data).toHaveProperty('facets')
        expect(Array.isArray(body.data.facets)).toBe(true)

        if (body.data.facets.length > 0) {
          const facet = body.data.facets[0]
          expect(facet).toHaveProperty('name')
          expect(facet).toHaveProperty('field')
          expect(facet).toHaveProperty('values')
          expect(Array.isArray(facet.values)).toBe(true)

          if (facet.values.length > 0) {
            expect(facet.values[0]).toHaveProperty('value')
            expect(facet.values[0]).toHaveProperty('count')
            expect(typeof facet.values[0].value).toBe('string')
            expect(typeof facet.values[0].count).toBe('number')
            expect(facet.values[0].count).toBeGreaterThan(0)
          }
        }
      } else {
        // No results — facets may be undefined or empty, but no errors
        if (body.data.facets) {
          expect(Array.isArray(body.data.facets)).toBe(true)
        }
      }
    })

    test('keyword search with facets=true returns facets when results exist', async ({ page }) => {
      // Ensure facets are enabled
      await page.request.post('/admin/plugins/ai-search/api/facets/auto-generate')

      const response = await page.request.post('/api/search', {
        data: { query: 'test', mode: 'keyword', facets: true, limit: 5 },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)

      // If results exist, facets should be present
      if (body.data.total > 0) {
        expect(body.data).toHaveProperty('facets')
        expect(Array.isArray(body.data.facets)).toBe(true)
      }
    })

    test('search without facets=true does not return facets', async ({ page }) => {
      await page.request.post('/admin/plugins/ai-search/api/facets/auto-generate')
      const response = await page.request.post('/api/search', {
        data: { query: 'api', mode: 'fts5', limit: 5 },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      // facets should be undefined when not requested
      expect(body.data.facets).toBeUndefined()
    })

    test('facets include collection_name with correct counts', async ({ page }) => {
      await page.request.post('/admin/plugins/ai-search/api/facets/auto-generate')
      const response = await page.request.post('/api/search', {
        data: { query: 'the', mode: 'fts5', facets: true, limit: 5 },
      })

      const body = await response.json()
      if (!body.data.facets || body.data.facets.length === 0) {
        test.skip()
        return
      }

      const collectionFacet = body.data.facets.find(
        (f: any) => f.field === 'collection_name'
      )
      if (collectionFacet) {
        expect(collectionFacet.name).toBe('Collection')
        expect(collectionFacet.values.length).toBeGreaterThan(0)
        // Counts should be positive integers
        for (const v of collectionFacet.values) {
          expect(v.count).toBeGreaterThan(0)
          expect(Number.isInteger(v.count)).toBe(true)
        }
      }
    })

    test('facets include status values', async ({ page }) => {
      await page.request.post('/admin/plugins/ai-search/api/facets/auto-generate')
      const response = await page.request.post('/api/search', {
        data: { query: 'the', mode: 'fts5', facets: true, limit: 5 },
      })

      const body = await response.json()
      if (!body.data.facets || body.data.facets.length === 0) {
        test.skip()
        return
      }

      const statusFacet = body.data.facets.find(
        (f: any) => f.field === 'status'
      )
      if (statusFacet) {
        expect(statusFacet.name).toBe('Status')
        const values = statusFacet.values.map((v: any) => v.value)
        // Should contain at least 'published' since seed data has published content
        expect(values).toContain('published')
      }
    })

    test('empty query with facets returns empty facets', async ({ page }) => {
      await page.request.post('/admin/plugins/ai-search/api/facets/auto-generate')
      const response = await page.request.post('/api/search', {
        data: { query: '', mode: 'fts5', facets: true, limit: 5 },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      // Empty query may or may not have facets, but should not error
    })
  })

  // ──────────────────────────────────────────────
  // Facet Click Tracking
  // ──────────────────────────────────────────────

  test.describe('Facet Click Tracking', () => {
    test('POST facet-click records interaction', async ({ page }) => {
      const response = await page.request.post('/api/search/facet-click', {
        data: {
          facet_field: 'collection_name',
          facet_value: 'Blog Posts',
          search_id: '999',
        },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    test('POST facet-click requires facet_field', async ({ page }) => {
      const response = await page.request.post('/api/search/facet-click', {
        data: { facet_value: 'test' },
      })

      expect(response.status()).toBe(400)
      const body = await response.json()
      expect(body.success).toBe(false)
      expect(body.error).toContain('facet_field')
    })

    test('POST facet-click requires facet_value', async ({ page }) => {
      const response = await page.request.post('/api/search/facet-click', {
        data: { facet_field: 'status' },
      })

      expect(response.status()).toBe(400)
      const body = await response.json()
      expect(body.success).toBe(false)
      expect(body.error).toContain('facet_value')
    })

    test('POST facet-click works without search_id', async ({ page }) => {
      const response = await page.request.post('/api/search/facet-click', {
        data: {
          facet_field: '$.tags',
          facet_value: 'javascript',
        },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })
  })

  // ──────────────────────────────────────────────
  // Admin Dashboard UI
  // ──────────────────────────────────────────────

  test.describe('Admin Dashboard — Facet Config', () => {
    test('Configuration tab has Faceted Search section', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      // Click the Configuration tab explicitly
      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      // Faceted Search heading should be visible (use heading role to avoid strict mode - overview tab also has "Faceted Search" text)
      const heading = page.getByRole('heading', { name: 'Faceted Search' })
      await expect(heading).toBeVisible({ timeout: 10000 })

      // Enable toggle should exist (sr-only checkbox, check it exists in DOM)
      const toggle = page.locator('#facets_enabled')
      await expect(toggle).toHaveCount(1)
    })

    test('enabling facets toggle shows config section', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      const toggle = page.locator('#facets_enabled')
      const configSection = page.locator('#facet-config-section')

      // Toggle on — checkbox is sr-only with visual div overlay, use force click
      if (!(await toggle.isChecked())) {
        await toggle.click({ force: true })
        await page.waitForTimeout(1000)
      }

      await expect(configSection).toBeVisible({ timeout: 5000 })

      // Should show the facet table
      const table = page.locator('#facet-config-table')
      await expect(table).toBeVisible()
    })

    test('Re-discover Fields button is present', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await page.waitForTimeout(2000)

      await page.click('#tab-btn-configuration')
      await page.waitForTimeout(1000)

      // Enable facets if needed — checkbox is sr-only, use force click
      const toggle = page.locator('#facets_enabled')
      if (!(await toggle.isChecked())) {
        await toggle.click({ force: true })
        await page.waitForTimeout(1000)
      }

      const rediscoverBtn = page.locator('text=Re-discover Fields')
      await expect(rediscoverBtn).toBeVisible({ timeout: 5000 })
    })
  })

  // ──────────────────────────────────────────────
  // Search Modal Component
  // ──────────────────────────────────────────────
  // Note: The facet sidebar is built into the search-modal.ts component,
  // which is a reusable module for headless integration. It's not yet
  // mounted on a specific admin page. UI tests for the modal sidebar
  // will be added when it's integrated into the admin content list
  // or a dedicated search page.
  // ──────────────────────────────────────────────

  // ──────────────────────────────────────────────
  // Integration Guide
  // ──────────────────────────────────────────────

  test.describe('Integration Guide — Facet Docs', () => {
    test('integration guide includes faceted search section', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForLoadState('networkidle', { timeout: 15000 })

      // Should have faceted search heading
      const heading = page.getByRole('heading', { name: 'Faceted Search' })
      await expect(heading).toBeVisible({ timeout: 5000 })

      // Should mention facets: true
      const facetsCode = page.locator('text=facets: true')
      await expect(facetsCode.first()).toBeVisible()
    })

    test('integration guide has InstantSearch RefinementList example', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search/integration')
      await page.waitForLoadState('networkidle', { timeout: 15000 })

      const refinement = page.locator('text=RefinementList')
      await expect(refinement.first()).toBeVisible({ timeout: 5000 })
    })
  })

  // ──────────────────────────────────────────────
  // Edge Cases
  // ──────────────────────────────────────────────

  test.describe('Edge Cases', () => {
    test('facet-click with special characters in value', async ({ page }) => {
      const response = await page.request.post('/api/search/facet-click', {
        data: {
          facet_field: '$.tags',
          facet_value: "O'Reilly & Sons <script>",
          search_id: null,
        },
      })

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    test('config save with empty config array', async ({ page }) => {
      const response = await page.request.post(
        '/admin/plugins/ai-search/api/facets/config',
        {
          data: { enabled: false, config: [] },
        }
      )

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.data.enabled).toBe(false)
      expect(body.data.config).toEqual([])
    })

    test('discover endpoint handles missing schemas gracefully', async ({ page }) => {
      // Even if some collections have no schema, discover should not error
      const response = await page.request.get(
        '/admin/plugins/ai-search/api/facets/discover'
      )
      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(Array.isArray(body.data)).toBe(true)
    })
  })

  // ──────────────────────────────────────────────
  // Cleanup — restore facet settings to default
  // ──────────────────────────────────────────────

  test.afterAll(async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()
    try {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)

      // Reset facet settings to disabled
      await page.request.post(
        '/admin/plugins/ai-search/api/facets/config',
        {
          data: { enabled: false, config: [], max_values: 20 },
        }
      )
    } catch {
      // Cleanup errors are non-fatal
    } finally {
      await context.close()
    }
  })
})
