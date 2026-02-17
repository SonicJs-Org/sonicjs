import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

const AGENT_API = '/admin/plugins/ai-search/api/agent'

test.describe('AI Search Quality Agent', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // =============================================
  // API: Status & Runs
  // =============================================

  test.describe('Agent Status API', () => {
    test('GET /api/agent/status returns stats and latest_run', async ({ page }) => {
      const response = await page.request.get(`${AGENT_API}/status`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json).toHaveProperty('success', true)
      expect(json).toHaveProperty('data')
      expect(json.data).toHaveProperty('stats')
      expect(json.data.stats).toHaveProperty('total')
      expect(json.data.stats).toHaveProperty('pending')
      expect(json.data.stats).toHaveProperty('applied')
      expect(json.data.stats).toHaveProperty('dismissed')
      expect(json.data.stats).toHaveProperty('byCategory')
      // latest_run can be null if no runs yet
      expect(json.data).toHaveProperty('latest_run')
    })

    test('GET /api/agent/runs returns array of runs', async ({ page }) => {
      const response = await page.request.get(`${AGENT_API}/runs`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json).toHaveProperty('success', true)
      expect(json).toHaveProperty('data')
      expect(Array.isArray(json.data)).toBe(true)
    })

    test('GET /api/agent/runs respects limit param', async ({ page }) => {
      const response = await page.request.get(`${AGENT_API}/runs?limit=1`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.length).toBeLessThanOrEqual(1)
    })
  })

  // =============================================
  // API: Run Analysis
  // =============================================

  test.describe('Run Analysis', () => {
    test('POST /api/agent/run triggers analysis and returns success', async ({ page }) => {
      const response = await page.request.post(`${AGENT_API}/run`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json).toHaveProperty('success', true)
      expect(json).toHaveProperty('message', 'Analysis started')
    })

    test('analysis run completes and status shows completed', async ({ page }) => {
      // Trigger a run
      const runResponse = await page.request.post(`${AGENT_API}/run`)
      expect(runResponse.status()).toBe(200)

      // Poll until completed (max 10s)
      let status = 'running'
      let attempts = 0
      while (status === 'running' && attempts < 20) {
        await page.waitForTimeout(500)
        const statusResponse = await page.request.get(`${AGENT_API}/status`)
        const statusJson = await statusResponse.json()
        if (statusJson.data?.latest_run) {
          status = statusJson.data.latest_run.status
        }
        attempts++
      }

      expect(status).toBe('completed')
    })

    test('completed run has recommendations_count and duration_ms', async ({ page }) => {
      // Trigger and wait for completion
      await page.request.post(`${AGENT_API}/run`)

      let latestRun: any = null
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const statusResponse = await page.request.get(`${AGENT_API}/status`)
        const statusJson = await statusResponse.json()
        if (statusJson.data?.latest_run?.status === 'completed') {
          latestRun = statusJson.data.latest_run
          break
        }
        attempts++
      }

      expect(latestRun).not.toBeNull()
      expect(latestRun.status).toBe('completed')
      expect(typeof latestRun.recommendations_count).toBe('number')
      expect(typeof latestRun.duration_ms).toBe('number')
      expect(latestRun.duration_ms).toBeGreaterThanOrEqual(0)
    })
  })

  // =============================================
  // API: Recommendations CRUD
  // =============================================

  test.describe('Recommendations API', () => {
    test('GET /api/agent/recommendations returns array', async ({ page }) => {
      const response = await page.request.get(`${AGENT_API}/recommendations`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json).toHaveProperty('success', true)
      expect(json).toHaveProperty('data')
      expect(Array.isArray(json.data)).toBe(true)
    })

    test('recommendations support status filter', async ({ page }) => {
      const response = await page.request.get(`${AGENT_API}/recommendations?status=pending`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json.success).toBe(true)
      // All returned recs should have pending status
      for (const rec of json.data) {
        expect(rec.status).toBe('pending')
      }
    })

    test('recommendations support category filter', async ({ page }) => {
      const response = await page.request.get(`${AGENT_API}/recommendations?category=low_ctr`)
      expect(response.status()).toBe(200)

      const json = await response.json()
      expect(json.success).toBe(true)
      for (const rec of json.data) {
        expect(rec.category).toBe('low_ctr')
      }
    })

    test('recommendation objects have required fields', async ({ page }) => {
      // Trigger a run first to ensure recommendations exist
      await page.request.post(`${AGENT_API}/run`)

      // Wait for run to complete
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const statusResponse = await page.request.get(`${AGENT_API}/status`)
        const statusJson = await statusResponse.json()
        if (statusJson.data?.latest_run?.status === 'completed') break
        attempts++
      }

      const response = await page.request.get(`${AGENT_API}/recommendations`)
      const json = await response.json()

      if (json.data.length > 0) {
        const rec = json.data[0]
        expect(rec).toHaveProperty('id')
        expect(rec).toHaveProperty('category')
        expect(rec).toHaveProperty('title')
        expect(rec).toHaveProperty('description')
        expect(rec).toHaveProperty('supporting_data')
        expect(rec).toHaveProperty('status')
        expect(rec).toHaveProperty('fingerprint')
        expect(rec).toHaveProperty('run_id')
        expect(rec).toHaveProperty('created_at')
        expect(rec).toHaveProperty('updated_at')

        // Category must be one of the 5 valid categories
        expect(['synonym', 'query_rule', 'low_ctr', 'unused_facet', 'content_gap']).toContain(rec.category)
        // Status must be one of the 3 valid statuses
        expect(['pending', 'applied', 'dismissed']).toContain(rec.status)
      }
    })
  })

  // =============================================
  // API: Dismiss
  // =============================================

  test.describe('Dismiss API', () => {
    test('POST /recommendations/:id/dismiss returns success for valid id', async ({ page }) => {
      // Run analysis to get recommendations
      await page.request.post(`${AGENT_API}/run`)
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status === 'completed') break
        attempts++
      }

      // Get a pending recommendation
      const listResponse = await page.request.get(`${AGENT_API}/recommendations?status=pending`)
      const listJson = await listResponse.json()

      if (listJson.data.length > 0) {
        const recId = listJson.data[0].id

        // Dismiss it
        const dismissResponse = await page.request.post(`${AGENT_API}/recommendations/${recId}/dismiss`)
        expect(dismissResponse.status()).toBe(200)
        const dismissJson = await dismissResponse.json()
        expect(dismissJson.success).toBe(true)

        // Verify it's now dismissed
        const verifyResponse = await page.request.get(`${AGENT_API}/recommendations?status=dismissed`)
        const verifyJson = await verifyResponse.json()
        const dismissed = verifyJson.data.find((r: any) => r.id === recId)
        expect(dismissed).toBeDefined()
        expect(dismissed.status).toBe('dismissed')
      }
    })

    test('POST /recommendations/:id/dismiss returns 404 for invalid id', async ({ page }) => {
      const response = await page.request.post(`${AGENT_API}/recommendations/nonexistent-id/dismiss`)
      expect(response.status()).toBe(404)
    })

    test('POST /recommendations/dismiss-all dismisses all pending', async ({ page }) => {
      // Run analysis to generate pending recs
      await page.request.post(`${AGENT_API}/run`)
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status === 'completed') break
        attempts++
      }

      // Get count of pending before
      const beforeResponse = await page.request.get(`${AGENT_API}/status`)
      const beforeJson = await beforeResponse.json()
      const pendingBefore = beforeJson.data.stats.pending

      if (pendingBefore > 0) {
        // Dismiss all
        const dismissResponse = await page.request.post(`${AGENT_API}/recommendations/dismiss-all`)
        expect(dismissResponse.status()).toBe(200)
        const dismissJson = await dismissResponse.json()
        expect(dismissJson.success).toBe(true)
        expect(dismissJson.data).toHaveProperty('dismissed')
        expect(dismissJson.data.dismissed).toBeGreaterThanOrEqual(1)

        // Verify pending count is now 0
        const afterResponse = await page.request.get(`${AGENT_API}/status`)
        const afterJson = await afterResponse.json()
        expect(afterJson.data.stats.pending).toBe(0)
      }
    })
  })

  // =============================================
  // API: Apply
  // =============================================

  test.describe('Apply API', () => {
    test('POST /recommendations/:id/apply marks informational recs as applied', async ({ page }) => {
      // Run analysis
      await page.request.post(`${AGENT_API}/run`)
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status === 'completed') break
        attempts++
      }

      // Get a pending informational rec (low_ctr, unused_facet, or content_gap)
      const listResponse = await page.request.get(`${AGENT_API}/recommendations?status=pending`)
      const listJson = await listResponse.json()
      const informationalRec = listJson.data.find(
        (r: any) => ['low_ctr', 'unused_facet', 'content_gap'].includes(r.category)
      )

      if (informationalRec) {
        const applyResponse = await page.request.post(`${AGENT_API}/recommendations/${informationalRec.id}/apply`)
        expect(applyResponse.status()).toBe(200)
        const applyJson = await applyResponse.json()
        expect(applyJson.success).toBe(true)
        expect(applyJson.message).toBe('Recommendation acknowledged')
      }
    })

    test('POST /recommendations/:id/apply returns 400 for non-pending rec', async ({ page }) => {
      // Run analysis
      await page.request.post(`${AGENT_API}/run`)
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status === 'completed') break
        attempts++
      }

      // Get a pending rec and dismiss it first
      const listResponse = await page.request.get(`${AGENT_API}/recommendations?status=pending`)
      const listJson = await listResponse.json()

      if (listJson.data.length > 0) {
        const recId = listJson.data[0].id
        // Dismiss it
        await page.request.post(`${AGENT_API}/recommendations/${recId}/dismiss`)

        // Now try to apply the dismissed rec — should fail
        const applyResponse = await page.request.post(`${AGENT_API}/recommendations/${recId}/apply`)
        expect(applyResponse.status()).toBe(400)
        const applyJson = await applyResponse.json()
        expect(applyJson.success).toBe(false)
      }
    })

    test('POST /recommendations/:id/apply returns error for invalid id', async ({ page }) => {
      const response = await page.request.post(`${AGENT_API}/recommendations/nonexistent-id/apply`)
      expect(response.status()).toBe(400)
      const json = await response.json()
      expect(json.success).toBe(false)
    })
  })

  // =============================================
  // Deduplication
  // =============================================

  test.describe('Deduplication', () => {
    test('running analysis twice does not duplicate pending recs', async ({ page }) => {
      // First run
      await page.request.post(`${AGENT_API}/run`)
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status === 'completed') break
        attempts++
      }

      // Count pending after first run
      const firstResponse = await page.request.get(`${AGENT_API}/status`)
      const firstJson = await firstResponse.json()
      const pendingAfterFirst = firstJson.data.stats.pending

      // Second run
      await page.request.post(`${AGENT_API}/run`)
      attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status !== 'running') break
        attempts++
      }

      // Count pending after second run — should be same (dedup)
      const secondResponse = await page.request.get(`${AGENT_API}/status`)
      const secondJson = await secondResponse.json()
      const pendingAfterSecond = secondJson.data.stats.pending

      expect(pendingAfterSecond).toBe(pendingAfterFirst)
    })

    test('dismissed recs can resurface on next run', async ({ page }) => {
      // Run analysis
      await page.request.post(`${AGENT_API}/run`)
      let attempts = 0
      while (attempts < 20) {
        await page.waitForTimeout(500)
        const s = await page.request.get(`${AGENT_API}/status`)
        const sj = await s.json()
        if (sj.data?.latest_run?.status === 'completed') break
        attempts++
      }

      // Get pending count
      const beforeStatus = await page.request.get(`${AGENT_API}/status`)
      const beforeJson = await beforeStatus.json()
      const pendingBefore = beforeJson.data.stats.pending

      if (pendingBefore > 0) {
        // Dismiss all
        await page.request.post(`${AGENT_API}/recommendations/dismiss-all`)

        // Verify pending is 0
        const midStatus = await page.request.get(`${AGENT_API}/status`)
        const midJson = await midStatus.json()
        expect(midJson.data.stats.pending).toBe(0)

        // Run again — dismissed recs should resurface
        await page.request.post(`${AGENT_API}/run`)
        attempts = 0
        while (attempts < 20) {
          await page.waitForTimeout(500)
          const s = await page.request.get(`${AGENT_API}/status`)
          const sj = await s.json()
          if (sj.data?.latest_run?.status !== 'running') break
          attempts++
        }

        const afterStatus = await page.request.get(`${AGENT_API}/status`)
        const afterJson = await afterStatus.json()
        // Dismissed recs should have resurfaced as pending
        expect(afterJson.data.stats.pending).toBe(pendingBefore)
      }
    })
  })

  // =============================================
  // Admin UI: Agent Tab
  // =============================================

  test.describe('Agent Tab UI', () => {
    test('admin search page has Agent tab button', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForLoadState('networkidle')

      const agentTabBtn = page.locator('#tab-btn-agent')
      await expect(agentTabBtn).toBeVisible()
      await expect(agentTabBtn).toHaveText('Agent')
    })

    test('clicking Agent tab shows agent panel', async ({ page }) => {
      await page.goto('/admin/search')
      await page.waitForLoadState('networkidle')

      // Click Agent tab
      await page.click('#tab-btn-agent')

      // Agent tab panel should be visible
      const agentPanel = page.locator('#tab-agent')
      await expect(agentPanel).toBeVisible()

      // Overview panel should be hidden
      const overviewPanel = page.locator('#tab-overview')
      await expect(overviewPanel).toBeHidden()
    })

    test('Agent tab contains Run Analysis button', async ({ page }) => {
      await page.goto('/admin/search#agent')
      await page.waitForLoadState('networkidle')

      // Switch to agent tab
      await page.click('#tab-btn-agent')

      // Should have Run Analysis button
      const runBtn = page.locator('button').filter({ hasText: 'Run Analysis' })
      await expect(runBtn).toBeVisible()
    })

    test('Agent tab loads via hash navigation', async ({ page }) => {
      await page.goto('/admin/search#agent')
      await page.waitForLoadState('networkidle')

      // Agent tab should be active
      const agentPanel = page.locator('#tab-agent')
      await expect(agentPanel).toBeVisible()

      // Tab button should have active styling
      const agentTabBtn = page.locator('#tab-btn-agent')
      await expect(agentTabBtn).toHaveClass(/text-indigo-600/)
    })

    test('Agent tab has stat cards section', async ({ page }) => {
      await page.goto('/admin/search#agent')
      await page.waitForLoadState('networkidle')
      await page.click('#tab-btn-agent')

      // Wait for lazy-loaded data
      await page.waitForTimeout(2000)

      // Should contain stat-related text
      const agentPanel = page.locator('#tab-agent')
      await expect(agentPanel).toContainText('Pending')
    })

    test('Agent tab has filter controls', async ({ page }) => {
      await page.goto('/admin/search#agent')
      await page.waitForLoadState('networkidle')
      await page.click('#tab-btn-agent')

      // Should have category and status filter dropdowns
      const agentPanel = page.locator('#tab-agent')
      const selects = agentPanel.locator('select')
      const selectCount = await selects.count()
      expect(selectCount).toBeGreaterThanOrEqual(2)
    })

    test('Agent tab has run history section', async ({ page }) => {
      await page.goto('/admin/search#agent')
      await page.waitForLoadState('networkidle')
      await page.click('#tab-btn-agent')

      const agentPanel = page.locator('#tab-agent')
      await expect(agentPanel).toContainText('Run History')
    })
  })
})
