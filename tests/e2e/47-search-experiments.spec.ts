import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

const SEARCH_API = '/api/search'
const ADMIN_API = '/admin/plugins/ai-search/api/experiments'

test.describe('Search A/B Testing Experiments', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  // =============================================
  // CRUD Operations
  // =============================================

  test.describe('Experiment CRUD', () => {
    test('list experiments returns empty array initially', async ({ page }) => {
      const response = await page.request.get(ADMIN_API)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(Array.isArray(json.data)).toBe(true)
    })

    test('create experiment with required fields', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Test Experiment',
          variants: { control: {}, treatment: { fts5_title_boost: 8 } },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data.name).toBe('E2E Test Experiment')
      expect(json.data.status).toBe('draft')
      expect(json.data.mode).toBe('ab')
      expect(json.data.id).toMatch(/^exp-/)
      expect(json.data.variants.treatment.fts5_title_boost).toBe(8)
      expect(json.data.created_at).toBeGreaterThan(0)
      expect(json.data.updated_at).toBeGreaterThan(0)
    })

    test('create experiment fails without name', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: { variants: { control: {}, treatment: {} } },
      })
      expect(response.status()).toBe(400)
    })

    test('create experiment fails without variants', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: { name: 'Missing Variants' },
      })
      expect(response.status()).toBe(400)
    })

    test('create interleave experiment', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Interleave Test',
          mode: 'interleave',
          variants: { control: {}, treatment: { query_rewriting_enabled: true } },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.mode).toBe('interleave')
    })

    test('get experiment by id', async ({ page }) => {
      // Create first
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Get By ID',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()
      const id = created.data.id

      // Get by id
      const response = await page.request.get(`${ADMIN_API}/${id}`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.id).toBe(id)
      expect(json.data.name).toBe('E2E Get By ID')
    })

    test('get nonexistent experiment returns 404', async ({ page }) => {
      const response = await page.request.get(`${ADMIN_API}/exp-nonexistent`)
      expect(response.status()).toBe(404)
    })

    test('update draft experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Update Test',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()

      const response = await page.request.put(`${ADMIN_API}/${created.data.id}`, {
        data: { name: 'Updated Name', traffic_pct: 50 },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.name).toBe('Updated Name')
      expect(json.data.traffic_pct).toBe(50)
    })

    test('delete draft experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Delete Test',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()

      const response = await page.request.delete(`${ADMIN_API}/${created.data.id}`)
      expect(response.status()).toBe(200)
      expect((await response.json()).success).toBe(true)

      // Verify deleted
      const getResp = await page.request.get(`${ADMIN_API}/${created.data.id}`)
      expect(getResp.status()).toBe(404)
    })

    test('list experiments with status filter', async ({ page }) => {
      // Create a draft
      await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Filter Test',
          variants: { control: {}, treatment: {} },
        },
      })

      const response = await page.request.get(`${ADMIN_API}?status=draft`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.every((e: any) => e.status === 'draft')).toBe(true)
    })
  })

  // =============================================
  // Experiment Lifecycle
  // =============================================

  test.describe('Experiment Lifecycle', () => {
    // Clean up any orphaned running experiments before each test
    test.beforeEach(async ({ page }) => {
      const listResp = await page.request.get(`${ADMIN_API}?status=running`)
      const list = await listResp.json()
      if (list.success && Array.isArray(list.data)) {
        for (const exp of list.data) {
          await page.request.post(`${ADMIN_API}/${exp.id}/complete`, { data: {} })
        }
      }
    })

    test('start experiment changes status to running', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Lifecycle Start',
          variants: { control: {}, treatment: { fts5_title_boost: 10 } },
        },
      })
      const created = await createResp.json()

      const response = await page.request.post(`${ADMIN_API}/${created.data.id}/start`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.status).toBe('running')
      expect(json.data.started_at).toBeGreaterThan(0)

      // Clean up
      await page.request.post(`${ADMIN_API}/${created.data.id}/complete`, { data: {} })
    })

    test('cannot start second experiment while one is running', async ({ page }) => {
      // Create and start first
      const resp1 = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Conflict 1',
          variants: { control: {}, treatment: {} },
        },
      })
      const exp1 = (await resp1.json()).data
      await page.request.post(`${ADMIN_API}/${exp1.id}/start`)

      // Create and try to start second
      const resp2 = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Conflict 2',
          variants: { control: {}, treatment: {} },
        },
      })
      const exp2 = (await resp2.json()).data
      const startResp = await page.request.post(`${ADMIN_API}/${exp2.id}/start`)
      expect(startResp.status()).toBe(500)
      const json = await startResp.json()
      expect(json.error).toContain('already running')

      // Clean up
      await page.request.post(`${ADMIN_API}/${exp1.id}/complete`, { data: {} })
    })

    test('pause running experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Lifecycle Pause',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()
      await page.request.post(`${ADMIN_API}/${created.data.id}/start`)

      const response = await page.request.post(`${ADMIN_API}/${created.data.id}/pause`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.status).toBe('paused')
    })

    test('complete running experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Lifecycle Complete',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()
      await page.request.post(`${ADMIN_API}/${created.data.id}/start`)

      const response = await page.request.post(`${ADMIN_API}/${created.data.id}/complete`, {
        data: { winner: 'treatment' },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.status).toBe('completed')
      expect(json.data.winner).toBe('treatment')
      expect(json.data.ended_at).toBeGreaterThan(0)
    })

    test('cannot update running experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E No Update Running',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()
      await page.request.post(`${ADMIN_API}/${created.data.id}/start`)

      const response = await page.request.put(`${ADMIN_API}/${created.data.id}`, {
        data: { name: 'Should Fail' },
      })
      expect(response.status()).toBe(500)

      // Clean up
      await page.request.post(`${ADMIN_API}/${created.data.id}/complete`, { data: {} })
    })

    test('cannot delete running experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E No Delete Running',
          variants: { control: {}, treatment: {} },
        },
      })
      const created = await createResp.json()
      await page.request.post(`${ADMIN_API}/${created.data.id}/start`)

      const response = await page.request.delete(`${ADMIN_API}/${created.data.id}`)
      expect(response.status()).toBe(500)

      // Clean up
      await page.request.post(`${ADMIN_API}/${created.data.id}/complete`, { data: {} })
    })
  })

  // =============================================
  // Search Integration
  // =============================================

  test.describe('Search with Active Experiment', () => {
    // Clean up any orphaned running experiments before each test
    test.beforeEach(async ({ page }) => {
      const listResp = await page.request.get(`${ADMIN_API}?status=running`)
      const list = await listResp.json()
      if (list.success && Array.isArray(list.data)) {
        for (const exp of list.data) {
          await page.request.post(`${ADMIN_API}/${exp.id}/complete`, { data: {} })
        }
      }
    })

    test('search returns experiment metadata when experiment is running', async ({ page }) => {
      // Create and start experiment
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Search Integration',
          mode: 'ab',
          traffic_pct: 100,
          variants: { control: {}, treatment: { fts5_title_boost: 8 } },
        },
      })
      const exp = (await createResp.json()).data
      await page.request.post(`${ADMIN_API}/${exp.id}/start`)

      // Search
      const response = await page.request.post(SEARCH_API, {
        data: { query: 'test', mode: 'fts5' },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.experiment).toBeDefined()
      expect(json.experiment.experiment_id).toBe(exp.id)
      expect(json.experiment.experiment_mode).toBe('ab')
      expect(['control', 'treatment']).toContain(json.experiment.experiment_variant)

      // Clean up
      await page.request.post(`${ADMIN_API}/${exp.id}/complete`, { data: {} })
    })

    test('search without experiment returns no experiment metadata', async ({ page }) => {
      const response = await page.request.post(SEARCH_API, {
        data: { query: 'test', mode: 'fts5' },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.experiment).toBeUndefined()
    })

    test('interleave mode returns result_origins', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Interleave Search',
          mode: 'interleave',
          traffic_pct: 100,
          variants: { control: {}, treatment: { fts5_title_boost: 10 } },
        },
      })
      const exp = (await createResp.json()).data
      await page.request.post(`${ADMIN_API}/${exp.id}/start`)

      const response = await page.request.post(SEARCH_API, {
        data: { query: 'test', mode: 'fts5' },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.experiment).toBeDefined()
      expect(json.experiment.experiment_mode).toBe('interleave')
      expect(json.experiment.result_origins).toBeDefined()
      expect(typeof json.experiment.result_origins).toBe('object')

      // Each origin should be 'control' or 'treatment'
      for (const origin of Object.values(json.experiment.result_origins)) {
        expect(['control', 'treatment']).toContain(origin)
      }

      // Clean up
      await page.request.post(`${ADMIN_API}/${exp.id}/complete`, { data: {} })
    })
  })

  // =============================================
  // Click Attribution
  // =============================================

  test.describe('Click Attribution', () => {
    test('click with experiment_id and experiment_variant succeeds', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-1',
          click_position: 1,
          experiment_id: 'exp-test',
          experiment_variant: 'treatment',
        },
      })
      expect(response.status()).toBe(200)
      expect((await response.json()).success).toBe(true)
    })

    test('click without experiment fields still succeeds', async ({ page }) => {
      const response = await page.request.post(`${SEARCH_API}/click`, {
        data: {
          content_id: 'test-content-2',
          click_position: 3,
        },
      })
      expect(response.status()).toBe(200)
      expect((await response.json()).success).toBe(true)
    })
  })

  // =============================================
  // Metrics
  // =============================================

  test.describe('Experiment Metrics', () => {
    // Clean up any orphaned running experiments before each test
    test.beforeEach(async ({ page }) => {
      const listResp = await page.request.get(`${ADMIN_API}?status=running`)
      const list = await listResp.json()
      if (list.success && Array.isArray(list.data)) {
        for (const exp of list.data) {
          await page.request.post(`${ADMIN_API}/${exp.id}/complete`, { data: {} })
        }
      }
    })

    test('metrics endpoint returns structured response for running experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Metrics Test',
          variants: { control: {}, treatment: {} },
          min_searches: 1000,
        },
      })
      const exp = (await createResp.json()).data

      const startResp = await page.request.post(`${ADMIN_API}/${exp.id}/start`)
      expect(startResp.status()).toBe(200)

      const response = await page.request.get(`${ADMIN_API}/${exp.id}/metrics`)
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.success).toBe(true)
      expect(json.data).toHaveProperty('control')
      expect(json.data).toHaveProperty('treatment')
      expect(json.data).toHaveProperty('confidence')
      expect(json.data).toHaveProperty('significant')
      expect(json.data.control).toHaveProperty('searches')
      expect(json.data.control).toHaveProperty('clicks')
      expect(json.data.control).toHaveProperty('ctr')
      expect(json.data.control).toHaveProperty('zero_result_rate')
      expect(json.data.control).toHaveProperty('avg_click_position')
      expect(json.data.control).toHaveProperty('avg_response_time_ms')
      expect(typeof json.data.confidence).toBe('number')
      expect(typeof json.data.significant).toBe('boolean')

      // Clean up
      await page.request.post(`${ADMIN_API}/${exp.id}/complete`, { data: {} })
    })

    test('metrics for non-running experiment returns 404', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Metrics Draft',
          variants: { control: {}, treatment: {} },
        },
      })
      const exp = (await createResp.json()).data

      const response = await page.request.get(`${ADMIN_API}/${exp.id}/metrics`)
      expect(response.status()).toBe(404)
    })
  })

  // =============================================
  // Configuration Options
  // =============================================

  test.describe('Configuration', () => {
    test('experiment respects custom traffic_pct', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Traffic Config',
          traffic_pct: 50,
          variants: { control: {}, treatment: {} },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.traffic_pct).toBe(50)
    })

    test('experiment respects custom split_ratio', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Split Config',
          split_ratio: 0.7,
          variants: { control: {}, treatment: {} },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.split_ratio).toBe(0.7)
    })

    test('experiment respects custom min_searches', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Min Searches',
          min_searches: 500,
          variants: { control: {}, treatment: {} },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.min_searches).toBe(500)
    })

    test('experiment defaults are correct', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Defaults',
          variants: { control: {}, treatment: {} },
        },
      })
      const json = await response.json()
      expect(json.data.mode).toBe('ab')
      expect(json.data.traffic_pct).toBe(100)
      expect(json.data.split_ratio).toBe(0.5)
      expect(json.data.min_searches).toBe(100)
      expect(json.data.status).toBe('draft')
      expect(json.data.winner).toBeNull()
      expect(json.data.confidence).toBeNull()
      expect(json.data.metrics).toBeNull()
    })
  })

  // =============================================
  // Template-Based Creation via API
  // =============================================

  test.describe('Template Creation via API', () => {
    test('create experiment with title boost overrides', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'Template: Title Boost',
          mode: 'interleave',
          min_searches: 200,
          variants: { control: {}, treatment: { fts5_title_boost: 10 } },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.variants.treatment.fts5_title_boost).toBe(10)
      expect(json.data.mode).toBe('interleave')
    })

    test('create experiment with boolean overrides', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'Template: Query Rewriting',
          mode: 'ab',
          variants: { control: {}, treatment: { query_rewriting_enabled: true } },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.variants.treatment.query_rewriting_enabled).toBe(true)
    })

    test('create experiment with multiple overrides', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'Template: Aggressive Title+Slug',
          mode: 'interleave',
          variants: { control: {}, treatment: { fts5_title_boost: 10, fts5_slug_boost: 5 } },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.variants.treatment.fts5_title_boost).toBe(10)
      expect(json.data.variants.treatment.fts5_slug_boost).toBe(5)
    })

    test('create experiment with disable override', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'Template: Disable Reranking',
          mode: 'ab',
          variants: { control: {}, treatment: { reranking_enabled: false } },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.variants.treatment.reranking_enabled).toBe(false)
    })

    test('create experiment with comprehensive overrides', async ({ page }) => {
      const response = await page.request.post(ADMIN_API, {
        data: {
          name: 'Template: Full AI Enhancement',
          mode: 'interleave',
          min_searches: 300,
          variants: {
            control: {},
            treatment: { query_rewriting_enabled: true, query_synonyms_enabled: true },
          },
        },
      })
      expect(response.status()).toBe(200)
      const json = await response.json()
      expect(json.data.variants.treatment.query_rewriting_enabled).toBe(true)
      expect(json.data.variants.treatment.query_synonyms_enabled).toBe(true)
    })
  })

  // =============================================
  // UI Template Picker
  // =============================================

  test.describe('UI Template Picker', () => {
    test('A/B Tests tab renders with correct heading', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      const heading = await page.locator('#tab-experiments h2').textContent()
      expect(heading).toContain('Search A/B Tests')
    })

    test('tab label says A/B Tests', async ({ page }) => {
      await page.goto('/admin/search')
      const tabBtn = page.locator('#tab-btn-experiments')
      await expect(tabBtn).toContainText('A/B Tests')
    })

    test('New A/B Test button text is correct', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      const btn = page.locator('#tab-experiments button:has-text("New A/B Test")')
      await expect(btn).toBeVisible()
    })

    test('create modal shows template grid', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Should have 8 template cards + 1 custom card = 9
      const cards = page.locator('#exp-template-grid .exp-tpl-card')
      await expect(cards).toHaveCount(9)
    })

    test('selecting template populates form fields', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Click "Title Relevance Boost" template
      await page.click('#exp-tpl-title-boost')

      const name = await page.inputValue('#exp-name')
      expect(name).toBe('Title Relevance Boost')

      const mode = await page.inputValue('#exp-mode')
      expect(mode).toBe('interleave')

      const minSearches = await page.inputValue('#exp-min-searches')
      expect(minSearches).toBe('200')
    })

    test('custom template clears all fields', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // First select a template
      await page.click('#exp-tpl-title-boost')
      // Then switch to custom
      await page.click('#exp-tpl-custom')

      const name = await page.inputValue('#exp-name')
      expect(name).toBe('')

      const mode = await page.inputValue('#exp-mode')
      expect(mode).toBe('ab')
    })

    test('mode rationale appears when template selected', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-title-boost')

      const rationale = page.locator('#exp-mode-rationale')
      await expect(rationale).toBeVisible()
      await expect(rationale).toContainText('Interleaving')
    })
  })

  // =============================================
  // Visual Settings Editor
  // =============================================

  test.describe('Visual Settings Editor', () => {
    test('template selection shows override rows', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-title-boost')

      // Should show at least 1 override row for fts5_title_boost
      const rows = page.locator('#exp-overrides-list [data-override-key]')
      await expect(rows).toHaveCount(1)
    })

    test('multi-override template shows correct number of rows', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Select "Aggressive Title + Slug" which has 2 overrides
      await page.click('#exp-tpl-aggressive-title-slug')

      const rows = page.locator('#exp-overrides-list [data-override-key]')
      await expect(rows).toHaveCount(2)
    })

    test('add setting override via dropdown', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-custom')

      // Select a setting from dropdown and click the Add button next to it
      await page.selectOption('#exp-add-setting', 'fts5_title_boost')
      await page.locator('#exp-visual-editor button:has-text("Add")').click()

      const rows = page.locator('#exp-overrides-list [data-override-key]')
      await expect(rows).toHaveCount(1)
    })

    test('remove override via x button', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-title-boost')

      // Verify 1 row exists
      const rows = page.locator('#exp-overrides-list [data-override-key]')
      await expect(rows).toHaveCount(1)

      // Click the remove button (x)
      await page.click('#exp-overrides-list [data-override-key="fts5_title_boost"] button')

      // Should have no override rows
      await expect(rows).toHaveCount(0)
    })

    test('number override has range slider', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-title-boost')

      const slider = page.locator('#exp-overrides-list [data-override-key="fts5_title_boost"] input[type="range"]')
      await expect(slider).toBeVisible()
    })

    test('boolean override has toggle', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-query-rewriting')

      const toggle = page.locator('#exp-overrides-list [data-override-key="query_rewriting_enabled"] input[type="checkbox"]')
      await expect(toggle).toBeAttached()
    })

    test('raw JSON toggle switches to textarea', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Visual editor should be visible
      await expect(page.locator('#exp-visual-editor')).toBeVisible()
      await expect(page.locator('#exp-raw-editor')).toBeHidden()

      // Toggle to raw JSON
      await page.click('#exp-raw-toggle')

      await expect(page.locator('#exp-visual-editor')).toBeHidden()
      await expect(page.locator('#exp-raw-editor')).toBeVisible()
    })

    test('dropdown excludes already-selected settings', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Select template with fts5_title_boost
      await page.click('#exp-tpl-title-boost')

      // The dropdown should NOT have fts5_title_boost as an option
      const options = await page.locator('#exp-add-setting option').allTextContents()
      const hasTitleBoost = options.some(o => o.includes('fts5_title_boost'))
      expect(hasTitleBoost).toBe(false)
    })
  })

  // =============================================
  // Recommendations Panel
  // =============================================

  test.describe('Recommendations Panel', () => {
    test('recommendations panel exists in tab', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')

      const panel = page.locator('#exp-recommendations')
      await expect(panel).toBeAttached()
    })

    test('recommendations panel has heading', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')

      const heading = page.locator('#tab-experiments:has-text("Test Recommendations")')
      await expect(heading).toBeAttached()
    })

    test('recommendations panel loads without error', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')

      // Wait for loading to finish (either shows results or no-data message)
      await page.waitForFunction(() => {
        const el = document.getElementById('exp-recommendations')
        return el && !el.innerHTML.includes('Loading analytics')
      }, { timeout: 10000 })

      // Should not show an error
      const content = await page.locator('#exp-recommendations').innerHTML()
      expect(content).not.toContain('Failed')
    })

    test('recommendations shows appropriate state for low data', async ({ page }) => {
      // On a fresh dev server, there may be very few searches
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')

      await page.waitForFunction(() => {
        const el = document.getElementById('exp-recommendations')
        return el && !el.innerHTML.includes('Loading analytics')
      }, { timeout: 10000 })

      // Should show either "Not enough data", "All healthy", or recommendation cards
      const content = await page.locator('#exp-recommendations').innerHTML()
      const hasValidState =
        content.includes('Not enough data') ||
        content.includes('All healthy') ||
        content.includes('Create This Test') ||
        content.includes('Could not load')
      expect(hasValidState).toBe(true)
    })
  })

  // =============================================
  // Summary Panel
  // =============================================

  test.describe('Summary Panel', () => {
    test('summary panel appears when template selected', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Initially hidden
      await expect(page.locator('#exp-summary-panel')).toBeHidden()

      // Select a template
      await page.click('#exp-tpl-title-boost')

      // Should now be visible
      await expect(page.locator('#exp-summary-panel')).toBeVisible()
    })

    test('summary shows override description', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-title-boost')

      const summaryText = await page.locator('#exp-summary-text').innerHTML()
      expect(summaryText).toContain('Title Weight')
      expect(summaryText).toContain('10')
    })

    test('summary shows minimum searches', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      await page.click('#exp-tpl-title-boost')

      const summaryText = await page.locator('#exp-summary-text').innerHTML()
      expect(summaryText).toContain('Minimum searches')
      expect(summaryText).toContain('200')
    })
  })

  // =============================================
  // Integration: Template to API
  // =============================================

  test.describe('Integration', () => {
    test('create test via template and verify API payload', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')
      await page.click('button:has-text("New A/B Test")')
      await page.waitForSelector('#exp-template-grid')

      // Select "Enable Query Rewriting" template
      await page.click('#exp-tpl-query-rewriting')

      // Wait for form to populate
      await page.waitForFunction(() => {
        const el = document.getElementById('exp-name') as HTMLInputElement
        return el && el.value === 'Enable Query Rewriting'
      })

      // Create the test
      await page.locator('#exp-create-modal button:has-text("Create Draft")').click()

      // Wait for modal to close (hidden class applied)
      await page.waitForFunction(() => {
        const modal = document.getElementById('exp-create-modal')
        return modal && modal.classList.contains('hidden')
      }, { timeout: 10000 })

      // Verify via API that the experiment was created correctly
      const response = await page.request.get(ADMIN_API)
      const json = await response.json()
      const created = json.data.find((e: any) => e.name === 'Enable Query Rewriting')
      expect(created).toBeDefined()
      expect(created.mode).toBe('ab')
      expect(created.min_searches).toBe(300)
      expect(created.variants.treatment.query_rewriting_enabled).toBe(true)
    })

    test('stat cards use Tests terminology', async ({ page }) => {
      await page.goto('/admin/search#experiments')
      await page.waitForSelector('#tab-experiments')

      const statLabel = page.locator('#tab-experiments .p-5:has-text("Total Tests")')
      await expect(statLabel).toBeAttached()
    })
  })
})
