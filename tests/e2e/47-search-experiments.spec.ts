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
      expect(json.experiment.id).toBe(exp.id)
      expect(json.experiment.mode).toBe('ab')
      expect(['control', 'treatment']).toContain(json.experiment.variant)

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
      expect(json.experiment.mode).toBe('interleave')
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
    test('metrics endpoint returns structured response for running experiment', async ({ page }) => {
      const createResp = await page.request.post(ADMIN_API, {
        data: {
          name: 'E2E Metrics Test',
          variants: { control: {}, treatment: {} },
          min_searches: 1000,
        },
      })
      const exp = (await createResp.json()).data
      await page.request.post(`${ADMIN_API}/${exp.id}/start`)

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
})
