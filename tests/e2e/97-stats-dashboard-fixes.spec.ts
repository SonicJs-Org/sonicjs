import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

// The telemetry ingest endpoint (`POST /v1/events`) and the install/snapshot dashboard cards are
// served by the separate `sonicjs-stats` worker (packages/stats, deployed to stats.sonicjs.com,
// with its own wrangler.toml and D1 database). The CMS app under test never registers
// `statsDashboardPlugin`, so those surfaces only exist when the stats worker is the deployment
// being pointed at. Detected at run time via its health endpoint.
test.describe('Stats dashboard data parsing @stats', () => {
  let statsWorker = false

  test.beforeAll(async ({ request }) => {
    const res = await request.get('/stats-health').catch(() => null)
    statsWorker = !!res && res.ok()
  })

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('dashboard renders without JS errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    expect(errors.filter((e) => !e.includes('Chart'))).toHaveLength(0)
  })

  test('install failures table has Step and Version columns', async ({ page }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    const failuresCard = page.locator('text=Install Failures').first()
    await expect(failuresCard).toBeVisible()

    const headers = page.locator('th')
    const headerTexts = await headers.allTextContents()
    const normalized = headerTexts.map((t) => t.toLowerCase())

    // Table should have Step and Version columns (not just Error + Count)
    expect(normalized.some((h) => h.includes('step'))).toBe(true)
    expect(normalized.some((h) => h.includes('version'))).toBe(true)
  })

  test('What People Build section renders when snapshot data exists', async ({ page }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('text=What People Build')).toBeVisible()
    // Section header is always present; charts render if data exists
    await expect(page.locator('text=Top Collections')).toBeVisible()
    await expect(page.locator('text=Active Plugins')).toBeVisible()
  })

  test('/v1/events accepts project_snapshot payload', async ({ request }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    const res = await request.post('/v1/events', {
      data: {
        data: {
          installation_id: 'test-e2e-install',
          event_type: 'project_snapshot',
          properties: {
            installation_id: 'test-e2e-install',
            collection_names: '["test_col"]',
            collection_counts: '{"test_col":5}',
            active_plugins: '["Test Plugin"]',
            field_type_histogram: '{"string":3}',
            doc_total: 5,
            sonicjs_version: '3.0.0-test',
          },
        },
      },
    })
    expect(res.status()).toBe(201)
    const body = await res.json()
    expect(body.success).toBe(true)
  })

  test('/v1/events accepts installation_failed with step', async ({ request }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    const res = await request.post('/v1/events', {
      data: {
        data: {
          installation_id: 'test-e2e-fail',
          event_type: 'installation_failed',
          properties: {
            errorType: 'Command failed with exit code 1',
            step: 'db_migrate',
            version: '3.0.0-test',
          },
        },
      },
    })
    expect(res.status()).toBe(201)
  })
})
