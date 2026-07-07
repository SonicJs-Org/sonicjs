import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Stats dashboard data parsing', () => {
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
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('text=What People Build')).toBeVisible()
    // Section header is always present; charts render if data exists
    await expect(page.locator('text=Top Collections')).toBeVisible()
    await expect(page.locator('text=Active Plugins')).toBeVisible()
  })

  test('/v1/events accepts project_snapshot payload', async ({ request }) => {
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
