import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

// Demo-login telemetry (`POST /v1/events`) and the "Demo Site Logins" dashboard cards belong to
// the separate `sonicjs-stats` worker (packages/stats → stats.sonicjs.com, own wrangler.toml +
// D1). The CMS app under test does not register `statsDashboardPlugin`; probe at run time.
test.describe('Demo login stats @stats', () => {
  let statsWorker = false

  test.beforeAll(async ({ request }) => {
    const res = await request.get('/stats-health').catch(() => null)
    statsWorker = !!res && res.ok()
  })

  test('/v1/events accepts demo_login event', async ({ request }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    const res = await request.post('/v1/events', {
      data: {
        data: {
          installation_id: 'demo-e2e-test',
          event_type: 'demo_login',
          properties: {},
          timestamp: new Date().toISOString(),
        },
      },
    })
    expect(res.status()).toBe(201)
    const body = await res.json()
    expect(body.success).toBe(true)
  })

  test('stats dashboard renders Demo Site Logins section', async ({ page }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    await loginAsAdmin(page)
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('text=Demo Site Logins')).toBeVisible()
    await expect(page.locator('text=Daily Demo Logins')).toBeVisible()
  })

  test('stats dashboard shows demo login KPIs', async ({ page }) => {
    test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
    await loginAsAdmin(page)
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('text=Total Logins')).toBeVisible()
    await expect(page.locator('text=Last 30 Days')).toBeVisible()
  })
})
