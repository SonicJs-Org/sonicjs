import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Demo login stats', () => {
  test('/v1/events accepts demo_login event', async ({ request }) => {
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
    await loginAsAdmin(page)
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('text=Demo Site Logins')).toBeVisible()
    await expect(page.locator('text=Daily Demo Logins')).toBeVisible()
  })

  test('stats dashboard shows demo login KPIs', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/dashboard')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('text=Total Logins')).toBeVisible()
    await expect(page.locator('text=Last 30 Days')).toBeVisible()
  })
})
