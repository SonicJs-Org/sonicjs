import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Security Audit Plugin — document model', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('dashboard page loads', async ({ page }) => {
    await page.goto('/admin/plugins/security-audit')
    await expect(page.locator('body')).not.toContainText('Error')
    await expect(page.locator('body')).not.toContainText('security_events')
  })

  test('event log page loads with empty state', async ({ page }) => {
    await page.goto('/admin/plugins/security-audit/events')
    await expect(page.locator('body')).not.toContainText('Error')
    await expect(page.locator('body')).not.toContainText('no such table: security_events')
  })

  test('stats API returns document-backed data', async ({ page }) => {
    const response = await page.request.get('/api/security-audit/stats')
    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body).toHaveProperty('totalEvents')
    expect(body).toHaveProperty('failedLogins24h')
    expect(body).toHaveProperty('eventsByType')
    expect(body).toHaveProperty('eventsBySeverity')
  })

  test('events API returns document-backed list', async ({ page }) => {
    const response = await page.request.get('/api/security-audit/events')
    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body).toHaveProperty('events')
    expect(body).toHaveProperty('total')
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('log and retrieve a security event via API', async ({ page }) => {
    // Trigger a login failure to log a security event via middleware
    await page.request.post('/auth/login', {
      data: { email: 'nonexistent@example.com', password: 'wrongpassword' },
      headers: { 'Content-Type': 'application/json' },
    })

    // Give the async log a moment to settle
    await page.waitForTimeout(500)

    const response = await page.request.get('/api/security-audit/events?type=login_failure')
    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('settings page loads', async ({ page }) => {
    await page.goto('/admin/plugins/security-audit/settings')
    await expect(page.locator('body')).not.toContainText('Error')
    await expect(page.locator('body')).not.toContainText('no such table')
  })
})
