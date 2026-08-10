import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('OAuth Providers - settings page @smoke @auth', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('shows Settings tab without needing prior saved settings', async ({ page }) => {
    await page.goto('/admin/plugins/oauth-providers')
    await expect(page.locator('#settings-tab')).toBeVisible()
  })

  test('renders GitHub and Google credential fields', async ({ page }) => {
    await page.goto('/admin/plugins/oauth-providers#settings')
    await expect(page.locator('#oauth_github_clientId')).toBeVisible()
    await expect(page.locator('#oauth_github_clientSecret')).toBeVisible()
    await expect(page.locator('#oauth_github_enabled')).toBeAttached()
    await expect(page.locator('#oauth_google_clientId')).toBeVisible()
    await expect(page.locator('#oauth_google_clientSecret')).toBeVisible()
    await expect(page.locator('#oauth_google_enabled')).toBeAttached()
  })

  test('saves and reloads nested provider settings correctly', async ({ page }) => {
    await page.goto('/admin/plugins/oauth-providers#settings')

    await page.fill('#oauth_github_clientId', 'test-gh-client-id')
    await page.fill('#oauth_github_clientSecret', 'test-gh-secret')

    const [response] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/admin/plugins/oauth-providers/settings') && r.request().method() === 'POST'),
      page.click('#save-button'),
    ])

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)

    // After reload, values persist
    await page.goto('/admin/plugins/oauth-providers#settings')
    await expect(page.locator('#oauth_github_clientId')).toHaveValue('test-gh-client-id')
  })
})
