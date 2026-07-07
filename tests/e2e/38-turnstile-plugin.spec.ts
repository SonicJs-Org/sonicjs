import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Turnstile Plugin @plugins', () => {
  test.beforeEach(async ({ page }) => {
    // Login as admin using the test helper
    await loginAsAdmin(page)
  })

  // Install and activate the Turnstile plugin before running tests
  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()
    
    try {
      // Login as admin
      await loginAsAdmin(page)
      
      // Try to install plugin (will fail gracefully if already installed)
      try {
        const installResponse = await page.request.post('/admin/plugins/install', {
          data: { name: 'turnstile-plugin' },
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000
        })
        console.log('Install response:', installResponse.status())
      } catch (e) {
        console.log('Install attempt (may already exist):', e.message)
      }
      
      // Try to activate plugin (will fail gracefully if already active)
      try {
        const activateResponse = await page.request.post('/admin/plugins/turnstile/activate', {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000
        })
        console.log('Activate response:', activateResponse.status())
      } catch (e) {
        console.log('Activate attempt (may already be active):', e.message)
      }
    } catch (error) {
      console.log('Setup error (tests may still work if plugin exists):', error.message)
    } finally {
      await context.close()
    }
  })

  test('should display Turnstile plugin in plugins list', async ({ page }) => {
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('h1:has-text("Plugins")', { timeout: 10000 })
    
    // Check if Turnstile plugin heading is visible (more specific than text match)
    const turnstileHeading = page.getByRole('heading', { name: 'Cloudflare Turnstile' })
    await expect(turnstileHeading).toBeVisible()
    
    // Check for security category or description text
    const turnstileDescription = page.getByText('CAPTCHA-free bot protection')
    await expect(turnstileDescription).toBeVisible()
  })

  test('should show Turnstile settings page', async ({ page }) => {
    // Navigate directly to the Turnstile plugin settings page
    await page.goto('/admin/plugins/turnstile')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('h2:has-text("Cloudflare Turnstile Settings")', { timeout: 10000 })
    
    // Should show settings page with Plugin Settings main heading
    await expect(page.getByRole('heading', { name: 'Plugin Settings' })).toBeVisible()
    
    // Should show Cloudflare Turnstile Settings subheading
    await expect(page.getByRole('heading', { name: 'Cloudflare Turnstile Settings' })).toBeVisible()
    
    // Check for all settings fields
    await expect(page.locator('input[name="setting_siteKey"]')).toBeVisible()
    await expect(page.locator('input[name="setting_secretKey"]')).toBeVisible()
    await expect(page.locator('select[name="setting_theme"]')).toBeVisible()
    await expect(page.locator('select[name="setting_size"]')).toBeVisible()
    await expect(page.locator('select[name="setting_mode"]')).toBeVisible()
    await expect(page.locator('select[name="setting_appearance"]')).toBeVisible()
  })

  test('should save Turnstile settings', async ({ page }) => {
    // Navigate directly to settings page
    await page.goto('/admin/plugins/turnstile')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await page.waitForSelector('input[name="setting_siteKey"]', { timeout: 10000 })
    
    // Fill in test keys (these are dummy keys for testing UI only)
    await page.fill('input[name="setting_siteKey"]', '1x00000000000000000000AA')
    await page.fill('input[name="setting_secretKey"]', '1x0000000000000000000000000000000AA')
    
    // Select options
    await page.selectOption('select[name="setting_theme"]', 'dark')
    await page.selectOption('select[name="setting_size"]', 'compact')
    
    // Enable Turnstile - use force click since the checkbox is visually hidden
    const enableToggle = page.locator('input[name="setting_enabled"]')
    if (!(await enableToggle.isChecked())) {
      await enableToggle.click({ force: true })
    }
    
    // Save settings and wait for the API response
    const saveResponsePromise = page.waitForResponse(
      response => response.url().includes('/admin/plugins/turnstile/settings') && response.status() === 200,
      { timeout: 10000 }
    )
    await page.click('button:has-text("Save Settings")')
    await saveResponsePromise

    // Should stay on plugin settings page
    await expect(page).toHaveURL(/\/admin\/plugins\/turnstile/)
  })

  // NOTE: The following tests require the Contact Form plugin from feature/contact-plugin-v1
  // They are skipped here since this branch only contains the Turnstile plugin
  // These tests should be enabled once both features are merged to main
  
  test.skip('should allow enabling Turnstile on contact form', async ({ page }) => {
    // First ensure Turnstile plugin is configured
    await page.goto('/admin/plugins')
    await page.click('text=Cloudflare Turnstile')
    await page.fill('input[name="setting_siteKey"]', '1x00000000000000000000AA')
    await page.fill('input[name="setting_secretKey"]', '1x0000000000000000000000000000000AA')
    await page.click('button:has-text("Save Settings")')
    
    // Go to contact form settings
    await page.goto('/admin/plugins')
    await page.click('text=Contact Form')
    
    // Enable Turnstile
    const turnstileToggle = page.locator('input[name="useTurnstile"]')
    if (!(await turnstileToggle.isChecked())) {
      await turnstileToggle.click()
    }
    
    // Save contact form settings
    await page.click('button:has-text("Save Settings")')
    
    // Verify settings were saved
    await expect(page.locator('text=Settings Saved')).toBeVisible({ timeout: 5000 })
  })

  test.skip('should show Turnstile widget on contact form when enabled', async ({ page }) => {
    // Note: This test requires real Turnstile keys to fully work
    // With dummy keys, the widget may not render properly
    
    await page.goto('/contact')
    
    // Check if the page loads
    await expect(page).toHaveURL('/contact')
    
    // Check if form exists
    const form = page.locator('form#cf')
    await expect(form).toBeVisible()
    
    // If Turnstile is enabled, the widget container should exist
    // (even if it doesn't fully render without valid keys)
    const turnstileContainer = page.locator('.cf-turnstile')
    const containerCount = await turnstileContainer.count()
    
    // Container may or may not be present depending on settings
    // This is more of a smoke test
    console.log(`Turnstile containers found: ${containerCount}`)
  })
})
