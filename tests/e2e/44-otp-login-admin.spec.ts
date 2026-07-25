import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

// TODO: These tests pass locally but fail in CI due to D1 migration timing issues
// Skipping until the CI D1 propagation issue is resolved
test.describe.skip('OTP Login Plugin Admin Page @smoke @auth', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test.describe('Plugin Settings Page', () => {
    test('should load the OTP Login page at /admin/plugins/otp-login', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content to load
      await page.waitForSelector('h1, h2, h3', { state: 'visible', timeout: 10000 })

      // Should show the plugin settings page with OTP Login content
      // The page title in the header should contain OTP Login
      await expect(page.locator('h1, h2').first()).toBeVisible()
    })

    test('should display test email form', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Check for Test OTP Email section
      await expect(page.locator('text=Test OTP Email').first()).toBeVisible()

      // Check email input field
      await expect(page.locator('input#testEmail')).toBeVisible()

      // Check send button
      await expect(page.locator('button#sendTestBtn')).toBeVisible()
      await expect(page.locator('#sendBtnText')).toContainText('Send Test Code')
    })

    test('should display email preview section', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Check for Email Preview section
      await expect(page.locator('text=Email Preview').first()).toBeVisible()

      // Check preview content
      await expect(page.locator('text=Your Login Code').first()).toBeVisible()
      await expect(page.locator('text=Enter this code to sign in').first()).toBeVisible()
      await expect(page.locator('text=Security Notice').first()).toBeVisible()
    })

    test('should display code settings form', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Check for Code Settings section
      await expect(page.locator('text=Code Settings').first()).toBeVisible()

      // Check form fields (using setting_ prefix)
      await expect(page.locator('input#setting_codeLength')).toBeVisible()
      await expect(page.locator('input#setting_codeExpiryMinutes')).toBeVisible()
      await expect(page.locator('input#setting_maxAttempts')).toBeVisible()
      await expect(page.locator('input#setting_rateLimitPerHour')).toBeVisible()
      await expect(page.locator('input#setting_allowNewUserRegistration')).toBeVisible()
    })

    test('should display quick links to related settings', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Check quick links (use .first() since links may appear multiple times)
      await expect(page.locator('a[href="/admin/plugins/email"]').first()).toBeVisible()
      await expect(page.locator('a[href="/admin/settings/general"]').first()).toBeVisible()
    })

    test('should show email configuration status', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Should show either configured or not configured status
      // (one of these should be visible depending on email plugin config)
      const configuredStatus = page.locator('text=Email configured')
      const notConfiguredStatus = page.locator('text=Email not configured')

      const isConfigured = await configuredStatus.isVisible()
      const isNotConfigured = await notConfiguredStatus.isVisible()

      // One of them must be visible
      expect(isConfigured || isNotConfigured).toBe(true)
    })

    test('should display features list', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Check features section (use .first() since text may appear multiple times)
      await expect(page.locator('text=Passwordless authentication').first()).toBeVisible()
      await expect(page.locator('text=Rate limiting protection').first()).toBeVisible()
      await expect(page.locator('text=Brute force prevention').first()).toBeVisible()
    })

    test('should have save settings button', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for page content
      await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

      // Check save button
      await expect(page.locator('button#save-button')).toBeVisible()
    })

    test('should send test code and show result', async ({ page }) => {
      await page.goto('/admin/plugins/otp-login')
      await page.waitForLoadState('networkidle')

      // Wait for form to be visible
      await page.waitForSelector('input#testEmail', { state: 'visible', timeout: 10000 })

      // Fill in email
      await page.fill('input#testEmail', 'test@example.com')

      // Click send button
      await page.click('button#sendTestBtn')

      // Should show loading state
      await expect(page.locator('#sendBtnText')).toContainText('Sending')

      // Wait for result (either success or error)
      await page.waitForSelector('#testResult:not(.hidden)', { timeout: 10000 })

      // Should show some result
      const resultBox = page.locator('#testResult')
      await expect(resultBox).toBeVisible()
    })
  })
})
