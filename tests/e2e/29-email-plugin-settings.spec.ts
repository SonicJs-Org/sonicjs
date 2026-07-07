import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

// TODO: These tests pass locally but fail in CI due to D1 migration timing issues
// Skipping until the CI D1 propagation issue is resolved
test.describe.skip('Email Plugin Settings @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should navigate to email plugin settings from plugins page', async ({ page }) => {
    // Navigate to plugins page
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Wait for plugin cards to load (any plugin card)
    await page.waitForSelector('.plugin-card', { state: 'visible', timeout: 15000 })

    // Find the email plugin card by data-name attribute and click it
    const emailPluginCard = page.locator('.plugin-card[data-name="Email"]')
    await expect(emailPluginCard).toBeVisible({ timeout: 15000 })

    // Click the email plugin card (whole card is clickable now)
    await emailPluginCard.click()

    // Should navigate to plugin settings page
    await page.waitForURL('**/admin/plugins/email', { timeout: 10000 })
    expect(page.url()).toContain('/admin/plugins/email')
  })

  test('should display email settings form with all fields', async ({ page }) => {
    // Navigate directly to email settings page
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('networkidle')

    // Wait for page content to load
    await page.waitForSelector('h3', { state: 'visible', timeout: 15000 })

    // Check for Resend configuration section
    await expect(page.locator('h3:has-text("Resend Configuration")').first()).toBeVisible({ timeout: 10000 })

    // Check all form fields are present (using setting_ prefix)
    await expect(page.locator('label:has-text("Resend API Key")').first()).toBeVisible()
    await expect(page.locator('input#setting_apiKey')).toBeVisible()
    await expect(page.locator('input#setting_apiKey')).toHaveAttribute('type', 'password')
    await expect(page.locator('input#setting_apiKey')).toHaveAttribute('required')

    await expect(page.locator('label:has-text("From Email")').first()).toBeVisible()
    await expect(page.locator('input#setting_fromEmail')).toBeVisible()
    await expect(page.locator('input#setting_fromEmail')).toHaveAttribute('type', 'email')
    await expect(page.locator('input#setting_fromEmail')).toHaveAttribute('required')

    await expect(page.locator('label:has-text("From Name")').first()).toBeVisible()
    await expect(page.locator('input#setting_fromName')).toBeVisible()
    await expect(page.locator('input#setting_fromName')).toHaveAttribute('type', 'text')
    await expect(page.locator('input#setting_fromName')).toHaveAttribute('required')

    await expect(page.locator('label:has-text("Reply-To Email")').first()).toBeVisible()
    await expect(page.locator('input#setting_replyTo')).toBeVisible()
    await expect(page.locator('input#setting_replyTo')).toHaveAttribute('type', 'email')

    await expect(page.locator('label:has-text("Logo URL")').first()).toBeVisible()
    await expect(page.locator('input#setting_logoUrl')).toBeVisible()
    await expect(page.locator('input#setting_logoUrl')).toHaveAttribute('type', 'url')

    // Check for action buttons
    await expect(page.locator('button#save-button')).toBeVisible()
    await expect(page.locator('button#testEmailBtn')).toBeVisible()

    // Check for info card
    await expect(page.locator('text=Email Templates Included').first()).toBeVisible()
    await expect(page.locator('text=Registration confirmation').first()).toBeVisible()
    await expect(page.locator('text=Email verification').first()).toBeVisible()
    await expect(page.locator('text=Password reset').first()).toBeVisible()
    await expect(page.locator('text=One-time code').first()).toBeVisible()
  })

  test('should save email settings successfully', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('networkidle')

    // Wait for form to be visible
    await page.waitForSelector('input#setting_apiKey', { state: 'visible', timeout: 10000 })

    // Fill in the form
    await page.fill('input#setting_apiKey', 're_test_api_key_12345')
    await page.fill('input#setting_fromEmail', 'noreply@test.com')
    await page.fill('input#setting_fromName', 'Test App')
    await page.fill('input#setting_replyTo', 'support@test.com')
    await page.fill('input#setting_logoUrl', 'https://test.com/logo.png')

    // Submit the form using the save button
    await page.click('button#save-button')

    // Wait for success message
    await expect(page.locator('text=Settings saved').first()).toBeVisible({ timeout: 10000 })
  })

  test('should validate required fields', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('networkidle')

    // Wait for form to be visible
    await page.waitForSelector('input#setting_apiKey', { state: 'visible', timeout: 10000 })

    // Clear any existing values and check required attributes
    const apiKeyField = page.locator('input#setting_apiKey')
    await expect(apiKeyField).toHaveAttribute('required')

    const fromEmailField = page.locator('input#setting_fromEmail')
    await expect(fromEmailField).toHaveAttribute('required')

    const fromNameField = page.locator('input#setting_fromName')
    await expect(fromNameField).toHaveAttribute('required')
  })

  test('should display test email section', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('networkidle')

    // Wait for page content
    await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

    // Check for test email section
    await expect(page.locator('h3:has-text("Send Test Email")').first()).toBeVisible()

    // Check test email input field
    await expect(page.locator('input#testEmailAddress')).toBeVisible()

    // Check test email button
    await expect(page.locator('button#testEmailBtn')).toBeVisible()
    await expect(page.locator('button#testEmailBtn')).toContainText('Send Test')
  })

  test('should not show "No Settings Available" message', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('networkidle')

    // Wait for page content
    await page.waitForSelector('h3', { state: 'visible', timeout: 10000 })

    // Should NOT show the generic "No Settings Available" message
    await expect(page.locator('text=No Settings Available')).not.toBeVisible()
    await expect(page.locator('text=No settings available')).not.toBeVisible()

    // Should show the settings form instead
    await expect(page.locator('h3:has-text("Resend Configuration")').first()).toBeVisible()
  })
})
