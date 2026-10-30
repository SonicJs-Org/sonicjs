import { test, expect, type Page } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * The settings form only renders for an installed plugin — an uninstalled one gets the generic
 * detail page with an Install button. Core plugins are not installed on a greenfield database,
 * so make that a precondition of the spec rather than an assumption about the environment.
 */
async function ensureEmailPluginInstalled(page: Page) {
  await page.request
    .post('/admin/plugins/install', {
      headers: { 'Content-Type': 'application/json' },
      data: { name: 'email' },
    })
    // Already installed → 400 from installPlugin; that is the state we want anyway.
    .catch(() => {})
}

test.describe('Email Plugin Settings @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await ensureEmailPluginInstalled(page)
  })

  test('should navigate to email plugin settings from plugins page', async ({ page }) => {
    // Navigate to plugins page
    await page.goto('/admin/plugins')
    await page.waitForLoadState('domcontentloaded')

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
    await page.waitForLoadState('domcontentloaded')

    // Check for the configuration section
    await expect(page.locator('h3:has-text("Email Configuration")').first()).toBeVisible({ timeout: 10000 })

    // Provider selector drives which transport-specific fields are shown
    const provider = page.locator('select#setting_provider')
    await expect(provider).toBeVisible()
    await expect(provider.locator('option')).toHaveText(['Cloudflare Email Service', 'Resend'])

    // The form renders whichever transport is currently saved, and the sibling "should save
    // email settings successfully" test persists Resend — so select the transport explicitly
    // rather than assuming a default. What is under test is that the selector drives which
    // transport-specific block is shown.
    await provider.selectOption('cloudflare')
    await expect(page.locator('input#setting_cfAccountId')).toBeVisible()
    await expect(page.locator('input#setting_cfEmailApiToken')).toBeVisible()
    await expect(page.locator('input#setting_cfEmailApiToken')).toHaveAttribute('type', 'password')
    await expect(page.locator('input#setting_resendApiKey')).toBeHidden()

    // Switching to Resend swaps the transport-specific block
    await provider.selectOption('resend')
    await expect(page.locator('label:has-text("Resend API Key")').first()).toBeVisible()
    await expect(page.locator('input#setting_resendApiKey')).toBeVisible()
    await expect(page.locator('input#setting_resendApiKey')).toHaveAttribute('type', 'password')
    await expect(page.locator('input#setting_cfAccountId')).toBeHidden()

    // Fields common to both transports
    await expect(page.locator('label:has-text("From Email")').first()).toBeVisible()
    await expect(page.locator('input#setting_fromEmail')).toBeVisible()
    await expect(page.locator('input#setting_fromEmail')).toHaveAttribute('type', 'email')
    await expect(page.locator('input#setting_fromEmail')).toHaveAttribute('required', '')

    await expect(page.locator('label:has-text("From Name")').first()).toBeVisible()
    await expect(page.locator('input#setting_fromName')).toBeVisible()
    await expect(page.locator('input#setting_fromName')).toHaveAttribute('type', 'text')
    await expect(page.locator('input#setting_fromName')).toHaveAttribute('required', '')

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
    await expect(page.getByText(/registration confirmation/i).first()).toBeVisible()
    await expect(page.getByText(/Email verification/i).first()).toBeVisible()
    await expect(page.getByText(/Password reset/i).first()).toBeVisible()
    await expect(page.getByText(/One-time code/i).first()).toBeVisible()
  })

  test('should save email settings successfully', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('domcontentloaded')

    // Wait for form to be visible
    await page.waitForSelector('select#setting_provider', { state: 'visible', timeout: 10000 })

    // Fill in the form — pick Resend so the API key field is part of the submission
    await page.selectOption('select#setting_provider', 'resend')
    await page.fill('input#setting_resendApiKey', 're_test_api_key_12345')
    await page.fill('input#setting_fromEmail', 'noreply@test.com')
    await page.fill('input#setting_fromName', 'Test App')
    await page.fill('input#setting_replyTo', 'support@test.com')
    await page.fill('input#setting_logoUrl', 'https://test.com/logo.png')

    // Submit the form using the save button
    await page.click('button#save-button')

    // Wait for success message
    await expect(page.locator('text=Settings saved').first()).toBeVisible({ timeout: 10000 })

    // The page reloads a second after saving; the values must survive the round trip
    await page.waitForLoadState('domcontentloaded')
    await expect(page.locator('input#setting_fromEmail')).toHaveValue('noreply@test.com', { timeout: 10000 })
    await expect(page.locator('input#setting_fromName')).toHaveValue('Test App')
  })

  test('should validate required fields', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('domcontentloaded')

    // Wait for form to be visible
    await page.waitForSelector('input#setting_fromEmail', { state: 'visible', timeout: 10000 })

    const fromEmailField = page.locator('input#setting_fromEmail')
    await expect(fromEmailField).toHaveAttribute('required', '')

    const fromNameField = page.locator('input#setting_fromName')
    await expect(fromNameField).toHaveAttribute('required', '')

    // Optional fields must not be marked required
    await expect(page.locator('input#setting_replyTo')).not.toHaveAttribute('required', '')
    await expect(page.locator('input#setting_logoUrl')).not.toHaveAttribute('required', '')
  })

  test('should display test email section', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('domcontentloaded')

    // Check for test email section
    await expect(page.locator('h3:has-text("Send Test Email")').first()).toBeVisible({ timeout: 10000 })

    // Check test email input field
    await expect(page.locator('input#testEmailAddress')).toBeVisible()

    // Check test email button
    await expect(page.locator('button#testEmailBtn')).toBeVisible()
    await expect(page.locator('button#testEmailBtn')).toContainText('Send Test')
  })

  test('should not show "No Settings Available" message', async ({ page }) => {
    await page.goto('/admin/plugins/email')
    await page.waitForLoadState('domcontentloaded')

    // Wait for page content
    await expect(page.locator('h3:has-text("Email Configuration")').first()).toBeVisible({ timeout: 10000 })

    // Should NOT show the generic "No Settings Available" message
    await expect(page.locator('text=No Settings Available')).not.toBeVisible()
    await expect(page.locator('text=No settings available')).not.toBeVisible()
  })
})
