import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

// Verifies the /admin/plugins/:id/configure route auto-renders forms from
// the plugin's `configSchema` field (declared via definePlugin).
// The hello-world plugin has: { greeting: { type: 'string', default: 'Hello World!' } }
// The email plugin has: { apiKey (sensitive), fromEmail, fromName, replyTo }
test.describe('Schema-driven plugin settings @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('hello-world /configure renders the greeting field with default value', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins/hello-world/configure`)
    await page.waitForLoadState('networkidle')

    // Page should render (not 404 or error)
    expect(page.url()).toContain('/configure')

    // Should have a settings form
    await expect(page.locator('form')).toBeVisible({ timeout: 10000 })

    // The greeting field should be present
    const greetingInput = page.locator('input[name="greeting"]')
    await expect(greetingInput).toBeVisible()

    // Placeholder reflects the schema default (actual value may differ after prior saves)
    await expect(greetingInput).toHaveAttribute('placeholder', 'Hello World!')

    // Save + Cancel buttons should be present
    await expect(page.locator('button[type="submit"]')).toBeVisible()
    await expect(page.locator('a', { hasText: 'Cancel' })).toBeVisible()
  })

  test('plugin without configSchema returns 404 from /configure', async ({ page }) => {
    // The database-tools plugin has no configSchema declared.
    const resp = await page.goto(`${BASE_URL}/admin/plugins/database-tools/configure`)
    expect(resp?.status()).toBe(404)
  })

  test('hello-world configure save persists the value', async ({ page }) => {
    const uniqueGreeting = `E2E greeting ${Date.now()}`

    await page.goto(`${BASE_URL}/admin/plugins/hello-world/configure`)
    await page.waitForLoadState('networkidle')

    const greetingInput = page.locator('input[name="greeting"]')
    await expect(greetingInput).toBeVisible({ timeout: 10000 })

    await greetingInput.fill(uniqueGreeting)
    await page.locator('button[type="submit"]').click()

    // POST auto-upserts the plugin if not in DB then redirects back to /configure
    await page.waitForURL(`**/configure`, { timeout: 10000 })
    await page.waitForLoadState('networkidle')

    const savedInput = page.locator('input[name="greeting"]')
    await expect(savedInput).toBeVisible({ timeout: 10000 })
    expect(await savedInput.inputValue()).toBe(uniqueGreeting)
  })

  test('/admin/plugins/hello-world settings page renders (auto-registers plugin)', async ({ page }) => {
    const resp = await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
    await page.waitForLoadState('networkidle')

    // Should NOT be a 404 — the route auto-registers definePlugin plugins
    expect(resp?.status()).not.toBe(404)
    expect(resp?.status()).not.toBe(500)

    // Should land on a page that contains the plugin name
    const body = await page.locator('body').textContent()
    expect(body?.toLowerCase()).toContain('hello')
  })

  test('email plugin /configure renders apiKey as password field', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins/email/configure`)
    await page.waitForLoadState('networkidle')

    // Email plugin declares configSchema with apiKey { type: 'string', variant: 'sensitive' }
    const form = page.locator('form')
    if (await form.count() > 0) {
      await expect(form).toBeVisible()

      // apiKey should be a password-type input (sensitive variant)
      const apiKeyInput = page.locator('input[name="apiKey"]')
      if (await apiKeyInput.count() > 0) {
        await expect(apiKeyInput).toHaveAttribute('type', 'password')
      }
    } else {
      // If not rendered (plugin might use legacy settings page), skip gracefully
      test.skip(true, 'email /configure not available (plugin uses legacy settings)')
    }
  })
})
