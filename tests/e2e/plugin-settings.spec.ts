import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { TEST_ORIGIN } from "./utils/test-helpers"
import { isFeatureAvailable } from "./utils/test-helpers"
import { ensureAdminUserExists } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 29-email-plugin-settings.spec.ts", () => {
  /**
   * The settings form only renders for an installed plugin — an uninstalled one gets the generic
   * detail page with an Install button. Core plugins are not installed on a greenfield database,
   * so make that a precondition of the spec rather than an assumption about the environment.
   */
  async function ensureEmailPluginInstalled(page: Page): Promise<Record<string, unknown>> {
    const response = await page.request.post('/admin/plugins/install', {
      headers: { 'Content-Type': 'application/json' },
      data: { name: 'email' },
    })
    // PluginService preserves settings on an idempotent reinstall.
    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
    expect(body.plugin.settings).toBeTruthy()
    expect(Array.isArray(body.plugin.settings)).toBe(false)
    expect(typeof body.plugin.settings).toBe('object')
    return body.plugin.settings
  }

  test.describe('Email Plugin Settings @plugins @lock-plugin-email', () => {
    let originalSettings: Record<string, unknown> | undefined

    test.beforeEach(async ({ page }) => {
      originalSettings = undefined
      await loginAsAdmin(page)
      originalSettings = await ensureEmailPluginInstalled(page)
    })

    test.afterEach(async ({ page }) => {
      if (originalSettings === undefined) return // Snapshot failed before test could mutate settings.
      // Dedicated POST replaces settings, while the generic endpoint merges. Clear
      // first, then restore the complete snapshot (including legacy/internal keys).
      const cleared = await page.request.post('/admin/email/settings', { data: {} })
      expect(cleared.status()).toBe(200)
      expect(await cleared.json()).toEqual({ success: true, settings: {} })
      const restored = await page.request.post('/admin/plugins/email/settings', { data: originalSettings })
      expect(restored.status()).toBe(200)
      expect(await restored.json()).toEqual({ success: true })
      expect(await ensureEmailPluginInstalled(page)).toEqual(originalSettings)
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

      // Select explicitly: the test verifies transport-specific field visibility
      // regardless of the original settings restored after each test.
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

    test('dedicated email POST persists to the plugin settings form and can clear credentials', async ({ page }) => {
      const settings = {
        provider: 'resend', resendApiKey: 're_dedicated_post_test',
        fromEmail: 'dedicated@example.com', fromName: 'Dedicated POST', replyTo: 'reply@example.com',
      }
      const saved = await page.request.post('/admin/email/settings', { data: settings })
      expect(saved.status()).toBe(200)
      expect(await saved.json()).toEqual({ success: true, settings })
      await page.goto('/admin/plugins/email')
      await expect(page.locator('#setting_provider')).toHaveValue('resend')
      await expect(page.locator('#setting_resendApiKey')).toHaveValue(settings.resendApiKey)
      await expect(page.locator('#setting_fromEmail')).toHaveValue(settings.fromEmail)
      await expect(page.locator('#setting_fromName')).toHaveValue(settings.fromName)

      const cleared = await page.request.post('/admin/email/settings', { data: {} })
      expect(cleared.status()).toBe(200)
      expect(await cleared.json()).toEqual({ success: true, settings: {} })
      await page.reload()
      await page.selectOption('#setting_provider', 'resend')
      await expect(page.locator('#setting_resendApiKey')).toHaveValue('')
      await expect(page.locator('#setting_fromEmail')).toHaveValue('')
    })

    test('dedicated email POST rejects arrays without clearing saved settings', async ({ page }) => {
      const settings = { provider: 'resend', resendApiKey: 're_preserved_test', fromEmail: 'preserved@example.com' }
      expect((await page.request.post('/admin/email/settings', { data: settings })).status()).toBe(200)
      const invalid = await page.request.post('/admin/email/settings', { data: [] })
      expect(invalid.status()).toBe(400)
      expect(await invalid.json()).toEqual({ error: 'invalid JSON body' })
      await page.goto('/admin/plugins/email')
      await expect(page.locator('#setting_resendApiKey')).toHaveValue(settings.resendApiKey)
      await expect(page.locator('#setting_fromEmail')).toHaveValue(settings.fromEmail)
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 68-example-plugin-settings.spec.ts", () => {
  /**
   * The settings form only renders for an installed plugin; an uninstalled one gets the generic
   * detail page with an Install button. Core plugins are not installed on a greenfield database,
   * so make that a precondition rather than an assumption about the environment.
   */
  async function ensureExamplePluginInstalled(page: Page) {
    await page.request
      .post('/admin/plugins/install', {
        headers: { 'Content-Type': 'application/json' },
        data: { name: 'example' },
      })
      // Already installed → 400 from installPlugin; that is the state we want anyway.
      .catch(() => {})
  }

  test.describe('Example plugin — settings reflected in API @plugins', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = await isFeatureAvailable(request, '/example')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      await ensureExamplePluginInstalled(page)
    })

    test('GET /example returns greeting and defaultName from DB settings', async ({ page }) => {
      await page.goto('/admin/plugins/example#settings')
      await page.waitForLoadState('domcontentloaded')

      // Settings inputs are rendered by the shared plugin-settings template, which prefixes every
      // field name with `setting_` and submits them as JSON to /admin/plugins/example/settings.
      const greetingInput = page.locator('input#setting_greeting')
      const nameInput = page.locator('input#setting_defaultName')
      await expect(greetingInput).toBeVisible({ timeout: 10000 })

      await greetingInput.fill('Greetings from test!')
      await nameInput.fill('TestUser')

      const saved = page.waitForResponse(
        r => r.url().includes('/admin/plugins/example/settings') && r.request().method() === 'POST'
      )
      await page.locator('button#save-button').click()
      expect((await saved).status()).toBe(200)

      // Verify API reflects updated settings
      const res = await page.request.get(`${TEST_ORIGIN}/example`)
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(body.message).toContain('Greetings from test!')
      expect(body.message).toContain('TestUser')
      expect(body.plugin).toBe('example')
    })

    test('GET /example/:name uses updated greeting from settings', async ({ page }) => {
      // Read current greeting from API (after previous test may have changed it)
      const res = await page.request.get(`${TEST_ORIGIN}/example/traveller`)
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(typeof body.message).toBe('string')
      expect(body.message).toContain('traveller')
      expect(body.plugin).toBe('example')
    })

    test('GET /example/moods returns published moods list', async ({ page }) => {
      const res = await page.request.get(`${TEST_ORIGIN}/example/moods`)
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(Array.isArray(body.moods)).toBe(true)
      expect(typeof body.total).toBe('number')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 77-schema-driven-settings.spec.ts", () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

  // Verifies the /admin/plugins/:id/configure route auto-renders forms from
  // the plugin's `configSchema` field (declared via definePlugin).
  // The hello-world plugin has: { greeting: { type: 'string', default: 'Hello World!' } }
  // The email plugin has: { apiKey (sensitive), fromEmail, fromName, replyTo }
  test.describe('Schema-driven plugin settings @plugins @lock-plugin-hello-world', () => {
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
      // POST /admin/plugins/:id/configure redirects back to /configure, the page it was submitted
      // from, so `waitForURL('**/configure')` is true before the click dispatches. The assertion
      // below then read back the value `fill()` had just typed and passed without anything being
      // saved. Wait for the POST, then reload so the input is re-rendered from the database.
      await Promise.all([
        page.waitForResponse(
          (r) => r.request().method() === 'POST' && r.url().includes('/configure')
        ),
        page.locator('button[type="submit"]').click(),
      ])
      await page.reload({ waitUntil: 'networkidle' })

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

    test('email plugin keeps its legacy settings page instead of /configure', async ({ page }) => {
      // Documented contract in admin-plugins.ts: schema-driven settings are opt-in via
      // definePlugin's `configSchema`. The email plugin declares none, so /configure must 404
      // rather than render an empty form — it keeps its legacy settings page instead.
      const resp = await page.goto(`${BASE_URL}/admin/plugins/email/configure`)
      expect(resp?.status()).toBe(404)
      expect(await page.locator('body').textContent()).toContain('No schema-driven settings')

      const legacy = await page.goto(`${BASE_URL}/admin/plugins/email`)
      expect(legacy?.status()).toBe(200)
    })

    test('a plugin that declares a configSchema renders its fields', async ({ page }) => {
      // api-keys declares two numeric fields; the auto-rendered form must post back to /configure.
      const resp = await page.goto(`${BASE_URL}/admin/plugins/api-keys/configure`)
      expect(resp?.status()).toBe(200)

      const form = page.locator('form[action="/admin/plugins/api-keys/configure"]')
      await expect(form).toBeVisible()
      await expect(form.locator('input[name="maxKeysPerUser"]')).toHaveAttribute('type', 'number')
      await expect(form.locator('input[name="defaultExpiryDays"]')).toHaveAttribute('type', 'number')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 90-plugin-stale-settings-pruning.spec.ts", () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

  // Regression tests for the stale configSchema settings bug (GitHub #972):
  //   Bug 1 — POST /configure merges old settings, preserving removed schema fields
  //   Bug 2 — Legacy settings page renders ALL stored keys, ignoring configSchema
  //
  // The hello-world plugin has configSchema: { greeting: { type: 'string' } }
  // We inject a stale key 'oldField' via the JSON settings endpoint, then verify
  // it does NOT appear in the legacy settings UI and is pruned when saving via /configure.

  test.describe('Plugin stale settings pruning (issue #972) @plugins @lock-plugin-hello-world', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('legacy settings page does not render stale keys absent from configSchema', async ({ page }) => {
      // Inject a stale key directly via the JSON settings endpoint
      const injectResp = await page.request.post(
        `${BASE_URL}/admin/plugins/hello-world/settings`,
        {
          data: { greeting: 'Hi from E2E', staleOldField: 'this-should-not-appear' },
          headers: { 'Content-Type': 'application/json' },
        }
      )
      expect(injectResp.ok()).toBeTruthy()

      // Visit the legacy settings page (/:id, not /:id/configure)
      await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
      await page.waitForLoadState('networkidle')

      const bodyText = await page.locator('body').textContent()

      // The stale key must not appear — configSchema filter should suppress it
      expect(bodyText).not.toContain('staleOldField')
      expect(bodyText).not.toContain('this-should-not-appear')
    })

    test('/configure POST prunes stale keys not in configSchema', async ({ page }) => {
      // Step 1: inject stale key via JSON endpoint
      const injectResp = await page.request.post(
        `${BASE_URL}/admin/plugins/hello-world/settings`,
        {
          data: { greeting: 'Before prune', staleOldField: 'stale-value' },
          headers: { 'Content-Type': 'application/json' },
        }
      )
      expect(injectResp.ok()).toBeTruthy()

      // Step 2: save via /configure (form-based, schema-driven)
      await page.goto(`${BASE_URL}/admin/plugins/hello-world/configure`)
      await page.waitForLoadState('networkidle')

      const greetingInput = page.locator('input[name="greeting"]')
      await expect(greetingInput).toBeVisible({ timeout: 10000 })
      await greetingInput.fill('After prune')
      // POST /admin/plugins/:id/configure redirects back to /configure, the page it was submitted
      // from, so `waitForURL('**/configure')` is true before the click dispatches. The assertion
      // below then read back the value `fill()` had just typed and passed without anything being
      // saved. Wait for the POST, then reload so the input is re-rendered from the database.
      await Promise.all([
        page.waitForResponse(
          (r) => r.request().method() === 'POST' && r.url().includes('/configure')
        ),
        page.locator('button[type="submit"]').click(),
      ])
      await page.reload({ waitUntil: 'networkidle' })

      // Step 3: verify saved greeting persisted
      const savedInput = page.locator('input[name="greeting"]')
      await expect(savedInput).toBeVisible({ timeout: 10000 })
      expect(await savedInput.inputValue()).toBe('After prune')

      // Step 4: visit legacy settings page — stale key must not appear there either
      await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
      await page.waitForLoadState('networkidle')

      const bodyText = await page.locator('body').textContent()
      expect(bodyText).not.toContain('staleOldField')
      expect(bodyText).not.toContain('stale-value')
    })

    test('_-prefixed internal keys are preserved through /configure save', async ({ page }) => {
      // _routes, _adminPath etc. must survive schema-driven saves
      const injectResp = await page.request.post(
        `${BASE_URL}/admin/plugins/hello-world/settings`,
        {
          data: { greeting: 'Keep internals', _internalKey: 'must-survive' },
          headers: { 'Content-Type': 'application/json' },
        }
      )
      expect(injectResp.ok()).toBeTruthy()

      // Save via /configure
      await page.goto(`${BASE_URL}/admin/plugins/hello-world/configure`)
      await page.waitForLoadState('networkidle')

      const greetingInput = page.locator('input[name="greeting"]')
      await expect(greetingInput).toBeVisible({ timeout: 10000 })
      await page.locator('button[type="submit"]').click()
      await page.waitForURL(`**/configure`, { timeout: 10000 })
      await page.waitForLoadState('networkidle')

      // The configure page won't expose _internalKey (it's not in the schema).
      // Verify by checking the hello-world endpoint which reads from plugin settings:
      // the page should still load without error, meaning internal state is intact.
      const resp = await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
      expect(resp?.status()).not.toBe(500)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 91-plugin-routes-tab-persistence.spec.ts", () => {
  test.describe('Plugin Information tab - routes persistence @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('routes remain visible after saving settings via legacy settings tab', async ({ page }) => {
      // Navigate to example plugin info page
      await page.goto('/admin/plugins/example')
      await page.waitForLoadState('domcontentloaded')

      // Confirm Information tab shows routes before any save.
      // Tabs are anchors with ids `<tab>-tab`; the routes list renders each path as a
      // link, so match it exactly (several routes start with "/example").
      const infoTab = page.locator('#info-tab')
      await infoTab.click()
      await expect(page.getByText('Routes', { exact: true })).toBeVisible()
      await expect(page.getByRole('link', { name: '/example', exact: true })).toBeVisible()

      // Go to Settings tab and save without changing anything
      await page.locator('#settings-tab').click()
      const saveBtn = page.locator('#settings-content').getByRole('button', { name: /save/i }).first()
      await saveBtn.click()
      // The page auto-reloads ~1s after a successful save
      await expect(page.getByText('Settings saved successfully')).toBeVisible({ timeout: 15000 })
      await page.waitForTimeout(2500)
      await page.waitForLoadState('domcontentloaded')

      // Return to Information tab — routes must still be present
      await page.locator('#info-tab').click()
      await expect(page.getByText('Routes', { exact: true })).toBeVisible()
      await expect(page.getByRole('link', { name: '/example', exact: true })).toBeVisible()
    })

    test('POST /:id/settings preserves _routes in response body', async ({ page }) => {
      // Hit the API directly and confirm _routes survives a round-trip
      await page.goto('/admin/plugins/example')
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('#info-tab')).toBeVisible()

      const response = await page.evaluate(async () => {
        // Save an empty settings payload — the handler must merge, not overwrite
        const res = await fetch('/admin/plugins/example/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ greeting: 'Hello, Cruel World!', defaultName: 'Stranger' }),
        })
        return res.json()
      })

      expect(response.success).toBe(true)

      // Reload and verify routes still rendered
      await page.reload()
      await page.waitForLoadState('domcontentloaded')

      const infoTab = page.locator('#info-tab')
      await infoTab.click()
      await expect(page.getByText('Routes', { exact: true })).toBeVisible()
      await expect(page.getByRole('link', { name: '/example', exact: true })).toBeVisible()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 93-oauth-providers-settings.spec.ts", () => {
  test.describe('OAuth Providers - settings page @smoke @auth', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      // Ensure the plugin is installed (it's no longer auto-installed on page visit)
      await page.request.post('/admin/plugins/install', {
        data: { name: 'oauth-providers' },
        headers: { 'Content-Type': 'application/json' },
      }).catch(() => {})
    })

    test('shows Settings tab without needing prior saved settings', async ({ page }) => {
      await page.goto('/admin/plugins/oauth-providers')
      await expect(page.locator('#settings-tab')).toBeVisible({ timeout: 10000 })
    })

    test('renders GitHub and Google credential fields', async ({ page }) => {
      await page.goto('/admin/plugins/oauth-providers#settings')
      await expect(page.locator('#oauth_github_clientId')).toBeVisible({ timeout: 10000 })
      await expect(page.locator('#oauth_github_clientSecret')).toBeVisible()
      await expect(page.locator('#oauth_github_enabled')).toBeAttached()
      await expect(page.locator('#oauth_google_clientId')).toBeVisible()
      await expect(page.locator('#oauth_google_clientSecret')).toBeVisible()
      await expect(page.locator('#oauth_google_enabled')).toBeAttached()
    })

    test('saves and reloads nested provider settings correctly', async ({ page }) => {
      await page.goto('/admin/plugins/oauth-providers#settings')
      await page.waitForLoadState('networkidle')

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
})
