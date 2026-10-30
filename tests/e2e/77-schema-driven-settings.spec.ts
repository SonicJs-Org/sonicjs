import { test, expect } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

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
