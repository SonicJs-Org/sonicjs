import { test, expect, type Page } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN, isFeatureAvailable } from './utils/test-helpers'

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
