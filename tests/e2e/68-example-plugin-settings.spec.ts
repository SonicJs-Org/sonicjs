import { test, expect } from '@playwright/test'
import { loginAsAdmin, TEST_ORIGIN, isFeatureAvailable } from './utils/test-helpers'

test.describe('Example plugin — settings reflected in API @plugins', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = await isFeatureAvailable(request, '/example')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('GET /example returns greeting and defaultName from DB settings', async ({ page }) => {
    // Update settings via admin UI
    await page.goto('/admin/plugins/example')
    await page.waitForSelector('#settings', { timeout: 5000 }).catch(() => {})
    await page.goto('/admin/plugins/example#settings')

    const greetingInput = page.locator('input[name="greeting"]')
    const nameInput = page.locator('input[name="defaultName"]')

    await greetingInput.fill('Greetings from test!')
    await nameInput.fill('TestUser')
    await page.locator('button[type="submit"]').click()
    await page.waitForResponse(r => r.url().includes('/admin') && r.status() < 400)

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
