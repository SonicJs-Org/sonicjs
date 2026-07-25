/**
 * E2E: Example plugin
 *
 * Verifies that the example demo plugin is correctly wired into the
 * SonicJS app: public API routes respond, the admin page loads, and the plugin
 * appears in the admin plugins list.
 */
import { test, expect } from '@playwright/test'
import { loginAsAdmin, isFeatureAvailable } from './utils/test-helpers'

const BASE = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Example plugin @plugins', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = await isFeatureAvailable(request, '/example')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  // ── Public API ─────────────────────────────────────────────────────────────

  // Note: routes are at /example/* (not /api/*) because user plugins
  // mount after the core /api/:collection catch-all — see plugin index.ts for why.
  test('GET /example returns greeting with random mood', async ({ request }) => {
    const res = await request.get(`${BASE}/example`)
    expect(res.status()).toBe(200)

    const body = await res.json()
    expect(body).toHaveProperty('message')
    expect(typeof body.message).toBe('string')
    expect(body.plugin).toBe('example')
    // mood field populated from the seeded moods collection
    expect(body).toHaveProperty('mood')
    expect(typeof body.mood).toBe('string')
  })

  test('GET /example/moods lists all published moods', async ({ request }) => {
    const res = await request.get(`${BASE}/example/moods`)
    expect(res.status()).toBe(200)

    const body = await res.json()
    expect(body).toHaveProperty('moods')
    expect(Array.isArray(body.moods)).toBe(true)
    // At least 1 mood seeded on boot
    expect(body.moods.length).toBeGreaterThanOrEqual(1)
    // Each mood has a name and emoji
    const first = body.moods[0]
    expect(first).toHaveProperty('name')
    expect(first).toHaveProperty('emoji')
  })

  test('GET /example/:name returns personalised greeting', async ({ request }) => {
    const res = await request.get(`${BASE}/example/traveller`)
    expect(res.status()).toBe(200)

    const body = await res.json()
    // The /:name route embeds the URL param in the response.
    expect(body.message).toContain('traveller')
    expect(body.plugin).toBe('example')
  })

  // ── Admin plugins list ─────────────────────────────────────────────────────

  test('plugin appears in /admin/plugins list', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/plugins')
    // The plugin self-registers via PluginService.ensurePlugin() in onBoot,
    // making it visible in the admin list without a manifest.json.
    await expect(page.locator('body')).toContainText('Example', { timeout: 10_000 })
  })

  // ── Admin page ─────────────────────────────────────────────────────────────

  test('admin page loads and shows plugin name', async ({ page }) => {
    await loginAsAdmin(page)
    const res = await page.goto('/admin/example')
    // Route must exist — not a 404.
    expect(res?.status()).toBeLessThan(400)
    // The admin page h1 should identify the plugin.
    await expect(page.locator('h1')).toContainText(/example/i)
  })

  test('admin page links to the public API', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/example')
    const apiLink = page.locator('a[href*="/example"]').first()
    await expect(apiLink).toBeVisible()
  })

  test('admin page has Manage Moods link to moods collection', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/example')
    const moodsLink = page.getByRole('link', { name: /manage moods/i })
    await expect(moodsLink).toBeVisible()
    await expect(moodsLink).toHaveAttribute('href', '/admin/content?model=example&page=1')
  })

  // ── Sidebar nav ────────────────────────────────────────────────────────────

  test('plugin settings page has View Page link to admin page', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/plugins/example')
    // _adminPath stored in settings on first boot → "View Page" button appears in header
    const viewLink = page.getByRole('link', { name: /view page/i })
    await expect(viewLink).toBeVisible()
    await expect(viewLink).toHaveAttribute('href', '/admin/example')
  })

  test('plugin menu entry appears in admin sidebar', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/content')
    // pluginMenuMiddleware merges plugin-menu-singleton entries (user plugins) into
    // the sidebar. The example plugin declares menu: [{ path: '/admin/example' }].
    const navLink = page.locator('nav a[href="/admin/example"]').first()
    await expect(navLink).toBeVisible()
    await expect(navLink).toContainText(/example/i)
  })
})
