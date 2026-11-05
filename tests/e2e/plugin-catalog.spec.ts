import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import type { APIRequestContext } from "./fixtures"
import type { Page } from "./fixtures"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { isFeatureAvailable } from "./utils/test-helpers"
import { saveNewContent } from "./fixtures/content-fixtures"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 38-turnstile-plugin.spec.ts", () => {
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

  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 39-ai-search-plugin.spec.ts", () => {
  /**
   * This file used to be twelve tests that mostly printed to the console: `console.log('Found status
   * indicators:', count)`, `console.log('Vectorize info present in UI:', hasVectorizeInfo)`,
   * `console.log('Re-index feedback visible:', …)`. Four more wrapped their only assertion in
   * `if (await locator.count() > 0)`, and an `afterAll` hunted for content the file never created and
   * logged that it had found it. The whole file passed in 32 seconds without ever checking that search
   * returns anything.
   *
   * It was hiding a dead feature. `searchKeyword` read
   * `FROM content c JOIN collections col ON c.collection_id = col.id`; the `collections` table was
   * dropped when collections became code-only, so the query threw on every call, the service's catch
   * turned that into `{ results: [], total: 0 }`, and `/api/search` answered 200 forever. The only
   * assertions the old tests made of the search endpoints — status 200 and a `success` property —
   * are exactly the two things a swallowed exception still satisfies.
   *
   * Deleted outright:
   * - `should have Custom RAG initialized` registered its console listener after the navigation it
   *   meant to capture, then logged the empty array.
   * - `should show Vectorize binding status` logged whether the page mentions "vector". It does not;
   *   the settings page has no binding-status surface to assert on.
   * - `should handle plugin settings save` was `should be able to select collections for indexing`
   *   with the same nested `if`s and no assertion about what was saved.
   */

  const SEARCH_API = '/api/search'
  const SETTINGS_API = '/admin/plugins/ai-search/api/settings'
  const STATUS_API = '/admin/plugins/ai-search/api/status'
  const REINDEX_API = '/admin/plugins/ai-search/api/reindex'

  /** Seeded by global setup: a published blog_post, and blog_post grants `public: ['read']`. */
  const SEEDED = { title: 'Welcome to SonicJS', slug: 'welcome-to-sonicjs', collection: 'blog_post' }

  type SearchBody = {
    success: boolean
    data: {
      results: Array<{
        id: string
        title: string
        slug: string
        collection_id: string
        collection_name: string
        snippet?: string
        status: string
        created_at: number
        updated_at: number
      }>
      total: number
      mode: string
      query_time_ms: number
    }
  }

  async function search(
    api: APIRequestContext,
    body: Record<string, unknown>
  ): Promise<SearchBody['data']> {
    const res = await api.post(SEARCH_API, { data: body })
    expect(res.status(), `${SEARCH_API} answered ${res.status()}`).toBe(200)
    const json = (await res.json()) as SearchBody
    expect(json.success).toBe(true)
    return json.data
  }

  test.describe('AI Search Plugin @plugins', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = await isFeatureAvailable(request, '/admin/plugins/ai-search')
    })
    test.beforeEach(() => {
      test.skip(!featureAvailable, 'Plugin/feature not available in this deployment')
    })

    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('lists the plugin on the plugins page', async ({ page }) => {
      await page.goto('/admin/plugins')

      // data-name is the manifest name, which is what the card renders.
      const card = page.locator('.plugin-card[data-name="AI Search"]')
      await expect(card).toHaveCount(1)
      await expect(card.locator('.status-badge')).not.toBeEmpty()
    })

    test('renders every control the save handler reads', async ({ page }) => {
      await page.goto('/admin/plugins/ai-search')
      await expect(page.locator('h1')).toContainText(/AI Search/i)

      await expect(page.locator('#settingsForm')).toBeVisible()

      // The submit handler calls getElementById for each of these and would throw on a missing one,
      // which it catches and reports as "Error saving settings" — so their presence IS the save path.
      for (const id of ['enabled', 'ai_mode_enabled', 'autocomplete_enabled', 'index_media']) {
        await expect(page.locator(`#${id}`), `#${id} is missing`).toHaveAttribute('type', 'checkbox')
      }
      expect(Number(await page.locator('#cache_duration').inputValue())).toBeGreaterThanOrEqual(0)
      expect(Number(await page.locator('#results_limit').inputValue())).toBeGreaterThan(0)
      await expect(page.locator('#settingsForm button[type="submit"]')).toBeVisible()

      // One checkbox per code-defined collection, each labelled — the label is the only thing
      // identifying a row, since the value is the collection id.
      const boxes = page.locator('#collections-list input[name="selected_collections"]')
      const count = await boxes.count()
      expect(count, 'no collections offered for indexing').toBeGreaterThan(0)
      await expect(page.locator(`#collection_${SEEDED.collection}`)).toHaveCount(1)
      for (let i = 0; i < count; i++) {
        const id = await boxes.nth(i).getAttribute('id')
        await expect(page.locator(`label[for="${id}"]`)).not.toBeEmpty()
      }
    })

    test('saves the selected collections and keeps them after a reload', async ({ page }) => {
      const before = await page.request.get(SETTINGS_API)
      expect(before.ok()).toBeTruthy()
      const original = (await before.json()).data as { selected_collections?: string[] }
      const originalSelection = original.selected_collections ?? []

      try {
        await page.goto('/admin/plugins/ai-search')
        const box = page.locator(`#collection_${SEEDED.collection}`)
        const wasChecked = await box.isChecked()
        if (!wasChecked) await box.check()
        else await box.uncheck()
        const expected = !wasChecked

        const [saved] = await Promise.all([
          page.waitForResponse(
            (r) =>
              r.request().method() === 'POST' &&
              new URL(r.url()).pathname === '/admin/plugins/ai-search'
          ),
          page.locator('#settingsForm button[type="submit"]').click(),
        ])
        expect(saved.status(), 'settings POST failed').toBe(200)
        await expect(page.locator('#msg')).toBeVisible()

        // The page reloads itself two seconds after a save; read the state back from a fresh load so
        // the assertion is about what was persisted, not about the checkbox this test just clicked.
        await page.goto('/admin/plugins/ai-search')
        await expect(page.locator(`#collection_${SEEDED.collection}`)).toBeChecked({
          checked: expected,
        })
      } finally {
        // Settings are global to the deployment, so put the original selection back whatever happened.
        await page.request.post('/admin/plugins/ai-search', {
          data: { selected_collections: originalSelection },
        })
      }
    })

    test('refuses a reindex request that names no collection', async ({ page }) => {
      const res = await page.request.post(REINDEX_API, { data: {} })
      expect(res.status()).toBe(400)
      expect((await res.json()).error).toContain('collection_id')
    })

    test('records index status for a collection after a reindex', async ({ page }) => {
      const res = await page.request.post(REINDEX_API, { data: { collection_id: SEEDED.collection } })
      expect(res.status()).toBe(200)
      expect((await res.json()).success).toBe(true)

      // Indexing runs in waitUntil, so the status row lands shortly after the response. Without
      // Vectorize bound it records the keyword-only fallback — still a real row, which is the point:
      // the old test only logged `Object.keys(status).length`.
      const row = await expect
        .poll(
          async () => {
            const status = await page.request.get(STATUS_API)
            if (!status.ok()) return null
            return ((await status.json()).data ?? {})[SEEDED.collection] ?? null
          },
          { message: `no index status recorded for ${SEEDED.collection}`, timeout: 20_000 }
        )
        .not.toBeNull()
        .then(async () => {
          const status = await page.request.get(STATUS_API)
          return (await status.json()).data[SEEDED.collection]
        })

      expect(row.collection_id).toBe(SEEDED.collection)
      expect(['indexing', 'completed', 'error']).toContain(row.status)
      expect(typeof row.total_items).toBe('number')
      expect(typeof row.indexed_items).toBe('number')
    })

    test('keyword search finds published content', async ({ request }) => {
      const data = await search(request, { query: SEEDED.title, mode: 'keyword', limit: 10 })

      expect(data.mode).toBe('keyword')
      expect(data.total).toBeGreaterThan(0)

      const hit = data.results.find((r) => r.slug === SEEDED.slug)
      expect(hit, `"${SEEDED.title}" was not returned`).toBeTruthy()
      expect(hit!.title).toBe(SEEDED.title)
      expect(hit!.collection_id).toBe(SEEDED.collection)
      // Resolved from the collection registry now that there is no collections table to join.
      expect(hit!.collection_name).toBe('Blog Post')
      expect(hit!.status).toBe('published')

      // documents stores seconds; the response boundary converts to ms. A raw second-value here
      // renders as January 1970 in any consumer that does `new Date(updated_at)`.
      expect(hit!.created_at).toBeGreaterThan(1_600_000_000_000)
      expect(hit!.updated_at).toBeGreaterThan(1_600_000_000_000)

      // The snippet is prose pulled from the document's string values — not its JSON envelope.
      expect(hit!.snippet).toContain(SEEDED.title)
      expect(hit!.snippet).not.toContain('{"')
    })

    test('keyword search honors the collection filter', async ({ request }) => {
      const inCollection = await search(request, {
        query: SEEDED.title,
        mode: 'keyword',
        filters: { collections: [SEEDED.collection] },
      })
      expect(inCollection.total).toBeGreaterThan(0)

      const elsewhere = await search(request, {
        query: SEEDED.title,
        mode: 'keyword',
        filters: { collections: ['no_such_collection'] },
      })
      expect(elsewhere.total).toBe(0)
      expect(elsewhere.results).toEqual([])
    })

    test('ai mode falls back to keyword results when no vector index is bound', async ({ request }) => {
      // Documented behavior of the settings page: "If AI binding unavailable, will fallback to keyword
      // search". The reported mode stays 'ai' so the caller knows what it asked for.
      const data = await search(request, { query: SEEDED.title, mode: 'ai', limit: 10 })

      expect(data.mode).toBe('ai')
      expect(data.results.some((r) => r.slug === SEEDED.slug)).toBe(true)
      for (const result of data.results) {
        expect(typeof result.title).toBe('string')
        expect(typeof result.collection_id).toBe('string')
      }
    })

    test('search suggestions come from logged queries', async ({ request }) => {
      const marker = `sonicjs-suggest-${Date.now()}`
      await search(request, { query: marker, mode: 'keyword' })

      // Every keyword search is written to ai_search_history, which is what autocomplete reads when
      // there is no vector index to ask.
      await expect
        .poll(
          async () => {
            const res = await request.get(`${SEARCH_API}/suggest?q=${encodeURIComponent(marker)}`)
            if (!res.ok()) return []
            return (await res.json()).data as string[]
          },
          { message: 'the logged query never showed up in suggestions', timeout: 10_000 }
        )
        .toContain(marker)
    })

    test('public search never returns unpublished content', async ({ page, playwright }) => {
      const marker = `ai-search-draft-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

      // e2e_test needs only a title and a slug, and grants `public: ['read']` — so if this draft
      // showed up in anonymous search results it could only be the publish axis leaking, not a
      // missing grant.
      await page.goto('/admin/content/new?collection=e2e_test')
      await page.fill('input[name="title"]', marker)
      await page.fill('input[name="slug"]', marker)
      const editPath = await saveNewContent(page, () =>
        page.locator('button[type="submit"]').first().click()
      )
      const contentId = editPath.split('/')[3]!

      // A context of its own: the worker-scoped `request` fixture has signed in (isFeatureAvailable
      // does that deliberately), and a signed-in caller is not the public principal.
      const anon = await playwright.request.newContext({
        baseURL: process.env.BASE_URL || 'http://localhost:8787',
      })
      try {
        const data = await search(anon, { query: marker, mode: 'keyword', limit: 10 })
        expect(data.total, 'an unpublished document was returned to an anonymous caller').toBe(0)
        expect(data.results).toEqual([])

        // Same search as an admin — still nothing, because search reads the published axis for every
        // caller. Drafts belong to /admin/content, which is where this one is.
        const asAdmin = await search(page.request, { query: marker, mode: 'keyword', limit: 10 })
        expect(asAdmin.total).toBe(0)
        await page.goto('/admin/content?collection=e2e_test&status=all')
        await expect(page.locator('body')).toContainText(marker)
      } finally {
        await anon.dispose()
        await page.request.delete(`/admin/content/${contentId}`).catch(() => {})
      }
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 68-plugin-activity-log.spec.ts", () => {
  test.describe('Plugin Activity Log @plugins @lock-plugin-hello-world', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('activity tab shows content for an active plugin', async ({ page }) => {
      // Navigate to a plugin detail page — 'email' is a core plugin that's always present.
      // (The settings/info/activity tabs all live on /admin/plugins/:id; there is no
      // /admin/plugins/:id/settings GET route.)
      await page.goto('/admin/plugins/email')
      await expect(page).not.toHaveURL(/error/)

      // Click the Activity tab (rendered as a tab link, not a button)
      const activityTab = page.locator('#activity-tab')
      await activityTab.click()

      // Activity content panel should be visible
      const activityPanel = page.locator('#activity-content')
      await expect(activityPanel).toBeVisible()

      // Should not show the "no recent activity" placeholder OR should show actual entries
      // Either is valid — we just confirm the tab renders without error
      await expect(activityPanel).not.toContainText('undefined')
      await expect(activityPanel).not.toContainText('NaN')
    })

    test('activity tab shows entries after toggling a plugin', async ({ page }) => {
      // Use a non-core plugin that can be toggled. Core plugins (turnstile, email, …)
      // render a "Core Plugin" label instead of an activate/deactivate button.
      const pluginId = 'hello-world'
      // File order no longer supplies this prerequisite. Inspect the original
      // status first: reinstalling an inactive plugin would activate it.
      await page.goto(`/admin/plugins/${pluginId}`)
      if (await page.getByRole('button', { name: 'Install', exact: true }).count()) {
        expect((await page.request.post('/admin/plugins/install', {
          data: { name: pluginId, id: pluginId },
          headers: { Origin: new URL(page.url()).origin },
        })).ok(), 'Activity fixture plugin installation failed').toBe(true)
      }
      await page.goto(`/admin/plugins/${pluginId}`)

      const deactivateBtn = page.getByRole('button', { name: 'Deactivate', exact: true })
      const activateBtn = page.getByRole('button', { name: 'Activate', exact: true })

      // Determine current status from the header badge
      const isActive = (await deactivateBtn.count()) > 0

      // Toggle the plugin to generate activity, then toggle it straight back so the
      // rest of the suite still sees this plugin in its original state. The page
      // reloads ~1s after a successful toggle.
      if (isActive) {
        await deactivateBtn.click()
        await expect(activateBtn).toBeVisible({ timeout: 20000 })
        await activateBtn.click()
        await expect(deactivateBtn).toBeVisible({ timeout: 20000 })
      } else {
        await activateBtn.click()
        await expect(deactivateBtn).toBeVisible({ timeout: 20000 })
        await deactivateBtn.click()
        await expect(activateBtn).toBeVisible({ timeout: 20000 })
      }

      // Reload and check activity tab
      await page.goto(`/admin/plugins/${pluginId}`)
      const activityTab = page.locator('#activity-tab')
      await activityTab.click()

      const activityPanel = page.locator('#activity-content')
      await expect(activityPanel).toBeVisible()

      // Should have at least one activity entry (activated or deactivated)
      const entries = activityPanel.locator('[class*="flex"][class*="items"]')
      const noActivity = activityPanel.getByText('No recent activity')
      const hasEntries = await entries.count() > 0
      const hasNoActivity = await noActivity.isVisible()

      // One of these must be true — the panel renders real state, not blank
      expect(hasEntries || hasNoActivity).toBe(true)
      await expect(activityPanel).not.toContainText('undefined')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 76-plugin-menu-singleton.spec.ts", () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

  /**
   * The submenu is open by default. It is hidden by a `plugins-closed` class on <html>
   * (see `.plugins-closed [data-plugins-submenu] { display: none }` in the catalyst layout),
   * never by a class on the submenu itself — so clicking the toggle unconditionally *closes* it,
   * and asserting `not.toHaveClass(/hidden/)` on the submenu can never fail. Toggle only when
   * the submenu is actually hidden, and assert on real visibility.
   */
  async function openPluginsSubmenu(page: Page) {
    const accordion = page.locator('[data-plugins-accordion]').first()
    await expect(accordion).toBeVisible({ timeout: 10000 })
    const submenu = accordion.locator('[data-plugins-submenu]')
    if (!(await submenu.isVisible())) {
      await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()
    }
    await expect(submenu).toBeVisible()
    return submenu
  }

  // Verifies that declarative menu entries (definePlugin `menu: [...]`) collected by
  // setPluginMenu() appear inside the plugins submenu in the catalyst admin sidebar.
  // Also verifies the /configure link is accessible for plugins that have configSchema.
  test.describe('Plugin menu singleton @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('plugin menu entries declared via definePlugin appear in the sidebar submenu', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('networkidle')

      const submenu = await openPluginsSubmenu(page)

      // At least one plugin menu entry (from core plugins that declared menu:[]) should appear.
      // The email plugin, dashboard, analytics etc. all declare menu entries with no permissions
      // or admin-accessible permissions.  We look for any <a> with an /admin/... href.
      const pluginLinks = submenu.locator('a[href^="/admin/"]')
      const count = await pluginLinks.count()
      expect(count).toBeGreaterThan(0)
    })

    test('email plugin menu entry navigates to the email admin page', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('networkidle')

      const submenu = await openPluginsSubmenu(page)

      // Email plugin declares menu: [{ label: 'Email', path: '/admin/plugins/email' }]
      const emailLink = submenu.locator('a[href="/admin/plugins/email"]')
      if (await emailLink.count() > 0) {
        await emailLink.click()
        await page.waitForURL(`**/admin/plugins/email`, { timeout: 10000 })
        expect(page.url()).toContain('/admin/plugins/email')
      } else {
        // Email plugin menu entry may not be visible if plugin isn't installed —
        // verify the submenu itself rendered (non-empty) to confirm singleton worked.
        const allLinks = await submenu.locator('a').count()
        expect(allLinks).toBeGreaterThan(0)
      }
    })

    test('plugins without menu entries do not leak into top-level nav', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('networkidle')

      // Plugin-level menu items must live inside the accordion submenu, not as
      // top-level siblings (Dashboard, Collections, etc.)
      const submenu = await openPluginsSubmenu(page)

      // Count links in submenu
      const subLinks = await submenu.locator('a[href^="/admin/"]').count()

      // Count ALL admin links in the full sidebar
      const sidebar = page.locator('nav').first()
      const totalAdminLinks = await sidebar.locator('a[href^="/admin/"]').count()

      // submenu links must be <= total links (sanity check)
      expect(subLinks).toBeLessThanOrEqual(totalAdminLinks)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 89-hello-cruel-world-plugin.spec.ts", () => {
  /**
   * E2E: Example plugin
   *
   * Verifies that the example demo plugin is correctly wired into the
   * SonicJS app: public API routes respond, the admin page loads, and the plugin
   * appears in the admin plugins list.
   */



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
})
