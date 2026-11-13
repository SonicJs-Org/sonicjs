import { test, expect } from './fixtures'
import type { Page } from './fixtures'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'

const PLUGIN = 'query-trace'
const PANEL = '#sjs-trace-panel'

// Plugin on/off state is global to the installation, so the scenarios run serially
// and the whole describe holds a lock against other specs.
test.describe('Query Trace plugin @plugins @lock-query-trace', () => {
  test.describe.configure({ mode: 'serial' })

  let page: Page
  let installedByTest = false
  // Install state before the suite ran: 'uninstalled' | 'inactive' | 'active' (card data-status).
  let originalStatus = 'uninstalled'

  async function setVisibility(visibility: 'opt-in' | 'all-admins') {
    const csrf = await getCsrfTokenFromPage(page)
    const res = await page.request.post(`/admin/plugins/${PLUGIN}/configure`, {
      headers: { Origin: TEST_ORIGIN, 'X-CSRF-Token': csrf },
      multipart: {
        visibility,
        warnQueryMs: '25',
        slowQueryMs: '100',
        captureCallers: 'on',
        serverTimingHeader: 'on',
        maxEntries: '1000',
      },
    })
    expect(res.ok(), `configure failed: ${res.status()}`).toBe(true)
  }

  async function clearTraceCookie() {
    await page.context().clearCookies({ name: 'sjs_trace' })
  }

  // Plugin state is cached per isolate for up to 30s; poll so multi-isolate deployments converge.
  async function expectPanel(url: string, visible: boolean) {
    await expect
      .poll(
        async () => {
          const res = await page.request.get(url)
          return (await res.text()).includes('id="sjs-trace-panel"')
        },
        { timeout: 45_000, intervals: [500, 1000, 2000] }
      )
      .toBe(visible)
  }

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext()
    page = await ctx.newPage()
    await loginAsAdmin(page)
    // Snapshot whatever state existed before the suite so afterAll can restore it.
    await page.goto('/admin/plugins')
    originalStatus = (await page.locator('.plugin-card[data-name="Query Trace"]').first().getAttribute('data-status')) ?? 'uninstalled'
    // Start from the fresh-install state: not installed.
    if (originalStatus !== 'uninstalled') {
      const res = await page.request.post(`/admin/plugins/${PLUGIN}/uninstall`, { headers: { Origin: TEST_ORIGIN } })
      expect(res.ok(), `initial uninstall failed: ${res.status()}`).toBe(true)
    }
  })

  test.afterAll(async () => {
    try {
      const un = await page.request.post(`/admin/plugins/${PLUGIN}/uninstall`, { headers: { Origin: TEST_ORIGIN } })
      // Uninstalling something already gone may legitimately fail; only a failure while installed matters.
      expect(un.ok() || !installedByTest, `final uninstall failed: ${un.status()}`).toBe(true)
      if (originalStatus !== 'uninstalled') {
        const inst = await page.request.post('/admin/plugins/install', {
          data: { name: PLUGIN, id: PLUGIN },
          headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
        })
        expect(inst.ok(), `restore install failed: ${inst.status()}`).toBe(true)
        if (originalStatus === 'inactive') {
          const off = await page.request.post(`/admin/plugins/${PLUGIN}/deactivate`, { headers: { Origin: TEST_ORIGIN } })
          expect(off.ok(), `restore deactivate failed: ${off.status()}`).toBe(true)
        }
      }
    } finally {
      await page.context().close()
    }
  })

  test('not installed: no panel, no Server-Timing', async () => {
    await page.goto('/admin/plugins')
    await expect(page.getByText('Query Trace').first()).toBeVisible()
    const res = await page.request.get('/admin/dashboard?trace=1', { maxRedirects: 0 })
    expect(res.headers()['server-timing']).toBeUndefined()
    await clearTraceCookie()
    await expectPanel('/admin/dashboard', false)
  })

  test('install → active, but opt-in default shows nothing without the cookie', async () => {
    const res = await page.request.post('/admin/plugins/install', {
      data: { name: PLUGIN, id: PLUGIN },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(res.ok()).toBe(true)
    installedByTest = true
    await clearTraceCookie()
    await expectPanel('/admin/dashboard', false)
  })

  test('?trace=1 redirects clean and panel is collapsed with a summary', async () => {
    await expectPanel('/admin/dashboard', false)
    // Another isolate may still hold the pre-install cached state (30s TTL); retry until one that sees it serves us.
    await expect
      .poll(
        async () => {
          await page.goto('/admin/dashboard?trace=1')
          return (await page.locator(PANEL).count()) > 0 && !page.url().includes('trace=')
        },
        { timeout: 45_000, intervals: [500, 1000, 2000] }
      )
      .toBe(true)
    const panel = page.locator(PANEL)
    await expect(panel).toBeAttached()
    await expect(panel).not.toHaveAttribute('open', '')
    const summary = page.getByTestId('trace-summary')
    await expect(summary).toContainText(/\d+(\.\d+)? ms server/)
    await expect(summary).toContainText(/\d+ D1/)
  })

  test('expanded panel lists queries sorted by duration with a cache column', async () => {
    await page.goto('/admin/dashboard')
    await page.getByTestId('trace-summary').click()
    const rows = page.getByTestId('trace-queries').locator('tbody tr')
    expect(await rows.count()).toBeGreaterThanOrEqual(1)
    const ms = async (i: number) => parseFloat((await rows.nth(i).locator('td').first().innerText()).trim())
    if ((await rows.count()) > 1) expect(await ms(0)).toBeGreaterThanOrEqual(await ms(1))
    await expect(rows.first().locator('td').nth(7)).toHaveText(/not cached|hit|miss/)
    await expect(page.getByTestId('trace-copy-json')).toBeVisible()
  })

  test('panel and Server-Timing persist on content and users pages', async () => {
    for (const url of ['/admin/content', '/admin/users']) {
      const res = await page.request.get(url)
      expect(res.headers()['server-timing'], url).toMatch(/total;dur=/)
      expect(await res.text(), url).toContain('id="sjs-trace-panel"')
    }
  })

  test('all-admins shows the panel without opt-in; reset to opt-in', async () => {
    await setVisibility('all-admins')
    await clearTraceCookie()
    await expectPanel('/admin/dashboard', true)
    await setVisibility('opt-in')
    await expectPanel('/admin/dashboard', false)
  })

  test('?trace=0 removes the panel; deactivating disables ?trace=1', async () => {
    await expect
      .poll(
        async () => {
          await page.goto('/admin/dashboard?trace=1')
          return (await page.locator(PANEL).count()) > 0
        },
        { timeout: 45_000, intervals: [500, 1000, 2000] }
      )
      .toBe(true)
    // ?trace=0 clears the cookie; retry with a fresh load so a lagging isolate can't flake this.
    await expect
      .poll(
        async () => {
          await page.goto('/admin/dashboard?trace=0')
          await page.reload()
          return await page.locator(PANEL).count()
        },
        { timeout: 45_000, intervals: [500, 1000, 2000] }
      )
      .toBe(0)

    const res = await page.request.post(`/admin/plugins/${PLUGIN}/deactivate`, { headers: { Origin: TEST_ORIGIN } })
    expect(res.ok()).toBe(true)
    // Deactivation only invalidates the serving isolate's cache; others converge within the 30s TTL.
    await expect
      .poll(
        async () => {
          await page.goto('/admin/dashboard?trace=1')
          return await page.locator(PANEL).count()
        },
        { timeout: 45_000, intervals: [500, 1000, 2000] }
      )
      .toBe(0)
    // Same URL as the poll above: without ?trace=1 opt-in visibility makes "absent" trivially true.
    await expectPanel('/admin/dashboard?trace=1', false)
  })

  test('anonymous request gets no Server-Timing even in all-admins mode', async ({ playwright }) => {
    expect(installedByTest).toBe(true)
    await page.request.post(`/admin/plugins/${PLUGIN}/activate`, { headers: { Origin: TEST_ORIGIN } })
    await setVisibility('all-admins')
    try {
      await expectPanel('/admin/dashboard', true)
      const anon = await playwright.request.newContext({ baseURL: TEST_ORIGIN })
      const res = await anon.get('/admin/dashboard', { maxRedirects: 0 })
      expect(res.headers()['server-timing']).toBeUndefined()
      expect(await res.text()).not.toContain('sjs-trace-panel')
      await anon.dispose()
    } finally {
      await setVisibility('opt-in')
    }
  })
})
