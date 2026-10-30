import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Chart.js belongs to the pages that chart, not to the shared admin layout.
 *
 * It used to be a plain `<script src>` in both admin layouts, so every admin page in the app
 * downloaded and executed ~200KB of charting library for a global nothing on the page touched.
 * That is paid by every visitor on every navigation, and in CI it is paid four times over at
 * once: the E2E job runs Chromium workers on a four-vCPU runner, and the measured failure mode
 * there is renderers contending for cores, not a slow server.
 *
 * So this asserts the split in both directions. A page that does not chart must not pull the
 * library in, and the dashboard — the one core page that does — must still get it and still draw.
 */
test.describe('Admin page weight @smoke', () => {
  const CHART_JS = /chart\.umd(\.min)?\.js/

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('pages that do not chart neither request nor define Chart.js', async ({ page }) => {
    const chartRequests: string[] = []
    page.on('request', (req) => {
      if (CHART_JS.test(req.url())) chartRequests.push(req.url())
    })

    for (const path of ['/admin/content', '/admin/media', '/admin/users']) {
      await page.goto(path, { waitUntil: 'domcontentloaded' })

      // The markup must not reference it...
      expect(
        await page.locator(`script[src*="chart.umd"]`).count(),
        `${path} still has a Chart.js script tag`
      ).toBe(0)

      // ...and nothing else may have smuggled the global in either. `typeof` rather than a
      // truthiness check so an undefined global reads as "absent" instead of throwing.
      expect(
        await page.evaluate(() => typeof (window as { Chart?: unknown }).Chart),
        `${path} defined a global Chart`
      ).toBe('undefined')
    }

    expect(
      chartRequests,
      `non-charting pages fetched Chart.js: ${chartRequests.join(', ')}`
    ).toEqual([])
  })

  test('the dashboard still loads Chart.js and draws its chart', async ({ page }) => {
    await page.goto('/admin/dashboard', { waitUntil: 'domcontentloaded' })

    await expect(page.locator('script[src*="chart.umd"]')).toHaveCount(1)
    await expect(page.locator('canvas#requestsChart')).toBeVisible()

    // The library has to actually arrive and run — a script tag alone would pass the check above
    // while leaving the canvas blank. Chart.js registers its constructor on `window`.
    await expect
      .poll(
        () => page.evaluate(() => typeof (window as { Chart?: unknown }).Chart),
        { message: 'Chart.js never defined window.Chart on the dashboard', timeout: 15_000 }
      )
      .toBe('function')

    // And the canvas is sized by Chart.js once it has taken it over, so a non-zero box means the
    // chart was constructed rather than merely that the element exists.
    const box = await page.locator('canvas#requestsChart').boundingBox()
    expect(box?.width ?? 0, 'the chart canvas has no width').toBeGreaterThan(0)
  })
})
