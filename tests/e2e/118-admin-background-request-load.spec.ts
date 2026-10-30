import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * The admin shell's background traffic, as a budget.
 *
 * Both tests here guard the same failure mode from opposite ends: requests the admin UI issues on
 * its own, which outlive the document that started them and queue up behind each other. Measured
 * against a preview deployment, a browser moving between admin pages accumulated upwards of
 * twenty-five concurrent in-flight requests — eleven of them copies of the same migration-status
 * check — and once that backlog existed, plain navigations waited tens of seconds behind it. The
 * whole E2E suite read as "flaky" as a result.
 */
test.describe('Admin background request load @smoke', () => {
  // `false`: do not let the helper land on /admin. Both tests below count requests the dashboard
  // issues, and the helper's own landing would start a first dashboard document whose poller is
  // still running — and, in the overlap test, still holding an intercepted response — when the
  // test navigates to /admin itself. That second document's first tick then overlaps the first
  // document's last one and the test reads 2 concurrent requests from two pages rather than from
  // a broken hx-sync. Each test navigates itself, so exactly one dashboard is ever live.
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page, false)
  })

  test('checks migration status once per session, not once per page view', async ({ page }) => {
    // Every other test in the suite loads one page, which is what the 90s default is sized for.
    // This one deliberately loads four (the login redirect plus the loop below) to prove the
    // count does not grow with navigations, so it needs a budget that scales with them. Against a
    // cold preview an admin page load has been measured at ~10s p90, and the default left no room
    // for that.
    test.setTimeout(180_000)

    // The pending-migrations banner used to re-query on every admin page's DOMContentLoaded.
    // The endpoint reads the migration bundle and the d1_migrations table (1.0-5.7s measured),
    // and answers "0 pending" on every healthy install, so paying for it per navigation was pure
    // background load. The count is now cached in sessionStorage.
    let statusRequests = 0
    page.on('request', (r) => {
      if (r.url().includes('/admin/api/migrations/status')) statusRequests++
    })

    // Three navigations, not five: the regression is "once per page view", so the second and third
    // loads already distinguish a cached count from a per-navigation one. The extra two only added
    // page loads to a test that was timing out on page loads.
    const paths = ['/admin', '/admin/content', '/admin/media']
    for (const path of paths) {
      await page.goto(path, { waitUntil: 'domcontentloaded' })
      // The check runs from a DOMContentLoaded handler, so give it a turn to fire before moving on.
      await page.waitForTimeout(600)
    }

    expect(
      statusRequests,
      `migration status was requested ${statusRequests}x across ${paths.length} admin navigations; ` +
        'it should be served from the session cache after the first'
    ).toBeLessThanOrEqual(1)
  })

  test('does not let the dashboard metrics poll overlap itself', async ({ page }) => {
    // The poll fires on a wall clock ("every 1s"), so without hx-sync a response slower than the
    // interval starts a queue that only grows. Hold every response for longer than the interval
    // to make the difference deterministic: unguarded this window issues one request per second,
    // guarded it issues one per completed response.
    const RESPONSE_DELAY_MS = 2_000
    const WINDOW_MS = 8_000

    let issued = 0
    let inFlight = 0
    let peakInFlight = 0

    await page.route('**/admin/dashboard/api/metrics*', async (route) => {
      issued++
      inFlight++
      peakInFlight = Math.max(peakInFlight, inFlight)
      await new Promise((resolve) => setTimeout(resolve, RESPONSE_DELAY_MS))
      inFlight--
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '',
      })
    })

    await page.goto('/admin', { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(WINDOW_MS)

    // Nothing to assert about the poll if the dashboard never started it.
    expect(issued, 'dashboard never polled /admin/dashboard/api/metrics').toBeGreaterThan(0)

    expect(
      peakInFlight,
      `${peakInFlight} metrics requests were in flight at once; hx-sync should drop a tick whose ` +
        'predecessor has not answered yet'
    ).toBe(1)

    // One per delayed response, plus slack for timing at the window edges. Unguarded, a 1s
    // trigger over this window issues roughly WINDOW_MS/1000 requests instead.
    const unguardedEstimate = WINDOW_MS / 1_000
    expect(
      issued,
      `${issued} metrics requests in ${WINDOW_MS}ms with each response held ${RESPONSE_DELAY_MS}ms; ` +
        `an unguarded 1s poll would issue about ${unguardedEstimate}`
    ).toBeLessThan(unguardedEstimate)
  })
})
