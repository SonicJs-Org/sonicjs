import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 100-demo-login-stats.spec.ts", () => {
  // Demo-login telemetry (`POST /v1/events`) and the "Demo Site Logins" dashboard cards belong to
  // the separate `sonicjs-stats` worker (packages/stats → stats.sonicjs.com, own wrangler.toml +
  // D1). The CMS app under test does not register `statsDashboardPlugin`; probe at run time.
  test.describe('Demo login stats @stats', () => {
    let statsWorker = false

    test.beforeAll(async ({ request }) => {
      const res = await request.get('/stats-health').catch(() => null)
      statsWorker = !!res && res.ok()
    })

    test('/v1/events accepts demo_login event', async ({ request }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      const res = await request.post('/v1/events', {
        data: {
          data: {
            installation_id: 'demo-e2e-test',
            event_type: 'demo_login',
            properties: {},
            timestamp: new Date().toISOString(),
          },
        },
      })
      expect(res.status()).toBe(201)
      const body = await res.json()
      expect(body.success).toBe(true)
    })

    test('stats dashboard renders Demo Site Logins section', async ({ page }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      await loginAsAdmin(page)
      await page.goto('/admin/dashboard')
      await page.waitForLoadState('networkidle')

      await expect(page.locator('text=Demo Site Logins')).toBeVisible()
      await expect(page.locator('text=Daily Demo Logins')).toBeVisible()
    })

    test('stats dashboard shows demo login KPIs', async ({ page }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      await loginAsAdmin(page)
      await page.goto('/admin/dashboard')
      await page.waitForLoadState('networkidle')

      await expect(page.locator('text=Total Logins')).toBeVisible()
      await expect(page.locator('text=Last 30 Days')).toBeVisible()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 119-admin-dashboard-fragments.spec.ts", () => {
  /**
   * The dashboard's htmx fragments, as a contract.
   *
   * `/admin/dashboard/stats` and `/admin/dashboard/storage` each used to run their queries one
   * after another — four serial D1 round trips for four independent counts. They now go out
   * together, which is only safe if the rendered numbers are unchanged, so these tests pin the
   * rendered output rather than the implementation: every card present, counts that reflect real
   * rows, and one request per fragment per dashboard load.
   */
  test.describe('Admin dashboard fragments @smoke', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('stats cards report real counts, not placeholder zeroes', async ({ page }) => {
      await page.goto('/admin', { waitUntil: 'domcontentloaded' })

      const stats = page.locator('#stats-container')
      await expect(stats).toBeVisible()

      for (const label of ['Total Collections', 'Content Items', 'Media Files', 'Active Users']) {
        await expect(stats, `"${label}" card missing from the stats fragment`).toContainText(label)
      }

      // The skeleton and the dynamic-menu variant both render before the fragment answers, so the
      // card text alone proves nothing. Read the numbers: a seeded install always has at least one
      // collection and the admin account we just signed in as.
      // NaN while the skeleton is still up: it renders four pulsing placeholder boxes with no
      // label text and no `.text-2xl`, so the cell genuinely does not exist yet. Returning NaN
      // rather than throwing keeps the poll below retrying instead of failing on the first tick.
      const valueFor = async (label: string): Promise<number> => {
        const cell = stats
          .locator('div.px-4.py-5', { hasText: label })
          .first()
          .locator('div.text-2xl')
          .first()
        if ((await cell.count()) === 0) return NaN
        return Number((await cell.innerText()).trim())
      }

      await expect
        .poll(async () => valueFor('Total Collections'), {
          message: 'collections count never became non-zero — the stats fragment did not load',
          timeout: 20_000,
        })
        .toBeGreaterThan(0)

      expect(await valueFor('Active Users'), 'at least the signed-in admin should be counted').toBeGreaterThan(0)
    })

    test('storage usage renders database and media rows', async ({ page }) => {
      await page.goto('/admin', { waitUntil: 'domcontentloaded' })

      const storage = page.locator('#storage-usage-container')
      await expect(storage).toBeVisible()
      await expect(storage).toContainText('Storage Usage')
      await expect(storage).toContainText('Database')
      await expect(storage).toContainText('Media Files')
    })

    test('each dashboard fragment is fetched once per page load', async ({ page }) => {
      // Both fragments are mounted on `hx-trigger="load"`. Two containers with the same id — which
      // the two dashboard render functions make easy to reintroduce — would double the admin
      // shell's startup traffic against endpoints that query D1.
      // Park on a page that mounts none of these fragments first. loginAsAdmin lands on /admin, and
      // its htmx triggers can still be firing when the test body starts — those requests belong to
      // the previous load but would be counted against this one.
      await page.goto('/admin/content', { waitUntil: 'domcontentloaded' })
      await page.waitForTimeout(1_000)

      const counts = new Map<string, number>()
      page.on('request', (r) => {
        const match = r.url().match(/\/admin\/dashboard\/(stats|storage|recent-activity)(\?|$)/)
        if (match) counts.set(match[1]!, (counts.get(match[1]!) ?? 0) + 1)
      })

      await page.goto('/admin', { waitUntil: 'domcontentloaded' })
      // Same 20s budget the first test in this file already gives this fragment. On a cold preview
      // isolate the load-triggered request can still be in flight well past the default 5s — CI run
      // 39605228238 failed here with the container still carrying `htmx-request` and holding the
      // skeleton's empty divs. Waiting longer costs nothing when the fragment is fast.
      await expect(page.locator('#stats-container')).toContainText('Total Collections', {
        timeout: 20_000,
      })
      await page.waitForTimeout(2_000)

      for (const fragment of ['stats', 'storage', 'recent-activity']) {
        expect(
          counts.get(fragment) ?? 0,
          `/admin/dashboard/${fragment} was requested ${counts.get(fragment) ?? 0}x on one dashboard load`
        ).toBe(1)
      }
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 123-admin-page-weight.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 71-home-link-redirect.spec.ts", () => {
  test.describe('Home Link and Admin Redirect @smoke', () => {
    test('/admin redirects to /admin/dashboard', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin');

      // Should redirect to /admin/dashboard
      await expect(page).toHaveURL('/admin/dashboard');
    });

  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 97-stats-dashboard-fixes.spec.ts", () => {
  // The telemetry ingest endpoint (`POST /v1/events`) and the install/snapshot dashboard cards are
  // served by the separate `sonicjs-stats` worker (packages/stats, deployed to stats.sonicjs.com,
  // with its own wrangler.toml and D1 database). The CMS app under test never registers
  // `statsDashboardPlugin`, so those surfaces only exist when the stats worker is the deployment
  // being pointed at. Detected at run time via its health endpoint.
  test.describe('Stats dashboard data parsing @stats', () => {
    let statsWorker = false

    test.beforeAll(async ({ request }) => {
      const res = await request.get('/stats-health').catch(() => null)
      statsWorker = !!res && res.ok()
    })

    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('dashboard renders without JS errors', async ({ page }) => {
      const errors: string[] = []
      page.on('pageerror', (err) => errors.push(err.message))

      await page.goto('/admin/dashboard')
      await page.waitForLoadState('networkidle')

      expect(errors.filter((e) => !e.includes('Chart'))).toHaveLength(0)
    })

    test('install failures table has Step and Version columns', async ({ page }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      await page.goto('/admin/dashboard')
      await page.waitForLoadState('networkidle')

      const failuresCard = page.locator('text=Install Failures').first()
      await expect(failuresCard).toBeVisible()

      const headers = page.locator('th')
      const headerTexts = await headers.allTextContents()
      const normalized = headerTexts.map((t) => t.toLowerCase())

      // Table should have Step and Version columns (not just Error + Count)
      expect(normalized.some((h) => h.includes('step'))).toBe(true)
      expect(normalized.some((h) => h.includes('version'))).toBe(true)
    })

    test('What People Build section renders when snapshot data exists', async ({ page }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      await page.goto('/admin/dashboard')
      await page.waitForLoadState('networkidle')

      await expect(page.locator('text=What People Build')).toBeVisible()
      // Section header is always present; charts render if data exists
      await expect(page.locator('text=Top Collections')).toBeVisible()
      await expect(page.locator('text=Active Plugins')).toBeVisible()
    })

    test('/v1/events accepts project_snapshot payload', async ({ request }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      const res = await request.post('/v1/events', {
        data: {
          data: {
            installation_id: 'test-e2e-install',
            event_type: 'project_snapshot',
            properties: {
              installation_id: 'test-e2e-install',
              collection_names: '["test_col"]',
              collection_counts: '{"test_col":5}',
              active_plugins: '["Test Plugin"]',
              field_type_histogram: '{"string":3}',
              doc_total: 5,
              sonicjs_version: '3.0.0-test',
            },
          },
        },
      })
      expect(res.status()).toBe(201)
      const body = await res.json()
      expect(body.success).toBe(true)
    })

    test('/v1/events accepts installation_failed with step', async ({ request }) => {
      test.skip(!statsWorker, 'Stats surfaces live in the separate sonicjs-stats worker (packages/stats)')
      const res = await request.post('/v1/events', {
        data: {
          data: {
            installation_id: 'test-e2e-fail',
            event_type: 'installation_failed',
            properties: {
              errorType: 'Command failed with exit code 1',
              step: 'db_migrate',
              version: '3.0.0-test',
            },
          },
        },
      })
      expect(res.status()).toBe(201)
    })
  })
})
