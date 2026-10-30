import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

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
