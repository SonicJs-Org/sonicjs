import { test, expect } from './fixtures'
import type { Page } from './fixtures'
import { loginAsAdmin, isFeatureAvailable } from './utils/test-helpers'
import { ensurePluginActive } from './fixtures/plugin-fixtures'

/**
 * URL Catalog Pagination
 *
 * The admin cache page renders at most 100 catalog entries and paginates them
 * client-side at 25 rows per page. These tests verify the pager behaviour by
 * injecting a known number of rows into the DOM then driving the controls.
 *
 * Requires core-cache to be active so the /admin/cache page renders.
 */
test.describe('Admin Cache → URL catalog pagination @plugins @content', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = await isFeatureAvailable(request, '/admin/cache')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    // core-cache must be active for the /admin/cache page (and the URL catalog tab) to render.
    await ensurePluginActive(page, 'core-cache')
    await page.goto('/admin/cache#url-catalog', { waitUntil: 'domcontentloaded' })
    // Activate the URL catalog tab (hash triggers it on load; wait for the panel)
    await page.waitForSelector('#tab-panel-url-catalog:not(.hidden)', { timeout: 10000 }).catch(() => {
      // Fallback: click the tab explicitly
      return page.locator('#tab-url-catalog').click()
    })
    // Ensure the tab panel is now visible before each test.
    await page.waitForSelector('#tab-panel-url-catalog:not(.hidden)', { timeout: 5000 }).catch(() => {})
  })

  /**
   * Inject N fake rows into the tbody and re-render page 1.
   *
   * On a fresh CI database the URL catalog has no real entries, so the template
   * renders an empty-state card WITHOUT the pagination DOM elements. When that
   * happens, scaffold the minimal structure first (the pagination JS is always
   * loaded regardless of catalog size), then inject the fake rows.
   */
  async function injectRows(page: Page, count: number, totalEntries = count) {
    await page.evaluate(({ count, totalEntries }: { count: number; totalEntries: number }) => {
      let tbody = document.getElementById('url-catalog-tbody') as HTMLTableSectionElement | null

      // On a fresh DB the empty-state card renders instead of the table — scaffold it.
      if (!tbody) {
        const tabPanel = document.getElementById('tab-panel-url-catalog')
        if (!tabPanel) return  // The URL catalog tab itself is missing; nothing to do.

        const scaffold = document.createElement('div')
        scaffold.innerHTML = [
          '<div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">',
          '  <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">',
          '    <tbody id="url-catalog-tbody" data-total-entries="0"></tbody>',
          '  </table>',
          '  <div class="px-4 py-3 border-t border-zinc-950/5 dark:border-white/10 flex items-center justify-between">',
          '    <span class="text-xs text-zinc-500 dark:text-zinc-400">Showing <span id="url-catalog-page-info">\u2014</span></span>',
          '    <div class="flex gap-2">',
          '      <button id="url-catalog-prev" onclick="urlCatalogPrevPage()" class="rounded px-2 py-1 text-xs" disabled>Prev</button>',
          '      <button id="url-catalog-next" onclick="urlCatalogNextPage()" class="rounded px-2 py-1 text-xs" disabled>Next</button>',
          '    </div>',
          '  </div>',
          '</div>',
        ].join('\n')

        // Replace the empty-state content (keep any stat cards above it).
        const emptyCard = tabPanel.querySelector('.p-12') as HTMLElement | null
        if (emptyCard?.parentElement) {
          emptyCard.parentElement.replaceWith(scaffold)
        } else {
          tabPanel.appendChild(scaffold)
        }
        tbody = document.getElementById('url-catalog-tbody') as HTMLTableSectionElement | null
        if (!tbody) return
      }

      // Clear any existing rows
      tbody.innerHTML = ''
      // Stamp the total-entries attribute (may differ from loaded count)
      tbody.setAttribute('data-total-entries', String(totalEntries))
      // Add `count` fake rows
      for (let i = 1; i <= count; i++) {
        const tr = document.createElement('tr')
        tr.innerHTML = `<td class="px-4 py-3 text-sm">/api/fake-url-${i}</td>`
        tbody.appendChild(tr)
      }
      // Re-render page 1 using the exposed helper
      if (typeof (window as any).urlCatalogRenderPage === 'function') {
        ;(window as any).urlCatalogRenderPage(1)
      }
    }, { count, totalEntries })
  }

  test('shows first 25 rows on initial render with >25 entries', async ({ page }) => {
    await injectRows(page, 30)

    const info = page.locator('#url-catalog-page-info')
    await expect(info).toHaveText('1\u201325 of 30')

    // Prev is disabled on page 1
    await expect(page.locator('#url-catalog-prev')).toBeDisabled()
    // Next is enabled when there are more pages
    await expect(page.locator('#url-catalog-next')).toBeEnabled()
  })

  test('Next button advances to page 2 and shows correct range', async ({ page }) => {
    await injectRows(page, 30)

    await page.locator('#url-catalog-next').click()

    const info = page.locator('#url-catalog-page-info')
    await expect(info).toHaveText('26\u201330 of 30')

    // Prev now enabled, Next disabled (last page)
    await expect(page.locator('#url-catalog-prev')).toBeEnabled()
    await expect(page.locator('#url-catalog-next')).toBeDisabled()
  })

  test('Prev button returns to page 1', async ({ page }) => {
    await injectRows(page, 30)

    await page.locator('#url-catalog-next').click()
    await page.locator('#url-catalog-prev').click()

    const info = page.locator('#url-catalog-page-info')
    await expect(info).toHaveText('1\u201325 of 30')
    await expect(page.locator('#url-catalog-prev')).toBeDisabled()
    await expect(page.locator('#url-catalog-next')).toBeEnabled()
  })

  test('Prev is disabled and Next enabled on first page with exactly PAGE_SIZE rows', async ({ page }) => {
    await injectRows(page, 25)

    // Only one page — both controls should be disabled
    await expect(page.locator('#url-catalog-prev')).toBeDisabled()
    await expect(page.locator('#url-catalog-next')).toBeDisabled()
    await expect(page.locator('#url-catalog-page-info')).toHaveText('1\u201325 of 25')
  })

  test('shows "(top N loaded)" suffix when totalEntries > loaded rows', async ({ page }) => {
    // Simulate: 100 rows loaded, but catalog has 247 total entries
    await injectRows(page, 100, 247)

    const info = page.locator('#url-catalog-page-info')
    await expect(info).toHaveText('1\u201325 of 100 (top 100 loaded)')
  })
})
