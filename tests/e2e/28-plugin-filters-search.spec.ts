import { test, expect, type Page } from './fixtures'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist,
  ensurePluginActive,
  setPluginStatus
} from './utils/test-helpers'

// The /admin/plugins filter UI is a checkbox group (`input[name="category"]` /
// `input[name="status"]`) plus a `#search-input` text box. Clearing every filter
// is the equivalent of the old "All Categories" / "All Status" select options.
async function clearFilters(page: Page) {
  // Index over ALL filter checkboxes, not over `:checked` — unchecking one shrinks
  // the `:checked` set and invalidates the remaining nth() locators.
  const boxes = page.locator('input[name="category"], input[name="status"]')
  const total = await boxes.count()
  for (let i = 0; i < total; i++) {
    const cb = boxes.nth(i)
    if (await cb.isChecked()) {
      await cb.uncheck()
    }
  }
  await page.fill('#search-input', '')
}

// The plugins page renders a card for every manifest in the registry, so the count is
// never zero on a working page. Each of these tests used to `return` early when it was,
// which turned a broken plugins page into a silent pass across seven tests at once.
async function pluginCardCount(page: Page) {
  const total = await page.locator('.plugin-card').count()
  expect(total, 'plugins page rendered no plugin cards').toBeGreaterThan(0)
  return total
}

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Plugin Filters and Search @plugins @lock-plugin-hello-world', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
    await page.goto(`${BASE_URL}/admin/plugins`)
  })

  test('should have filter controls', async ({ page }) => {
    // Category filter: a checkbox per category
    const categoryFilters = page.locator('input[name="category"]')
    expect(await categoryFilters.count()).toBeGreaterThan(0)
    await expect(page.locator('#category-security')).toBeVisible()

    // Status filter: a checkbox per status
    const statusFilters = page.locator('input[name="status"]')
    expect(await statusFilters.count()).toBeGreaterThan(0)
    await expect(page.locator('#status-active')).toBeVisible()

    // Check for search input
    const searchInput = page.locator('#search-input')
    await expect(searchInput).toBeVisible()
  })

  test('should filter plugins by category', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Select security category
    await page.check('#category-security')
    await page.waitForTimeout(500) // Allow filter to apply

    // Check that only security plugins are visible
    const visiblePlugins = await page.locator('.plugin-card:visible').count()

    // `core-auth` and `two-factor-auth` are both category `security`, so a working filter
    // always leaves cards on screen. Without this floor a filter that hid *everything*
    // passed, because the per-card loop below has nothing to iterate over.
    expect(visiblePlugins, 'security filter hid every plugin').toBeGreaterThan(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Verify all visible plugins have security category
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const category = await card.getAttribute('data-category')
      expect(category).toBe('security')
    }

    // Reset filter
    await clearFilters(page)
    await page.waitForTimeout(500)

    // Should show all plugins again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should filter plugins by status', async ({ page }) => {
    // The "Inactive" checkbox renders `disabled` whenever no plugin has that status
    // (admin-plugins-list.template.ts: `isDisabled = count === 0`), so the inactive half
    // of this test needs a plugin parked there. multi-tenant is non-core and inert while
    // inactive, which makes it the safe one to hold in that state.
    expect(await setPluginStatus(page, 'multi-tenant', 'inactive')).toBe(true)
    await page.reload()

    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Select active status
    await page.check('#status-active')
    await page.waitForTimeout(500) // Allow filter to apply

    // Check that only active plugins are visible
    const visiblePlugins = await page.locator('.plugin-card:visible').count()

    // Four plugins are active after bootstrap, so this is never legitimately zero.
    expect(visiblePlugins, 'active filter hid every plugin').toBeGreaterThan(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Verify all visible plugins have active status
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const status = await card.getAttribute('data-status')
      expect(status).toBe('active')
    }

    // Try inactive status
    await page.uncheck('#status-active')
    await page.check('#status-inactive')
    await page.waitForTimeout(500)

    const inactivePlugins = await page.locator('.plugin-card:visible').count()

    // This is what the `multi-tenant` setup at the top of the test is for. The count was
    // read and then thrown away -- the only assertion over it was commented out -- so the
    // inactive half of "filter plugins by status" tested nothing.
    expect(inactivePlugins, 'inactive filter hid the plugin parked at inactive').toBeGreaterThan(0)
    for (const card of await page.locator('.plugin-card:visible').all()) {
      expect(await card.getAttribute('data-status')).toBe('inactive')
    }
    await expect(page.locator('.plugin-card[data-name*="multi-tenant" i]')).toBeVisible()
    expect(visiblePlugins + inactivePlugins).toBeLessThanOrEqual(totalPlugins)

    // Reset filter
    await clearFilters(page)
    await page.waitForTimeout(500)

    // Should show all plugins again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should search plugins by name', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Get first plugin name
    const firstCard = page.locator('.plugin-card').first()
    const firstPluginName = (await firstCard.getAttribute('data-name')) ?? ''

    expect(firstPluginName, 'plugin card is missing its data-name attribute').not.toBe('')

    // Search for first few characters of the name
    const searchTerm = firstPluginName.substring(0, 4).toLowerCase()
    await page.fill('#search-input', searchTerm)
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show filtered results
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBeGreaterThan(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // All visible plugins should match search term
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const name = await card.getAttribute('data-name')
      const description = await card.getAttribute('data-description')
      const matchesName = name?.toLowerCase().includes(searchTerm) || false
      const matchesDescription = description?.toLowerCase().includes(searchTerm) || false
      expect(matchesName || matchesDescription).toBe(true)
    }

    // Clear search
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)

    // Should show all plugins again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should search plugins by description', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Search for common word that might be in descriptions
    await page.fill('#search-input', 'management')
    await page.waitForTimeout(500) // Allow filter to apply

    // Six catalog descriptions contain "management" (auth, media, database tools, forms,
    // redirects, subscriptions), so a working description filter matches some and hides others.
    // `toBeGreaterThanOrEqual(0)` held for every count, including zero -- i.e. for a filter that
    // matched nothing because it never looked at descriptions at all.
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins, 'searching descriptions for "management" matched nothing').toBeGreaterThan(0)
    expect(visiblePlugins, 'the description filter hid nothing').toBeLessThan(totalPlugins)

    // Clear search
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)
  })

  test('should combine category and status filters', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Select security category AND active status
    await page.check('#category-security')
    await page.check('#status-active')
    await page.waitForTimeout(500) // Allow filter to apply

    const visiblePlugins = await page.locator('.plugin-card:visible').count()

    // security + active describes `core-auth` and `two-factor-auth`, so the intersection
    // is never empty on a working page -- and an empty one would skip the loop below.
    expect(visiblePlugins, 'security+active filter hid every plugin').toBeGreaterThan(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Verify all visible plugins match both filters
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const category = await card.getAttribute('data-category')
      const status = await card.getAttribute('data-status')
      expect(category).toBe('security')
      expect(status).toBe('active')
    }

    // Reset filters
    await clearFilters(page)
    await page.waitForTimeout(500)
  })

  test('should combine all three filters', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Apply all three filters
    await page.check('#category-security')
    await page.check('#status-active')
    await page.fill('#search-input', 'auth')
    await page.waitForTimeout(500) // Allow filter to apply

    const visiblePlugins = await page.locator('.plugin-card:visible').count()

    // `core-auth` is security, active, and matches "auth", so all three filters together
    // still leave it on screen. The old `toBeGreaterThanOrEqual(0)` was true of every
    // possible outcome, and the guarded loop under it never ran when the count was zero.
    expect(visiblePlugins, 'three-filter combination hid every plugin').toBeGreaterThan(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    {
      const visibleCards = await page.locator('.plugin-card:visible').all()
      for (const card of visibleCards) {
        const category = await card.getAttribute('data-category')
        const status = await card.getAttribute('data-status')
        const name = await card.getAttribute('data-name')
        const description = await card.getAttribute('data-description')

        expect(category).toBe('security')
        expect(status).toBe('active')

        const matchesSearch =
          name?.toLowerCase().includes('auth') ||
          description?.toLowerCase().includes('auth')
        expect(matchesSearch).toBe(true)
      }
    }

    // Reset all filters
    await clearFilters(page)
    await page.waitForTimeout(500)
  })

  test('should show no results message when no plugins match', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await pluginCardCount(page)

    // Search for something that definitely won't match
    await page.fill('#search-input', 'xyzabc123nonexistent')
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show no plugins
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBe(0)

    // Should show "no results" message
    const noResultsMsg = page.locator('#no-results-message')
    await expect(noResultsMsg).toBeVisible()
    await expect(noResultsMsg).toContainText('No plugins found')

    // Clear search
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)

    // No results message should be hidden
    await expect(noResultsMsg).not.toBeVisible()

    // Plugins should be visible again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should maintain filter state when toggling plugin status', async ({ page }) => {
    // The card only renders a switch once the plugin is installed — an uninstalled card
    // just gets an Install button — so put Hello World in a known installed+active state.
    expect(await ensurePluginActive(page, 'hello-world')).toBe(true)
    await page.reload()

    // Apply a filter first. "utilities" contains the Hello World demo plugin, which
    // is safe to toggle (it only contributes a demo page).
    await page.check('#category-utilities')
    await page.waitForTimeout(500)

    const initialCount = await page.locator('.plugin-card:visible').count()
    expect(initialCount).toBeGreaterThan(0)

    // Toggle an installed plugin in the filtered set. Installed cards expose a
    // switch (role="switch"); uninstalled ones only expose an Install button.
    const toggleCard = page.locator('.plugin-card[data-name="Hello World"]')
    await expect(toggleCard).toBeVisible()
    const toggle = toggleCard.locator('button[role="switch"]')
    const wasChecked = (await toggle.getAttribute('aria-checked')) ?? 'true'
    const flipped = wasChecked === 'true' ? 'false' : 'true'

    try {
      await toggle.click()
      await expect(toggle).toHaveAttribute('aria-checked', flipped, { timeout: 10000 })

      // Verify category filter is still applied after the toggle
      await expect(page.locator('#category-utilities')).toBeChecked()
      expect(await page.locator('.plugin-card:visible').count()).toBe(initialCount)

      // The status filter reads `data-status` off the card, and togglePlugin() used to
      // update the badge and the switch but not that attribute -- so a plugin you had
      // just switched off went on filtering as active until the next full page load.
      const flippedStatus = flipped === 'true' ? 'active' : 'inactive'
      await expect(toggleCard).toHaveAttribute('data-status', flippedStatus)
      await page.check(`#status-${flippedStatus}`)
      await page.waitForTimeout(500)
      await expect(toggleCard).toBeVisible()
      await page.uncheck(`#status-${flippedStatus}`)
      await page.waitForTimeout(500)

      // A second click on the switch used to navigate to the plugin settings page:
      // togglePlugin() rebound button.onclick without event.stopPropagation(), so the
      // click bubbled to the card's openPluginSettings() handler. Restoring through the
      // UI is what proves that is fixed; it used to have to go through the API.
      await toggle.click()
      await expect(toggle).toHaveAttribute('aria-checked', wasChecked, { timeout: 10000 })
      await expect(page).toHaveURL(/\/admin\/plugins(\?|$)/)
    } finally {
      const restoreAction = wasChecked === 'true' ? 'activate' : 'deactivate'
      const res = await page.request.post(`/admin/plugins/hello-world/${restoreAction}`, {
        headers: { 'Content-Type': 'application/json' },
      })
      expect(res.ok()).toBe(true)
    }

    // Reset filter
    await clearFilters(page)
    await page.waitForTimeout(500)
  })

  test('should have correct category options', async ({ page }) => {
    // Each category is a labelled checkbox; the label carries the display name
    // plus a count, e.g. "Security (7)".
    const labels = await page.locator('aside label[for^="category-"]').allTextContents()
    const names = labels.map((l) => l.replace(/\s*\(\d+\)\s*$/, '').trim())

    expect(names).toContain('Content Management')
    expect(names).toContain('Media')
    expect(names).toContain('SEO & Analytics')
    expect(names).toContain('Security')
    expect(names).toContain('Utilities')
    expect(names).toContain('System')
    expect(names).toContain('Development')

    // "All Categories" is now expressed as "no category checked" — every card shows.
    const total = await page.locator('.plugin-card').count()
    expect(await page.locator('input[name="category"]:checked').count()).toBe(0)
    expect(await page.locator('.plugin-card:visible').count()).toBe(total)
  })

  test('should have correct status options', async ({ page }) => {
    // Each status is a labelled checkbox; the label carries the status name plus a count.
    const labels = await page.locator('aside label[for^="status-"]').allTextContents()
    const names = labels.map((l) => l.replace(/\s*\(\d+\)\s*$/, '').trim())

    expect(names).toContain('Active')
    expect(names).toContain('Inactive')
    expect(names).toContain('Error')
    expect(names).toContain('Available to Install')

    // "All Status" is now expressed as "no status checked" — every card shows.
    const total = await page.locator('.plugin-card').count()
    expect(await page.locator('input[name="status"]:checked').count()).toBe(0)
    expect(await page.locator('.plugin-card:visible').count()).toBe(total)
  })
})
