import { test, expect } from './fixtures'
import { 
  loginAsAdmin, 
  ensureAdminUserExists,
  ensureWorkflowTablesExist,
  ensurePluginActive
} from './utils/test-helpers'

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Plugin Management @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  test('should access plugins page and show basic UI', async ({ page }) => {
    // Navigate to plugins page
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Check page title
    await expect(page.locator('h1')).toContainText('Plugins')
    
    // Check for the install affordance. The old global "Install Plugin" dropdown was
    // replaced by a per-card Install button on every uninstalled catalog plugin.
    const installButtons = page.locator('.plugin-card[data-status="uninstalled"] button:has-text("Install")')
    expect(await installButtons.count()).toBeGreaterThan(0)
    await expect(installButtons.first()).toBeVisible()

    // The catalog is code-defined, so cards are always rendered
    const pluginCount = await page.locator('.plugin-card').count()
    expect(pluginCount).toBeGreaterThan(0)

    // Check for at least one plugin card
    await expect(page.locator('.plugin-card').first()).toBeVisible()
  })

  test('should show plugin stats', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)

    // Check for stats tiles. The tile is a label div followed by a value div;
    // the label reads "Total" (it used to read "Total Plugins").
    const totalLabel = page.getByText('Total', { exact: true }).first()
    await expect(totalLabel).toBeVisible()

    // The count sits in the sibling div right after the label
    const totalValue = totalLabel.locator('xpath=following-sibling::div[1]')
    await expect(totalValue).toBeVisible()
    await expect(totalValue).toHaveText(/^\d+$/)

    // The remaining tiles should be present too
    await expect(page.getByText('Active', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('Errors', { exact: true }).first()).toBeVisible()
  })

  test('should display existing plugins', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Ensure at least one plugin exists
    let pluginCount = await page.locator('.plugin-card').count()
    if (pluginCount === 0) {
      // Install FAQ plugin
      await page.click('button:has-text("Install Plugin")')
      await expect(page.locator('#plugin-dropdown')).toBeVisible()
      await page.click('button:has-text("FAQ System")')
      await page.waitForTimeout(2000)
      await page.reload()
      pluginCount = await page.locator('.plugin-card').count()
    }
    
    expect(pluginCount).toBeGreaterThan(0)
    
    // First plugin should have required elements
    const firstPlugin = page.locator('.plugin-card').first()
    await expect(firstPlugin.locator('h3')).toBeVisible() // Plugin name
    await expect(firstPlugin.locator('.status-badge')).toBeVisible() // Status
  })

  test('should install a catalog plugin if not present', async ({ page }) => {
    // The "FAQ System" demo plugin and the global "Install Plugin" dropdown it was
    // reached through are both gone. Install is now a per-card button.
    // "Magic Link Authentication" is a non-core plugin with no admin menu entry
    // (adminMenu: null), so installing it has no side effects on the rest of the
    // suite; it is uninstalled again at the end.
    const PLUGIN_ID = 'magic-link-auth'
    const PLUGIN_NAME = 'Magic Link Authentication'
    const card = page.locator(`.plugin-card[data-name="${PLUGIN_NAME}"]`)

    await page.goto(`${BASE_URL}/admin/plugins`)

    // Check if the plugin is installed already
    await expect(card).toBeVisible()
    const wasUninstalled = (await card.getAttribute('data-status')) === 'uninstalled'

    try {
      if (wasUninstalled) {
        // Install it from its card
        await card.locator('button:has-text("Install")').click()

        // Wait for installation success (the page reloads ~1.5s afterwards)
        await expect(page.locator('text=installed successfully')).toBeVisible({ timeout: 10000 })
        await expect(
          page.locator(`.plugin-card[data-name="${PLUGIN_NAME}"][data-status="active"]`)
        ).toBeVisible({ timeout: 20000 })
      }

      // Either way the plugin is now present and no longer uninstalled
      await expect(card).toBeVisible()
      await expect(card).not.toHaveAttribute('data-status', 'uninstalled')
    } finally {
      // Restore the catalog to the state the rest of the suite expects
      if (wasUninstalled) {
        const res = await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/uninstall`, {
          headers: { 'Content-Type': 'application/json' },
        })
        expect(res.ok()).toBe(true)
      }
    }
  })

  test('should show plugin actions', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)

    // The catalog is code-defined, so cards are always rendered
    const pluginCount = await page.locator('.plugin-card').count()
    expect(pluginCount).toBeGreaterThan(0)

    // Not `.first()`: the list is ordered `isCore DESC, title ASC` (PluginService.getAllPlugins),
    // so the first card is always a core plugin, and `core-auth`/`core-media` are in
    // `criticalCorePlugins` — they render a deliberately inert <div> toggle titled "Core plugin
    // cannot be disabled", with no Install and no uninstall button. Asserting an interactive
    // control on the first card therefore passed or failed purely on which plugins happened to be
    // installed when the spec ran. Assert the invariant that actually holds instead: every card
    // renders one of the three affordances the template can produce.
    const actionless = await page.locator('.plugin-card').evaluateAll((cards) =>
      cards
        .filter(
          (card) =>
            !card.querySelector('button[role="switch"], [title="Core plugin cannot be disabled"]') &&
            !Array.from(card.querySelectorAll('button')).some((b) => b.textContent?.trim() === 'Install')
        )
        .map((card) => card.getAttribute('data-name'))
    )
    expect(actionless, 'plugin cards rendering no action control').toEqual([])

    // ...and at least one card exposes a control the operator can actually click.
    const interactive = await page
      .locator('.plugin-card button[role="switch"], .plugin-card button:has-text("Install")')
      .count()
    expect(interactive).toBeGreaterThan(0)
  })

  // Both of the tests that used to live here were written against a plugins UI that no
  // longer exists. Activate/Deactivate are now a single toggle switch, and there is no
  // Settings button -- the card itself opens the settings page. Each test looked for its
  // control with `if (count > 0)` inside a loop over three cards and did nothing when it
  // found none, so neither has asserted anything since the redesign.
  //
  // `hello-world` is the suite's designated safe mutation target; the lock tag serializes
  // this against the other specs that install and toggle it.
  test('should toggle plugin status @lock-plugin-hello-world', async ({ page }) => {
    expect(await ensurePluginActive(page, 'hello-world')).toBe(true)
    await page.goto(`${BASE_URL}/admin/plugins`)

    const card = page.locator('.plugin-card[data-name="Hello World"]')
    await expect(card).toBeVisible()
    await expect(card).toHaveAttribute('data-status', 'active')

    const toggle = card.locator('button.toggle-button')
    await expect(toggle).toHaveAttribute('aria-checked', 'true')

    try {
      await toggle.click()

      // The badge, the switch and the card's own data-status all have to agree. They are
      // written by three separate lines of the toggle handler, and data-status is the one
      // the status filter reads.
      await expect(card.locator('.status-badge')).toContainText('Inactive', { timeout: 10_000 })
      await expect(toggle).toHaveAttribute('aria-checked', 'false')
      await expect(card).toHaveAttribute('data-status', 'inactive')

      await toggle.click()
      await expect(card.locator('.status-badge')).toContainText('Active', { timeout: 10_000 })
      await expect(toggle).toHaveAttribute('aria-checked', 'true')
      await expect(card).toHaveAttribute('data-status', 'active')

      // Reload to confirm the switch wrote through to the server rather than only to the
      // DOM -- the previous version of this test could not tell the difference.
      await page.reload()
      await expect(page.locator('.plugin-card[data-name="Hello World"]')).toHaveAttribute(
        'data-status',
        'active'
      )
    } finally {
      await ensurePluginActive(page, 'hello-world')
    }
  })

  test('should access plugin settings', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)

    const card = page.locator('.plugin-card').first()
    await expect(card).toBeVisible()
    const name = (await card.getAttribute('data-name')) ?? ''
    expect(name, 'first plugin card has no data-name').not.toBe('')

    // The card is the control: `openPluginSettings(id)` is wired to its onclick, and the
    // per-card buttons all call event.stopPropagation() to avoid triggering it.
    await card.click()
    await page.waitForURL(/\/admin\/plugins\/[^/]+$/, { timeout: 15_000 })
    await expect(page.locator('h1')).toContainText('Plugin Settings')
    await expect(page.locator('h2').first()).toContainText(name)
  })

  test('should show installable plugin options', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // The install dropdown was replaced by a per-card Install button on every
    // uninstalled catalog plugin, so the installable options are those cards.
    const installButtons = page.locator('.plugin-card[data-status="uninstalled"] button:has-text("Install")')
    
    // Should have at least one installable option, and it should be clickable
    const buttonCount = await installButtons.count()
    expect(buttonCount).toBeGreaterThan(0)
    await expect(installButtons.first()).toBeVisible()
    await expect(installButtons.first()).toBeEnabled()
  })

  test('should filter plugins by search', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Find search input
    const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]')
    // The whole body was wrapped in `if (hasSearch > 0)`, and the one assertion inside --
    // `toBeGreaterThanOrEqual(0)` -- is true of every possible count, so this test passed
    // whether the box existed, whether it filtered, and whether it filtered correctly.
    expect(await searchInput.count(), 'no search box on the plugins page').toBeGreaterThan(0)

    const totalCards = await page.locator('.plugin-card').count()
    await searchInput.fill('auth')
    await page.waitForTimeout(1000) // Allow filter to apply

    // `core-auth` and `two-factor-auth` both match, and plenty of plugins do not, so a
    // working filter lands strictly between "nothing" and "everything".
    const visibleCards = await page.locator('.plugin-card:visible').count()
    expect(visibleCards, 'searching "auth" matched no plugin').toBeGreaterThan(0)
    expect(visibleCards, 'searching "auth" did not filter anything out').toBeLessThan(totalCards)

    // Clear search
    await searchInput.fill('')
    await page.waitForTimeout(500)
    expect(await page.locator('.plugin-card:visible').count()).toBe(totalCards)
  })

  test('should show plugin information', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Each plugin card should show basic info
    const firstCard = page.locator('.plugin-card').first()
    
    // Should have plugin name
    await expect(firstCard.locator('h3, h2')).toBeVisible()
    
    // Should have version info
    await expect(firstCard.locator('text=/v?\\d+\\.\\d+/')).toBeVisible()
    
    // Should have status
    await expect(firstCard.locator('.status-badge')).toBeVisible()
  })

  test('should handle plugin categories', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Look for category information
    const cards = page.locator('.plugin-card')
    const count = await cards.count()
    
    // Cards always exist on a working page, so the guard only ever hid a broken one.
    expect(count, 'plugins page rendered no cards').toBeGreaterThan(0)
    await expect(page.locator('text=/security|content|media|system/i').first()).toBeVisible()
  })

  test('should show core vs non-core plugins', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Core plugins should not have uninstall option
    const corePlugins = page.locator('.plugin-card').filter({ hasText: /Authentication|Media|Workflow/ })
    const coreCount = await corePlugins.count()
    
    // `core-auth` and `core-media` are always installed, so a zero count here means the
    // filter stopped matching -- at which point the rule below was never checked at all.
    expect(coreCount, 'no core plugin cards found').toBeGreaterThan(0)

    const firstCore = corePlugins.first()
    // Core plugins typically don't have uninstall buttons
    const hasUninstall = await firstCore.locator('button:has-text("Uninstall")').count()
    expect(hasUninstall).toBe(0)
  })

  test('should validate plugin management permissions', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Admin user should be able to access plugins page
    await expect(page.locator('h1')).toContainText('Plugins')
    
    // Should not show access denied message
    await expect(page.locator('text=Access denied')).not.toBeVisible()
    await expect(page.locator('text=Unauthorized')).not.toBeVisible()
  })
})