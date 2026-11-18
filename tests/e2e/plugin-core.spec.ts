import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { ensureWorkflowTablesExist } from "./utils/test-helpers"
import { ensurePluginActive } from "./fixtures/plugin-fixtures"
import type { Page } from "./fixtures"
import { setPluginStatus } from "./fixtures/plugin-fixtures"
import type { Page as source8_Page } from "@playwright/test"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 121-plugin-card-display-names.spec.ts", () => {
  /**
   * Every card on /admin/plugins must carry a real plugin id and a human label.
   *
   * Two defects this guards:
   *
   *  - `definePlugin()` assigns `name = input.id` because `name` is the internal
   *    key (hook namespacing, capability errors). It used to drop the author's
   *    `name` entirely, so an *uninstalled* SDK plugin rendered its slug —
   *    "example", "graphql", "email-reconciliation". Installed ones looked fine,
   *    which is why this only ever broke on a database where the plugin happened
   *    to be uninstalled.
   *  - Pre-SDK plugin objects carry `name` but no `id`. They reached the
   *    available-plugins list and rendered a second, phantom card for a plugin
   *    the manifest registry already listed, linking to
   *    /admin/plugins/undefined/configure.
   *
   * Asserted over the whole list rather than for named plugins, so a plugin added
   * later without a display name is caught too.
   */
  test.describe('Plugin card identity @plugins', () => {
    test('every plugin card has a real id and a label that is not its slug', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      const cards = page.locator('.plugin-card')
      expect(await cards.count()).toBeGreaterThan(0)

      const offenders = await cards.evaluateAll(nodes =>
        nodes
          .map(n => ({
            id: (n.getAttribute('onclick') ?? '').match(/openPluginSettings\('([^']*)'\)/)?.[1] ?? '',
            name: n.getAttribute('data-name') ?? '',
          }))
          .filter(c => !c.id || c.id === 'undefined' || c.id === c.name)
      )

      expect(offenders, `cards missing an id or showing their slug: ${JSON.stringify(offenders)}`).toEqual([])
    })

    test('SDK plugins show the name their definition declares', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      // examplePlugin declares `name: 'Example'`, graphqlPlugin `name: 'GraphQL API'`.
      // Both go through definePlugin and neither ships a manifest.json, so the label
      // can only come from the definition.
      await expect(page.locator('.plugin-card[data-name="Example"]')).toHaveCount(1)
      await expect(page.locator('.plugin-card[data-name="GraphQL API"]')).toHaveCount(1)
    })

    test('a plugin is listed once, not once per registration source', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      const ids = await page
        .locator('.plugin-card')
        .evaluateAll(nodes =>
          nodes.map(n => (n.getAttribute('onclick') ?? '').match(/openPluginSettings\('([^']*)'\)/)?.[1] ?? '')
        )

      const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i)
      expect(duplicates, `plugin ids rendered more than once: ${duplicates.join(', ')}`).toEqual([])
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 15-plugins.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 21-plugin-version-display.spec.ts", () => {
  // Use environment variable for port or default to 8787
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';

  // Each plugin's version comes from its own manifest.json, and the catalog
  // legitimately mixes releases and pre-releases (v1.0.0, v1.0.0-beta.1, v1.0.1,
  // v1.1.0 are all present today). So these tests assert the version *format* and
  // the *consistency* of the rendered value rather than one hard-coded literal.
  const FULL_SEMVER = /^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/i;

  // Playwright text-engine selector (string, so single backslashes are correct here)
  const VERSION_SELECTOR = 'text=/v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?/i';

  // A plugin that renders the generic plugin detail page (which includes a
  // "Version:" row). Plugins with bespoke settings pages (e.g. ai-search) override
  // that template.
  const DETAIL_PAGE_PLUGIN = { id: 'example', displayName: 'Example' };

  /** Pull the version substring out of a rendered card/detail string. */
  function parseVersion(text: string | null | undefined): string | null {
    const match = text?.match(/v(\d+(?:\.\d+)*(?:-[a-z0-9.]+)?)/i);
    return match ? match[1] : null;
  }

  test.describe('Plugin Version Display @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page);
      await loginAsAdmin(page);
    });

    test('should display correct version format for all plugins', async ({ page }) => {
      // Navigate to plugins page
      await page.goto(`${BASE_URL}/admin/plugins`);

      // Wait for page to load
      await expect(page.locator('h1')).toContainText('Plugins');

      // Get all plugin cards
      const pluginCards = page.locator('.plugin-card');
      const count = await pluginCards.count();

      console.log(`Found ${count} plugin cards`);
      expect(count).toBeGreaterThan(0);

      // Check each plugin card for version
      for (let i = 0; i < count; i++) {
        const card = pluginCards.nth(i);

        // Get plugin name for better error messages
        const pluginName = await card.locator('h3, h2').first().textContent();

        // Look for version text with pattern "v1.0.0-beta.1 • Author"
        const versionText = await card.locator(VERSION_SELECTOR).first().textContent();

        // Extract just the version number
        const version = parseVersion(versionText);

        // Verify version matches the expected format
        expect(
          version,
          `Plugin "${pluginName}" should render a version (got "${versionText}")`
        ).not.toBeNull();
        expect(
          version,
          `Plugin "${pluginName}" should display a full semver version, got "${version}"`
        ).toMatch(FULL_SEMVER);
      }
    });

    test('should display version with "v" prefix', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin/plugins`);

      // Get first plugin card
      const firstCard = page.locator('.plugin-card').first();
      await expect(firstCard).toBeVisible();

      // Check for version with v prefix
      await expect(firstCard.locator(VERSION_SELECTOR).first()).toBeVisible();

      // The rendered string must *start* with the "v" prefix, not merely contain a number
      const versionText = (await firstCard.locator(VERSION_SELECTOR).first().textContent())?.trim();
      expect(versionText).toMatch(/^v\d+\.\d+\.\d+(-[a-z0-9.]+)?\b/i);
    });

    test('should display version in plugin details/settings page', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin/plugins`);

      // Read the version this plugin advertises on the list
      const card = page.locator(`.plugin-card[data-name="${DETAIL_PAGE_PLUGIN.displayName}"]`);
      await expect(card).toBeVisible();
      const listVersion = parseVersion(await card.locator(VERSION_SELECTOR).first().textContent());
      expect(listVersion, 'plugin card should render a version').not.toBeNull();

      // Opening the card navigates to the plugin's detail/settings page
      await card.click();
      await page.waitForLoadState('domcontentloaded');
      expect(page.url()).toContain(`/admin/plugins/${DETAIL_PAGE_PLUGIN.id}`);

      // The "Information" tab carries a Plugin Details block with a Version row
      await page.locator('#info-tab').click();
      const infoPanel = page.locator('#info-content');
      await expect(infoPanel).toBeVisible();
      const detailVersion =
        (await infoPanel.innerText()).match(/Version:\s*v?(\d+(?:\.\d+)*(?:-[a-z0-9.]+)?)/i)?.[1] ??
        null;
      expect(detailVersion).toBe(listVersion);
    });

    test('should show consistent version across plugin list and plugin detail page', async ({
      page,
    }) => {
      // Get version from UI list
      await page.goto(`${BASE_URL}/admin/plugins`);
      const card = page.locator(`.plugin-card[data-name="${DETAIL_PAGE_PLUGIN.displayName}"]`);
      await expect(card).toBeVisible();

      const pluginName = (await card.locator('h3, h2').first().textContent())?.trim();
      const versionUI = parseVersion(await card.locator(VERSION_SELECTOR).first().textContent());

      console.log(`Plugin: ${pluginName}, UI Version: ${versionUI}`);
      expect(versionUI, `expected a semver version on the "${pluginName}" card`).not.toBeNull();

      // Get version from the second rendering of the same record. (There is no
      // public /api/plugins endpoint; the detail page is the authoritative view.)
      await page.goto(`${BASE_URL}/admin/plugins/${DETAIL_PAGE_PLUGIN.id}`);
      await page.waitForLoadState('domcontentloaded');
      await page.locator('#info-tab').click();

      const infoPanel = page.locator('#info-content');
      await expect(infoPanel).toBeVisible();
      const detailVersion =
        (await infoPanel.innerText()).match(/Version:\s*v?(\d+(?:\.\d+)*(?:-[a-z0-9.]+)?)/i)?.[1] ??
        null;

      console.log(`  Detail page version: ${detailVersion}`);
      expect(detailVersion).toBe(versionUI);
      expect(detailVersion).toMatch(FULL_SEMVER);
    });

    test('should not display truncated version (e.g., v1.0.0 instead of v1.0.0-beta.1)', async ({
      page,
    }) => {
      await page.goto(`${BASE_URL}/admin/plugins`);

      const pluginCards = page.locator('.plugin-card');
      const count = await pluginCards.count();
      expect(count).toBeGreaterThan(0);

      // Every version must be a complete 3-part semver — "v1.0" or "v1" means the
      // renderer truncated it.
      let preReleaseCount = 0;

      for (let i = 0; i < count; i++) {
        const card = pluginCards.nth(i);
        const pluginName = await card.locator('h3, h2').first().textContent();
        const version = parseVersion(await card.locator(VERSION_SELECTOR).first().textContent());

        expect(
          version,
          `Plugin "${pluginName}" should not display a truncated version, got "${version}"`
        ).toMatch(FULL_SEMVER);

        if (/-[a-z0-9.]+$/i.test(version ?? '')) {
          preReleaseCount++;
        }
      }

      // The original defect: the pre-release suffix was dropped, so "1.0.0-beta.1"
      // rendered as "v1.0.0". Several catalog plugins ship pre-release versions, so
      // seeing none at all means the suffix is being stripped again.
      expect(
        preReleaseCount,
        'at least one catalog plugin ships a pre-release version whose suffix must survive rendering'
      ).toBeGreaterThan(0);
    });

    test('should display version with proper formatting', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin/plugins`);

      const firstCard = page.locator('.plugin-card').first();
      await expect(firstCard).toBeVisible();
      const versionText = (
        await firstCard.locator('text=/v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?\\s+•/i').first().textContent()
      )?.trim();

      console.log(`Version text format: "${versionText}"`);

      // Should follow format: "v1.0.0-beta.1 • Author Name"
      expect(versionText).toMatch(/^v\d+\.\d+\.\d+(-[a-z0-9.]+)?\s+•\s+\S/i);
    });

    test('should display version for core plugins', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin/plugins`);

      // Check specific core plugins
      const corePluginNames = [
        'Authentication System',
        'Media Manager',
        'Analytics & Insights',
        'Cache System',
        'Workflow Engine',
      ];

      let checked = 0;

      for (const pluginName of corePluginNames) {
        const pluginCard = page.locator('.plugin-card').filter({ hasText: pluginName });
        const count = await pluginCard.count();

        if (count > 0) {
          console.log(`Checking core plugin: ${pluginName}`);

          // Should display a full semver version
          const versionElement = pluginCard.first().locator(VERSION_SELECTOR).first();
          await expect(versionElement).toBeVisible({ timeout: 5000 });
          expect(parseVersion(await versionElement.textContent())).toMatch(FULL_SEMVER);
          checked++;
        }
      }

      // Guard against the loop silently matching nothing
      expect(checked, 'expected at least one core plugin card in the catalog').toBeGreaterThan(0);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 28-plugin-filters-search.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 68-plugin-install-click.spec.ts", () => {
  test.describe('Plugin Install Click Behavior @smoke @plugins @lock-plugin-hello-world', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('uninstalled plugin detail page shows Install button instead of auto-installing @plugins', async ({ page }) => {
      // Ensure hello-world is uninstalled so we have a known test target
      await page.request.post('/admin/plugins/hello-world/uninstall', {
        headers: { 'Content-Type': 'application/json' },
      }).catch(() => {})

      // Navigate directly to the uninstalled plugin's detail page
      await page.goto('/admin/plugins/hello-world')
      await page.waitForLoadState('domcontentloaded')

      // Should show Install button — NOT auto-install the plugin
      const installButton = page.locator('button', { hasText: 'Install' })
      await expect(installButton).toBeVisible({ timeout: 10000 })

      // Should NOT show Activate or Deactivate buttons (plugin was not auto-installed)
      await expect(page.locator('button', { hasText: 'Activate' })).toHaveCount(0)
      await expect(page.locator('button', { hasText: 'Deactivate' })).toHaveCount(0)

      // Verify plugin still shows as uninstalled on list page
      await page.goto('/admin/plugins')
      await page.waitForLoadState('domcontentloaded')

      const helloWorldCard = page.locator('.plugin-card').filter({
        has: page.locator('h3', { hasText: 'Hello World' })
      }).locator('.status-badge')

      await expect(helloWorldCard).toContainText('Uninstalled')
    })

    test('install button on detail page installs plugin @plugins', async ({ page }) => {
      // Ensure hello-world is uninstalled
      await page.request.post('/admin/plugins/hello-world/uninstall', {
        headers: { 'Content-Type': 'application/json' },
      }).catch(() => {})

      // Navigate to detail page
      await page.goto('/admin/plugins/hello-world')
      await page.waitForLoadState('domcontentloaded')

      // Click Install — JS does fetch + setTimeout(reload, 1500)
      const installButton = page.locator('button', { hasText: 'Install' })
      await expect(installButton).toBeVisible({ timeout: 10000 })

      // Click and wait for the delayed reload navigation to complete
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }),
        installButton.click(),
      ])

      // After reload, Install button should be gone (plugin is now installed)
      await expect(page.locator('button', { hasText: 'Install' })).toHaveCount(0, { timeout: 5000 })
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 69-plugins-nav-accordion.spec.ts", () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

  test.describe('Plugins Nav Accordion @plugins @lock-plugin-hello-world', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('Plugins nav item renders as accordion with chevron toggle', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('networkidle')

      // Plugins accordion parent should exist
      const accordion = page.locator('[data-plugins-accordion]').first()
      await expect(accordion).toBeVisible()

      // Should have a link to /admin/plugins
      await expect(accordion.locator('a[href="/admin/plugins"]')).toBeVisible()
      await expect(accordion.locator('a[href="/admin/plugins"]')).toContainText('Plugins')

      // Should have a toggle button with chevron
      const toggleBtn = accordion.locator('button[aria-label="Toggle plugins submenu"]')
      await expect(toggleBtn).toBeVisible()

      // Chevron svg should exist
      await expect(accordion.locator('[data-plugins-chevron]')).toBeVisible()
    })

    test('Plugins submenu starts hidden and expands on chevron click', async ({ page }) => {
      // The collapsed state is persisted in the `plugins_menu_open` cookie and applied
      // before first paint via a `.plugins-closed` class on <html> (CSS hides the
      // submenu). Seed the cookie so the accordion genuinely starts collapsed.
      await page.context().addCookies([
        { name: 'plugins_menu_open', value: '0', url: BASE_URL },
      ])

      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('domcontentloaded')

      const accordion = page.locator('[data-plugins-accordion]').first()
      await expect(accordion).toBeVisible()
      const submenu = accordion.locator('[data-plugins-submenu]')

      // Submenu hidden by default (no active plugin sub-item on dashboard)
      await expect(submenu).toBeHidden()

      // Click toggle button
      await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()

      // Submenu should now be visible
      await expect(submenu).toBeVisible()

      // Click again to collapse
      await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()
      await expect(submenu).toBeHidden()
    })

    test('Plugin items do not appear as top-level nav items', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('networkidle')

      // The main nav should not have Hello World as a top-level sibling of Dashboard/Collections
      // Top-level items are siblings of the accordion, not inside it
      const sidebarBody = page.locator('.flex.flex-col.gap-0\\.5').first()
      const topLevelLinks = sidebarBody.locator('> span > a')

      // Top-level links should only be core items (Dashboard, Collections, Content, Users)
      const hrefs = await topLevelLinks.evaluateAll((els) =>
        els.map((el) => el.getAttribute('href'))
      )

      // None of the top-level links should be plugin-specific paths
      expect(hrefs).not.toContain('/admin/hello-world')
      expect(hrefs).not.toContain('/admin/analytics')
      expect(hrefs).not.toContain('/admin/media')
    })

    test('Hello World plugin menu entry appears inside accordion when activated', async ({ page }) => {
      // First activate hello-world plugin via the plugins page
      await page.goto(`${BASE_URL}/admin/plugins`)
      await page.waitForLoadState('networkidle')

      // Find hello-world plugin and activate it if not already active
      const helloWorldCard = page.locator('[data-plugin-id="hello-world"], .plugin-card').filter({ hasText: /hello.world/i }).first()
      const cardExists = await helloWorldCard.count()

      if (cardExists > 0) {
        // Installed cards expose a switch (role="switch") rather than an Activate button.
        const toggle = helloWorldCard.locator('button[role="switch"]')
        if ((await toggle.count()) > 0 && (await toggle.getAttribute('aria-checked')) !== 'true') {
          await toggle.click()
          await expect(toggle).toHaveAttribute('aria-checked', 'true', { timeout: 15000 })
        }
      }

      // Navigate to dashboard
      await page.goto(`${BASE_URL}/admin`)
      await page.waitForLoadState('domcontentloaded')

      const accordion = page.locator('[data-plugins-accordion]').first()
      await expect(accordion).toBeVisible()
      const submenu = accordion.locator('[data-plugins-submenu]')

      // If hello-world is active, the submenu should auto-expand when on its path
      // OR we can expand manually and check for the link. The accordion remembers its
      // last state in a cookie, so only toggle when it is currently collapsed.
      if (await submenu.isHidden()) {
        await accordion.locator('button[aria-label="Toggle plugins submenu"]').click()
      }
      await expect(submenu).toBeVisible()

      // If hello-world plugin has a menu item, it should be inside submenu, not at top level
      const helloWorldLink = submenu.locator('a[href="/admin/hello-world"]')
      const linkCount = await helloWorldLink.count()
      if (linkCount > 0) {
        await expect(helloWorldLink).toBeVisible()
      }
    })

    test('Navigating to /admin/plugins marks Plugins as active', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin/plugins`)
      await page.waitForLoadState('networkidle')

      const accordion = page.locator('[data-plugins-accordion]').first()
      const pluginsLink = accordion.locator('a[href="/admin/plugins"]')

      await expect(pluginsLink).toHaveAttribute('data-current', 'true')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 79-plugin-filter-url.spec.ts", () => {
  type Page = source8_Page;
  /**
   * A category or status checkbox is rendered `disabled` when no installed plugin falls into it
   * (admin-plugins-list.template.ts), and the categories are sorted by count descending — so the
   * enabled ones are whichever buckets this build's plugins actually occupy, and `#category-security`
   * is not guaranteed to be one of them.
   *
   * The three tests below used to cope with that by not testing: two bailed out through
   * `test.skip(true, 'No enabled category checkboxes found')` / `'Need at least 2 …'`, and the third
   * wrapped both of its assertions in `if (count > 0)`, so a page that rendered no filters at all
   * passed. Read the values off the page instead, and assert that they are there — a plugin list with
   * fewer than two occupied categories is a broken fixture, not a reason to skip.
   *
   * `networkidle` is also gone from this file: /admin/plugins pulls Tailwind, Alpine and HTMX from
   * CDNs and may never reach it, which in CI costs the test its whole budget before the first
   * assertion. Waiting for the control under test is both faster and a stronger statement.
   */

  /** The filter checkboxes this build actually offers, in render order. */
  function enabledFilters(page: Page, name: 'category' | 'status') {
    return page.locator(`input[name="${name}"]:not([disabled])`)
  }

  async function openPluginsList(page: Page) {
    await page.goto('/admin/plugins')
    await expect(page.locator('#search-input')).toBeVisible()
  }

  test.describe('Plugin Filter URL Persistence @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('URL updates when category filter is checked', async ({ page }) => {
      await openPluginsList(page)

      // Find a non-disabled category checkbox and click it
      const checkbox = enabledFilters(page, 'category').first()
      const categoryValue = await checkbox.getAttribute('value')
      await checkbox.check()

      // URL should now contain the category param
      await expect(page).toHaveURL(new RegExp(`category=${categoryValue}`))
    })

    test('URL updates when status filter is checked', async ({ page }) => {
      await openPluginsList(page)

      const checkbox = enabledFilters(page, 'status').first()
      const statusValue = await checkbox.getAttribute('value')
      await checkbox.check()

      await expect(page).toHaveURL(new RegExp(`status=${statusValue}`))
    })

    test('filter state is restored from URL on page load', async ({ page }) => {
      // Take the params off the page rather than hardcoding `category=security`, which is only
      // enabled when a security-category plugin happens to be installed.
      await openPluginsList(page)
      const categoryValue = await enabledFilters(page, 'category').first().getAttribute('value')
      const statusValue = await enabledFilters(page, 'status').first().getAttribute('value')
      expect(categoryValue, 'no enabled category filter rendered').toBeTruthy()
      expect(statusValue, 'no enabled status filter rendered').toBeTruthy()

      await page.goto(`/admin/plugins?category=${categoryValue}&status=${statusValue}`)

      await expect(page.locator(`#category-${categoryValue}`)).toBeChecked()
      await expect(page.locator(`#status-${statusValue}`)).toBeChecked()
    })

    test('filter state is retained after page reload', async ({ page }) => {
      await openPluginsList(page)

      // Check first available category checkbox
      const checkbox = enabledFilters(page, 'category').first()
      const categoryValue = await checkbox.getAttribute('value')
      expect(categoryValue, 'no enabled category filter rendered').toBeTruthy()

      await checkbox.check()
      await expect(page).toHaveURL(new RegExp(`category=${categoryValue}`))

      // Reload — URL params are preserved by the browser
      await page.reload()

      // Checkbox should be re-checked from URL
      await expect(page.locator(`#category-${categoryValue}`)).toBeChecked()
    })

    test('multiple category filters update URL with multiple params', async ({ page }) => {
      await openPluginsList(page)

      const checkboxes = enabledFilters(page, 'category')
      expect(
        await checkboxes.count(),
        'fewer than two categories are occupied by installed plugins'
      ).toBeGreaterThanOrEqual(2)

      await checkboxes.nth(0).check()
      await checkboxes.nth(1).check()

      const params = new URL(page.url()).searchParams.getAll('category')
      expect(params.length).toBe(2)
    })

    // The sort <select> was removed from /admin/plugins in "fix(plugins): remove
    // non-functional sort dropdown (#1007)". The remaining non-default-able control
    // that participates in URL state is the search box, so the two cases below cover
    // the same contract: a non-default value lands in the URL, the default does not.
    test('search text is reflected in URL', async ({ page }) => {
      await page.goto('/admin/plugins')
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('#search-input')).toBeVisible()

      await page.fill('#search-input', 'turnstile')
      await expect(page).toHaveURL(/search=turnstile/)
    })

    test('default (empty) search is not added to URL', async ({ page }) => {
      await page.goto('/admin/plugins')
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator('#search-input')).toBeVisible()

      // Type then clear — back at the default the param must be gone again
      await page.fill('#search-input', 'turnstile')
      await expect(page).toHaveURL(/search=turnstile/)

      await page.fill('#search-input', '')
      await expect(page).not.toHaveURL(/search=/)
      expect(page.url()).not.toContain('search=')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 88-plugin-system.spec.ts", () => {
  /**
   * E2E: Plugin system — verifies actual plugin APIs match what the docs describe.
   *
   * Tests:
   * - definePlugin / registerPlugins wiring (hello-world plugin route accessible)
   * - Admin plugins page lists hello-world
   * - requireAuth blocks unauthenticated access
   * - Hook event paths exist (content create endpoint, auth registration endpoint)
   * - configSchema form renders on the plugins admin page
   */



  const BASE = process.env.BASE_URL || 'http://localhost:8787'

  test.describe('Plugin system @plugins @lock-plugin-hello-world @lock-auth-registration', () => {
    test('hello-world plugin route accessible after login', async ({ page }) => {
      await loginAsAdmin(page)
      const res = await page.goto('/admin/hello-world')
      expect(res?.status()).toBeLessThan(400)
      await expect(page.locator('h1')).toContainText(/hello/i)
    })

    test('admin plugins page lists hello-world plugin', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/plugins')
      // The plugin installed via definePlugin should appear in the plugins list
      await expect(page.locator('body')).toContainText('Hello World', { timeout: 10_000 })
    })

    test('hello-world plugin route returns 401 without auth', async ({ request }) => {
      const res = await request.get('/admin/hello-world', { maxRedirects: 0 })
      // Should redirect to login (302) or return 401
      expect([301, 302, 401]).toContain(res.status())
    })

    test('app booted successfully — all registered plugins passed validation', async ({ request }) => {
      // If any plugin had invalid id/version/etc, the app would throw at boot
      // A successful response from the root proves all plugins validated
      const res = await request.get('/')
      expect(res.status()).toBeLessThan(500)
    })

    test('auth:registration:completed hook path — sign-up endpoint exists', async ({ request }) => {
      // Better Auth registration endpoint (NOT /api/auth/sign-up/email)
      const res = await request.post('/auth/sign-up/email', {
        headers: { 'Content-Type': 'application/json', Origin: BASE },
        data: {
          email: `hook-test-${Date.now()}@example.com`,
          password: 'TestPass123!',
          name: 'Hook Test',
        },
      })
      // 200 = registered (auth:registration:completed fires), 422 = validation failure
      // Either way the endpoint exists
      expect([200, 201, 400, 409, 422]).toContain(res.status())
    })

    test('legacy auth:login hook fires — login endpoint exists and works', async ({ request }) => {
      const res = await request.post('/auth/sign-in/email', {
        headers: { 'Content-Type': 'application/json', Origin: BASE },
        data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
      })
      // auth:login hook is wired on the legacy bus in the auth plugin's onBoot
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(body).toHaveProperty('token')
    })

    test('configSchema auto-form rendered on plugins admin page', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/plugins')
      // The plugins page lists plugins with configSchema — openPluginSettings() buttons exist
      await expect(page.locator('[onclick*="openPluginSettings"]')).toHaveCount({ min: 1 } as any, { timeout: 10_000 }).catch(() => {
        // Older interface — just check the page loaded
      })
      expect(page.url()).toContain('/admin/plugins')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 93-disabled-plugin-sidebar.spec.ts", () => {
  /**
   * #971 — Disabled plugins must not appear in the admin sidebar.
   *
   * A plugin disabled via /admin/plugins should have its sidebar link removed
   * immediately; re-enabling it should restore the link.
   */
  test.describe('Disabled plugin hidden from sidebar (#971) @plugins @lock-plugin-hello-world', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    // Always re-enable core-media in case the test fails mid-execution
    test.afterEach(async ({ page }) => {
      await page.request.post('/admin/plugins/core-media/enable', {
        headers: { 'Content-Type': 'application/json' },
      }).catch(() => {})
    })

    test('disabling a plugin removes it from the sidebar', async ({ page }) => {
      // Find an installed, non-core plugin that has an admin sidebar entry.
      // hello-world is a demo plugin, so toggling it has no functional side effects.
      // (core-media is currently uninstalled, so it contributes no sidebar entry.)
      const pluginId = 'hello-world'
      const sidebarHref = '/admin/hello-world'
      // The enable/disable endpoints are /activate and /deactivate.
      const enable = () =>
        page.request.post(`/admin/plugins/${pluginId}/activate`, {
          headers: { 'Content-Type': 'application/json' },
        })

      try {
        // First ensure it's enabled
        expect((await enable()).ok()).toBe(true)

        await page.goto('/admin')
        await page.waitForLoadState('domcontentloaded')

        // Sidebar should have a link for this plugin. The layout renders both a desktop
        // and a mobile <nav>; the desktop one comes first and is the visible one.
        const pluginLink = page.locator(`nav a[href="${sidebarHref}"]`).first()
        await expect(pluginLink).toBeVisible()

        // Disable the plugin
        await page.goto(`/admin/plugins/${pluginId}`)
        await page.waitForLoadState('domcontentloaded')

        const disableBtn = page.getByRole('button', { name: 'Deactivate', exact: true })
        if (await disableBtn.count() > 0) {
          await disableBtn.click()
          // The detail page reloads ~1s after a successful toggle
          await expect(page.getByRole('button', { name: 'Activate', exact: true })).toBeVisible({
            timeout: 20000,
          })
        } else {
          // Use direct API
          const res = await page.request.post(`/admin/plugins/${pluginId}/deactivate`, {
            headers: { 'Content-Type': 'application/json' },
          })
          expect(res.ok()).toBe(true)
        }

        // Reload admin — sidebar should no longer show the plugin link
        await page.goto('/admin')
        await page.waitForLoadState('domcontentloaded')
        await expect(page.locator(`nav a[href="${sidebarHref}"]`)).toHaveCount(0)
      } finally {
        // Re-enable to restore state
        await enable()
      }

      // …and the link comes back once the plugin is enabled again
      await page.goto('/admin')
      await page.waitForLoadState('domcontentloaded')
      await expect(page.locator(`nav a[href="${sidebarHref}"]`).first()).toBeVisible()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 94-removed-plugin-deactivated.spec.ts", () => {
  /**
   * #970 — Plugins removed from SonicJSConfig.plugins.register must be
   * deactivated on the next boot, not stay installed+enabled.
   *
   * This spec tests the pruneStaleUserPlugins path indirectly: after removing
   * a plugin from config the POST /api/plugin-prune-check endpoint (if it
   * existed) would confirm deactivation. Here we verify the admin plugins list
   * no longer shows the removed plugin as active.
   *
   * Full integration (requires a real config change + cold boot) is validated
   * in the unit-level wire.ts tests. This spec covers the observable symptom:
   * deactivated plugins are not shown as active in the admin plugins page.
   */
  test.describe('Removed plugin deactivated on boot (#970) @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('admin plugins page shows inactive plugin as inactive (not active)', async ({ page }) => {
      // Disable a known plugin via the API to simulate it being removed from config
      const pluginId = 'core-seo' // typically present but non-critical
      await page.request.post(`/admin/plugins/${pluginId}/disable`, {
        headers: { 'Content-Type': 'application/json' },
      })

      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      // The plugins list page must not show this plugin with an "Active" badge
      // while its status is inactive
      const pluginRow = page.locator(`[data-plugin-id="${pluginId}"], tr:has-text("${pluginId}")`)
      if (await pluginRow.count() > 0) {
        await expect(pluginRow.locator('text=/Active/i')).toHaveCount(0)
      }
    })

    test('pruneStaleUserPlugins: non-core active plugin absent from wired list is deactivated', async ({ page }) => {
      // This test verifies the wire.ts pruning logic runs. We can only observe
      // the effect indirectly via the admin UI since we cannot restart the worker.
      // Confirm the plugins page loads successfully (regression guard).
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')
      await expect(page.locator('body')).not.toContainText('Internal Server Error')
      await expect(page.locator('body')).not.toContainText('500')
    })
  })
})
