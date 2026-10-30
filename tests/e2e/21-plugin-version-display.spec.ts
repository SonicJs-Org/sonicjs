import { test, expect } from './fixtures';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

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
