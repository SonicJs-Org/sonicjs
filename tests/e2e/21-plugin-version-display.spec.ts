import { test, expect } from '@playwright/test';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';

// Expected version for all plugins (should match manifest.json files)
const EXPECTED_VERSION = '1.0.0-beta.1';

test.describe('Plugin Version Display', () => {
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
      console.log(`Checking plugin: ${pluginName}`);

      // Look for version text with pattern "v1.0.0-beta.1 by..."
      const versionText = await card.locator('text=/v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?/i').first().textContent();

      // Extract just the version number
      const versionMatch = versionText?.match(/v?(\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?)/i);
      const version = versionMatch ? versionMatch[1] : null;

      console.log(`  Version found: ${version}`);

      // Verify version matches expected format
      expect(version, `Plugin "${pluginName}" should display version ${EXPECTED_VERSION}`).toBe(EXPECTED_VERSION);
    }
  });

  test('should display version with "v" prefix', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`);

    // Get first plugin card
    const firstCard = page.locator('.plugin-card').first();
    await expect(firstCard).toBeVisible();

    // Check for version with v prefix
    await expect(firstCard.locator('text=/v\\d+\\.\\d+\\.\\d+/i')).toBeVisible();

    // Verify it specifically shows "v1.0.0-beta.1"
    await expect(firstCard.locator(`text=v${EXPECTED_VERSION}`)).toBeVisible();
  });

  test('should display version in plugin details/settings page', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`);

    // Find a plugin with settings button
    const pluginCards = page.locator('.plugin-card');
    const count = await pluginCards.count();

    for (let i = 0; i < Math.min(count, 3); i++) {
      const card = pluginCards.nth(i);
      const pluginName = await card.locator('h3, h2').first().textContent();
      const settingsBtn = card.locator('button[title="Settings"], button:has-text("Settings")');

      const hasSettings = await settingsBtn.count();
      if (hasSettings > 0) {
        console.log(`Checking settings page for plugin: ${pluginName}`);
        await settingsBtn.click();

        // Should navigate to plugin settings page
        await expect(page.url()).toContain('/admin/plugins/');

        // Check if version is displayed on settings page
        const versionOnSettings = await page.locator('text=/v?\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?/i').first().textContent();
        console.log(`  Version on settings page: ${versionOnSettings}`);

        // Version should contain the expected version
        expect(versionOnSettings).toContain(EXPECTED_VERSION);

        // Go back to plugins list
        await page.goto(`${BASE_URL}/admin/plugins`);
        break;
      }
    }
  });

  test('should show consistent version across plugin list and API', async ({ page, request }) => {
    // Get version from UI
    await page.goto(`${BASE_URL}/admin/plugins`);
    const firstCard = page.locator('.plugin-card').first();
    await expect(firstCard).toBeVisible();

    const pluginNameElement = await firstCard.locator('h3, h2').first();
    const pluginName = await pluginNameElement.textContent();

    const versionTextUI = await firstCard.locator('text=/v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?/i').first().textContent();
    const versionMatchUI = versionTextUI?.match(/v?(\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?)/i);
    const versionUI = versionMatchUI ? versionMatchUI[1] : null;

    console.log(`Plugin: ${pluginName}, UI Version: ${versionUI}`);

    // Get version from API
    const response = await request.get(`${BASE_URL}/api/plugins`);
    expect(response.ok()).toBeTruthy();

    const apiData = await response.json();

    // Find matching plugin in API response
    const plugin = apiData.data?.find((p: any) =>
      p.name === pluginName?.trim() || p.display_name === pluginName?.trim()
    );

    if (plugin) {
      console.log(`  API Version: ${plugin.version}`);
      expect(plugin.version).toBe(versionUI);
      expect(plugin.version).toBe(EXPECTED_VERSION);
    }
  });

  test('should not display truncated version (e.g., v1.0.0 instead of v1.0.0-beta.1)', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`);

    const pluginCards = page.locator('.plugin-card');
    const count = await pluginCards.count();

    // Check that no plugin shows just "v1.0.0" without the "-beta.1"
    for (let i = 0; i < count; i++) {
      const card = pluginCards.nth(i);
      const pluginName = await card.locator('h3, h2').first().textContent();

      // Should NOT find exact match for "v1.0.0 " (with space after, indicating no beta suffix)
      const hasTruncatedVersion = await card.locator('text=/v1\\.0\\.0\\s/').count();

      expect(hasTruncatedVersion,
        `Plugin "${pluginName}" should not display truncated version "v1.0.0" without beta suffix`
      ).toBe(0);
    }
  });

  test('should display version with proper formatting', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`);

    const firstCard = page.locator('.plugin-card').first();
    const versionText = await firstCard.locator('text=/v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?\\s+by/i').textContent();

    console.log(`Version text format: "${versionText}"`);

    // Should follow format: "v1.0.0-beta.1 by Author Name"
    expect(versionText).toMatch(/v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?\\s+by/i);

    // Specifically should show beta version
    expect(versionText).toContain(EXPECTED_VERSION);
  });

  test('should display version for core plugins', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`);

    // Check specific core plugins
    const corePluginNames = [
      'Authentication System',
      'Media Manager',
      'Analytics & Insights',
      'Cache System',
      'Workflow Engine'
    ];

    for (const pluginName of corePluginNames) {
      const pluginCard = page.locator('.plugin-card').filter({ hasText: pluginName });
      const count = await pluginCard.count();

      if (count > 0) {
        console.log(`Checking core plugin: ${pluginName}`);

        // Should display version
        const versionElement = pluginCard.locator(`text=v${EXPECTED_VERSION}`);
        await expect(versionElement).toBeVisible({ timeout: 5000 });

        console.log(`  ✓ Version ${EXPECTED_VERSION} displayed correctly`);
      }
    }
  });
});
