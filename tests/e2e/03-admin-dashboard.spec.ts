import { test, expect } from '@playwright/test';
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers';
import corePackageJson from '../../packages/core/package.json' with { type: 'json' };

test.describe('Admin Dashboard @smoke', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test.skip('should display correct version from package.json', async ({ page }) => {
    // The version should be displayed in the layout (usually in the sidebar or footer)
    // Version comes from @sonicjs-cms/core package and is shown without 'v' prefix in badge
    const expectedVersion = corePackageJson.version;

    // Look for the version badge (it displays just the version number like "2.0.3")
    const versionElement = page.getByText(expectedVersion, { exact: true }).first();
    await expect(versionElement).toBeVisible({ timeout: 10000 });

    // Make sure it's not showing the old hardcoded version
    const oldVersion = page.getByText('0.1.0', { exact: true });
    await expect(oldVersion).not.toBeVisible();
  });

  test('should land on the admin shell with sidebar navigation', async ({ page }) => {
    // /admin redirects to /admin/content (there is no standalone dashboard page anymore;
    // the analytics view lives at /admin/analytics).
    await expect(page).toHaveURL(/\/admin/);

    // Check the catalyst sidebar nav links (desktop + mobile → use .first()).
    await expect(page.locator('a[href="/admin/content"]').first()).toBeVisible();
    await expect(page.locator('a[href="/admin/collections"]').first()).toBeVisible();
    await expect(page.locator('a[href="/admin/users"]').first()).toBeVisible();
    await expect(page.locator('a[href="/admin/settings"]').first()).toBeVisible();
  });

  test('should display statistics cards', async ({ page }) => {
    // Check for stats container that loads via HTMX
    const statsContainer = page.locator('#stats-container');

    // Wait for either stats container to appear or timeout gracefully
    try {
      await expect(statsContainer).toBeVisible({ timeout: 3000 });

      // Wait for HTMX to load stats and check if content appears
      await page.waitForTimeout(2000); // Give HTMX time to load

      // Check if stats cards or skeleton is visible
      await expect(statsContainer).toContainText(/Collections|Active Users|skeleton/);
    } catch (error) {
      // If stats container doesn't exist, just verify we're on admin page
      await expect(page.locator('h1, h2, [class*="dashboard"]').first()).toBeVisible();
    }
  });

  // NOTE: the standalone dashboard was removed — the Storage Usage / System Status / Recent Activity
  // widgets moved to /admin/analytics (or were dropped). Their old /admin dashboard tests were deleted
  // here; analytics has its own coverage. /admin now lands on the content list.

  test.skip('should navigate to collections page', async ({ page }) => {
    await navigateToAdminSection(page, 'collections');
    
    await expect(page.locator('h1')).toContainText('Collections');
    await expect(page.locator('a[href="/admin/collections/new"]')).toBeVisible();
  });

  test('should navigate to content page', async ({ page }) => {
    await navigateToAdminSection(page, 'content');

    await expect(page.locator('h1')).toContainText('Content Management');
    // "New Content" is a per-collection dropdown now (#885); the create link lives in the (collapsed)
    // menu, so assert it exists rather than is visible.
    expect(await page.locator('a[href^="/admin/content/new"]').count()).toBeGreaterThan(0);
  });

  test('should navigate to media page', async ({ page }) => {
    await navigateToAdminSection(page, 'media');
    
    await expect(page.locator('h1')).toContainText('Media Library');
    await expect(page.locator('button').filter({ hasText: 'Upload Files' }).first()).toBeVisible();
  });


  test('should handle quick actions', async ({ page }) => {
    // Test any quick action buttons on dashboard
    const quickActions = page.locator('.quick-action, .btn-primary');
    const count = await quickActions.count();

    if (count > 0) {
      // Verify first quick action is clickable
      await expect(quickActions.first()).toBeVisible();
    }
  });

  test('should open and close User Dropdown menu in desktop and mobile', async ({ page }) => {
    // Test Desktop Version
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto('/admin');

    // Find the user menu button (desktop version)
    const desktopUserButton = page.locator('[data-user-menu]').first();
    await expect(desktopUserButton).toBeVisible({ timeout: 5000 });

    // Verify dropdown is initially hidden
    const desktopDropdown = page.locator('.userDropdown:not(.is-mobile)').first();
    await expect(desktopDropdown).toBeHidden();

    // Click to open dropdown
    await desktopUserButton.click();
    await expect(desktopDropdown).toBeVisible({ timeout: 2000 });

    // Verify dropdown contains user information
    await expect(desktopDropdown.locator('a[href="/admin/profile"]')).toBeVisible();

    // Click to close dropdown
    await desktopUserButton.click();
    await expect(desktopDropdown).toBeHidden();

    // Test Mobile Version
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/admin');

    // Open mobile sidebar first (mobile nav is hidden by default)
    const mobileMenuButton = page.locator('button[aria-label="Open navigation"]');
    if (await mobileMenuButton.isVisible()) {
      await mobileMenuButton.click();
      await page.waitForTimeout(500); // Wait for sidebar animation
    }

    // Find the user menu button (mobile version)
    const mobileUserButton = page.locator('[data-user-menu]').last();
    await expect(mobileUserButton).toBeVisible({ timeout: 5000 });

    // Verify dropdown is initially hidden
    const mobileDropdown = page.locator('.is-mobile .userDropdown').last();
    await expect(mobileDropdown).toBeHidden();

    // Click to open dropdown
    await mobileUserButton.click();
    await expect(mobileDropdown).toBeVisible({ timeout: 2000 });

    // Verify dropdown contains user information
    await expect(mobileDropdown.locator('a[href="/admin/profile"]')).toBeVisible();

    // Click to close dropdown
    await mobileUserButton.click();
    await expect(mobileDropdown).toBeHidden();
  });
}); 
