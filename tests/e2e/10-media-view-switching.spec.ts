import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Media View Switching @media', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/media');
    await page.waitForLoadState('networkidle');
  });

  test('should switch between grid and list views bidirectionally', async ({ page }) => {
    // Verify default view is grid by checking the container class
    const mediaGridContainer = page.locator('#media-grid > div.media-grid');
    await expect(mediaGridContainer).toBeVisible();

    // Find the view selector dropdown
    const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });
    await expect(viewSelector).toBeVisible();

    // Verify grid is selected
    await expect(viewSelector).toHaveValue('grid');

    // Switch to list view
    await viewSelector.selectOption('list');
    await page.waitForLoadState('networkidle');

    // Verify list view is active - list view uses space-y-4 class
    const listViewContainer = page.locator('#media-grid > div.space-y-4');
    await expect(listViewContainer).toBeVisible();
    await expect(mediaGridContainer).not.toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    // Switch back to grid view
    await viewSelector.selectOption('grid');
    await page.waitForLoadState('networkidle');

    // Verify grid view is active again
    await expect(mediaGridContainer).toBeVisible();
    await expect(listViewContainer).not.toBeVisible();
    await expect(viewSelector).toHaveValue('grid');

    // Test multiple switches to ensure consistency
    await viewSelector.selectOption('list');
    await page.waitForLoadState('networkidle');
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    await viewSelector.selectOption('grid');
    await page.waitForLoadState('networkidle');
    await expect(mediaGridContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('grid');

    await viewSelector.selectOption('list');
    await page.waitForLoadState('networkidle');
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');
  });

  test('should persist view preference across page reloads', async ({ page }) => {
    const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });

    // Switch to list view
    await viewSelector.selectOption('list');
    await page.waitForLoadState('networkidle');

    // Verify list view is active
    const listViewContainer = page.locator('#media-grid > div.space-y-4');
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    // Reload page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Verify list view is still active after reload
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    // Switch back to grid and reload
    await viewSelector.selectOption('grid');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);

    await page.reload();
    await page.waitForLoadState('networkidle');

    // Verify grid view is active after reload
    const mediaGridContainer = page.locator('#media-grid > div.media-grid');
    await expect(mediaGridContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('grid');
  });

  test('should reflect selected view in dropdown', async ({ page }) => {
    const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });

    // Initial state: grid should be selected
    await expect(viewSelector).toHaveValue('grid');

    // Switch to list view
    await viewSelector.selectOption('list');
    await page.waitForLoadState('networkidle');

    // List should now be selected
    await expect(viewSelector).toHaveValue('list');

    // Switch back to grid
    await viewSelector.selectOption('grid');
    await page.waitForLoadState('networkidle');

    // Grid should be selected again
    await expect(viewSelector).toHaveValue('grid');
  });
});
