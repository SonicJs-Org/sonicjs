import { test, expect, type Page } from './fixtures';
import { loginAsAdmin, gotoMediaLibrary } from './utils/test-helpers';

/**
 * Pick a view and wait for the resulting navigation.
 *
 * The View select is not htmx — its `onchange` runs
 * `window.location.href = updateUrlParam('view', this.value)`, so every change is a full page
 * load of the same route with `?view=<value>`. Nothing here is instantaneous, and the assertions
 * below are about which container the *server* rendered, so the URL has to have changed before
 * they mean anything.
 */
async function selectView(page: Page, view: 'grid' | 'list') {
  const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });
  await viewSelector.selectOption(view);
  await page.waitForURL(new RegExp(`[?&]view=${view}(&|$)`));
}

test.describe('Media View Switching @media', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page, false);
    await gotoMediaLibrary(page);
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
    await selectView(page, 'list');

    // Verify list view is active - list view uses space-y-4 class
    const listViewContainer = page.locator('#media-grid > div.space-y-4');
    await expect(listViewContainer).toBeVisible();
    await expect(mediaGridContainer).not.toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    // Switch back to grid view
    await selectView(page, 'grid');

    // Verify grid view is active again
    await expect(mediaGridContainer).toBeVisible();
    await expect(listViewContainer).not.toBeVisible();
    await expect(viewSelector).toHaveValue('grid');

    // Test multiple switches to ensure consistency
    await selectView(page, 'list');
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    await selectView(page, 'grid');
    await expect(mediaGridContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('grid');

    await selectView(page, 'list');
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');
  });

  test('should persist view preference across page reloads', async ({ page }) => {
    const viewSelector = page.locator('select').filter({ has: page.locator('option:has-text("Grid")') });

    // Switch to list view
    await selectView(page, 'list');

    // Verify list view is active
    const listViewContainer = page.locator('#media-grid > div.space-y-4');
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    // Reload page
    await page.reload();

    // Verify list view is still active after reload
    await expect(listViewContainer).toBeVisible();
    await expect(viewSelector).toHaveValue('list');

    // Switch back to grid, then reload. `reload()` re-requests whatever URL the page is
    // currently on, so it has to run after the `?view=grid` navigation has committed — the
    // 500ms sleep that used to stand in for that wait expired first on a slow preview, the
    // reload re-fetched `?view=list`, and the grid container was never in the document.
    await selectView(page, 'grid');
    await page.reload();

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
    await selectView(page, 'list');

    // List should now be selected
    await expect(viewSelector).toHaveValue('list');

    // Switch back to grid
    await selectView(page, 'grid');

    // Grid should be selected again
    await expect(viewSelector).toHaveValue('grid');
  });
});
