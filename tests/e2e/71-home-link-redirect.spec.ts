import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe('Home Link and Admin Redirect', () => {
  test('/admin redirects to /admin/content', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin');

    // Should redirect to /admin/content
    await expect(page).toHaveURL('/admin/content');
  });

  test('Home link appears in sidebar and navigates to /admin', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/content');

    // Find the Home link in the sidebar
    const homeLink = page.locator('nav a[href="/admin"]');

    // Verify it exists and is visible
    await expect(homeLink).toBeVisible();

    // Verify it has the "Home" label
    await expect(homeLink).toContainText('Home');

    // Click the Home link
    await homeLink.click();

    // Should redirect to /admin/content (since /admin redirects to /admin/content)
    await expect(page).toHaveURL('/admin/content');
  });

  test('Home link has correct icon', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/content');

    // Find the Home link in the sidebar
    const homeLink = page.locator('nav a[href="/admin"]');

    // Verify it has an SVG icon (home icon)
    const icon = homeLink.locator('svg');
    await expect(icon).toBeVisible();
  });
});
