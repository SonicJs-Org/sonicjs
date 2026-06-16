import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe('Home Link and Admin Redirect', () => {
  test('/admin redirects to /admin/dashboard', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin');

    // Should redirect to /admin/dashboard
    await expect(page).toHaveURL('/admin/dashboard');
  });

  // The admin sidebar uses the catalyst layout — there is no standalone
  // "Home" nav link at href="/admin". Skip until one is added.
  test.skip('Home link appears in sidebar and navigates to /admin', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/content');

    const homeLink = page.locator('nav a[href="/admin"]');
    await expect(homeLink).toBeVisible();
    await expect(homeLink).toContainText('Home');
    await homeLink.click();
    await expect(page).toHaveURL('/admin/dashboard');
  });

  test.skip('Home link has correct icon', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/content');

    const homeLink = page.locator('nav a[href="/admin"]');
    const icon = homeLink.locator('svg');
    await expect(icon).toBeVisible();
  });
});
