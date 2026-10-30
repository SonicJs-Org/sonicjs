import { test, expect } from './fixtures';
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers';


test.describe('Turnstile Forms List Buttons @forms', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should show Examples and Quick Reference buttons on forms list', async ({ page }) => {
    await page.goto('/admin/forms');
    await page.waitForLoadState('networkidle');

    // Check for Examples button
    const examplesBtn = page.locator('a[href="/admin/forms/examples"], button:has-text("Examples")');
    await expect(examplesBtn.first()).toBeVisible();

    // Check for Quick Reference button
    const quickRefBtn = page.locator('a[href="/admin/forms/docs"], button:has-text("Quick Reference")');
    await expect(quickRefBtn.first()).toBeVisible();
  });

  test('should navigate to Examples page from forms list', async ({ page }) => {
    await page.goto('/admin/forms');
    await page.waitForLoadState('networkidle');

    const examplesBtn = page.locator('a[href="/admin/forms/examples"]').first();
    await examplesBtn.click();
    
    await page.waitForURL(/\/admin\/forms\/examples/);
    await expect(page).toHaveURL(/\/admin\/forms\/examples/);
  });

  test('should navigate to Quick Reference page from forms list', async ({ page }) => {
    await page.goto('/admin/forms');
    await page.waitForLoadState('networkidle');

    const quickRefBtn = page.locator('a[href="/admin/forms/docs"]').first();
    await quickRefBtn.click();
    
    await page.waitForURL(/\/admin\/forms\/docs/);
    await expect(page).toHaveURL(/\/admin\/forms\/docs/);
  });
});
