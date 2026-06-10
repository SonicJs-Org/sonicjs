import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe('Settings - WIP cleanup', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('removed tabs no longer appear in nav', async ({ page }) => {
    await page.goto('/admin/settings/general');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('a[href="/admin/settings/appearance"]')).toHaveCount(0);
    await expect(page.locator('a[href="/admin/settings/notifications"]')).toHaveCount(0);
    await expect(page.locator('a[href="/admin/settings/storage"]')).toHaveCount(0);
  });

  test('removed routes return 404', async ({ page }) => {
    for (const path of ['/admin/settings/appearance', '/admin/settings/notifications', '/admin/settings/storage']) {
      const resp = await page.goto(path);
      expect(resp?.status()).toBe(404);
    }
  });

  test('security tab shows only Session/JWT fields, no WIP banner', async ({ page }) => {
    await page.goto('/admin/settings/security');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#jwtExpiresIn')).toBeVisible();
    await expect(page.locator('#jwtRefreshGraceSeconds')).toBeVisible();
    await expect(page.locator('button:has-text("Save Session Settings")')).toBeVisible();

    await expect(page.getByText('Work in Progress')).toHaveCount(0);
    await expect(page.locator('input[name="twoFactorEnabled"]')).toHaveCount(0);
    await expect(page.locator('input[name="sessionTimeout"]')).toHaveCount(0);
    await expect(page.locator('textarea[name="ipWhitelist"]')).toHaveCount(0);
  });

  test('remaining settings tabs render', async ({ page }) => {
    for (const path of [
      '/admin/settings/general',
      '/admin/settings/security',
      '/admin/settings/migrations',
      '/admin/settings/database-tools',
    ]) {
      const resp = await page.goto(path);
      expect(resp?.status()).toBe(200);
      await expect(page.locator('h1')).toContainText('Settings');
    }
  });
});
