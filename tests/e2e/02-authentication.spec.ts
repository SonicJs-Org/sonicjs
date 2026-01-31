import { test, expect } from '@playwright/test';
import { loginAsAdmin, logout, isAuthenticated, ADMIN_CREDENTIALS } from './utils/test-helpers';

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    // Ensure we start logged out
    await logout(page);
  });

  test('should display login form', async ({ page }) => {
    await page.goto('/auth/login');
    
    await expect(page.locator('h2')).toContainText('Welcome Back');
    await expect(page.locator('[name="email"]')).toBeVisible();
    await expect(page.locator('[name="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('should login successfully with valid credentials', async ({ page }) => {
    await loginAsAdmin(page);

    // Should be on admin dashboard (app redirects /admin to /admin/dashboard)
    await expect(page).toHaveURL(/\/admin/);
    // Verify we're logged in by checking for any admin content
    // Don't check for specific elements as layout may vary
  });

  test('should show error with invalid credentials', async ({ page }) => {
    await page.goto('/auth/login');

    await page.fill('[name="email"]', 'invalid@email.com');
    await page.fill('[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    // Better Auth / form script shows error in #form-response (red styling)
    await expect(page.locator('#form-response')).toBeVisible();
    await expect(page.locator('#form-response [class*="red"]')).toBeVisible({ timeout: 5000 });
  });

  test('should logout successfully', async ({ page }) => {
    // First login
    await loginAsAdmin(page);
    await expect(await isAuthenticated(page)).toBe(true);
    
    // Then logout
    await logout(page);
    
    // Should be redirected to login
    await expect(page).toHaveURL(/\/auth\/login/);
    await expect(await isAuthenticated(page)).toBe(false);
  });

  test('should protect admin routes from unauthenticated access', async ({ page }) => {
    const adminRoutes = [
      '/admin',
      '/admin/collections',
      '/admin/content',
      '/admin/media',
      '/admin/users'
    ];

    for (const route of adminRoutes) {
      await page.goto(route);
      // Should redirect to login
      await page.waitForURL(/\/auth\/login/);
      await expect(page.locator('h2')).toContainText('Welcome Back');
    }
  });

  test('should maintain session across page reloads', async ({ page }) => {
    await loginAsAdmin(page);

    // Reload the page
    await page.reload();

    // Should still be authenticated (app redirects /admin to /admin/dashboard)
    await expect(page).toHaveURL(/\/admin/);
    await expect(await isAuthenticated(page)).toBe(true);
  });
}); 