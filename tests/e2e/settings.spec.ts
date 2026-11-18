import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 27-settings-general.spec.ts", () => {
  test.describe('Settings - General Tab @auth', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should display general settings page', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Check for general settings header
      await expect(page.locator('h1')).toContainText('Settings');

      // Check for general tab being active
      const generalTab = page.locator('a[href="/admin/settings/general"]');
      await expect(generalTab).toBeVisible();

      // Check for form fields
      await expect(page.locator('input[name="siteName"]')).toBeVisible();
      await expect(page.locator('textarea[name="siteDescription"]')).toBeVisible();
      await expect(page.locator('input[name="adminEmail"]')).toBeVisible();
      await expect(page.locator('select[name="timezone"]')).toBeVisible();
      await expect(page.locator('select[name="language"]')).toBeVisible();
    });

    test('should load default settings values', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Check default values are loaded
      const siteName = await page.locator('input[name="siteName"]').inputValue();
      expect(siteName).toBeTruthy(); // Should have a value (either default or saved)

      const siteDescription = await page.locator('textarea[name="siteDescription"]').inputValue();
      expect(siteDescription).toBeTruthy(); // Should have a value
    });

    test('should save general settings successfully', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Fill in new values
      const uniqueSiteName = `SonicJS Test ${Date.now()}`;
      const uniqueDescription = `Test description ${Date.now()}`;

      await page.locator('input[name="siteName"]').fill(uniqueSiteName);
      await page.locator('textarea[name="siteDescription"]').fill(uniqueDescription);
      await page.locator('select[name="timezone"]').selectOption('America/New_York');
      await page.locator('select[name="language"]').selectOption('en');

      // Wait for the response to complete
      const responsePromise = page.waitForResponse(response =>
        response.url().includes('/admin/settings/general') && response.request().method() === 'POST'
      );

      // Click save button
      await page.locator('button:has-text("Save Changes")').click();

      // Wait for the save to complete
      const response = await responsePromise;
      expect(response.status()).toBe(200);

      // Wait a bit for database to be updated
      await page.waitForTimeout(1000);

      // Reload page and verify values persisted
      await page.reload();
      await page.waitForLoadState('networkidle');

      // Wait for form to be populated
      await page.waitForTimeout(500);

      const savedSiteName = await page.locator('input[name="siteName"]').inputValue();
      const savedDescription = await page.locator('textarea[name="siteDescription"]').inputValue();
      const savedTimezone = await page.locator('select[name="timezone"]').inputValue();

      expect(savedSiteName).toBe(uniqueSiteName);
      expect(savedDescription).toBe(uniqueDescription);
      expect(savedTimezone).toBe('America/New_York');
    });

    test('should toggle maintenance mode', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      const maintenanceModeCheckbox = page.locator('input[name="maintenanceMode"]');
      await expect(maintenanceModeCheckbox).toBeVisible();

      const initialState = await maintenanceModeCheckbox.isChecked();

      try {
        // Toggle it
        await maintenanceModeCheckbox.click();
        await page.locator('button:has-text("Save Changes")').click();
        await page.waitForTimeout(1000);

        // Reload and verify
        await page.reload();
        await page.waitForLoadState('networkidle');

        const newState = await page.locator('input[name="maintenanceMode"]').isChecked();
        expect(newState).toBe(!initialState);
      } finally {
        // Restore the original state even when the assertion above fails — settings are a single
        // shared row, so a leaked "on" here is inherited by every later run of this spec.
        await page.reload();
        await page.waitForLoadState('networkidle');
        const checkbox = page.locator('input[name="maintenanceMode"]');
        if ((await checkbox.isChecked()) !== initialState) {
          await checkbox.click();
          await page.locator('button:has-text("Save Changes")').click();
          await page.waitForTimeout(1000);
        }
      }
    });

    test('should validate required fields', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Clear required fields
      await page.locator('input[name="siteName"]').fill('');
      await page.locator('textarea[name="siteDescription"]').fill('');

      // Try to save, and wait for the POST rather than for a fixed second: the notification only
      // exists between the response landing and its own five-second self-destruct.
      const [response] = await Promise.all([
        page.waitForResponse(
          (r) => r.url().includes('/admin/settings/general') && r.request().method() === 'POST',
          { timeout: 30000 }
        ),
        page.locator('button:has-text("Save Changes")').click(),
      ]);

      expect(response.status(), 'an empty site name was accepted').toBe(400);
      expect((await response.json()).error).toMatch(/required/i);

      // ...and the rejection has to reach the operator, not just the network tab.
      await expect(page.locator('#notification-container')).toContainText(/required/i, {
        timeout: 10000,
      });
    });

    test('should update admin email', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Capture original to restore after test
      const originalEmail = await page.locator('input[name="adminEmail"]').inputValue();
      const newAdminEmail = `admin-${Date.now()}@example.com`;

      await page.locator('input[name="adminEmail"]').fill(newAdminEmail);
      await page.locator('button:has-text("Save Changes")').click();
      await page.waitForTimeout(1000);

      // Reload and verify
      await page.reload();
      await page.waitForLoadState('networkidle');

      const savedEmail = await page.locator('input[name="adminEmail"]').inputValue();
      expect(savedEmail).toBe(newAdminEmail);

      // Restore original email
      await page.locator('input[name="adminEmail"]').fill(originalEmail);
      await page.locator('button:has-text("Save Changes")').click();
      await page.waitForTimeout(1000);
    });

    test('should switch between settings tabs', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Click on security tab
      await page.locator('a[href="/admin/settings/security"]').click();
      await page.waitForLoadState('networkidle');

      expect(page.url()).toContain('/admin/settings/security');

      // Go back to general
      await page.locator('a[href="/admin/settings/general"]').click();
      await page.waitForLoadState('networkidle');

      expect(page.url()).toContain('/admin/settings/general');
    });

    test('should show save button loading state', async ({ page }) => {
      await page.goto('/admin/settings/general');
      await page.waitForLoadState('networkidle');

      // Make a change
      const uniqueSiteName = `Test Save Loading ${Date.now()}`;
      await page.locator('input[name="siteName"]').fill(uniqueSiteName);

      const saveButton = page.locator('button:has-text("Save Changes")');

      // Wait for the response
      const responsePromise = page.waitForResponse(response =>
        response.url().includes('/admin/settings/general') && response.request().method() === 'POST'
      );

      // Click save button
      await saveButton.click();

      // Wait for save to complete
      const response = await responsePromise;
      expect(response.status()).toBe(200);

      // Button should return to normal state (not disabled)
      await expect(saveButton).toBeEnabled();
      await expect(saveButton).toContainText(/Save Changes/i);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 47-settings-wip-cleanup.spec.ts", () => {
  test.describe('Settings - WIP cleanup @auth', () => {
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
})
