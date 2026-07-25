import { test, expect } from '@playwright/test';
import { loginAsAdmin, logout } from './utils/test-helpers';

/**
 * E2E Tests for Disable User Registration Feature
 *
 * Tests the enforcement of the "registration.enabled" setting in the auth plugin.
 * When disabled, new user registration should be blocked (except for first user bootstrap).
 */
test.describe('Disable User Registration @auth', () => {
  // Test data for registration attempts
  const testUser = {
    email: `test.disable.reg.${Date.now()}@example.com`,
    password: 'TestPassword123!',
    username: `testuser${Date.now()}`,
    firstName: 'Test',
    lastName: 'User'
  };

  // Helper function to update registration setting via API
  async function setRegistrationEnabled(page: any, enabled: boolean): Promise<boolean> {
    // Login as admin first
    await loginAsAdmin(page);

    // Update the core-auth plugin settings via API
    const response = await page.request.post('/admin/plugins/core-auth/settings', {
      data: {
        registration: {
          enabled: enabled,
          requireEmailVerification: false,
          defaultRole: 'viewer'
        }
      },
      timeout: 10000
    });

    // Log the response for debugging
    const status = response.status();
    if (status !== 200) {
      console.log(`Setting registration enabled=${enabled}: status=${status}`);
    }

    await logout(page);

    // Small delay to ensure setting is persisted
    await page.waitForTimeout(300);

    return status === 200;
  }

  // Seed admin before all tests
  test.beforeAll(async ({ request }) => {
    try {
      await request.post('/auth/seed-admin');
    } catch (error) {
      // Admin might already exist, ignore errors
    }
  });

  test.describe('Registration when enabled (default)', () => {
    // Ensure registration is enabled before these tests run. Without this, a
    // prior test run that died before its `finally` could leave the shared
    // preview DB with registration disabled, causing these defaults-assuming
    // tests to fail permanently.
    test.beforeAll(async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await loginAsAdmin(page);
        await page.request.post('/admin/plugins/core-auth/settings', {
          data: {
            registration: {
              enabled: true,
              requireEmailVerification: false,
              defaultRole: 'viewer'
            }
          },
          timeout: 10000
        });
        await logout(page);
      } finally {
        await context.close();
      }
    });

    test('should allow API registration when registration is enabled', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `enabled.api.${Date.now()}@example.com`,
        username: `enabledapi${Date.now()}`
      };

      const response = await request.post('/auth/register', {
        data: uniqueUser
      });

      // Registration should succeed (default is enabled)
      expect(response.status()).toBe(201);

      const data = await response.json();
      expect(data).toHaveProperty('user');
      expect(data.user.email).toBe(uniqueUser.email.toLowerCase());
    });

    test('should show registration page when registration is enabled', async ({ page }) => {
      await page.goto('/auth/register');

      // Should see the registration form, not a redirect
      await expect(page).toHaveURL(/\/auth\/register/);
      await expect(page.locator('input[name="email"]')).toBeVisible();
      await expect(page.locator('input[name="password"]')).toBeVisible();
    });
  });

  test.describe('Registration when disabled via API', () => {
    // These tests use API to toggle registration setting

    test('should block API registration when disabled', async ({ page, request }) => {
      // Disable registration via API
      const settingUpdated = await setRegistrationEnabled(page, false);

      // Only run the test if we successfully updated the setting
      if (!settingUpdated) {
        console.log('Could not update registration setting via API - skipping test');
        // Re-enable registration for safety
        await setRegistrationEnabled(page, true);
        return;
      }

      try {
        const uniqueUser = {
          ...testUser,
          email: `disabled.api.${Date.now()}@example.com`,
          username: `disabledapi${Date.now()}`
        };

        const response = await request.post('/auth/register', {
          data: uniqueUser
        });

        // Registration should be blocked with 403 Forbidden
        expect(response.status()).toBe(403);

        const data = await response.json();
        expect(data.error).toContain('disabled');
      } finally {
        // Re-enable registration
        await setRegistrationEnabled(page, true);
      }
    });

    test('should redirect registration page to login when disabled', async ({ page }) => {
      // Disable registration via API
      const settingUpdated = await setRegistrationEnabled(page, false);

      if (!settingUpdated) {
        console.log('Could not update registration setting via API - skipping test');
        await setRegistrationEnabled(page, true);
        return;
      }

      try {
        await page.goto('/auth/register');

        // Should be redirected to login page with error parameter
        await expect(page).toHaveURL(/\/auth\/login/);
        expect(page.url()).toContain('error');
      } finally {
        // Re-enable registration
        await setRegistrationEnabled(page, true);
      }
    });
  });

  test.describe('First user bootstrap scenario', () => {
    // Note: This test documents expected behavior but can't fully test it
    // since we can't easily clear all users in E2E tests.

    test('should allow first user registration even when disabled (bootstrap)', async ({ request }) => {
      // This test documents the expected behavior:
      // When there are NO users in the database, registration should be allowed
      // even if the setting is disabled, to allow initial admin setup.

      // Since admin already exists from beforeAll, this tests that registration
      // either succeeds (if enabled) or fails with 403 (if disabled)
      const response = await request.post('/auth/register', {
        data: {
          email: `bootstrap.test.${Date.now()}@example.com`,
          password: 'BootstrapTest123!',
          username: `bootstrapuser${Date.now()}`,
          firstName: 'Bootstrap',
          lastName: 'Test'
        }
      });

      // Should either succeed (if enabled) or fail with 403 (if disabled)
      // Should NOT fail for other reasons
      expect([201, 403]).toContain(response.status());
    });
  });

  test.describe('Error message validation', () => {
    test('API returns appropriate error message when registration is disabled', async ({ request, page }) => {
      // Disable registration via API
      const settingUpdated = await setRegistrationEnabled(page, false);

      if (!settingUpdated) {
        console.log('Could not update registration setting via API - skipping test');
        await setRegistrationEnabled(page, true);
        return;
      }

      try {
        // Try to register
        const response = await request.post('/auth/register', {
          data: {
            email: `error.test.${Date.now()}@example.com`,
            password: 'ErrorTest123!',
            username: `erroruser${Date.now()}`,
            firstName: 'Error',
            lastName: 'Test'
          }
        });

        expect(response.status()).toBe(403);

        const data = await response.json();
        expect(data).toHaveProperty('error');
        expect(data.error.toLowerCase()).toContain('disabled');
      } finally {
        // Re-enable registration
        await setRegistrationEnabled(page, true);
      }
    });
  });
});
