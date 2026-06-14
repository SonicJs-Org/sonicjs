import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

// Phase 1: user profiles are stored as `user_profile` documents (is_auth type),
// not the dropped auth_user_profiles table. This verifies the admin user-edit
// page persists profile fields through the document-backed path, and that the
// auth-owned type does not leak into the content surface.
test.describe('User profile (document-backed)', () => {
  test('persists profile fields written on the user edit page', async ({ page }) => {
    await loginAsAdmin(page);

    // Create a target user via the registration API to get a stable id.
    const ts = Date.now();
    const reg = await page.request.post('/auth/register', {
      data: {
        email: `profiledoc${ts}@example.com`,
        username: `profiledoc${ts}`,
        password: 'TestPassword123!',
        firstName: 'Profile',
        lastName: 'Doc',
      },
    });
    expect(reg.ok()).toBeTruthy();
    const userId = (await reg.json()).user?.id;
    expect(userId).toBeTruthy();

    // Edit the user's profile. The standard profile now carries only displayName (bio lives on
    // auth_user; company/website/etc. were removed) plus the custom-fields namespace.
    await page.goto(`/admin/users/${userId}/edit`);
    const displayName = `Display ${ts}`;
    await page.fill('input[name="profile_display_name"]', displayName);
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');

    // Reload the edit page; the value must survive a round-trip through the user_profile document.
    await page.goto(`/admin/users/${userId}/edit`);
    await expect(page.locator('input[name="profile_display_name"]')).toHaveValue(displayName);
  });

  test('user_profile type is not offered as content', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');
    // The auth-owned user_profile type is excluded from content surfaces
    // (internal + is_auth), so it must not appear as a selectable model.
    await expect(page.locator('text=User Profile')).toHaveCount(0);
  });
});
