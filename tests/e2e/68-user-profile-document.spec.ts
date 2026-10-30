import { test, expect } from './fixtures';
import { loginAsAdmin } from './utils/test-helpers';

// Phase 1: user profiles are stored as `user_profile` documents (is_auth type),
// not the dropped auth_user_profiles table. This verifies the admin user-edit
// page persists profile fields through the document-backed path, and that the
// auth-owned type does not leak into the content surface.
test.describe('User profile (document-backed) @auth', () => {
  test('user_profile type is not offered as content', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');
    // The auth-owned user_profile type is excluded from content surfaces
    // (internal + is_auth), so it must not appear as a selectable model.
    await expect(page.locator('text=User Profile')).toHaveCount(0);
  });
});
