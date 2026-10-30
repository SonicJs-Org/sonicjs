import { test, expect } from './fixtures';
import { loginAsAdmin } from './utils/test-helpers';

test.describe('Home Link and Admin Redirect @smoke', () => {
  test('/admin redirects to /admin/dashboard', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin');

    // Should redirect to /admin/dashboard
    await expect(page).toHaveURL('/admin/dashboard');
  });

});
