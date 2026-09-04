import { test, expect, Page } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

/**
 * Profile fields on the admin user-edit page.
 *
 * The field set is a CODE-defined model: `my-sonicjs-app/src/user-profile.model.ts` calls
 * `defineUserProfile()` with bio / company / jobTitle / website. The form renders the one
 * standard field as `profile_display_name` and every declared custom field as
 * `custom_<name>`; both halves round-trip through the `user_profile` document.
 *
 * The form is HTMX (`hx-put="/admin/users/:id"`, target `#form-messages`) and never
 * navigates, so every save waits on the PUT response rather than on a URL change.
 */

const CUSTOM_FIELDS = ['custom_bio', 'custom_company', 'custom_jobTitle', 'custom_website'];

async function registerUser(page: Page, prefix: string): Promise<string> {
  const ts = Date.now();
  const res = await page.request.post('/auth/register', {
    data: {
      email: `${prefix}${ts}@example.com`,
      username: `${prefix}${ts}`,
      password: 'TestPassword123!',
      firstName: 'Profile',
      lastName: 'Test',
    },
  });
  expect(res.ok(), `registration failed: ${await res.text()}`).toBeTruthy();
  const userId = (await res.json()).user?.id;
  expect(userId).toBeTruthy();
  return userId;
}

async function saveUserForm(page: Page, userId: string) {
  const saved = page.waitForResponse(
    (r) => r.request().method() === 'PUT' && r.url().includes(`/admin/users/${userId}`),
    { timeout: 20000 },
  );
  await page.click('button[type="submit"]');
  expect((await saved).ok()).toBeTruthy();
}

test.describe('User Profile Edit on User Edit Page @auth', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('renders the Profile Information section with the code-defined fields', async ({ page }) => {
    const userId = await registerUser(page, 'profileshow');
    await page.goto(`/admin/users/${userId}/edit`);

    await expect(page.locator('h3').filter({ hasText: 'Profile Information' })).toBeVisible();

    // The single standard field.
    await expect(page.locator('input[name="profile_display_name"]')).toBeVisible();

    // Every field declared in defineUserProfile(), namespaced under custom_*.
    await expect(page.locator('textarea[name="custom_bio"]')).toBeVisible();
    await expect(page.locator('input[name="custom_company"]')).toBeVisible();
    await expect(page.locator('input[name="custom_jobTitle"]')).toBeVisible();
    await expect(page.locator('input[name="custom_website"]')).toBeVisible();
  });

  test('saves and reloads profile data', async ({ page }) => {
    const userId = await registerUser(page, 'profilesave');
    await page.goto(`/admin/users/${userId}/edit`);

    await page.fill('input[name="profile_display_name"]', 'Test Display Name');
    await page.fill('textarea[name="custom_bio"]', 'This is a test bio for the user profile.');
    await page.fill('input[name="custom_company"]', 'Test Company Inc');
    await page.fill('input[name="custom_jobTitle"]', 'Software Engineer');
    await page.fill('input[name="custom_website"]', 'https://example.com');

    await saveUserForm(page, userId);

    await page.goto(`/admin/users/${userId}/edit`);
    await expect(page.locator('input[name="profile_display_name"]')).toHaveValue('Test Display Name');
    await expect(page.locator('textarea[name="custom_bio"]')).toHaveValue('This is a test bio for the user profile.');
    await expect(page.locator('input[name="custom_company"]')).toHaveValue('Test Company Inc');
    await expect(page.locator('input[name="custom_jobTitle"]')).toHaveValue('Software Engineer');
    await expect(page.locator('input[name="custom_website"]')).toHaveValue('https://example.com');
  });

  test('updates a subset of fields and leaves the rest intact', async ({ page }) => {
    const userId = await registerUser(page, 'profileupd');

    await page.goto(`/admin/users/${userId}/edit`);
    await page.fill('input[name="profile_display_name"]', 'Original Name');
    await page.fill('input[name="custom_company"]', 'Original Company');
    await page.fill('input[name="custom_jobTitle"]', 'Software Engineer');
    await saveUserForm(page, userId);

    await page.goto(`/admin/users/${userId}/edit`);
    await page.fill('input[name="profile_display_name"]', 'Updated Display Name');
    await page.fill('input[name="custom_company"]', 'Updated Company LLC');
    await saveUserForm(page, userId);

    await page.goto(`/admin/users/${userId}/edit`);
    await expect(page.locator('input[name="profile_display_name"]')).toHaveValue('Updated Display Name');
    await expect(page.locator('input[name="custom_company"]')).toHaveValue('Updated Company LLC');
    // Untouched on the second save — must not be wiped by the partial update.
    await expect(page.locator('input[name="custom_jobTitle"]')).toHaveValue('Software Engineer');
  });

  test('leaves profile fields empty when a user is saved without filling them', async ({ page }) => {
    const userId = await registerUser(page, 'noprofile');

    // Save the user touching only Basic Information — no profile document should be
    // conjured with placeholder values.
    await page.goto(`/admin/users/${userId}/edit`);
    await page.fill('input[name="first_name"]', 'No');
    await page.fill('input[name="last_name"]', 'Profile');
    await saveUserForm(page, userId);

    await page.goto(`/admin/users/${userId}/edit`);
    await expect(page.locator('input[name="first_name"]')).toHaveValue('No');
    await expect(page.locator('input[name="profile_display_name"]')).toHaveValue('');
    for (const name of CUSTOM_FIELDS) {
      const field = page.locator(`[name="${name}"]`);
      await expect(field).toHaveValue('');
    }
  });
});
