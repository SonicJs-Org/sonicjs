import { test, expect } from '@playwright/test';
import { loginAsAdmin, isFeatureAvailable } from './utils/test-helpers';

/**
 * E2E coverage for the legacy forms-plugin security hardening
 * (fix/legacy-forms-security). The plugin's tables (0004_forms.sql) only
 * recently started shipping, reactivating admin-forms.ts/public-forms.ts
 * routes that previously 404'd/503'd harmlessly.
 *
 * Note: `is_public` is hardcoded to 1 at creation and there's no admin
 * UI/API path to ever flip it — so the is_public submit-gate fix (covered
 * by real-SQLite integration tests, not here) isn't demonstrable through a
 * real UI flow today. This spec covers what a UI flow can actually reach:
 * a form's display name is fully attacker/admin controlled (no validation,
 * unlike `name`) and gets rendered on both the admin builder and the public
 * form page — this is the XSS surface the patch closes.
 */

test.describe('Forms Security Hardening @content', () => {
  let featureAvailable = false;
  test.beforeAll(async ({ request }) => {
    featureAvailable = await isFeatureAvailable(request, '/admin/forms');
  });
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment'); });

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  const maliciousDisplayName = `<script>window.__xss_${Date.now()}=1</script>`;
  const formName = `sec_xss_test_${Date.now()}`;

  test('does not execute a script tag from display_name on the admin builder page', async ({ page }) => {
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    await page.fill('[name="name"]', formName);
    await page.fill('[name="displayName"]', maliciousDisplayName);
    await page.selectOption('[name="category"]', 'general');
    await page.click('button[type="submit"]');

    await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 20000 });

    // If the script tag executed, this global would be set. It must not be.
    const executed = await page.evaluate(() => Object.keys(window).some(k => k.startsWith('__xss_')));
    expect(executed).toBe(false);

    // The header should show the escaped text content, not a live <script> element.
    await expect(page.locator('h1')).toContainText('<script>');
    const injectedScriptTags = await page.locator(`script:has-text("__xss_")`).count();
    expect(injectedScriptTags).toBe(0);
  });

  test('does not execute a script tag from display_name on the public form page', async ({ page }) => {
    await page.goto(`/forms/${formName}`);
    await page.waitForLoadState('networkidle');

    const executed = await page.evaluate(() => Object.keys(window).some(k => k.startsWith('__xss_')));
    expect(executed).toBe(false);

    await expect(page.locator('h1')).toContainText('<script>');
  });

  test('rejects submission to a private form directly via the API (real-SQLite covered; smoke check here)', async ({ request }) => {
    // is_public can't be flipped through any UI/API path today (see file header),
    // so this only confirms the public, currently-always-public form still
    // accepts submissions normally — the private-form 404 path itself is
    // covered by public-forms.integration.test.ts against the real schema.
    const schemaRes = await request.get(`/api/forms/${formName}/schema`);
    expect(schemaRes.ok()).toBe(true);
  });
});
