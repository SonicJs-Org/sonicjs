import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

/**
 * E2E coverage for the dynamic RBAC matrix at /admin/rbac.
 *
 * Verifies the matrix renders inside the admin chrome, and — the important part
 * — that editing a permission cell and saving actually persists across a reload
 * (the round-trip through POST /admin/rbac/grants → rbac_role_grants → re-render).
 *
 * The test edits a single system role (Viewer) in single-column "compare" mode
 * so the save touches only that role, then restores the original grant so the
 * suite is idempotent and leaves the seeded matrix untouched.
 */
test.describe('Admin RBAC matrix', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('renders the permission matrix inside the admin chrome', async ({ page }) => {
    await page.goto('/admin/rbac');
    await page.waitForLoadState('networkidle');

    // Admin must actually reach the page (rbac:manage via *:manage), not bounce to login.
    await expect(page).toHaveURL(/\/admin\/rbac/);
    await expect(page.locator('text=Permission matrix')).toBeVisible();
    // The Users <-> Roles & Permissions tab bar is present.
    await expect(page.locator('a[href="/admin/rbac"][aria-current="page"]')).toBeVisible();
    const matrix = page.locator('form[action="/admin/rbac/grants"]');
    // `access` is only used for portal entry and should not be a generic matrix column.
    await expect(matrix.locator('th', { hasText: /^access$/i })).toHaveCount(0);
    await expect(page.locator('label', { hasText: /Access portal/i }).first()).toBeVisible();
    // At least one permission cell is rendered.
    await expect(matrix.locator('input[type="radio"][data-verb]').first()).toBeVisible();
  });

  test('saving a permission cell persists across reload', async ({ page }) => {
    await page.goto('/admin/rbac');
    await page.waitForLoadState('networkidle');

    // Resolve the Viewer role id from its compare checkbox, then view that role
    // alone so the matrix has exactly one editable column.
    const viewerCheckbox = page
      .locator('label', { hasText: /viewer/i })
      .locator('input[name="roles"]');
    await expect(viewerCheckbox).toHaveCount(1);
    const viewerId = await viewerCheckbox.getAttribute('value');
    expect(viewerId).toBeTruthy();

    const compareUrl = `/admin/rbac?compare=1&roles=${encodeURIComponent(viewerId!)}`;
    await page.goto(compareUrl);
    await page.waitForLoadState('networkidle');

    // Target a single, stable cell: content : delete (a cell that supports None/Own/Any).
    const cellRadios = page.locator(`input[type="radio"][data-role="${viewerId}"][data-res="content"][data-verb="delete"]`);
    const cellRadio = (value: string) =>
      page.locator(`input[type="radio"][data-role="${viewerId}"][data-res="content"][data-verb="delete"][value="${value}"]`);
    await expect(cellRadios.first()).toBeVisible();

    let original = 'none';
    for (const value of ['any', 'own', 'none']) {
      if (await cellRadio(value).isChecked()) {
        original = value;
        break;
      }
    }
    const next = original === 'any' ? 'none' : 'any';

    await cellRadio(next).check({ force: true });
    await page.locator('button:has-text("Save changes")').click();

    // Save redirects back to the same compare view; confirm the change stuck.
    await page.waitForURL(/\/admin\/rbac/);
    await page.goto(compareUrl);
    await page.waitForLoadState('networkidle');

    await expect(cellRadio(next)).toBeChecked();

    // Restore the original grant so the test is idempotent.
    await cellRadio(original).check({ force: true });
    await page.locator('button:has-text("Save changes")').click();
    await page.waitForURL(/\/admin\/rbac/);
    await page.goto(compareUrl);
    await page.waitForLoadState('networkidle');
    await expect(
      page.locator(`input[type="radio"][data-role="${viewerId}"][data-res="content"][data-verb="delete"][value="${original}"]`)
    ).toBeChecked();
  });

  test('admin column is locked (full access, read-only)', async ({ page }) => {
    // View only the Administrator role; every cell should be disabled.
    await page.goto('/admin/rbac');
    await page.waitForLoadState('networkidle');

    const adminCheckbox = page
      .locator('label', { hasText: /admin/i })
      .locator('input[name="roles"]')
      .first();
    const adminId = await adminCheckbox.getAttribute('value');
    expect(adminId).toBeTruthy();

    await page.goto(`/admin/rbac?compare=1&roles=${encodeURIComponent(adminId!)}`);
    await page.waitForLoadState('networkidle');

    const adminCell = page.locator('input[type="radio"][data-verb]').first();
    await expect(adminCell).toBeVisible();
    await expect(adminCell).toBeDisabled();
  });
});
