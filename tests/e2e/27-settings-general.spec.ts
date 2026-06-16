import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe('Settings - General Tab', () => {
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

    // Find the maintenance mode checkbox
    const maintenanceModeCheckbox = page.locator('input[name="maintenanceMode"]');
    await expect(maintenanceModeCheckbox).toBeVisible();

    // Get current state
    const initialState = await maintenanceModeCheckbox.isChecked();

    // Toggle it
    await maintenanceModeCheckbox.click();

    // Save settings
    await page.locator('button:has-text("Save Changes")').click();
    await page.waitForTimeout(1000);

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('networkidle');

    const newState = await page.locator('input[name="maintenanceMode"]').isChecked();
    expect(newState).toBe(!initialState);
  });

  test('should validate required fields', async ({ page }) => {
    await page.goto('/admin/settings/general');
    await page.waitForLoadState('networkidle');

    // Clear required fields
    await page.locator('input[name="siteName"]').fill('');
    await page.locator('textarea[name="siteDescription"]').fill('');

    // Try to save
    await page.locator('button:has-text("Save Changes")').click();
    await page.waitForTimeout(1000);

    // Should show an error (either validation message or notification)
    // We expect either an HTML5 validation or an error notification
    const siteNameField = page.locator('input[name="siteName"]');
    const isInvalid = await siteNameField.evaluate((el: HTMLInputElement) => !el.validity.valid);

    // If HTML5 validation isn't triggered, check for error notification
    if (!isInvalid) {
      // Should see error notification or error state
      const hasErrorNotification = await page.locator('text=/required|error/i').count() > 0;
      expect(hasErrorNotification).toBeTruthy();
    }
  });

  test('should update admin email', async ({ page }) => {
    await page.goto('/admin/settings/general');
    await page.waitForLoadState('networkidle');

    const newAdminEmail = `admin-${Date.now()}@example.com`;

    await page.locator('input[name="adminEmail"]').fill(newAdminEmail);
    await page.locator('button:has-text("Save Changes")').click();
    await page.waitForTimeout(1000);

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('networkidle');

    const savedEmail = await page.locator('input[name="adminEmail"]').inputValue();
    expect(savedEmail).toBe(newAdminEmail);
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
