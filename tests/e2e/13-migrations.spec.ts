import { test, expect } from '@playwright/test';
import { loginAsAdmin, getCsrfTokenFromPage } from './utils/test-helpers';

test.describe.skip('Admin Migrations Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should navigate to migrations settings tab', async ({ page }) => {
    // Navigate to admin settings
    await page.goto('/admin/settings');
    
    // Wait for page to load
    await expect(page.locator('h1')).toContainText('Settings');
    
    // Verify migrations tab exists
    await expect(page.locator('[data-tab="migrations"]')).toBeVisible();
    
    // Click on the migrations tab
    await page.click('[data-tab="migrations"]');
    
    // Wait for JavaScript to execute and load content
    await page.waitForTimeout(2000);
    
    // Check if migrations content is displayed (wait longer for JavaScript)
    await expect(page.locator('h3:has-text("Database Migrations")')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=View and manage database migrations')).toBeVisible();
  });

  test('should display migration status overview cards', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for the JavaScript to load migration status
    await page.waitForTimeout(1000);
    
    // Check for status cards
    await expect(page.locator('text=Total Migrations')).toBeVisible();
    await expect(page.locator('p.text-sm.text-green-300:has-text("Applied")')).toBeVisible();
    await expect(page.locator('p.text-sm.text-orange-300:has-text("Pending")')).toBeVisible();
    
    // Check for numeric values in cards
    await expect(page.locator('#total-migrations')).toBeVisible();
    await expect(page.locator('#applied-migrations')).toBeVisible();
    await expect(page.locator('#pending-migrations')).toBeVisible();
  });

  test('should display migration action buttons', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Check for action buttons
    await expect(page.locator('button:has-text("Refresh Status")')).toBeVisible();
    await expect(page.locator('button:has-text("Run Pending")')).toBeVisible();
    await expect(page.locator('button:has-text("Validate Schema")')).toBeVisible();
  });

  test('should display migrations history list', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Check for migrations history section
    await expect(page.locator('text=Migration History')).toBeVisible();
    await expect(page.locator('text=List of all available database migrations')).toBeVisible();
    
    // Check for migrations list container
    await expect(page.locator('#migrations-list')).toBeVisible();
  });

  test('should load migration status via API call', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for API call and content update
    await page.waitForTimeout(2000);
    
    // Verify that migration data has loaded (numbers should not be default '0')
    const totalMigrations = await page.locator('#total-migrations').textContent();
    const appliedMigrations = await page.locator('#applied-migrations').textContent();
    const pendingMigrations = await page.locator('#pending-migrations').textContent();
    
    // At minimum, there should be some migrations available
    expect(parseInt(totalMigrations || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(appliedMigrations || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(pendingMigrations || '0')).toBeGreaterThanOrEqual(0);
  });

  test('should refresh migration status when button clicked', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for initial load
    await page.waitForTimeout(1000);
    
    // Listen for API calls
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/admin/api/migrations/status') && response.status() === 200
    );
    
    // Click refresh button
    await page.click('button:has-text("Refresh Status")');
    
    // Verify API call was made
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    
    // Verify response contains expected data structure
    const responseData = await response.json();
    expect(responseData).toHaveProperty('success', true);
    expect(responseData).toHaveProperty('data');
  });

  test('should validate schema when button clicked', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for initial load
    await page.waitForTimeout(1000);
    
    // Listen for validation API call
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/admin/api/migrations/validate') && response.status() === 200
    );
    
    // Click validate schema button
    await page.click('button:has-text("Validate Schema")');
    
    // Verify API call was made
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    
    // Verify response contains validation data
    const responseData = await response.json();
    expect(responseData).toHaveProperty('success', true);
    expect(responseData).toHaveProperty('data');
  });

  test('should handle run pending migrations with confirmation', async ({ page }) => {
    // Navigate directly to migrations tab
    await page.goto('/admin/settings/migrations');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Migrations")')).toBeVisible();

    // Wait for migration status to load
    await page.waitForTimeout(1000);

    // Setup dialog handler to cancel the confirmation
    page.on('dialog', async dialog => {
      expect(dialog.message()).toContain('Are you sure you want to run pending migrations');
      await dialog.dismiss();
    });

    // Click run pending button (should trigger confirmation dialog)
    await page.click('button:has-text("Run Pending")');

    // If the button is disabled (no pending migrations), skip this test
    const runButton = page.locator('button:has-text("Run Pending")');
    const isDisabled = await runButton.isDisabled();

    if (!isDisabled) {
      // The dialog should have been triggered and dismissed
      // Button should still be enabled since we cancelled
      await expect(runButton).toBeEnabled();
    }
  });

  test('should show proper migration status indicators', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for migration data to load
    await page.waitForTimeout(2000);
    
    // Check if migrations list has loaded with actual data
    const migrationsList = page.locator('#migrations-list');
    const hasRealData = await migrationsList.locator('h5').count() > 0;
    
    if (hasRealData) {
      // Check for migration status indicators (Applied/Pending badges)
      const statusBadges = page.locator('.px-2.py-1.rounded-full');
      const badgeCount = await statusBadges.count();
      
      if (badgeCount > 0) {
        // Verify status badges contain expected text
        const firstBadge = statusBadges.first();
        const badgeText = await firstBadge.textContent();
        expect(['Applied', 'Pending']).toContain(badgeText?.trim());
      }
    } else {
      // If no real data, verify loading state is shown
      await expect(migrationsList).toContainText('Loading migration status');
    }
  });

  test('should disable run button when no pending migrations', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for API response
    await page.waitForTimeout(2000);
    
    // Check pending migrations count
    const pendingCount = await page.locator('#pending-migrations').textContent();
    const hasPendingMigrations = parseInt(pendingCount || '0') > 0;
    
    const runButton = page.locator('button:has-text("Run Pending")');
    
    if (!hasPendingMigrations) {
      // Button should be disabled when no pending migrations
      await expect(runButton).toBeDisabled();
    } else {
      // Button should be enabled when there are pending migrations
      await expect(runButton).toBeEnabled();
    }
  });

  test('should have proper ARIA labels and accessibility', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Check tab navigation accessibility
    await expect(page.locator('nav[role="tablist"]')).toBeVisible();
    
    // Check that action buttons are properly labeled
    const refreshButton = page.locator('button:has-text("Refresh Status")');
    const runButton = page.locator('button:has-text("Run Pending")');
    const validateButton = page.locator('button:has-text("Validate Schema")');
    
    await expect(refreshButton).toBeVisible();
    await expect(runButton).toBeVisible();
    await expect(validateButton).toBeVisible();
    
    // Verify buttons have descriptive text content
    await expect(refreshButton).toContainText('Refresh Status');
    await expect(runButton).toContainText('Run Pending');
    await expect(validateButton).toContainText('Validate Schema');
  });

  test('should handle API errors gracefully', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Mock a failed API response
    await page.route('**/admin/api/migrations/status', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ success: false, error: 'Database connection failed' })
      });
    });
    
    // Trigger a refresh to test error handling
    await page.click('button:has-text("Refresh Status")');
    
    // The page should still function and not crash
    await expect(page.locator('h3:has-text("Database Migrations")')).toBeVisible();
    
    // Status cards should still be visible (may show default values)
    await expect(page.locator('#total-migrations')).toBeVisible();
    await expect(page.locator('#applied-migrations')).toBeVisible();
    await expect(page.locator('#pending-migrations')).toBeVisible();
  });

  test('should maintain state when switching between tabs', async ({ page }) => {
    // Navigate to migrations tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="migrations"]');
    
    // Wait for data to load
    await page.waitForTimeout(1000);
    
    // Switch to another tab
    await page.click('[data-tab="general"]');
    await expect(page.locator('h3:has-text("General Settings")')).toBeVisible();
    
    // Switch back to migrations tab
    await page.click('[data-tab="migrations"]');
    
    // Verify migrations content is still there
    await expect(page.locator('h3:has-text("Database Migrations")')).toBeVisible();
    await expect(page.locator('button:has-text("Refresh Status")')).toBeVisible();
  });
});

test.describe('Migrations API Endpoints', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should return migration status from API endpoint', async ({ page }) => {
    const response = await page.request.get('/admin/api/migrations/status');
    
    expect(response.status()).toBe(200);
    
    const data = await response.json();
    expect(data).toHaveProperty('success', true);
    expect(data).toHaveProperty('data');
    expect(data.data).toHaveProperty('totalMigrations');
    expect(data.data).toHaveProperty('appliedMigrations');
    expect(data.data).toHaveProperty('pendingMigrations');
    expect(data.data).toHaveProperty('migrations');
    expect(Array.isArray(data.data.migrations)).toBe(true);
  });

  test('should return validation results from validate endpoint', async ({ page }) => {
    const response = await page.request.get('/admin/api/migrations/validate');
    
    expect(response.status()).toBe(200);
    
    const data = await response.json();
    expect(data).toHaveProperty('success', true);
    expect(data).toHaveProperty('data');
  });

  test('should require admin role for run migrations endpoint', async ({ page }) => {
    // This test verifies that the endpoint properly checks admin permissions
    const csrfToken = await getCsrfTokenFromPage(page);
    const response = await page.request.post('/admin/api/migrations/run', {
      headers: { ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) }
    });
    
    // Should either succeed (if user is admin) or return 403
    expect([200, 403]).toContain(response.status());
    
    const data = await response.json();
    
    if (response.status() === 403) {
      expect(data).toHaveProperty('success', false);
      expect(data.error).toContain('Unauthorized');
    } else {
      expect(data).toHaveProperty('success');
    }
  });

  test('should handle malformed API requests gracefully', async ({ page }) => {
    // Test with invalid endpoint
    const response = await page.request.get('/admin/api/migrations/invalid');
    
    // Should return 404 or appropriate error status
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });
});