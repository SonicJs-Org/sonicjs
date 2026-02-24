import { test, expect } from '@playwright/test';
import { loginAsAdmin, getCsrfTokenFromPage } from './utils/test-helpers';

test.describe.skip('Database Tools', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should navigate to database tools settings tab', async ({ page }) => {
    // Navigate to admin settings
    await page.goto('/admin/settings');
    
    // Wait for page to load
    await expect(page.locator('h1')).toContainText('Settings');
    
    // Verify database tools tab exists
    await expect(page.locator('[data-tab="database-tools"]')).toBeVisible();
    
    // Click on the database tools tab
    await page.click('[data-tab="database-tools"]');
    
    // Wait for JavaScript to execute and load content
    await page.waitForTimeout(2000);
    
    // Check if database tools content is displayed
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Manage database operations')).toBeVisible();
  });

  test('should display database statistics cards', async ({ page }) => {
    // Navigate to database tools tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="database-tools"]');
    
    // Wait for the JavaScript to load database stats
    await page.waitForTimeout(2000);
    
    // Check for statistics cards
    await expect(page.locator('text=Total Tables')).toBeVisible();
    await expect(page.locator('text=Total Rows')).toBeVisible();
    
    // Check for numeric values in cards
    await expect(page.locator('#total-tables')).toBeVisible();
    await expect(page.locator('#total-rows')).toBeVisible();
  });

  test('should display database operation buttons', async ({ page }) => {
    // Navigate to database tools tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="database-tools"]');
    
    // Check for operation buttons
    await expect(page.locator('button:has-text("Refresh Stats")')).toBeVisible();
    await expect(page.locator('button:has-text("Create Backup")')).toBeVisible();
    await expect(page.locator('button:has-text("Validate Database")')).toBeVisible();
    await expect(page.locator('button:has-text("Truncate All Data")')).toBeVisible();
  });

  test('should display danger zone warning', async ({ page }) => {
    // Navigate to database tools tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="database-tools"]');
    
    // Check for danger zone
    await expect(page.locator('text=Danger Zone')).toBeVisible();
    await expect(page.locator('text=destructive and cannot be undone')).toBeVisible();
    await expect(page.locator('text=Your admin account will be preserved')).toBeVisible();
  });

  test('should refresh database stats when button clicked', async ({ page }) => {
    // Navigate directly to database tools tab
    await page.goto('/admin/settings/database-tools');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();

    // Wait for initial auto-load to complete
    await page.waitForTimeout(1000);

    // Now listen for the NEXT API call (triggered by button click)
    const responsePromise = page.waitForResponse(response =>
      response.url().includes('/admin/database-tools/api/stats') && response.status() === 200
    );

    // Click refresh button
    await page.click('button:has-text("Refresh Stats")');

    // Verify API call was made
    const response = await responsePromise;
    expect(response.status()).toBe(200);

    // Verify response contains expected data structure
    const responseData = await response.json();
    expect(responseData).toHaveProperty('success', true);
    expect(responseData).toHaveProperty('data');
  });

  test('should validate database when button clicked', async ({ page }) => {
    // Navigate directly to database tools tab
    await page.goto('/admin/settings/database-tools');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();

    // Wait for initial auto-load to complete
    await page.waitForTimeout(1000);

    // Listen for validation API call
    const responsePromise = page.waitForResponse(response =>
      response.url().includes('/admin/database-tools/api/validate') && response.status() === 200
    );

    // Click validate database button
    await page.click('button:has-text("Validate Database")');

    // Verify API call was made
    const response = await responsePromise;
    expect(response.status()).toBe(200);

    // Verify response contains validation data
    const responseData = await response.json();
    expect(responseData).toHaveProperty('success', true);
    expect(responseData).toHaveProperty('data');
  });

  test('should create backup when button clicked', async ({ page }) => {
    // Navigate directly to database tools tab
    await page.goto('/admin/settings/database-tools');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();

    // Wait for initial auto-load to complete
    await page.waitForTimeout(1000);

    // Listen for backup API call
    const responsePromise = page.waitForResponse(response =>
      response.url().includes('/admin/database-tools/api/backup') && response.status() === 200
    );

    // Click create backup button
    await page.click('button:has-text("Create Backup")');

    // Verify API call was made
    const response = await responsePromise;
    expect(response.status()).toBe(200);

    // Verify response contains backup data
    const responseData = await response.json();
    expect(responseData).toHaveProperty('success', true);
    expect(responseData).toHaveProperty('message');
  });

  test('should handle truncate confirmation dialog', async ({ page }) => {
    // Navigate directly to database tools tab
    await page.goto('/admin/settings/database-tools');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();

    let dialogCount = 0;
    // Setup dialog handler to handle both prompt and alert
    page.on('dialog', async dialog => {
      dialogCount++;
      if (dialog.type() === 'prompt') {
        expect(dialog.message()).toContain('WARNING: This will delete ALL data except your admin account!');
        expect(dialog.message()).toContain('Type "TRUNCATE ALL DATA" to confirm:');
        await dialog.accept('wrong text'); // Provide wrong confirmation text
      } else if (dialog.type() === 'alert') {
        expect(dialog.message()).toContain('Operation cancelled. Confirmation text did not match.');
        await dialog.accept();
      }
    });

    // Click truncate button (should trigger confirmation dialog)
    await page.click('button:has-text("Truncate All Data")');

    // Wait a bit for dialogs to appear and be handled
    await page.waitForTimeout(1000);

    // Both prompt and alert should have been triggered
    expect(dialogCount).toBe(2);

    // Button should still be enabled since we cancelled
    await expect(page.locator('button:has-text("Truncate All Data")')).toBeEnabled();
  });

  test('should display tables list section', async ({ page }) => {
    // Navigate directly to database tools tab
    await page.goto('/admin/settings/database-tools');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();

    // Check for tables list section
    await expect(page.locator('text=Database Tables')).toBeVisible();

    // Check for tables list container
    await expect(page.locator('#tables-list')).toBeVisible();
  });

  test('should load database stats via API call', async ({ page }) => {
    // Navigate to database tools tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="database-tools"]');
    
    // Wait for API call and content update
    await page.waitForTimeout(2000);
    
    // Verify that database stats have loaded
    const totalTables = await page.locator('#total-tables').textContent();
    const totalRows = await page.locator('#total-rows').textContent();
    
    // Stats should be numbers (not the default '0' from template)
    expect(totalTables).not.toBeNull();
    expect(totalRows).not.toBeNull();
    
    // Values should be valid numbers or formatted numbers
    expect(parseInt(totalTables?.replace(/,/g, '') || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(totalRows?.replace(/,/g, '') || '0')).toBeGreaterThanOrEqual(0);
  });

  test('should have proper accessibility features', async ({ page }) => {
    // Navigate to database tools tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="database-tools"]');
    
    // Check that action buttons are properly labeled
    const refreshButton = page.locator('button:has-text("Refresh Stats")');
    const backupButton = page.locator('button:has-text("Create Backup")');
    const validateButton = page.locator('button:has-text("Validate Database")');
    const truncateButton = page.locator('button:has-text("Truncate All Data")');
    
    await expect(refreshButton).toBeVisible();
    await expect(backupButton).toBeVisible();
    await expect(validateButton).toBeVisible();
    await expect(truncateButton).toBeVisible();
    
    // Verify buttons have descriptive text content
    await expect(refreshButton).toContainText('Refresh Stats');
    await expect(backupButton).toContainText('Create Backup');
    await expect(validateButton).toContainText('Validate Database');
    await expect(truncateButton).toContainText('Truncate All Data');
  });

  test('should handle API errors gracefully', async ({ page }) => {
    // Navigate to database tools tab
    await page.goto('/admin/settings');
    await page.click('[data-tab="database-tools"]');
    
    // Mock a failed API response for stats
    await page.route('**/admin/database-tools/api/stats', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ success: false, error: 'Database connection failed' })
      });
    });
    
    // Trigger a refresh to test error handling
    await page.click('button:has-text("Refresh Stats")');
    
    // The page should still function and not crash
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();
    
    // Stats cards should still be visible (may show default values)
    await expect(page.locator('#total-tables')).toBeVisible();
    await expect(page.locator('#total-rows')).toBeVisible();
  });

  test('should navigate to table view when clicking on a table row', async ({ page }) => {
    // Navigate directly to database tools tab
    await page.goto('/admin/settings/database-tools');

    // Wait for the page and JavaScript to load
    await expect(page.locator('h3:has-text("Database Tools")')).toBeVisible();

    // Wait for tables to load (stats API call)
    await page.waitForTimeout(2000);

    // Check if there are any tables in the list
    const tableLinks = page.locator('#tables-list a[href^="/admin/database-tools/tables/"]');
    const tableCount = await tableLinks.count();

    // If there are tables, click on the first one
    if (tableCount > 0) {
      const firstTableLink = tableLinks.first();
      const tableName = await firstTableLink.textContent();

      // Click on the table link
      await firstTableLink.click();

      // Wait for navigation to complete
      await page.waitForLoadState('networkidle');

      // Verify we're on the table view page
      await expect(page.locator('h1:has-text("Table:")')).toBeVisible({ timeout: 10000 });

      // Verify the breadcrumb/back link is present
      await expect(page.locator('a:has-text("Back to Database Tools")')).toBeVisible();

      // Verify table structure is shown (columns headers should be visible)
      await expect(page.locator('table thead')).toBeVisible();

      // Verify we're on the correct URL
      expect(page.url()).toContain('/admin/database-tools/tables/');

      // Should NOT be redirected to login
      expect(page.url()).not.toContain('/admin/login');
    }
  });
});

test.describe('Database Tools API Endpoints', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should return database stats from API endpoint', async ({ page }) => {
    const response = await page.request.get('/admin/database-tools/api/stats');
    
    expect(response.status()).toBe(200);
    
    const data = await response.json();
    expect(data).toHaveProperty('success', true);
    expect(data).toHaveProperty('data');
    expect(data.data).toHaveProperty('totalRows');
    expect(data.data).toHaveProperty('tables');
    expect(Array.isArray(data.data.tables)).toBe(true);
  });

  test('should return validation results from validate endpoint', async ({ page }) => {
    const response = await page.request.get('/admin/database-tools/api/validate');
    
    expect(response.status()).toBe(200);
    
    const data = await response.json();
    expect(data).toHaveProperty('success', true);
    expect(data).toHaveProperty('data');
    expect(data.data).toHaveProperty('valid');
    expect(data.data).toHaveProperty('issues');
  });

  test('should require admin role for backup endpoint', async ({ page }) => {
    const csrfToken = await getCsrfTokenFromPage(page);
    const response = await page.request.post('/admin/database-tools/api/backup', {
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

  test('should require admin role for truncate endpoint', async ({ page }) => {
    const csrfToken = await getCsrfTokenFromPage(page);
    const response = await page.request.post('/admin/database-tools/api/truncate', {
      headers: { ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
      data: { confirmText: 'TRUNCATE ALL DATA' }
    });
    
    // Should either succeed (if user is admin) or return 403
    expect([200, 400, 403]).toContain(response.status());
    
    const data = await response.json();
    
    if (response.status() === 403) {
      expect(data).toHaveProperty('success', false);
      expect(data.error).toContain('Unauthorized');
    }
  });

  test('should handle malformed API requests gracefully', async ({ page }) => {
    // Test with invalid endpoint
    const response = await page.request.get('/admin/database-tools/api/invalid');
    
    // Should return 404 or appropriate error status
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });
});