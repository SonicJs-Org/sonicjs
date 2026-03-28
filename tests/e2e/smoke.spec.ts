import { test, expect } from '@playwright/test';
import { loginAsAdmin, checkAPIHealth, ADMIN_CREDENTIALS } from './utils/test-helpers';

/**
 * Smoke Test Suite
 *
 * Critical path validation - runs quickly (2-3 minutes) to catch major issues.
 * These tests verify the core functionality that must work for the app to be usable.
 *
 * Run with: npm run e2e:smoke
 */
test.describe('Smoke Tests - Critical Path', () => {

  test('API health check returns running status', async ({ request }) => {
    const response = await request.get('/health');
    expect(response.ok()).toBeTruthy();

    const health = await response.json();
    expect(health).toHaveProperty('name', 'SonicJS AI');
    expect(health).toHaveProperty('status', 'running');
    expect(health).toHaveProperty('version');
    expect(health.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(health).toHaveProperty('timestamp');
  });

  test('Home page redirects to login when not authenticated', async ({ page }) => {
    const response = await page.goto('/');
    expect(response?.status()).toBe(200);

    // Should redirect to login page
    await page.waitForURL(/\/auth\/login/);

    // Verify we're on the login page
    expect(page.url()).toContain('/auth/login');
    await expect(page.locator('h2')).toContainText('Welcome Back');
  });

  test('Admin routes require authentication', async ({ page }) => {
    // Try to access admin without auth
    await page.goto('/admin');

    // Should redirect to login
    await page.waitForURL(/\/auth\/login/);

    // Verify we're on the login page with error message
    expect(page.url()).toContain('/auth/login');
    await expect(page.locator('h2')).toContainText('Welcome Back');
    await expect(page.locator('.bg-error\\/10')).toContainText('Please login to access the admin area');
  });

  test('Login with valid credentials succeeds', async ({ page }) => {
    await loginAsAdmin(page);

    // Should be on admin dashboard
    await expect(page).toHaveURL(/\/admin/);

    // Verify we can see admin UI elements
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1')).toContainText('Dashboard');
  });

  test('Dashboard loads with stats and recent activity', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin');
    await page.waitForLoadState('networkidle');

    // Verify stats container loads
    const statsContainer = page.locator('#stats-container');
    await expect(statsContainer).toBeVisible();

    // Wait for stats to load via HTMX
    await page.waitForTimeout(2000);

    // Verify recent activity loads
    await page.waitForSelector('#recent-activity-container', { timeout: 10000 });
    const activityContainer = page.locator('#recent-activity-container');
    await expect(activityContainer).toBeVisible();
  });

  test('Collections API is accessible and returns data', async ({ request }) => {
    // Use public API endpoint which doesn't require auth
    const response = await request.get('/api/collections');
    expect(response.ok()).toBeTruthy();

    const collectionsData = await response.json();
    expect(collectionsData).toHaveProperty('data');
    expect(Array.isArray(collectionsData.data)).toBe(true);
    expect(collectionsData.data.length).toBeGreaterThan(0);
  });

  test.skip('Create content via backend form', async ({ page, context }) => {
    await loginAsAdmin(page);

    const timestamp = Date.now();
    const testTitle = `Smoke Test ${timestamp}`;

    // Navigate to create content page
    await page.goto('/admin/content/new');
    await page.waitForSelector('h1', { timeout: 5000 });

    // Select the first available collection
    const collectionLink = page.locator('a[href*="/admin/content/new?collection="]').first();
    await expect(collectionLink).toBeVisible({ timeout: 5000 });

    // Get the collection ID from the URL for cleanup later
    const href = await collectionLink.getAttribute('href');
    const collectionIdMatch = href?.match(/collection=([^&]+)/);
    const collectionId = collectionIdMatch ? collectionIdMatch[1] : null;

    await collectionLink.click();

    // Wait for form to load
    await page.waitForSelector('form#content-form', { timeout: 10000 });

    // Fill title field
    const titleField = page.locator('input[name="title"], input[id="title"]').first();
    await expect(titleField).toBeVisible();
    await titleField.fill(testTitle);

    // Get the Save button that's actually inside (or references) the form
    const saveButton = page.locator('button[name="action"][value="save"]').first();
    await expect(saveButton).toBeVisible({ timeout: 5000 });

    // Click the save button and wait for network activity
    await Promise.all([
      page.waitForResponse(resp => resp.url().includes('/admin/content') && resp.request().method() === 'POST'),
      saveButton.click()
    ]);

    // Wait for response to be processed
    await page.waitForTimeout(2000);

    // Verify content was created via API
    if (collectionId) {
      const contentResponse = await context.request.get(`/api/content?collection=${collectionId}&limit=20`);
      expect(contentResponse.ok()).toBeTruthy();
      const contentData = await contentResponse.json();

      // Find the content we just created
      const createdContent = contentData.data?.find((c: any) => c.data?.title === testTitle);

      // Content should have been created
      expect(createdContent).toBeTruthy();

      // Cleanup: delete the created content
      if (createdContent) {
        await context.request.delete(`/api/content/${createdContent.id}`);
      }
    }
  });

  test('Media upload and cleanup works', async ({ page, context }) => {
    await loginAsAdmin(page);

    // Create a minimal valid JPEG
    const testImageBuffer = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
      0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
      0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
      0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
      0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
      0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
      0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,
      0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
      0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4,
      0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C,
      0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9
    ]);

    const formData = new FormData();
    const blob = new Blob([testImageBuffer], { type: 'image/jpeg' });
    const timestamp = Date.now();
    formData.append('files', blob, `smoke-test-${timestamp}.jpg`);
    formData.append('folder', 'test');

    const uploadResponse = await context.request.post('/api/media/upload-multiple', {
      multipart: formData
    });

    expect(uploadResponse.ok()).toBeTruthy();
    const result = await uploadResponse.json();
    expect(result).toHaveProperty('uploaded');
    expect(result.uploaded).toHaveLength(1);
    expect(result.uploaded[0]).toHaveProperty('id');

    // Cleanup - delete the uploaded file
    const fileId = result.uploaded[0].id;
    const deleteResponse = await context.request.post('/api/media/bulk-delete', {
      data: { fileIds: [fileId] }
    });

    expect(deleteResponse.ok()).toBeTruthy();
  });

  test('Database connectivity via stats query', async ({ page }) => {
    await loginAsAdmin(page);

    // Navigate to admin dashboard
    await page.goto('/admin');
    await page.waitForLoadState('networkidle');

    // Wait for stats to load (requires DB connection)
    await page.waitForSelector('#stats-container', { timeout: 10000 });
    await page.waitForTimeout(2000);

    const statsContainer = page.locator('#stats-container');
    await expect(statsContainer).toBeVisible();

    // Verify stats contain actual data (not skeleton loaders)
    const statsText = await statsContainer.textContent();
    expect(statsText).toContain('Total Collections');
    expect(statsText).toContain('Content Items');
    expect(statsText).toContain('Media Files');
    expect(statsText).toContain('Active Users');
  });

  test('Recent activity displays content changes', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin');
    await page.waitForLoadState('networkidle');

    // Wait for recent activity section to load via HTMX
    await page.waitForSelector('#recent-activity-container', { timeout: 10000 });
    await page.waitForTimeout(2000);

    const activityContainer = page.locator('#recent-activity-container');
    await expect(activityContainer).toBeVisible();

    // Verify it has the expected structure
    await expect(activityContainer.locator('h3')).toContainText('Recent Activity');

    // Should have either activity items or empty state
    const activityList = activityContainer.locator('ul[role="list"]');
    await expect(activityList).toBeVisible();
  });

  test('API error handling returns proper status codes', async ({ request }) => {
    // Test 404 for non-existent endpoint
    const notFoundResponse = await request.get('/api/nonexistent-endpoint');
    expect(notFoundResponse.status()).toBe(404);

    // Test 404 for non-existent content
    const contentResponse = await request.get('/api/content/99999999');
    expect(contentResponse.status()).toBe(404);
  });

  test('CORS headers are present on API endpoints', async ({ request }) => {
    // Use the origin configured in CORS_ORIGINS (wrangler.toml)
    const response = await request.get('/api', {
      headers: {
        'Origin': 'http://localhost:8787'
      }
    });

    expect(response.ok()).toBeTruthy();

    // Verify CORS header echoes back the allowed origin
    const corsHeader = response.headers()['access-control-allow-origin'];
    expect(corsHeader).toBe('http://localhost:8787');
  });

  test('API returns correct content-type headers', async ({ request }) => {
    const response = await request.get('/health');

    expect(response.ok()).toBeTruthy();

    const contentType = response.headers()['content-type'];
    expect(contentType).toContain('application/json');
  });

  test('Session persists across page reloads', async ({ page }) => {
    await loginAsAdmin(page);

    // Navigate to dashboard
    await page.goto('/admin');
    await expect(page).toHaveURL(/\/admin/);

    // Reload the page
    await page.reload();

    // Should still be authenticated and on admin page
    await expect(page).toHaveURL(/\/admin/);
    await expect(page.locator('h1')).toContainText('Dashboard');
  });

  test('Logout successfully clears session', async ({ page }) => {
    // First login
    await loginAsAdmin(page);
    await expect(page).toHaveURL(/\/admin/);

    // Click logout (if you have a logout button)
    // For now, we'll use the helper function
    await page.goto('/auth/logout');

    // Should redirect to login
    await page.waitForURL(/\/auth\/login/);

    // Try to access admin again
    await page.goto('/admin');

    // Should redirect back to login
    await page.waitForURL(/\/auth\/login/);
    await expect(page.locator('h2')).toContainText('Welcome Back');
  });
});
