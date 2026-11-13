import { test, expect } from './fixtures';
import { loginAsAdmin, getCsrfTokenFromPage } from './utils/test-helpers';

test.describe('Migrations API Endpoints @content @media @api', () => {
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

  test('should report every bundled migration as applied', async ({ page }) => {
    // The test above only asserts the keys exist, which `toHaveProperty` is happy with when
    // every count is zero. This one reads the numbers, because the handler stopped repairing
    // the schema as a side effect of being called and that change had to be visible somewhere:
    // a status read that silently reported nothing would pass the shape test unchanged.
    for (const endpoint of ['/admin/api/migrations/status', '/admin/settings/api/migrations/status']) {
      const response = await page.request.get(endpoint);
      expect(response.status()).toBe(200);

      const { success, data } = await response.json();
      expect(success).toBe(true);
      expect(data.totalMigrations, 'no migrations in the bundle').toBeGreaterThan(0);
      expect(data.migrations).toHaveLength(data.totalMigrations);
      expect(data.appliedMigrations).toBe(data.totalMigrations);
      // CI provisions a migrated database; both admin routes must read that ledger.
      expect(data.pendingMigrations, 'migrations are pending on a migrated database').toBe(0);
      for (const migration of data.migrations) {
        expect(migration.applied).toBe(true);
        expect(typeof migration.appliedAt).toBe('string');
        expect(migration.appliedAt.length).toBeGreaterThan(0);
      }
    }
  });

  test('should report the same status and timestamps through both endpoints on repeated reads', async ({ page }) => {
    // Reading status used to run PRAGMA + ALTER per active document type, so the first call
    // could change what the second one saw. It is a pure read now; pin that it is stable.
    const firstResponse = await page.request.get('/admin/api/migrations/status');
    expect(firstResponse.status()).toBe(200);
    const first = await firstResponse.json();
    expect(first.success).toBe(true);
    expect(typeof first.data.lastApplied).toBe('string');
    expect(first.data.lastApplied.length).toBeGreaterThan(0);

    for (const endpoint of ['/admin/api/migrations/status', '/admin/settings/api/migrations/status']) {
      for (let read = 0; read < 2; read++) {
        const response = await page.request.get(endpoint);
        expect(response.status()).toBe(200);
        const result = await response.json();
        expect(result.success).toBe(true);
        // Includes totals, lastApplied and every migration's appliedAt timestamp.
        expect(result.data).toEqual(first.data);
      }
    }
  });

  test('should return validation results from validate endpoint', async ({ page }) => {
    const response = await page.request.get('/admin/api/migrations/validate');
    
    expect(response.status()).toBe(200);
    
    const data = await response.json();
    expect(data).toHaveProperty('success', true);
    expect(data).toHaveProperty('data');
  });

  test('should explain that migration execution is managed by Wrangler', async ({ page }) => {
    const csrfToken = await getCsrfTokenFromPage(page);
    const response = await page.request.post('/admin/api/migrations/run', {
      headers: { ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) }
    });

    expect(response.status()).toBe(409);
    
    const data = await response.json();
    expect(data).toHaveProperty('success', false);
    expect(data.message).toContain('wrangler d1 migrations apply');
  });

  test('should handle malformed API requests gracefully', async ({ page }) => {
    // Test with invalid endpoint
    const response = await page.request.get('/admin/api/migrations/invalid');
    
    // Should return 404 or appropriate error status
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });
});
