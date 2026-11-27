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
    //
    // Uses expect.poll: D1 replication can briefly lag after e2e-setup applies migrations,
    // causing the first read to show pending migrations that clear within a few seconds.
    await expect.poll(
      async () => {
        const response = await page.request.get('/admin/api/migrations/status')
        if (response.status() !== 200) return { pending: -1, total: 0, applied: 0 }
        const { data } = await response.json()
        return { pending: data.pendingMigrations ?? -1, total: data.totalMigrations ?? 0, applied: data.appliedMigrations ?? 0 }
      },
      { message: 'migrations are pending on a migrated database (D1 replication lag?)', timeout: 10000, intervals: [1000, 2000, 3000] },
    ).toMatchObject({ pending: 0 })

    // Also check the shape invariant once migrations are confirmed applied.
    const response = await page.request.get('/admin/api/migrations/status')
    expect(response.status()).toBe(200)
    const { data } = await response.json()
    expect(data.totalMigrations, 'no migrations in the bundle').toBeGreaterThan(0)
    expect(data.migrations).toHaveLength(data.totalMigrations)
    expect(data.appliedMigrations + data.pendingMigrations).toBe(data.totalMigrations)
    expect(data.pendingMigrations, 'migrations are pending on a migrated database').toBe(0)
  });

  test('should report the same status when read twice', async ({ page }) => {
    // Reading status used to run PRAGMA + ALTER per active document type, so the first call
    // could change what the second one saw. It is a pure read now; pin that it is stable.
    const first = await (await page.request.get('/admin/api/migrations/status')).json();
    const second = await (await page.request.get('/admin/api/migrations/status')).json();
    expect(second.data.totalMigrations).toBe(first.data.totalMigrations);
    expect(second.data.appliedMigrations).toBe(first.data.appliedMigrations);
    expect(second.data.pendingMigrations).toBe(first.data.pendingMigrations);
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
