import { test, expect } from '@playwright/test';
import { checkAPIHealth } from './utils/test-helpers';

test.describe('Health Checks @smoke', () => {
  test('API health endpoint should return running status', async ({ page }) => {
    const health = await checkAPIHealth(page);

    expect(health).toHaveProperty('name', 'SonicJS AI');
    expect(health).toHaveProperty('version'); // Version comes from @sonicjs-cms/core package
    expect(health.version).toMatch(/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/); // semver, incl. prerelease (e.g. 3.0.0-beta.2)
    expect(health).toHaveProperty('status', 'running');
    expect(health).toHaveProperty('timestamp');
  });

  test('404 routes should return not found', async ({ request }) => {
    // Use request API directly to check 404 status without redirect following
    const response = await request.get('/api/nonexistent-route-12345');
    expect(response.status()).toBe(404);
  });
}); 