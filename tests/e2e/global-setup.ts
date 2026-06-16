import { chromium, FullConfig } from '@playwright/test';

/**
 * Global setup for E2E tests
 * Runs once before all tests
 */
async function globalSetup(config: FullConfig) {
  console.log('\n🧹 Running global test cleanup before tests...\n');

  const browser = await chromium.launch();
  const page = await browser.newPage();

  try {
    // Get the base URL from environment or config
    const baseURL = process.env.BASE_URL || config.projects[0]?.use?.baseURL || 'http://localhost:8787';

    console.log(`Using base URL: ${baseURL}`);

    // Clean up test data from prior runs
    const cleanupResponse = await page.request.post(`${baseURL}/test-cleanup`, {
      headers: { 'Content-Type': 'application/json' }
    });
    if (cleanupResponse.ok()) {
      const result = await cleanupResponse.json();
      console.log(`✓ Test cleanup successful: ${result.deletedCount} items removed`);
    } else {
      console.log(`⚠ Test cleanup returned status: ${cleanupResponse.status()}`);
    }

    // Ensure admin user exists (idempotent)
    try {
      await page.request.post(`${baseURL}/auth/seed-admin`, {
        headers: { 'Content-Type': 'application/json' }
      });
      console.log('✓ Admin user seeded');
    } catch {
      // Non-fatal
    }

    // Restore default seed content (welcome blog post may have been soft-deleted)
    try {
      const seedRes = await page.request.post(`${baseURL}/test-seed-defaults`, {
        headers: { 'Content-Type': 'application/json' }
      });
      if (seedRes.ok()) {
        const r = await seedRes.json() as any;
        console.log(`✓ Default content: ${r.message ?? r.action}`);
      }
    } catch {
      // Non-fatal
    }

    console.log('');
  } catch (error) {
    console.log(`⚠ Test cleanup failed: ${error}\n`);
  } finally {
    await browser.close();
  }
}

export default globalSetup;
