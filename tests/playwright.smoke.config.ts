import { defineConfig } from '@playwright/test';
import baseConfig from './playwright.config';

/**
 * Smoke Test Configuration
 *
 * Fast, focused test suite that validates critical functionality.
 * Runs 10-15 essential tests in 2-3 minutes.
 *
 * Usage:
 *   npm run e2e:smoke        - Run smoke tests
 *   npm run e2e:smoke:ui     - Run with Playwright UI
 */
export default defineConfig({
  ...baseConfig,
  testDir: './e2e',
  testMatch: /.*smoke\.spec\.ts$/,

  // Smoke test specific settings
  retries: 0, // Fail fast - no retries for smoke tests
  workers: 1, // Run serially for stability and speed
  timeout: 30000, // 30 second timeout per test

  // Use line reporter for cleaner output
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report-smoke', open: 'never' }],
    ['json', { outputFile: 'test-results/smoke-results.json' }],
    ['junit', { outputFile: 'test-results/smoke-junit.xml' }],
  ],

  use: {
    ...baseConfig.use,
    // Faster settings for smoke tests
    actionTimeout: 10000,
    navigationTimeout: 15000,
  },
});
