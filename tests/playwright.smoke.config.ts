import { cmsReportingTarget, playwrightReporting } from './reporting/options'
import { defineConfig } from '@playwright/test';
import baseConfig from './playwright.config';

/**
 * Smoke Test Configuration
 *
 * Fast, focused test suite that validates critical functionality.
 * Preserves the original 28 smoke tests after forms consolidation.
 *
 * Usage:
 *   npm run e2e:smoke        - Run smoke tests
 *   npm run e2e:smoke:ui     - Run with Playwright UI
 */
export default defineConfig({
  ...baseConfig,
  testDir: './e2e',
  testMatch: /.*(?:smoke|forms)\.spec\.ts$/,
  // Playwright matches the full test title, including filename and Source scope.
  // Select only the former forms-smoke scope, not every test in forms.spec.ts.
  grep: /smoke\.spec\.ts/,

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
    ...playwrightReporting('cms-smoke', cmsReportingTarget(process.env)),
  ],

  use: {
    ...baseConfig.use,
    // Faster settings for smoke tests
    actionTimeout: 10000,
    navigationTimeout: 15000,
  },
});
