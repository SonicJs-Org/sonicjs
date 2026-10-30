import { defineConfig, devices } from '@playwright/test'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const ci = !!process.env.CI
const baseURL = process.env.BASE_URL || 'http://localhost:8787'
// Remote preview (BASE_URL set) has inherent network flakiness that local runs don't.
const remotePreview = !!process.env.BASE_URL

export default defineConfig({
  testDir: './e2e',
  // File-level parallelism only; global-state specs still require narrow @lock-* tags.
  fullyParallel: false,
  forbidOnly: ci,
  // Remote previews need more retries to absorb transient CF Worker cold-start / network flakiness.
  // Local runs use 1 retry as a diagnostic signal, not a green-by-retry policy.
  retries: ci ? (remotePreview ? 3 : 1) : 0,
  // TODO: enable once the remaining flaky tests are stabilized.
  // failOnFlakyTests: ci && !remotePreview,
  maxFailures: ci ? 25 : 0,
  timeout: ci ? 120_000 : 90_000,
  // Retain the measured existing concurrency until full-suite comparisons justify changing it.
  workers: ci ? 2 : 1,
  outputDir: resolve(here, '../test-results'),
  reporter: [
    ['list'],
    ['html', { outputFolder: resolve(here, '../playwright-report'), open: 'never' }],
    ['json', { outputFile: resolve(here, '../test-results/results.json') }],
    ['junit', { outputFile: resolve(here, '../test-results/junit.xml') }],
  ],
  globalSetup: resolve(here, './e2e/global-setup.ts'),
  globalTeardown: resolve(here, './e2e/global-teardown.ts'),
  use: {
    baseURL,
    actionTimeout: 30_000,
    navigationTimeout: 30_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  // npm run dev chooses a directory-hashed port, not 8787. Use an explicit port and no
  // background watcher. Build core first so tests cannot accidentally exercise stale dist.
  webServer: process.env.BASE_URL ? undefined : {
    command: 'npx wrangler dev --local --port 8787' +
      (process.env.E2E_PERSIST_DIR ? ' --persist-to "$E2E_PERSIST_DIR"' : ''),
    cwd: resolve(here, '../my-sonicjs-app'),
    url: baseURL,
    reuseExistingServer: !ci && process.env.E2E_REUSE_SERVER === '1',
    timeout: 180_000,
  },
})
