import { defineConfig, devices } from '@playwright/test'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const ci = !!process.env.CI
const baseURL = process.env.BASE_URL || 'http://localhost:8787'

export default defineConfig({
  testDir: './e2e',
  // File-level parallelism only; global-state specs still require narrow @lock-* tags.
  fullyParallel: false,
  forbidOnly: ci,
  // One diagnostic retry, not a green-by-retry policy. First-attempt failures fail CI.
  retries: ci ? 1 : 0,
  failOnFlakyTests: ci,
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
    reuseExistingServer: !ci,
    timeout: 180_000,
  },
})
