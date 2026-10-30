import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Marketing site (www) E2E configuration.
 *
 * These specs exercise the Next.js marketing site in `www/`, NOT the CMS worker. They used to
 * live in `tests/e2e/` alongside the CMS specs, where they could never pass: that suite points
 * `baseURL` at the CMS, whose `/` redirects to `/auth/login` (see `smoke.spec.ts`), so every
 * `goto('/')` landed on the login page instead of the marketing home.
 *
 * Usage:
 *   npm run e2e:www                                  - boots `www` dev server on :3010
 *   WWW_BASE_URL=https://sonicjs.com npm run e2e:www - run against a deployment
 */
export default defineConfig({
  testDir: './www',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  timeout: 60 * 1000,
  workers: process.env.CI ? 4 : 1,
  reporter: 'html',
  use: {
    baseURL: process.env.WWW_BASE_URL || 'http://localhost:3010',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: process.env.WWW_BASE_URL ? undefined : {
    command: 'npm run dev',
    cwd: resolve(__dirname, '../www'),
    url: 'http://localhost:3010',
    reuseExistingServer: true,
    // Next.js cold start compiles on first request; give it room.
    timeout: 300 * 1000,
  },
});
