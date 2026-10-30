import { defineConfig } from '@playwright/test'
import base from './playwright.config'

// Runner-only browser regressions: no application, database, or credentials required.
export default defineConfig({
  ...base,
  testMatch: '126-runner-contracts.spec.ts',
  globalSetup: undefined,
  globalTeardown: undefined,
  webServer: undefined,
  retries: 0,
  reporter: [['list']],
})
