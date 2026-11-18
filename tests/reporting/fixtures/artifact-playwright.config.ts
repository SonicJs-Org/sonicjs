import { defineConfig } from '@playwright/test'
export default defineConfig({
  testDir: '.', testMatch: 'semantics.case.ts', workers: 1,
  outputDir: process.env.ARTIFACT_NATIVE_RESULTS,
  projects: [{ name: 'chromium' }],
  reporter: [['@flakiness/playwright', { disableUpload: true, open: 'never', outputFolder: process.env.ARTIFACT_NATIVE_OUTPUT }]],
})
