import { defineConfig } from '@playwright/test'
import { createReportingOptions, writeInvocationManifest } from '../options'
const reporting = createReportingOptions({ suite: 'runner-contracts', target: 'none' })
Object.assign(process.env, reporting.environment)
writeInvocationManifest(reporting)
console.log(`REPORT_FOLDER=${reporting.outputFolder}`)
export default defineConfig({
  testDir: '.',
  testMatch: 'vendor-playwright.case.ts',
  outputDir: `${reporting.outputFolder}/native-results`,
  reporter: [['list'], reporting.playwright],
  workers: 1,
})
