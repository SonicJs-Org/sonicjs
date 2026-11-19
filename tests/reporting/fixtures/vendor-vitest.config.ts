import { defineConfig } from 'vitest/config'
import { createReportingOptions, repositoryRoot, writeInvocationManifest } from '../options'
const reporting = createReportingOptions({ suite: 'reporting-contracts', target: 'none' })
Object.assign(process.env, reporting.environment)
writeInvocationManifest(reporting)
console.log(`REPORT_FOLDER=${reporting.outputFolder}`)
export default defineConfig({
  root: repositoryRoot,
  test: {
    include: ['tests/reporting/fixtures/vendor-vitest.case.ts'],
    ...reporting.vitest,
  },
})
