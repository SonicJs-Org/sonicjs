import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { defineConfig } from 'vitest/config'
import { vitestReporting } from '../vitest-integration'
import { repositoryRoot, createReportingOptions } from '../options'
const raw = process.env.RAW_VENDOR_WATCH === '1' ? createReportingOptions({ suite: 'runner-contracts', target: 'none' }) : undefined
if (raw) {
  Object.assign(process.env, raw.environment)
  console.log(`[flakiness] Report: ${raw.outputFolder}`)
}
const reporting = raw?.vitest ?? vitestReporting('runner-contracts')
if (process.env.CASE_MODE === 'duplicate') {
  const reporters = reporting.reporters as any[]
  const vendor = reporters.find(r => Array.isArray(r) && r[0] === '@flakiness/vitest')
  // Observe only public reporter options in the real runner, before vendor finalization.
  reporters.splice(2, 0, {
    onTestRunStart() {
      vendor[1].disableUpload = false
      console.log('DUPLICATE_UPLOAD_BEFORE=false')
    },
    onTestRunEnd() {
      console.log(`DUPLICATE_UPLOAD_AFTER=${vendor[1].disableUpload}`)
      if (vendor[1].disableUpload !== true) throw new Error('Duplicate preflight did not disable upload')
    },
  })
}
if (process.env.REPORT_COLLISION === '1') {
  const reporters = reporting.reporters
  const vendor = (Array.isArray(reporters) ? reporters : []).find(r => Array.isArray(r)) as [string, { outputFolder: string }]
  mkdirSync(vendor[1].outputFolder, { recursive: true })
  const blocker = join(vendor[1].outputFolder, 'blocker')
  writeFileSync(blocker, 'file')
  vendor[1].outputFolder = join(blocker, 'child')
}
export default defineConfig({
  root: repositoryRoot,
  server: { watch: { usePolling: true, interval: 50 } },
  test: {
    ...reporting,
    include: process.env.WATCH_CASE_FILE ? [process.env.WATCH_CASE_FILE] : [process.env.CASE_MODE === 'import' ? 'tests/reporting/fixtures/vitest-import.case.ts' : 'tests/reporting/fixtures/vitest-semantics.case.ts'],
    setupFiles: process.env.CASE_MODE === 'setup' ? ['tests/reporting/fixtures/vitest-setup.ts'] : [],
    retry: process.env.CASE_MODE === 'retry' ? 1 : 0,
    testTimeout: 10_000,
  },
})
