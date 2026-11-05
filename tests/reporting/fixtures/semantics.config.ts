import { defineConfig } from '@playwright/test'
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createReportingOptions, repositoryRoot } from '../options'
const options = createReportingOptions({ suite: 'runner-contracts', target: 'none' })
Object.assign(process.env, options.environment)
if (process.env.REPORT_COLLISION === '1') {
  mkdirSync(options.outputFolder, { recursive: true })
  const collision = join(options.outputFolder, 'file')
  writeFileSync(collision, 'blocked')
  options.playwright[1].outputFolder = join(collision, 'child')
}
if (process.env.REPORT_COLLISION === 'unwritable') {
  const blocked = join(options.outputFolder, 'readonly')
  mkdirSync(blocked, { recursive: true })
  chmodSync(blocked, 0o500)
  process.on('exit', () => chmodSync(blocked, 0o700))
  options.playwright[1].outputFolder = join(blocked, 'child')
}
console.log(`REPORT_FOLDER=${options.outputFolder}`)
export default defineConfig({
  testDir: '.',
  testMatch: process.env.CASE_MODE === 'import' ? 'import-error.case.ts' : 'semantics.case.ts',
  globalSetup: process.env.CASE_MODE === 'setup' ? './setup-error.ts' : undefined,
  retries: process.env.CASE_MODE === 'retry' ? 1 : 0,
  timeout: 500,
  workers: 1,
  outputDir: join(repositoryRoot, 'test-results/reporting-contracts'),
  reporter: [
    ['list'],
    ['json', { outputFile: join(`${options.outputFolder}-native`, 'native.json') }],
    ['junit', { outputFile: join(`${options.outputFolder}-native`, 'native.xml') }],
    ['html', { outputFolder: join(`${options.outputFolder}-native`, 'html'), open: 'never' }],
    options.playwright,
  ],
})
