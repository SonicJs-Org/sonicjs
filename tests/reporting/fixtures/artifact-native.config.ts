import { defineConfig } from 'vitest/config'
import { repositoryRoot } from '../options'
export default defineConfig({ root: repositoryRoot, test: {
  include: [process.env.ARTIFACT_NATIVE_IMPORT_ERROR === '1' ? 'tests/reporting/fixtures/artifact-import-error.case.ts' : 'tests/reporting/fixtures/vendor-vitest.case.ts'], includeTaskLocation: true,
  reporters: [['@flakiness/vitest', { disableUpload: true, outputFolder: process.env.ARTIFACT_NATIVE_OUTPUT, commitId: process.env.ARTIFACT_NATIVE_COMMIT ?? 'a'.repeat(40) }]],
} })
