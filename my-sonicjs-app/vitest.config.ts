import { defineConfig } from 'vitest/config'
import inherited from '../vitest.config'
import { vitestReporting } from '../tests/reporting/vitest-integration'

// Same ancestor discovery, excludes, and coverage, still relative to invocation cwd.
// Preserve the contact-form Playwright import failure; this is not a test migration.
export default defineConfig({
  ...inherited,
  test: { ...inherited.test, ...vitestReporting('sample-unit') },
})
