import { vitestReporting } from './vitest-integration'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  root: fileURLToPath(new URL('../..', import.meta.url)),
  test: {
    ...vitestReporting('reporting-contracts'),
    include: ['tests/reporting/*.test.ts'],
    includeTaskLocation: true,
    testTimeout: 30_000,
  },
})
