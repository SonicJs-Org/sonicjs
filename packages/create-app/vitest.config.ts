import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'
import { vitestReporting } from '../../tests/reporting/vitest-integration'
export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  test: {
    ...vitestReporting('create-app-cli'),
    include: ['test-cli.test.ts'],
    testTimeout: 90_000,
  },
})
