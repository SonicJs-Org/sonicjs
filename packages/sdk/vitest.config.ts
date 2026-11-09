import { vitestReporting } from '../../tests/reporting/vitest-integration'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    ...vitestReporting('sdk-unit'),
    globals: true,
    environment: 'node',
  },
})
