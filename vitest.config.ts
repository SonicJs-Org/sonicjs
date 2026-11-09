import { vitestReporting } from './tests/reporting/vitest-integration'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    ...vitestReporting('root-unit'),
    globals: true,
    environment: 'node',
    include: ['src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    exclude: ['node_modules', 'dist', '.next'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.{js,ts}'],
      exclude: [
        'src/**/*.{test,spec}.{js,ts}',
        'src/**/*.d.ts',
        'src/scripts/**',
        'src/templates/**',
        'src/routes/**',
        'src/plugins/**',
        'src/collections/**',
        'src/index.ts',
        'src/db/index.ts',
        'src/types/**',
        'src/content/rich-text.ts',
        'src/content/versioning.ts',
        'src/content/workflow.ts',
        'src/services/migrations.ts',
        'src/services/logger.ts',
        'src/services/automation.ts',
        'src/services/webhooks.ts',
        'src/services/plugin-*.ts',
        'src/services/collection-*.ts',
        'src/middleware/bootstrap.ts',
        'src/middleware/logging.ts',
        'src/middleware/performance.ts',
        'src/middleware/rate-limit-middleware.ts',
        'src/utils/template-renderer-backup.ts',
        'src/tests/**'
      ],
      thresholds: {
        global: {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90
        }
      }
    }
  },
})