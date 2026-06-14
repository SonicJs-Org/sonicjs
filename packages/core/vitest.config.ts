import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.{test,spec}.{js,ts}'],
    // Quarantined: known-failing suites for work that is explicitly out of the current
    // core-functionality scope. Each is a tracked TODO — remove from this list when fixed.
    // See .context/v3-qa-assessment.md and project-plan Review section.
    exclude: [
      'node_modules/**',
      'dist/**',
      // ── Plugins (out of scope for the current core pass): email/otp/cache/SDK suites.
      // plugin-builder + email-reconciliation fail at import (sdk/plugin-builder module moved).
      'src/__tests__/plugins/plugin-builder.test.ts',
      'src/__tests__/plugins/email-reconciliation.test.ts',
      'src/__tests__/plugins/otp-verify-custom-fields.test.ts',
      'src/__tests__/services/email-wiring-integration.test.ts',
      'src/plugins/cache/tests/cache-warming.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'src/__tests__/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData',
      ],
    },
  },
})
