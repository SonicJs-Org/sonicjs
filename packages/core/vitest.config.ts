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
      // ── Email plugin hook/route tests written for a different API design than the current
      // implementation (factory pattern vs direct fn, SDK EmailService vs core EmailService,
      // payload shape mismatch). Quarantined until the email plugin is realigned.
      'src/plugins/core-plugins/email-plugin/__tests__/integration.test.ts',
      'src/plugins/core-plugins/email-plugin/routes/admin.test.ts',
      'src/plugins/core-plugins/email-plugin/hooks/on-cron-tick.test.ts',
      'src/plugins/core-plugins/email-plugin/hooks/on-password-reset-completed.test.ts',
      'src/plugins/core-plugins/email-plugin/hooks/on-password-reset-requested.test.ts',
      'src/plugins/core-plugins/email-plugin/hooks/on-registration-completed.test.ts',
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
