import { defineConfig } from 'vitest/config'

// Unit tests for the stats Worker's pure helpers (run with `npm test` in this package, and from the
// root `npm run test:cov`, which CI's unit-tests job runs).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
