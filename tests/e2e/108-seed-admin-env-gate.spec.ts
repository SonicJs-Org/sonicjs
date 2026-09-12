import { test, expect } from '@playwright/test'

// The seed-admin endpoint is now gated fail-closed to non-production environments.
// The E2E preview runs with ENVIRONMENT=development (an allowed value), so this
// spec is a regression guard: the gate must NOT break the seeding path that the
// rest of the suite (and first-boot login) depends on. The denied path
// (production/unset → 403) is covered by the unit test seed-admin-gate.test.ts,
// since the preview environment cannot be flipped to production here.

test.describe('seed-admin environment gate @smoke @auth', () => {
  test('seed-admin still succeeds in the development preview', async ({ request }) => {
    const res = await request.post('/auth/seed-admin')
    expect(res.ok()).toBe(true)
    const body = await res.json()
    expect(body.message).toBe('Seed complete')
  })

  test('the seeded admin can log in after gating', async ({ request }) => {
    await request.post('/auth/seed-admin')
    const res = await request.post('/auth/login', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
    })
    expect(res.ok()).toBe(true)
    const body = await res.json()
    expect(body.user?.email).toBe('admin@sonicjs.com')
  })
})
