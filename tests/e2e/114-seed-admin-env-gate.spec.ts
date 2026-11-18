import { test, expect } from './fixtures'
import { seedAdminPastRateLimit } from './utils/test-helpers'

test.describe('seed-admin environment gate @smoke @auth', () => {
  // The endpoint under test is rate limited to 10 requests per minute and the rest of the suite
  // calls it too, so both tests poll past the limiter rather than asserting on whichever response
  // happened to land. That poll can outlast the default 60s timeout — see seedAdminPastRateLimit.
  test.setTimeout(150_000)

  test('seed-admin succeeds in the development preview', async ({ request }) => {
    const res = await seedAdminPastRateLimit(request)
    expect(res.ok(), `seed-admin never got past the rate limiter: ${res.status()}`).toBe(true)
    const body = await res.json()
    expect(body.message).toBe('Seed complete')
  })

  test('seeded admin can log in', async ({ request }) => {
    await seedAdminPastRateLimit(request)
    const baseURL = process.env.BASE_URL || 'http://localhost:8787'
    const res = await request.post('/auth/sign-in/email', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
      headers: { 'Content-Type': 'application/json', Origin: baseURL },
    })
    expect(res.ok()).toBe(true)
  })
})
