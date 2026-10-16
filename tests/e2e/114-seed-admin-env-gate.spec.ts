import { test, expect } from '@playwright/test'

test.describe('seed-admin environment gate @smoke @auth', () => {
  test('seed-admin succeeds in the development preview', async ({ request }) => {
    const res = await request.post('/auth/seed-admin')
    expect(res.ok()).toBe(true)
    const body = await res.json()
    expect(body.message).toBe('Seed complete')
  })

  test('seeded admin can log in', async ({ request }) => {
    await request.post('/auth/seed-admin')
    const baseURL = process.env.BASE_URL || 'http://localhost:8787'
    const res = await request.post('/auth/sign-in/email', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
      headers: { 'Content-Type': 'application/json', Origin: baseURL },
    })
    expect(res.ok()).toBe(true)
  })
})
