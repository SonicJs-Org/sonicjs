import { test, expect } from '@playwright/test'

test.describe('POST /auth/login returns token', () => {
  test.beforeAll(async ({ request }) => {
    await request.post('/auth/seed-admin')
  })

  test('login response includes token field', async ({ request }) => {
    const res = await request.post('/auth/login', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
    })
    expect(res.ok()).toBe(true)
    const body = await res.json()
    expect(body.user).toBeTruthy()
    expect(typeof body.token).toBe('string')
    expect(body.token.length).toBeGreaterThan(0)
  })

  test('returned token works for Bearer auth on /auth/me', async ({ request }) => {
    const loginRes = await request.post('/auth/login', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
    })
    const { token } = await loginRes.json()

    const meRes = await request.get('/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(meRes.ok()).toBe(true)
    const body = await meRes.json()
    expect(body.user?.email).toBe('admin@sonicjs.com')
  })

  test('auth_token cookie set on login', async ({ request }) => {
    const res = await request.post('/auth/login', {
      data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
    })
    expect(res.ok()).toBe(true)
    // Verify the response body includes the token (primary signal)
    const body = await res.json()
    expect(typeof body.token).toBe('string')
    // Cookie header may contain multiple cookies joined by \n
    const headers = res.headers()
    const cookies = (headers['set-cookie'] ?? '').split('\n').join('; ')
    expect(cookies).toContain('auth_token')
  })
})
