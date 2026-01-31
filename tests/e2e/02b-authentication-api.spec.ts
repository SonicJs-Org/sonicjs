import { test, expect } from '@playwright/test'
import { ADMIN_CREDENTIALS } from './utils/test-helpers'

const BETTER_AUTH_SESSION_COOKIE = 'better-auth.session_token'

test.describe('Authentication API (Better Auth)', () => {
  const testUser = {
    name: 'Test User',
    email: 'test.api.user@example.com',
    password: 'TestPassword123!'
  }

  test.beforeAll(async ({ request }) => {
    try {
      await request.post('/auth/seed-admin')
    } catch {
      // Admin might already exist
    }
  })

  test.describe('POST /auth/sign-up/email - User Registration', () => {
    test('should register a new user successfully', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `test.${Date.now()}@example.com`,
        name: `Test User ${Date.now()}`
      }

      const response = await request.post('/auth/sign-up/email', {
        data: { name: uniqueUser.name, email: uniqueUser.email, password: uniqueUser.password }
      })

      expect(response.status()).toBe(200)
      const data = await response.json()
      expect(data).toHaveProperty('user')
      expect(data.user).toHaveProperty('id')
      expect(data.user.email).toBe(uniqueUser.email.toLowerCase())
      expect(data.user.name).toBe(uniqueUser.name)
      const cookies = response.headers()['set-cookie']
      expect(cookies).toBeTruthy()
      expect(cookies).toContain(BETTER_AUTH_SESSION_COOKIE)
    })

    test('should normalize email to lowercase', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `TEST.UPPERCASE.${Date.now()}@EXAMPLE.COM`,
        name: `Test ${Date.now()}`
      }

      const response = await request.post('/auth/sign-up/email', {
        data: { name: uniqueUser.name, email: uniqueUser.email, password: uniqueUser.password }
      })

      expect(response.status()).toBe(200)
      const data = await response.json()
      expect(data.user.email).toBe(uniqueUser.email.toLowerCase())
    })

    test('should validate required fields', async ({ request }) => {
      const invalidPayloads = [
        { email: 'test@example.com' },
        { name: 'Test', email: '' },
        { name: 'Test', email: 'invalid-email', password: 'password123' },
        { name: 'Test', email: 'test@example.com', password: '123' }
      ]

      for (const payload of invalidPayloads) {
        const response = await request.post('/auth/sign-up/email', {
          data: payload
        })
        expect(response.status()).toBeGreaterThanOrEqual(400)
        expect(response.status()).toBeLessThan(500)
      }
    })

    test('should prevent duplicate email registration', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `duplicate.test.${Date.now()}@example.com`,
        name: `Test ${Date.now()}`
      }

      const firstResponse = await request.post('/auth/sign-up/email', {
        data: { name: uniqueUser.name, email: uniqueUser.email, password: uniqueUser.password }
      })
      expect(firstResponse.status()).toBe(200)

      const secondResponse = await request.post('/auth/sign-up/email', {
        data: { name: 'Other', email: uniqueUser.email, password: 'OtherPass123!' }
      })
      expect(secondResponse.status()).toBe(400)
      const data = await secondResponse.json()
      expect(data.message ?? data.error ?? '').toMatch(/already|exist|email/i)
    })

    test('should set session cookie on registration', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `cookie.test.${Date.now()}@example.com`,
        name: `Test ${Date.now()}`
      }

      const response = await request.post('/auth/sign-up/email', {
        data: { name: uniqueUser.name, email: uniqueUser.email, password: uniqueUser.password }
      })
      expect(response.status()).toBe(200)
      const cookies = response.headers()['set-cookie']
      expect(cookies).toBeTruthy()
      expect(cookies).toContain(BETTER_AUTH_SESSION_COOKIE)
      expect(cookies).toContain('HttpOnly')
      expect(cookies).toContain('SameSite')
    })
  })

  test.describe('POST /auth/sign-in/email - User Login', () => {
    test('should login successfully with valid credentials', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })

      expect(response.status()).toBe(200)
      const data = await response.json()
      expect(data).toHaveProperty('user')
      expect(data.user).toMatchObject({
        email: ADMIN_CREDENTIALS.email
      })
      const cookies = response.headers()['set-cookie']
      expect(cookies).toBeTruthy()
      expect(cookies).toContain(BETTER_AUTH_SESSION_COOKIE)
    })

    test('should normalize email to lowercase on login', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email.toUpperCase(),
          password: ADMIN_CREDENTIALS.password
        }
      })

      expect(response.status()).toBe(200)
      const data = await response.json()
      expect(data.user.email).toBe(ADMIN_CREDENTIALS.email.toLowerCase())
    })

    test('should fail with invalid email', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email', {
        data: {
          email: 'nonexistent@example.com',
          password: 'anypassword'
        }
      })

      expect(response.status()).toBe(401)
      const data = await response.json()
      expect(data.message ?? data.error ?? '').toMatch(/invalid|credential|password/i)
    })

    test('should fail with invalid password', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: 'wrongpassword'
        }
      })

      expect(response.status()).toBe(401)
      const data = await response.json()
      expect(data.message ?? data.error ?? '').toMatch(/invalid|credential|password/i)
    })

    test('should set session cookie on login', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })

      expect(response.status()).toBe(200)
      const cookies = response.headers()['set-cookie']
      expect(cookies).toBeTruthy()
      expect(cookies).toContain(BETTER_AUTH_SESSION_COOKIE)
      expect(cookies).toContain('HttpOnly')
      expect(cookies).toContain('SameSite')
    })
  })

  test.describe('POST /auth/sign-out - User Logout', () => {
    test('should logout successfully', async ({ request }) => {
      const loginResponse = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })
      expect(loginResponse.status()).toBe(200)

      const cookies = loginResponse.headers()['set-cookie']
      const sessionCookie = cookies?.split(';')[0] ?? ''

      const logoutResponse = await request.post('/auth/sign-out', {
        headers: { Cookie: sessionCookie }
      })

      expect(logoutResponse.status()).toBe(200)
      const logoutCookies = logoutResponse.headers()['set-cookie']
      expect(logoutCookies).toBeTruthy()
      expect(logoutCookies).toMatch(new RegExp(`${BETTER_AUTH_SESSION_COOKIE.replace('.', '\\.')}=`))
      expect(logoutCookies).toMatch(/Max-Age=0|expires=/i)
    })
  })

  test.describe('GET /auth/me - Current User', () => {
    test('should return current user when authenticated', async ({ request }) => {
      const loginResponse = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })
      expect(loginResponse.status()).toBe(200)

      const cookies = loginResponse.headers()['set-cookie']
      const sessionCookie = cookies?.split(';')[0] ?? ''

      const meResponse = await request.get('/auth/me', {
        headers: { Cookie: sessionCookie }
      })

      expect(meResponse.status()).toBe(200)
      const data = await meResponse.json()
      expect(data).toHaveProperty('user')
      expect(data.user).toMatchObject({
        email: ADMIN_CREDENTIALS.email,
        username: 'admin',
        role: 'admin'
      })
      expect(data.user).not.toHaveProperty('password_hash')
      expect(data.user).not.toHaveProperty('password')
    })

    test('should return 401 when not authenticated', async ({ request }) => {
      const response = await request.get('/auth/me')
      expect(response.status()).toBe(401)
      const data = await response.json()
      expect(data.error).toMatch(/auth|required/i)
    })
  })

  test.describe('POST /auth/refresh', () => {
    test('should return message (session managed by Better Auth)', async ({ request }) => {
      const loginResponse = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })
      expect(loginResponse.status()).toBe(200)
      const cookies = loginResponse.headers()['set-cookie']
      const sessionCookie = cookies?.split(';')[0] ?? ''

      const refreshResponse = await request.post('/auth/refresh', {
        headers: { Cookie: sessionCookie }
      })

      expect(refreshResponse.status()).toBe(200)
      const data = await refreshResponse.json()
      expect(data.message).toMatch(/Better Auth|session|refresh/i)
    })

    test('should return 401 when not authenticated', async ({ request }) => {
      const response = await request.post('/auth/refresh')
      expect(response.status()).toBe(401)
      const data = await response.json()
      expect(data.error).toMatch(/auth|required/i)
    })
  })

  test.describe('Security Tests', () => {
    test('should not expose sensitive data in registration response', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `security.test.${Date.now()}@example.com`,
        name: `Test ${Date.now()}`
      }

      const response = await request.post('/auth/sign-up/email', {
        data: { name: uniqueUser.name, email: uniqueUser.email, password: uniqueUser.password }
      })
      expect(response.status()).toBe(200)
      const data = await response.json()
      expect(data.user).not.toHaveProperty('password')
      expect(data.user).not.toHaveProperty('password_hash')
      expect(data.user).not.toHaveProperty('passwordHash')
      expect(JSON.stringify(data)).not.toContain(uniqueUser.password)
    })

    test('should handle SQL injection attempts safely', async ({ request }) => {
      const maliciousPayloads = [
        { email: "admin@sonicjs.com' OR '1'='1", password: 'anything' },
        { email: "admin@sonicjs.com'; DROP TABLE users; --", password: 'anything' },
        { email: 'admin@sonicjs.com', password: "' OR '1'='1" }
      ]

      for (const payload of maliciousPayloads) {
        const response = await request.post('/auth/sign-in/email', { data: payload })
        expect(response.status()).toBeGreaterThanOrEqual(400)
        expect(response.status()).toBeLessThan(500)
        const data = await response.json()
        const err = (data.message ?? data.error ?? '').toString()
        expect(err).not.toMatch(/SQL|syntax/i)
      }
    })

    test('should enforce secure cookies', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })
      expect(response.status()).toBe(200)
      const cookies = response.headers()['set-cookie']
      expect(cookies).toContain('HttpOnly')
      expect(cookies).toContain('SameSite')
    })
  })

  test.describe('Session Management', () => {
    test('should maintain session across requests', async ({ request }) => {
      const loginResponse = await request.post('/auth/sign-in/email', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      })
      expect(loginResponse.status()).toBe(200)
      const cookies = loginResponse.headers()['set-cookie']
      const sessionCookie = cookies?.split(';')[0] ?? ''

      const meResponse = await request.get('/auth/me', {
        headers: { Cookie: sessionCookie }
      })
      expect(meResponse.status()).toBe(200)

      const refreshResponse = await request.post('/auth/refresh', {
        headers: { Cookie: sessionCookie }
      })
      expect(refreshResponse.status()).toBe(200)
    })
  })
})
