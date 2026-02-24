import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import {
  generateCsrfToken,
  validateCsrfToken,
  csrfProtection,
  arrayBufferToBase64Url,
} from '../../middleware/csrf'

const TEST_SECRET = 'test-csrf-secret-for-unit-tests'
const ALT_SECRET = 'different-secret-entirely'

// ============================================================================
// Token Generation & Validation
// ============================================================================

describe('generateCsrfToken', () => {
  it('should generate a token in nonce.signature format', async () => {
    const token = await generateCsrfToken(TEST_SECRET)
    expect(token).toContain('.')
    const parts = token.split('.')
    expect(parts).toHaveLength(2)
    expect(parts[0]!.length).toBeGreaterThan(0)
    expect(parts[1]!.length).toBeGreaterThan(0)
  })

  it('should generate unique tokens on each call', async () => {
    const token1 = await generateCsrfToken(TEST_SECRET)
    const token2 = await generateCsrfToken(TEST_SECRET)
    expect(token1).not.toBe(token2)
  })
})

describe('validateCsrfToken', () => {
  it('should validate a correctly signed token', async () => {
    const token = await generateCsrfToken(TEST_SECRET)
    const isValid = await validateCsrfToken(token, TEST_SECRET)
    expect(isValid).toBe(true)
  })

  it('should reject a token signed with a different secret', async () => {
    const token = await generateCsrfToken(TEST_SECRET)
    const isValid = await validateCsrfToken(token, ALT_SECRET)
    expect(isValid).toBe(false)
  })

  it('should reject a token with a tampered nonce', async () => {
    const token = await generateCsrfToken(TEST_SECRET)
    const [_nonce, signature] = token.split('.')
    const tamperedToken = `tampered-nonce.${signature}`
    const isValid = await validateCsrfToken(tamperedToken, TEST_SECRET)
    expect(isValid).toBe(false)
  })

  it('should reject a token with a tampered signature', async () => {
    const token = await generateCsrfToken(TEST_SECRET)
    const [nonce, _signature] = token.split('.')
    const tamperedToken = `${nonce}.tampered-signature-AAAA`
    const isValid = await validateCsrfToken(tamperedToken, TEST_SECRET)
    expect(isValid).toBe(false)
  })

  it('should reject an empty string', async () => {
    const isValid = await validateCsrfToken('', TEST_SECRET)
    expect(isValid).toBe(false)
  })

  it('should reject a token without a dot', async () => {
    const isValid = await validateCsrfToken('nodothere', TEST_SECRET)
    expect(isValid).toBe(false)
  })

  it('should reject null/undefined', async () => {
    expect(await validateCsrfToken(null as any, TEST_SECRET)).toBe(false)
    expect(await validateCsrfToken(undefined as any, TEST_SECRET)).toBe(false)
  })
})

describe('arrayBufferToBase64Url', () => {
  it('should produce url-safe base64 without padding', async () => {
    const bytes = new Uint8Array([0, 255, 128, 64])
    const result = arrayBufferToBase64Url(bytes.buffer)
    expect(result).not.toContain('+')
    expect(result).not.toContain('/')
    expect(result).not.toContain('=')
  })
})

// ============================================================================
// Middleware Integration Tests
// ============================================================================

function createApp(opts?: { exemptPaths?: string[] }) {
  const app = new Hono<{
    Bindings: { JWT_SECRET?: string; ENVIRONMENT?: string }
    Variables: { csrfToken?: string }
  }>()

  app.use('*', csrfProtection(opts))

  // Test routes
  app.get('/admin/dashboard', (c) => c.text('dashboard'))
  app.post('/admin/content', (c) => c.text('created'))
  app.put('/admin/content/1', (c) => c.text('updated'))
  app.delete('/admin/content/1', (c) => c.text('deleted'))
  app.patch('/admin/content/1', (c) => c.text('patched'))
  app.post('/auth/login', (c) => c.text('login'))
  app.post('/auth/login/form', (c) => c.text('login-form'))
  app.post('/auth/register', (c) => c.text('register'))
  app.post('/auth/register/form', (c) => c.text('register-form'))
  app.post('/auth/seed-admin', (c) => c.text('seed'))
  app.post('/auth/accept-invitation', (c) => c.text('accept'))
  app.post('/auth/reset-password', (c) => c.text('reset'))
  app.post('/forms/submit', (c) => c.text('form-submitted'))
  app.post('/api/forms/submit', (c) => c.text('api-form-submitted'))
  app.post('/admin/forms/save', (c) => c.text('admin-form-saved'))
  app.post('/api/content', (c) => c.text('api-content'))
  app.get('/api/content', (c) => c.text('api-list'))
  app.post('/custom/exempt', (c) => c.text('custom-exempt'))

  return app
}

// Helper to build request with env bindings
function createReq(method: string, path: string, headers: Record<string, string> = {}) {
  return new Request(`http://localhost${path}`, {
    method,
    headers,
  })
}

describe('csrfProtection middleware', () => {
  describe('safe methods', () => {
    it('should allow GET requests through', async () => {
      const app = createApp()
      const res = await app.request('/admin/dashboard', {}, { JWT_SECRET: TEST_SECRET })
      expect(res.status).toBe(200)
    })

    it('should set csrf_token cookie on GET when none exists', async () => {
      const app = createApp()
      const res = await app.request('/admin/dashboard', {}, { JWT_SECRET: TEST_SECRET })
      expect(res.status).toBe(200)
      const setCookieHeader = res.headers.get('set-cookie')
      expect(setCookieHeader).toContain('csrf_token=')
      expect(setCookieHeader).toContain('SameSite=Strict')
      expect(setCookieHeader).toContain('Path=/')
    })

    it('should allow HEAD requests through', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('HEAD', '/admin/dashboard'),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should allow OPTIONS requests through', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('OPTIONS', '/admin/dashboard'),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      // OPTIONS may return 404 since no explicit OPTIONS handler, but should not be 403
      expect(res.status).not.toBe(403)
    })
  })

  describe('reuse existing valid cookie', () => {
    it('should NOT set a new cookie if existing csrf_token has valid HMAC', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('GET', '/admin/dashboard', {
          Cookie: `csrf_token=${token}`,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
      // Should NOT have a Set-Cookie for csrf_token since existing is valid
      const setCookieHeader = res.headers.get('set-cookie')
      expect(setCookieHeader).toBeNull()
    })

    it('should regenerate csrf_token when existing cookie has invalid HMAC', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('GET', '/admin/dashboard', {
          Cookie: 'csrf_token=invalid-nonce.invalid-sig',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
      const setCookieHeader = res.headers.get('set-cookie')
      expect(setCookieHeader).toContain('csrf_token=')
    })
  })

  describe('state-changing requests with cookie auth', () => {
    it('should allow POST with valid matching header + cookie', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: `auth_token=some-jwt; csrf_token=${token}`,
          'X-CSRF-Token': token,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
      expect(await res.text()).toBe('created')
    })

    it('should reject POST with missing csrf_token cookie', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: 'auth_token=some-jwt',
          'X-CSRF-Token': token,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
    })

    it('should reject POST with missing X-CSRF-Token header', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: `auth_token=some-jwt; csrf_token=${token}`,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
    })

    it('should reject POST with mismatched header and cookie', async () => {
      const app = createApp()
      const token1 = await generateCsrfToken(TEST_SECRET)
      const token2 = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: `auth_token=some-jwt; csrf_token=${token1}`,
          'X-CSRF-Token': token2,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
    })

    it('should reject POST with invalid signature in token', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: 'auth_token=some-jwt; csrf_token=fake-nonce.fake-sig',
          'X-CSRF-Token': 'fake-nonce.fake-sig',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
    })

    it('should validate PUT requests', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('PUT', '/admin/content/1', {
          Cookie: `auth_token=some-jwt; csrf_token=${token}`,
          'X-CSRF-Token': token,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should validate DELETE requests', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('DELETE', '/admin/content/1', {
          Cookie: `auth_token=some-jwt; csrf_token=${token}`,
          'X-CSRF-Token': token,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should validate PATCH requests', async () => {
      const app = createApp()
      const token = await generateCsrfToken(TEST_SECRET)
      const res = await app.request(
        createReq('PATCH', '/admin/content/1', {
          Cookie: `auth_token=some-jwt; csrf_token=${token}`,
          'X-CSRF-Token': token,
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })
  })

  describe('exempt paths', () => {
    it('should exempt /auth/login', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/auth/login', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /auth/login/form', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/auth/login/form', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /auth/register', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/auth/register', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /auth/seed-admin', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/auth/seed-admin', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /auth/accept-invitation', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/auth/accept-invitation', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /auth/reset-password', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/auth/reset-password', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /forms/* (public form submissions)', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/forms/submit', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt /api/forms/* (public API form submissions)', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/api/forms/submit', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should NOT exempt /admin/forms/* (admin form management)', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/admin/forms/save', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
    })

    it('should accept custom exempt paths', async () => {
      const app = createApp({ exemptPaths: ['/custom/exempt'] })
      const res = await app.request(
        createReq('POST', '/custom/exempt', {
          Cookie: 'auth_token=some-jwt',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })
  })

  describe('Bearer-only / API-key-only exemption', () => {
    it('should exempt requests with no auth_token cookie (Bearer-only)', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/api/content', {
          Authorization: 'Bearer some-jwt-token',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })

    it('should exempt requests with no auth_token cookie (API-key-only)', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/api/content', {
          'X-API-Key': 'some-api-key',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(200)
    })
  })

  describe('error responses', () => {
    it('should return HTML error for browser requests (Accept: text/html)', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: 'auth_token=some-jwt',
          Accept: 'text/html,application/xhtml+xml',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
      const body = await res.text()
      expect(body).toContain('403 Forbidden')
      expect(body).toContain('CSRF token missing')
    })

    it('should return JSON error for API requests', async () => {
      const app = createApp()
      const res = await app.request(
        createReq('POST', '/admin/content', {
          Cookie: 'auth_token=some-jwt',
          Accept: 'application/json',
        }),
        {},
        { JWT_SECRET: TEST_SECRET }
      )
      expect(res.status).toBe(403)
      const body = await res.json()
      expect(body.error).toBe('CSRF token missing')
      expect(body.status).toBe(403)
    })
  })

  describe('JWT_SECRET fallback warning', () => {
    it('should warn when JWT_SECRET is missing in production', async () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      const app = createApp()

      await app.request('/admin/dashboard', {}, { ENVIRONMENT: 'production' })

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('JWT_SECRET is not set in production')
      )
      consoleSpy.mockRestore()
    })

    it('should NOT warn in development mode', async () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      const app = createApp()

      await app.request('/admin/dashboard', {}, { ENVIRONMENT: 'development' })

      expect(consoleSpy).not.toHaveBeenCalledWith(
        expect.stringContaining('JWT_SECRET is not set in production')
      )
      consoleSpy.mockRestore()
    })
  })
})
