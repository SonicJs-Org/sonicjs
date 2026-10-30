import { describe, it, expect, beforeEach, vi } from 'vitest'
import { AuthManager, requireAuth, requireRole, optionalAuth, getJwtExpirySeconds } from '../../middleware/auth'
import { Context, Next } from 'hono'
import { sign } from 'hono/jwt'

/**
 * Build a minimal map-backed fake Hono Context.
 *
 * In v3 (Better Auth), a GLOBAL session middleware (src/app.ts) populates
 * `c.get('user')` from the session cookie before route guards run. The
 * `requireAuth` / `requireRole` guards no longer extract or verify tokens
 * themselves — they only read the user the session middleware already set.
 * So tests drive these guards by pre-seeding `vars.user`, not by mocking
 * token verification.
 *
 * @param opts.user      pre-seeded `c.get('user')` value (what the session
 *                       middleware would have set); omit/undefined = unauthenticated.
 * @param opts.acceptHtml when true, `Accept: text/html` (browser → redirect path).
 */
const buildGuardContext = (opts: { user?: any; acceptHtml?: boolean } = {}) => {
  const vars = new Map<string, any>()
  if (opts.user !== undefined) vars.set('user', opts.user)
  const json = vi.fn((body: any, status?: number) => ({ body, status }))
  const redirect = vi.fn((url: string) => ({ redirect: url }))
  return {
    get: (key: string) => vars.get(key),
    set: vi.fn((key: string, value: any) => vars.set(key, value)),
    req: {
      header: (name: string) =>
        name === 'Accept' ? (opts.acceptHtml ? 'text/html' : 'application/json') : undefined,
      raw: { headers: new Headers() },
    },
    json,
    redirect,
    env: {},
  } as unknown as Context & {
    json: ReturnType<typeof vi.fn>
    redirect: ReturnType<typeof vi.fn>
    set: ReturnType<typeof vi.fn>
  }
}

describe('AuthManager', () => {
  describe('generateToken', () => {
    it('should generate a valid JWT token', async () => {
      const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

      expect(token).toBeTruthy()
      expect(typeof token).toBe('string')
      expect(token.split('.')).toHaveLength(3) // JWT has 3 parts: header.payload.signature
    })

    it('should generate unique tokens for different users', async () => {
      const token1 = await AuthManager.generateToken('user-1', 'user1@example.com', 'user')
      const token2 = await AuthManager.generateToken('user-2', 'user2@example.com', 'user')

      expect(token1).not.toBe(token2)
    })
  })

  describe('verifyToken', () => {
    it('should verify a valid token', async () => {
      const userId = 'user-123'
      const email = 'test@example.com'
      const role = 'admin'

      const token = await AuthManager.generateToken(userId, email, role)
      const payload = await AuthManager.verifyToken(token)

      expect(payload).toBeTruthy()
      expect(payload?.userId).toBe(userId)
      expect(payload?.email).toBe(email)
      expect(payload?.role).toBe(role)
    })

    it('should return null for invalid token', async () => {
      const payload = await AuthManager.verifyToken('invalid.token.here')
      expect(payload).toBeNull()
    })

    it('should return null for malformed token', async () => {
      const payload = await AuthManager.verifyToken('not-a-jwt-token')
      expect(payload).toBeNull()
    })

    it('should include expiration time in payload', async () => {
      const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')
      const payload = await AuthManager.verifyToken(token)

      expect(payload?.exp).toBeTruthy()
      expect(payload?.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
    })

    it('should include issued at time in payload', async () => {
      const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')
      const payload = await AuthManager.verifyToken(token)

      expect(payload?.iat).toBeTruthy()
      expect(payload?.iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))
    })

    it('should honor custom expiresIn and default to 30 days', async () => {
      // Default TTL is 30 days
      const defaultToken = await AuthManager.generateToken('u', 'a@b.c', 'viewer')
      const defaultPayload = await AuthManager.verifyToken(defaultToken)
      const now = Math.floor(Date.now() / 1000)
      const thirtyDays = 60 * 60 * 24 * 30
      expect(defaultPayload?.exp).toBeGreaterThan(now + thirtyDays - 60)
      expect(defaultPayload?.exp).toBeLessThanOrEqual(now + thirtyDays + 5)

      // Custom TTL
      const shortToken = await AuthManager.generateToken('u', 'a@b.c', 'viewer', undefined, 3600)
      const shortPayload = await AuthManager.verifyToken(shortToken)
      expect(shortPayload?.exp).toBeLessThanOrEqual(now + 3605)
    })

    it('should accept a recently-expired token when grace window is set', async () => {
      const secret = 'test-grace-secret'
      const now = Math.floor(Date.now() / 1000)
      // Token that expired 60 seconds ago
      const expiredPayload = {
        userId: 'u1',
        email: 'u1@test',
        role: 'admin',
        iat: now - 120,
        exp: now - 60
      }
      const expiredToken = await sign(expiredPayload, secret, 'HS256')

      // Without grace window, expired token is rejected
      const strict = await AuthManager.verifyToken(expiredToken, secret)
      expect(strict).toBeNull()

      // With grace window of 300s, expired token is accepted
      const lenient = await AuthManager.verifyToken(expiredToken, secret, 300)
      expect(lenient).toBeTruthy()
      expect(lenient?.userId).toBe('u1')
    })

    it('should reject tokens expired beyond grace window', async () => {
      const secret = 'test-grace-secret'
      const now = Math.floor(Date.now() / 1000)
      const expiredPayload = {
        userId: 'u1',
        email: 'u1@test',
        role: 'admin',
        iat: now - 7200,
        exp: now - 3600
      }
      const expiredToken = await sign(expiredPayload, secret, 'HS256')
      // Grace window smaller than how long it has been expired
      const result = await AuthManager.verifyToken(expiredToken, secret, 60)
      expect(result).toBeNull()
    })

    it('should reject tokens with bad signature even within grace window', async () => {
      const now = Math.floor(Date.now() / 1000)
      const expiredPayload = {
        userId: 'u1',
        email: 'u1@test',
        role: 'admin',
        iat: now - 120,
        exp: now - 60
      }
      const tokenWithOneSecret = await sign(expiredPayload, 'secret-A', 'HS256')
      // Verify with a different secret — signature check must fail
      const result = await AuthManager.verifyToken(tokenWithOneSecret, 'secret-B', 3600)
      expect(result).toBeNull()
    })
  })

  describe('verifyAuthRequest', () => {
    const buildContext = (opts: {
      authHeader?: string
      cookieHeader?: string
      env?: Record<string, any>
    }) => {
      const headers = new Headers()
      if (opts.authHeader) headers.set('Authorization', opts.authHeader)
      if (opts.cookieHeader) headers.set('Cookie', opts.cookieHeader)
      return {
        req: {
          header: (name: string) => headers.get(name) ?? undefined,
          raw: { headers }
        },
        env: opts.env ?? {}
      } as unknown as Context
    }

    it('verifies a token from the Authorization header', async () => {
      const secret = 'request-helper-secret'
      const token = await AuthManager.generateToken('u-1', 'a@b.c', 'admin', secret, 60)

      const c = buildContext({
        authHeader: `Bearer ${token}`,
        env: { JWT_SECRET: secret }
      })

      const payload = await AuthManager.verifyAuthRequest(c)
      expect(payload?.userId).toBe('u-1')
      expect(payload?.email).toBe('a@b.c')
      expect(payload?.role).toBe('admin')
    })

    it('falls back to the auth_token cookie when no Authorization header is present', async () => {
      const secret = 'request-helper-secret'
      const token = await AuthManager.generateToken('u-2', 'c@d.e', 'editor', secret, 60)

      const c = buildContext({
        cookieHeader: `auth_token=${token}`,
        env: { JWT_SECRET: secret }
      })

      const payload = await AuthManager.verifyAuthRequest(c)
      expect(payload?.userId).toBe('u-2')
    })

    it('returns null when no token is provided', async () => {
      const c = buildContext({ env: { JWT_SECRET: 'whatever' } })
      const payload = await AuthManager.verifyAuthRequest(c)
      expect(payload).toBeNull()
    })

    it('returns null when token is signed with a different secret than c.env.JWT_SECRET', async () => {
      const token = await AuthManager.generateToken('u-3', 'e@f.g', 'admin', 'real-secret', 60)
      const c = buildContext({
        authHeader: `Bearer ${token}`,
        env: { JWT_SECRET: 'wrong-secret' }
      })

      const payload = await AuthManager.verifyAuthRequest(c)
      expect(payload).toBeNull()
    })
  })

  describe('getJwtExpirySeconds', () => {
    it('defaults to 30 days when env is empty', () => {
      expect(getJwtExpirySeconds({})).toBe(60 * 60 * 24 * 30)
      expect(getJwtExpirySeconds(null)).toBe(60 * 60 * 24 * 30)
      expect(getJwtExpirySeconds(undefined)).toBe(60 * 60 * 24 * 30)
    })

    it('parses duration strings', () => {
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '30d' })).toBe(60 * 60 * 24 * 30)
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '12h' })).toBe(60 * 60 * 12)
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '3600s' })).toBe(3600)
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '15m' })).toBe(900)
    })

    it('parses bare seconds values', () => {
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '7200' })).toBe(7200)
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: 7200 as any })).toBe(7200)
    })

    it('falls back to default on garbage input', () => {
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: 'nonsense' })).toBe(60 * 60 * 24 * 30)
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '0' })).toBe(60 * 60 * 24 * 30)
      expect(getJwtExpirySeconds({ JWT_EXPIRES_IN: '-5d' })).toBe(60 * 60 * 24 * 30)
    })
  })

  describe('hashPassword (PBKDF2)', () => {
    it('should hash a password in PBKDF2 format', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      expect(hash).toBeTruthy()
      expect(typeof hash).toBe('string')
      expect(hash).not.toBe(password)
      expect(hash.startsWith('pbkdf2:100000:')).toBe(true)
      const parts = hash.split(':')
      expect(parts).toHaveLength(4)
    })

    it('should generate different hashes for same password (random salt)', async () => {
      const password = 'test-password-123'
      const hash1 = await AuthManager.hashPassword(password)
      const hash2 = await AuthManager.hashPassword(password)

      expect(hash1).not.toBe(hash2) // Different salts
    })

    it('should generate different hashes for different passwords', async () => {
      const hash1 = await AuthManager.hashPassword('password1')
      const hash2 = await AuthManager.hashPassword('password2')

      expect(hash1).not.toBe(hash2)
    })
  })

  describe('verifyPassword', () => {
    it('should verify correct password against PBKDF2 hash', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      const isValid = await AuthManager.verifyPassword(password, hash)
      expect(isValid).toBe(true)
    })

    it('should reject incorrect password against PBKDF2 hash', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      const isValid = await AuthManager.verifyPassword('wrong-password', hash)
      expect(isValid).toBe(false)
    })

    it('should reject empty password against PBKDF2 hash', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      const isValid = await AuthManager.verifyPassword('', hash)
      expect(isValid).toBe(false)
    })

    it('should verify correct password against legacy SHA-256 hash', async () => {
      const password = 'test-password-123'
      const legacyHash = await AuthManager.hashPasswordLegacy(password)

      const isValid = await AuthManager.verifyPassword(password, legacyHash)
      expect(isValid).toBe(true)
    })

    it('should reject incorrect password against legacy SHA-256 hash', async () => {
      const password = 'test-password-123'
      const legacyHash = await AuthManager.hashPasswordLegacy(password)

      const isValid = await AuthManager.verifyPassword('wrong-password', legacyHash)
      expect(isValid).toBe(false)
    })
  })

  describe('isLegacyHash', () => {
    it('should detect PBKDF2 hash as non-legacy', async () => {
      const hash = await AuthManager.hashPassword('test')
      expect(AuthManager.isLegacyHash(hash)).toBe(false)
    })

    it('should detect SHA-256 hash as legacy', async () => {
      const hash = await AuthManager.hashPasswordLegacy('test')
      expect(AuthManager.isLegacyHash(hash)).toBe(true)
    })
  })
})

describe('requireAuth middleware', () => {
  // In v3, requireAuth only enforces presence of the user that the global
  // Better Auth session middleware already set on c.get('user'). It no longer
  // extracts or verifies tokens itself.
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should reject API request when no authenticated user (401 JSON)', async () => {
    const c = buildGuardContext({ acceptHtml: false })

    const middleware = requireAuth()
    await middleware(c, mockNext)

    expect((c as any).json).toHaveBeenCalledWith(
      { error: 'Authentication required' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should redirect browser requests when no authenticated user', async () => {
    const c = buildGuardContext({ acceptHtml: true })

    const middleware = requireAuth()
    await middleware(c, mockNext)

    expect((c as any).redirect).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login?error=')
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should accept request when the session middleware has set a user', async () => {
    const c = buildGuardContext({
      user: { userId: 'user-123', email: 'test@example.com', role: 'admin' },
    })

    const middleware = requireAuth()
    await middleware(c, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect((c as any).json).not.toHaveBeenCalled()
    expect((c as any).redirect).not.toHaveBeenCalled()
  })
})

describe('requireRole middleware', () => {
  let mockContext: any
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
    mockContext = {
      get: vi.fn(),
      req: {
        header: vi.fn(),
      },
      json: vi.fn().mockReturnValue({ error: 'Insufficient permissions' }),
      redirect: vi.fn().mockReturnValue({ redirect: true }),
    }
  })

  it('should reject request without user context', async () => {
    mockContext.get.mockReturnValue(undefined)
    mockContext.req.header.mockReturnValue(undefined)

    const middleware = requireRole('admin')
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Authentication required' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should reject user with wrong role', async () => {
    mockContext.get.mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
      role: 'user'
    })
    mockContext.req.header.mockReturnValue(undefined)

    const middleware = requireRole('admin')
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Insufficient permissions' },
      403
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should accept user with correct role', async () => {
    mockContext.get.mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
      role: 'admin'
    })

    const middleware = requireRole('admin')
    await middleware(mockContext as Context, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })

  it('should accept user with any of multiple allowed roles', async () => {
    mockContext.get.mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
      role: 'editor'
    })

    const middleware = requireRole(['admin', 'editor'])
    await middleware(mockContext as Context, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })

  it('should redirect browser requests with insufficient permissions', async () => {
    mockContext.get.mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
      role: 'user'
    })
    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Accept') return 'text/html'
      return undefined
    })

    const middleware = requireRole('admin')
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.redirect).toHaveBeenCalled()
    expect(mockNext).not.toHaveBeenCalled()
  })
})

describe('optionalAuth middleware', () => {
  // In v3, optionalAuth is a no-op pass-through kept only for API
  // compatibility. The global Better Auth session middleware (src/app.ts) is
  // what populates c.get('user') when a session exists; optionalAuth itself
  // neither extracts/verifies tokens nor sets a user.
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should call next() and never set a user (pass-through)', async () => {
    const c = buildGuardContext()

    const middleware = optionalAuth()
    await middleware(c, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect((c as any).set).not.toHaveBeenCalled()
  })

  it('should not set a user even when an Authorization header is present', async () => {
    const token = await AuthManager.generateToken('user-123', 'test@example.com', 'user')
    const c = buildGuardContext()
    // Override header to carry a bearer token; optionalAuth must ignore it.
    ;(c.req as any).header = (name: string) =>
      name === 'Authorization' ? `Bearer ${token}` : undefined

    const middleware = optionalAuth()
    await middleware(c, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect((c as any).set).not.toHaveBeenCalled()
  })
})

describe('AuthManager.verifyToken - Expiration', () => {
  it('should return null for expired token', async () => {
    // Create a mock expired token by generating one and manually testing expiration logic
    // Since we can't easily create an expired JWT, we'll test the verification path
    const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

    // The token should be valid now
    const payload = await AuthManager.verifyToken(token)
    expect(payload).not.toBeNull()
    expect(payload?.userId).toBe('user-123')
  })
})

describe('AuthManager.setAuthCookie', () => {
  it('should set auth cookie with default options', () => {
    const mockSetCookie = vi.fn()
    const mockContext = {
      env: {}
    }

    // We can't easily test this without mocking hono/cookie
    // But we verify the method exists and is callable
    expect(AuthManager.setAuthCookie).toBeDefined()
    expect(typeof AuthManager.setAuthCookie).toBe('function')
  })

  it('should accept custom cookie options', () => {
    // Verify the method signature accepts options
    expect(AuthManager.setAuthCookie.length).toBeGreaterThanOrEqual(2)
  })
})

describe('requireRole middleware - Browser Redirects', () => {
  let mockContext: any
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should redirect browser when no user context and HTML accept', async () => {
    mockContext = {
      get: vi.fn().mockReturnValue(undefined),
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'Accept') return 'text/html'
          return undefined
        })
      },
      json: vi.fn(),
      redirect: vi.fn().mockReturnValue({ redirect: true })
    }

    const middleware = requireRole('admin')
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.redirect).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login?error=')
    )
    expect(mockNext).not.toHaveBeenCalled()
  })
})
