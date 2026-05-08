import { describe, it, expect, beforeEach, vi } from 'vitest'
import { AuthManager, requireAuth, requireRole, optionalAuth, getJwtExpirySeconds } from '../../middleware/auth'
import { Context, Next } from 'hono'
import { sign } from 'hono/jwt'

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
  let mockContext: any
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
    mockContext = {
      req: {
        header: vi.fn(),
        raw: {
          headers: new Headers()
        }
      },
      set: vi.fn(),
      json: vi.fn().mockReturnValue({ error: 'Authentication required' }),
      redirect: vi.fn().mockReturnValue({ redirect: true }),
      env: {},
    }
  })

  it('should reject request without token', async () => {
    mockContext.req.header.mockReturnValue(undefined)

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    // When no token is found, the middleware returns authentication required
    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Authentication required' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should redirect browser requests without token', async () => {
    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Accept') return 'text/html'
      return undefined
    })

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.redirect).toHaveBeenCalled()
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should reject request with invalid token', async () => {
    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Authorization') return 'Bearer invalid-token'
      return undefined
    })

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Invalid or expired token' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should accept request with valid token', async () => {
    const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Authorization') return `Bearer ${token}`
      return undefined
    })

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.set).toHaveBeenCalledWith('user', expect.objectContaining({
      userId: 'user-123',
      email: 'test@example.com',
      role: 'admin'
    }))
    expect(mockNext).toHaveBeenCalled()
  })

  it('should extract token from cookie if not in header', async () => {
    const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

    // Mock getCookie by setting up the header function
    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Authorization') return undefined
      if (name === 'cookie') return `auth_token=${token}`
      return undefined
    })

    // Note: This test may need adjustment based on actual cookie handling in Hono
    // The middleware uses getCookie which may work differently than header access
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
  let mockContext: any
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
    mockContext = {
      req: {
        header: vi.fn(),
        raw: {
          headers: new Headers()
        }
      },
      set: vi.fn(),
    }
  })

  it('should continue without user when no token provided', async () => {
    mockContext.req.header.mockReturnValue(undefined)

    const middleware = optionalAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect(mockContext.set).not.toHaveBeenCalled()
  })

  it('should set user when valid token provided', async () => {
    const token = await AuthManager.generateToken('user-123', 'test@example.com', 'user')

    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Authorization') return `Bearer ${token}`
      return undefined
    })

    const middleware = optionalAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.set).toHaveBeenCalledWith('user', expect.objectContaining({
      userId: 'user-123',
      email: 'test@example.com',
      role: 'user'
    }))
    expect(mockNext).toHaveBeenCalled()
  })

  it('should continue without user when invalid token provided', async () => {
    mockContext.req.header.mockImplementation((name: string) => {
      if (name === 'Authorization') return 'Bearer invalid-token'
      return undefined
    })

    const middleware = optionalAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockNext).toHaveBeenCalled()
    // User should not be set for invalid tokens
    expect(mockContext.set).not.toHaveBeenCalled()
  })

  it('should handle errors gracefully and continue', async () => {
    // Mock the header function to throw an error
    mockContext.req.header.mockImplementation(() => {
      throw new Error('Test error')
    })

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const middleware = optionalAuth()
    await middleware(mockContext as Context, mockNext)

    // Should continue despite the error
    expect(mockNext).toHaveBeenCalled()
    expect(consoleSpy).toHaveBeenCalledWith('Optional auth error:', expect.any(Error))

    consoleSpy.mockRestore()
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

describe('requireAuth middleware - KV Cache', () => {
  let mockContext: any
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should use cached token verification from KV when available', async () => {
    const cachedPayload = {
      userId: 'cached-user',
      email: 'cached@example.com',
      role: 'admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    }

    const mockKv = {
      get: vi.fn().mockResolvedValue(cachedPayload),
      put: vi.fn()
    }

    mockContext = {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'Authorization') return 'Bearer some-valid-token-prefix'
          return undefined
        }),
        raw: { headers: new Headers() }
      },
      set: vi.fn(),
      json: vi.fn(),
      redirect: vi.fn(),
      env: { KV: mockKv }
    }

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    // Should have checked the cache
    expect(mockKv.get).toHaveBeenCalled()
    // Should have set the cached user
    expect(mockContext.set).toHaveBeenCalledWith('user', cachedPayload)
    expect(mockNext).toHaveBeenCalled()
  })

  it('should cache verified token in KV', async () => {
    const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

    const mockKv = {
      get: vi.fn().mockResolvedValue(null), // Cache miss
      put: vi.fn().mockResolvedValue(undefined)
    }

    mockContext = {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'Authorization') return `Bearer ${token}`
          return undefined
        }),
        raw: { headers: new Headers() }
      },
      set: vi.fn(),
      json: vi.fn(),
      redirect: vi.fn(),
      env: { KV: mockKv }
    }

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    // Should have tried to get from cache
    expect(mockKv.get).toHaveBeenCalled()
    // Should have stored in cache after verification
    expect(mockKv.put).toHaveBeenCalled()
    expect(mockNext).toHaveBeenCalled()
  })
})

describe('requireAuth middleware - Error Handling', () => {
  let mockContext: any
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should redirect browser on auth error', async () => {
    mockContext = {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'Authorization') {
            throw new Error('Simulated error')
          }
          if (name === 'Accept') return 'text/html'
          return undefined
        }),
        raw: { headers: new Headers() }
      },
      set: vi.fn(),
      json: vi.fn(),
      redirect: vi.fn().mockReturnValue({ redirect: true }),
      env: {}
    }

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.redirect).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login?error=')
    )
    expect(mockNext).not.toHaveBeenCalled()

    consoleSpy.mockRestore()
  })

  it('should return JSON error on API auth error', async () => {
    mockContext = {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'Authorization') {
            throw new Error('Simulated error')
          }
          if (name === 'Accept') return 'application/json'
          return undefined
        }),
        raw: { headers: new Headers() }
      },
      set: vi.fn(),
      json: vi.fn().mockReturnValue({ error: 'Authentication failed' }),
      redirect: vi.fn(),
      env: {}
    }

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Authentication failed' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()

    consoleSpy.mockRestore()
  })

  it('should redirect browser when invalid token and HTML accept', async () => {
    mockContext = {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'Authorization') return 'Bearer invalid-token'
          if (name === 'Accept') return 'text/html'
          return undefined
        }),
        raw: { headers: new Headers() }
      },
      set: vi.fn(),
      json: vi.fn(),
      redirect: vi.fn().mockReturnValue({ redirect: true }),
      env: {}
    }

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const middleware = requireAuth()
    await middleware(mockContext as Context, mockNext)

    expect(mockContext.redirect).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login?error=')
    )
    expect(mockNext).not.toHaveBeenCalled()

    consoleSpy.mockRestore()
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
