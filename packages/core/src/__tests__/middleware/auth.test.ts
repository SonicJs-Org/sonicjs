import { describe, it, expect, beforeEach, vi } from 'vitest'
import { AuthManager, requireAuth, requireRole, optionalAuth } from '../../middleware/auth'
import type { Context, Next } from 'hono'

describe('AuthManager', () => {
  describe('generateToken', () => {
    it('should throw (deprecated; use Better Auth)', async () => {
      await expect(
        AuthManager.generateToken('user-123', 'test@example.com', 'admin')
      ).rejects.toThrow('JWT generation is deprecated')
    })
  })

  describe('verifyToken', () => {
    it('should return null (session is verified by Better Auth)', async () => {
      const payload = await AuthManager.verifyToken('any-token')
      expect(payload).toBeNull()
    })
  })

  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      expect(hash).toBeTruthy()
      expect(typeof hash).toBe('string')
      expect(hash).not.toBe(password)
      expect(hash.length).toBe(64)
    })

    it('should generate same hash for same password', async () => {
      const password = 'test-password-123'
      const hash1 = await AuthManager.hashPassword(password)
      const hash2 = await AuthManager.hashPassword(password)

      expect(hash1).toBe(hash2)
    })

    it('should generate different hashes for different passwords', async () => {
      const hash1 = await AuthManager.hashPassword('password1')
      const hash2 = await AuthManager.hashPassword('password2')

      expect(hash1).not.toBe(hash2)
    })
  })

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      const isValid = await AuthManager.verifyPassword(password, hash)
      expect(isValid).toBe(true)
    })

    it('should reject incorrect password', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      const isValid = await AuthManager.verifyPassword('wrong-password', hash)
      expect(isValid).toBe(false)
    })

    it('should reject empty password', async () => {
      const password = 'test-password-123'
      const hash = await AuthManager.hashPassword(password)

      const isValid = await AuthManager.verifyPassword('', hash)
      expect(isValid).toBe(false)
    })
  })

  describe('setAuthCookie', () => {
    it('should be defined and callable', () => {
      expect(AuthManager.setAuthCookie).toBeDefined()
      expect(typeof AuthManager.setAuthCookie).toBe('function')
    })
  })
})

describe('requireAuth middleware', () => {
  let mockContext: Context
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
    mockContext = {
      get: vi.fn(),
      set: vi.fn(),
      json: vi.fn().mockReturnValue({ error: 'Authentication required' }),
      redirect: vi.fn().mockReturnValue({ redirect: true }),
      req: { header: vi.fn() },
      env: {}
    } as unknown as Context
  })

  it('should reject request when user not set (no session)', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockReturnValue(undefined)
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockReturnValue(undefined)

    const middleware = requireAuth()
    await middleware(mockContext, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Authentication required' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should redirect browser requests when user not set', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockReturnValue(undefined)
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockImplementation((name: string) =>
      name === 'Accept' ? 'text/html' : undefined
    )

    const middleware = requireAuth()
    await middleware(mockContext, mockNext)

    expect(mockContext.redirect).toHaveBeenCalled()
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should accept request when user is set by session middleware', async () => {
    const user = { userId: 'user-123', email: 'test@example.com', role: 'admin', exp: 0, iat: 0 }
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockImplementation((key: string) =>
      key === 'user' ? user : undefined
    )

    const middleware = requireAuth()
    await middleware(mockContext, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })
})

describe('requireRole middleware', () => {
  let mockContext: Context
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
    mockContext = {
      get: vi.fn(),
      req: { header: vi.fn() },
      json: vi.fn().mockReturnValue({ error: 'Insufficient permissions' }),
      redirect: vi.fn().mockReturnValue({ redirect: true })
    } as unknown as Context
  })

  it('should reject request without user context', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockReturnValue(undefined)
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockReturnValue(undefined)

    const middleware = requireRole('admin')
    await middleware(mockContext, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Authentication required' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should reject user with wrong role', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockImplementation((key: string) =>
      key === 'user'
        ? { userId: 'user-123', email: 'test@example.com', role: 'user' }
        : undefined
    )
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockReturnValue(undefined)

    const middleware = requireRole('admin')
    await middleware(mockContext, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Insufficient permissions' },
      403
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should accept user with correct role', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockImplementation((key: string) =>
      key === 'user'
        ? { userId: 'user-123', email: 'test@example.com', role: 'admin' }
        : undefined
    )

    const middleware = requireRole('admin')
    await middleware(mockContext, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })

  it('should accept user with any of multiple allowed roles', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockImplementation((key: string) =>
      key === 'user'
        ? { userId: 'user-123', email: 'test@example.com', role: 'editor' }
        : undefined
    )

    const middleware = requireRole(['admin', 'editor'])
    await middleware(mockContext, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })

  it('should redirect browser requests with insufficient permissions', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockImplementation((key: string) =>
      key === 'user'
        ? { userId: 'user-123', email: 'test@example.com', role: 'user' }
        : undefined
    )
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockImplementation((name: string) =>
      name === 'Accept' ? 'text/html' : undefined
    )

    const middleware = requireRole('admin')
    await middleware(mockContext, mockNext)

    expect(mockContext.redirect).toHaveBeenCalled()
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should redirect browser when no user context and HTML accept', async () => {
    ;(mockContext.get as ReturnType<typeof vi.fn>).mockReturnValue(undefined)
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockImplementation((name: string) =>
      name === 'Accept' ? 'text/html' : undefined
    )

    const middleware = requireRole('admin')
    await middleware(mockContext, mockNext)

    expect(mockContext.redirect).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login?error=')
    )
    expect(mockNext).not.toHaveBeenCalled()
  })
})

describe('optionalAuth middleware', () => {
  let mockContext: Context
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
    mockContext = {
      req: { header: vi.fn(), raw: { headers: new Headers() } },
      set: vi.fn()
    } as unknown as Context
  })

  it('should always call next (user is set by global session middleware)', async () => {
    ;(mockContext.req.header as ReturnType<typeof vi.fn>).mockReturnValue(undefined)

    const middleware = optionalAuth()
    await middleware(mockContext, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })

  it('should continue when no user in context', async () => {
    const middleware = optionalAuth()
    await middleware(mockContext, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })
})

describe('requireAuth middleware - Error Handling', () => {
  let mockContext: Context
  let mockNext: Next

  beforeEach(() => {
    mockNext = vi.fn()
  })

  it('should redirect browser on missing user when Accept is text/html', async () => {
    mockContext = {
      get: vi.fn().mockReturnValue(undefined),
      req: {
        header: vi.fn().mockImplementation((name: string) =>
          name === 'Accept' ? 'text/html' : undefined
        )
      },
      set: vi.fn(),
      json: vi.fn(),
      redirect: vi.fn().mockReturnValue({ redirect: true }),
      env: {}
    } as unknown as Context

    const middleware = requireAuth()
    await middleware(mockContext, mockNext)

    expect(mockContext.redirect).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login?error=')
    )
    expect(mockNext).not.toHaveBeenCalled()
  })

  it('should return JSON error when no user and Accept is application/json', async () => {
    mockContext = {
      get: vi.fn().mockReturnValue(undefined),
      req: {
        header: vi.fn().mockImplementation((name: string) =>
          name === 'Accept' ? 'application/json' : undefined
        )
      },
      set: vi.fn(),
      json: vi.fn().mockReturnValue({ error: 'Authentication required' }),
      redirect: vi.fn(),
      env: {}
    } as unknown as Context

    const middleware = requireAuth()
    await middleware(mockContext, mockNext)

    expect(mockContext.json).toHaveBeenCalledWith(
      { error: 'Authentication required' },
      401
    )
    expect(mockNext).not.toHaveBeenCalled()
  })
})
