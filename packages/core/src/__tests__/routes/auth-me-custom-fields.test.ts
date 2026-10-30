import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => {
    c.set('user', { userId: 'user-123', email: 'test@example.com', role: 'viewer' })
    await next()
  },
  AuthManager: {
    generateToken: vi.fn(),
    verifyToken: vi.fn(),
    hashPassword: vi.fn(),
  },
  generateCsrfToken: vi.fn().mockResolvedValue('csrf'),
  rateLimit: () => async (_c: any, next: any) => { await next() },
}))

vi.mock('../../middleware/auth', () => ({
  getJwtExpirySecondsFromDb: vi.fn().mockResolvedValue(3600),
  getJwtRefreshGraceSecondsFromDb: vi.fn().mockResolvedValue(86400),
}))

vi.mock('../../templates/pages/auth-login.template', () => ({
  renderLoginPage: () => '',
  LoginPageData: {},
}))

vi.mock('../../templates/pages/auth-register.template', () => ({
  renderRegisterPage: () => '',
  RegisterPageData: {},
}))

vi.mock('../../services', () => ({
  getCacheService: vi.fn().mockReturnValue(null),
  CACHE_CONFIGS: {},
}))

vi.mock('../../services/auth-validation', () => ({
  authValidationService: {},
  isRegistrationEnabled: vi.fn().mockResolvedValue(true),
  isFirstUserRegistration: vi.fn().mockResolvedValue(false),
}))

const getCustomDataMock = vi.fn()
vi.mock('../../plugins/core-plugins/user-profiles', () => ({
  getUserProfileConfig: vi.fn().mockReturnValue(null),
  getRegistrationFields: vi.fn().mockReturnValue([]),
  getProfileFieldDefaults: vi.fn().mockReturnValue({}),
  sanitizeCustomData: vi.fn().mockReturnValue({}),
  saveCustomData: vi.fn(),
  getCustomData: (...args: any[]) => getCustomDataMock(...args),
}))

import authRoutes from '../../routes/auth'

const baseUserRow = {
  id: 'user-123',
  email: 'test@example.com',
  first_name: 'Test',
  last_name: 'User',
  role: 'viewer',
  created_at: 1700000000,
}

const createMockDb = (userRow: any) => ({
  prepare: vi.fn().mockReturnValue({
    bind: vi.fn().mockReturnValue({
      first: vi.fn().mockResolvedValue(userRow),
    }),
  }),
})

describe('GET /auth/me custom field surfacing', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('merges custom defineUserProfile fields into the user response', async () => {
    getCustomDataMock.mockResolvedValue({ plan: 'lifetime', tier: 5 })

    const app = new Hono()
    app.route('/auth', authRoutes)

    const res = await app.request('/auth/me', {}, {
      DB: createMockDb(baseUserRow),
    })

    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.user).toMatchObject({
      ...baseUserRow,
      plan: 'lifetime',
      tier: 5,
    })
    expect(getCustomDataMock).toHaveBeenCalledWith(expect.anything(), 'user-123')
  })

  it('returns the standard fields when no custom data is registered', async () => {
    getCustomDataMock.mockResolvedValue({})

    const app = new Hono()
    app.route('/auth', authRoutes)

    const res = await app.request('/auth/me', {}, {
      DB: createMockDb(baseUserRow),
    })

    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.user).toEqual(baseUserRow)
  })

  it('returns 404 when the user is missing', async () => {
    getCustomDataMock.mockResolvedValue({})

    const app = new Hono()
    app.route('/auth', authRoutes)

    const res = await app.request('/auth/me', {}, {
      DB: createMockDb(null),
    })

    expect(res.status).toBe(404)
  })
})
