import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'

const verifyCodeMock = vi.fn()
const incrementAttemptsMock = vi.fn()

vi.mock('../../plugins/core-plugins/otp-login-plugin/otp-service', () => ({
  OTPService: class {
    verifyCode = (...args: any[]) => verifyCodeMock(...args)
    incrementAttempts = (...args: any[]) => incrementAttemptsMock(...args)
  },
}))

vi.mock('../../middleware', () => ({
  AuthManager: {
    generateToken: vi.fn().mockResolvedValue('jwt-token'),
  },
}))

vi.mock('../../middleware/auth', () => ({
  getJwtExpirySecondsFromDb: vi.fn().mockResolvedValue(3600),
}))

vi.mock('../../services/settings', () => ({
  SettingsService: vi.fn(),
}))

vi.mock('../../plugins/core-plugins/otp-login-plugin/email-templates', () => ({
  renderOTPEmail: vi.fn().mockReturnValue(''),
}))

const getCustomDataMock = vi.fn()
vi.mock('../../plugins/core-plugins/user-profiles', () => ({
  getCustomData: (...args: any[]) => getCustomDataMock(...args),
}))

import { createOTPLoginPlugin } from '../../plugins/core-plugins/otp-login-plugin'

const baseUserRow = {
  id: 'user-123',
  email: 'test@example.com',
  first_name: 'Test',
  last_name: 'User',
  role: 'viewer',
  is_active: 1,
  created_at: 1700000000,
}

const buildOtpApp = () => {
  const plugin = createOTPLoginPlugin()
  const route = plugin.routes!.find((r) => r.path === '/auth/otp')!
  const app = new Hono()
  app.route('/auth/otp', route.handler)
  return app
}

const createMockDb = (userRow: any) => {
  return {
    prepare: vi.fn().mockImplementation((sql: string) => ({
      first: vi.fn().mockResolvedValue(
        sql.includes('plugins') ? { settings: null } : null
      ),
      bind: vi.fn().mockReturnValue({
        first: vi.fn().mockResolvedValue(userRow),
        run: vi.fn().mockResolvedValue({ success: true }),
      }),
    })),
  }
}

describe('POST /auth/otp/verify custom field surfacing', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    verifyCodeMock.mockResolvedValue({ valid: true })
  })

  it('merges defineUserProfile fields into the verify response', async () => {
    getCustomDataMock.mockResolvedValue({ plan: 'lifetime', tier: 5 })

    const res = await buildOtpApp().request(
      '/auth/otp/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', code: '123456' }),
      },
      { DB: createMockDb(baseUserRow), JWT_SECRET: 'test' }
    )

    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.success).toBe(true)
    expect(body.user).toMatchObject({
      id: 'user-123',
      email: 'test@example.com',

      first_name: 'Test',
      last_name: 'User',
      role: 'viewer',
      created_at: 1700000000,
      plan: 'lifetime',
      tier: 5,
    })
    expect(body.user).not.toHaveProperty('is_active')
    expect(getCustomDataMock).toHaveBeenCalledWith(expect.anything(), 'user-123')
  })

  it('returns standard user fields when no custom data is registered', async () => {
    getCustomDataMock.mockResolvedValue({})

    const res = await buildOtpApp().request(
      '/auth/otp/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', code: '123456' }),
      },
      { DB: createMockDb(baseUserRow), JWT_SECRET: 'test' }
    )

    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.user).toMatchObject({
      id: 'user-123',
      email: 'test@example.com',

      first_name: 'Test',
      last_name: 'User',
      role: 'viewer',
      created_at: 1700000000,
    })
    expect(body.user).not.toHaveProperty('is_active')
  })
})
