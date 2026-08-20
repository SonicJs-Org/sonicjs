import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'

// The seed-admin endpoint mints a fixed-credential admin. These tests pin the
// fail-closed environment gate that keeps it off real deployments: only explicit
// non-production ENVIRONMENT values may reach the handler; 'production' and an
// unset value are denied with 403.

vi.mock('../../middleware', () => ({
  requireAuth: () => async (_c: any, next: any) => { await next() },
  AuthManager: {
    hashPassword: vi.fn().mockResolvedValue('pbkdf2:100000:aa:bb'),
    generateToken: vi.fn(),
    verifyToken: vi.fn(),
  },
  generateCsrfToken: vi.fn().mockResolvedValue('csrf'),
  rateLimit: () => async (_c: any, next: any) => { await next() },
}))

vi.mock('../../middleware/auth', () => ({
  getJwtExpirySecondsFromDb: vi.fn().mockResolvedValue(3600),
  getJwtRefreshGraceSecondsFromDb: vi.fn().mockResolvedValue(86400),
}))

vi.mock('../../templates/pages/auth-login.template', () => ({ renderLoginPage: () => '', LoginPageData: {} }))
vi.mock('../../templates/pages/auth-register.template', () => ({ renderRegisterPage: () => '', RegisterPageData: {} }))
vi.mock('../../services', () => ({ getCacheService: vi.fn().mockReturnValue(null), CACHE_CONFIGS: {} }))
vi.mock('../../services/auth-validation', () => ({
  authValidationService: {},
  isRegistrationEnabled: vi.fn().mockResolvedValue(true),
  isFirstUserRegistration: vi.fn().mockResolvedValue(false),
}))
vi.mock('../../plugins/core-plugins/user-profiles', () => ({
  getUserProfileConfig: vi.fn().mockReturnValue(null),
  getRegistrationFields: vi.fn().mockReturnValue([]),
  getProfileFieldDefaults: vi.fn().mockReturnValue({}),
  sanitizeCustomData: vi.fn().mockReturnValue({}),
  saveCustomData: vi.fn(),
  getCustomData: vi.fn(),
}))
vi.mock('../../services/rbac', () => ({
  RbacService: class {
    ensureSystemRbacSeed = vi.fn().mockResolvedValue(undefined)
    addUserRoleByName = vi.fn().mockResolvedValue(undefined)
  },
}))
vi.mock('../../services/document-types-seed', () => ({
  bootstrapDocumentTypes: vi.fn().mockResolvedValue(undefined),
}))

import authRoutes from '../../routes/auth'

function makeDb() {
  const stmt = {
    bind: vi.fn().mockReturnThis(),
    first: vi.fn().mockResolvedValue(null),
    run: vi.fn().mockResolvedValue({}),
  }
  return { prepare: vi.fn().mockReturnValue(stmt), batch: vi.fn().mockResolvedValue([]) }
}

const app = new Hono()
app.route('/auth', authRoutes)

const post = (env: Record<string, unknown>) =>
  app.request('/auth/seed-admin', { method: 'POST' }, env as any)

describe('POST /auth/seed-admin environment gate @auth', () => {
  it('denies (403) when ENVIRONMENT is production', async () => {
    const res = await post({ DB: makeDb(), ENVIRONMENT: 'production' })
    expect(res.status).toBe(403)
  })

  it('denies (403) when ENVIRONMENT is unset', async () => {
    const res = await post({ DB: makeDb() })
    expect(res.status).toBe(403)
  })

  it('denies (403) for an unrecognized ENVIRONMENT value', async () => {
    const res = await post({ DB: makeDb(), ENVIRONMENT: 'staging' })
    expect(res.status).toBe(403)
  })

  it('is case-insensitive on the production denial', async () => {
    const res = await post({ DB: makeDb(), ENVIRONMENT: 'Production' })
    expect(res.status).toBe(403)
  })

  it('allows the seed to run in development (gate does not block)', async () => {
    const res = await post({ DB: makeDb(), ENVIRONMENT: 'development' })
    expect(res.status).not.toBe(403)
    const body = await res.json() as { message?: string }
    expect(body.message).toBe('Seed complete')
  })

  it.each(['test', 'e2e', 'preview', 'local'])('allows the seed to run in %s', async (env) => {
    const res = await post({ DB: makeDb(), ENVIRONMENT: env })
    expect(res.status).not.toBe(403)
  })
})
