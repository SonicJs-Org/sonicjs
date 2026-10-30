import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { adminRoutes } from './admin'
import { setEmailService, resetEmailService } from '../../../../services/email/email-service-singleton'
import type { Bindings, Variables } from '../../../../app'
import type { EmailService, SendEmailResult } from '../../../sdk/types'
import type { PermissionsManager } from '../../../../services/permissions'

// Mock requireAuth so unit tests don't need real JWT cookies or a full DB.
// The makeApp helper below controls which user (if any) is injected and what
// roles their PermissionsManager carries — gating decisions read from
// permissions, not from JWT.role (removed in 1c-finalize).
let mockAuthUser: Variables['user'] | undefined
let mockAuthRoles: string[] = []

vi.mock('../../../../middleware', () => ({
  requireAuth: () => async (c: { set: (k: string, v: unknown) => void }, next: () => Promise<void>) => {
    if (mockAuthUser) {
      c.set('user', mockAuthUser)
      const roles = mockAuthRoles
      c.set('permissions', {
        hasRole: (...rs: string[]) => rs.some(r => roles.includes(r)),
        getRoles: () => roles,
        can: async () => roles.includes('admin'),
        require: async () => {},
        load: async () => {},
      } as unknown as PermissionsManager)
    }
    await next()
  },
}))

function makeDb(): D1Database {
  return {
    prepare: vi.fn(() => ({
      bind: vi.fn(() => ({
        run: vi.fn(async () => ({})),
        first: vi.fn(async () => null),
        all: vi.fn(async () => ({ results: [] })),
      })),
      first: vi.fn(async () => null),
      all: vi.fn(async () => ({ results: [] })),
      run: vi.fn(async () => ({})),
    })),
  } as unknown as D1Database
}

const adminUser: NonNullable<Variables['user']> = {
  userId: 'u-admin',
  email: 'admin@example.com',
  exp: 9999999999,
  iat: 0,
}

function makeApp(
  user: Variables['user'],
  roles: string[] = ['admin'],
): Hono<{ Bindings: Bindings; Variables: Variables }> {
  mockAuthUser = user
  mockAuthRoles = user ? roles : []
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()
  app.route('/', adminRoutes)
  return app
}

function makeEmailService(overrides: Partial<SendEmailResult> = {}): EmailService {
  return {
    send: vi.fn(async () => ({
      status: 'submitted',
      logId: 'log-1',
      cloudflareMessageId: 'cf-1',
      ...overrides,
    } as SendEmailResult)),
  }
}

const mockEnv = { DB: makeDb(), PUBLIC_URL: 'https://example.com' }

beforeEach(() => {
  resetEmailService()
  mockAuthUser = undefined
})

describe('POST /settings', () => {
  it('returns 403 when no authenticated user', async () => {
    const app = makeApp(undefined)
    const res = await app.fetch(
      new Request('http://localhost/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
      mockEnv,
    )
    expect(res.status).toBe(403)
    const json = await res.json() as { error: string }
    expect(json.error).toMatch(/admin role required/i)
  })

  it('returns 403 when user is not admin', async () => {
    const app = makeApp(adminUser, ['editor'])
    const res = await app.fetch(
      new Request('http://localhost/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
      mockEnv,
    )
    expect(res.status).toBe(403)
  })

  it('returns 400 on invalid JSON body', async () => {
    const app = makeApp(adminUser)
    const res = await app.fetch(
      new Request('http://localhost/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not-json{{',
      }),
      mockEnv,
    )
    expect(res.status).toBe(400)
    const json = await res.json() as { error: string }
    expect(json.error).toMatch(/invalid JSON/i)
  })

  it('returns 200 and stores cleaned settings', async () => {
    const app = makeApp(adminUser)
    const res = await app.fetch(
      new Request('http://localhost/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fromEmail: '  noreply@example.com  ',
          fromName: 'Test Site',
          replyTo: 'reply@example.com',
          logoUrl: 'https://example.com/logo.png',
        }),
      }),
      mockEnv,
    )
    expect(res.status).toBe(200)
    const json = await res.json() as { success: boolean; settings: Record<string, string> }
    expect(json.success).toBe(true)
    expect(json.settings.fromEmail).toBe('noreply@example.com') // whitespace trimmed
    expect(json.settings.fromName).toBe('Test Site')
  })
})

describe('POST /test', () => {
  it('returns 403 when no authenticated user', async () => {
    const app = makeApp(undefined)
    const res = await app.fetch(
      new Request('http://localhost/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
      mockEnv,
    )
    expect(res.status).toBe(403)
  })

  it('returns 400 when no recipient can be determined', async () => {
    const email = makeEmailService()
    setEmailService(email)
    // user.email is empty string + no body.to — neither source provides a recipient
    const app = makeApp({ ...adminUser, email: '' })
    const res = await app.fetch(
      new Request('http://localhost/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
      mockEnv,
    )
    expect(res.status).toBe(400)
    const json = await res.json() as { error: string }
    expect(json.error).toMatch(/no recipient/i)
    expect(email.send).not.toHaveBeenCalled()
  })

  it('returns 200 on successful send using body.to', async () => {
    const email = makeEmailService()
    setEmailService(email)
    const app = makeApp(adminUser)
    const res = await app.fetch(
      new Request('http://localhost/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: 'smoke@example.com' }),
      }),
      mockEnv,
    )
    expect(res.status).toBe(200)
    const json = await res.json() as { success: boolean }
    expect(json.success).toBe(true)
    expect(email.send).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'smoke@example.com', purpose: 'test' }),
    )
  })

  it('falls back to user.email when no body.to provided', async () => {
    const email = makeEmailService()
    setEmailService(email)
    const app = makeApp(adminUser)
    const res = await app.fetch(
      new Request('http://localhost/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
      mockEnv,
    )
    expect(res.status).toBe(200)
    expect(email.send).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'admin@example.com' }),
    )
  })

  it('returns 400 when EmailService throws (e.g. missing fromEmail)', async () => {
    const email: EmailService = {
      send: vi.fn(async () => {
        throw new Error('fromEmail is required')
      }),
    }
    setEmailService(email)
    const app = makeApp(adminUser)
    const res = await app.fetch(
      new Request('http://localhost/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: 'test@example.com' }),
      }),
      mockEnv,
    )
    expect(res.status).toBe(400)
    const json = await res.json() as { error: string }
    expect(json.error).toMatch(/fromEmail is required/i)
  })
})
