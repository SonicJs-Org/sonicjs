import { describe, it, expect, vi, beforeEach } from 'vitest'
import { onPasswordResetRequested } from './on-password-reset-requested'
import {
  setEmailService,
  resetEmailService,
} from '../../../../services/email-service-singleton'
import type { EmailService, SendEmailResult, SonicHookContext } from '../../../sdk/types'

function makeCtx(opts: {
  user?: { id: string; email: string; first_name: string | null } | null
}): SonicHookContext {
  const userRow = opts.user === undefined ? { id: 'u-1', email: 'u@e.c', first_name: 'Marco' } : opts.user

  const db = {
    prepare: vi.fn((sql: string) => ({
      bind: vi.fn(() => ({
        first: vi.fn(async () => {
          if (/FROM users/i.test(sql)) return userRow
          return null
        }),
        all: vi.fn(async () => ({ results: [{ key: 'siteName', value: JSON.stringify('SonicJS') }] })),
      })),
      first: vi.fn(async () => null),
      all: vi.fn(async () => ({ results: [{ key: 'siteName', value: JSON.stringify('SonicJS') }] })),
    })),
  } as unknown as D1Database

  return {
    env: { DB: db, PUBLIC_URL: 'https://example.com' } as never,
    pluginId: 'email',
    plugins: { byId: new Map(), ordered: [] },
  } as unknown as SonicHookContext
}

function makeEmailService(result: Partial<SendEmailResult> = {}): EmailService {
  return {
    send: vi.fn(async () => ({
      status: 'submitted',
      logId: 'log-1',
      cloudflareMessageId: 'cf-1',
      ...result,
    } as SendEmailResult)),
  }
}

beforeEach(() => {
  resetEmailService()
})

describe('onPasswordResetRequested', () => {
  it('builds reset link from PUBLIC_URL + resetToken and sends', async () => {
    const email = makeEmailService()
    setEmailService(email)

    await onPasswordResetRequested(makeCtx({}), {
      type: 'auth:password-reset:requested',
      userId: 'u-1',
      email: 'u@e.c',
      resetToken: 'tok-abc123',
      expiresAt: 1700001000000,
      timestamp: 1700000000000,
    })

    const call = (email.send as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]
    expect(call).toMatchObject({
      to: 'u@e.c',
      purpose: 'password_reset',
      userId: 'u-1',
      templateName: 'auth.password-reset',
    })
    expect(call.html).toContain('https://example.com/auth/reset-password?token=tok-abc123')
  })

  it('logs warning when send returns failed_at_send', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const email = makeEmailService({ status: 'failed_at_send', errorCode: 'send_rejected', errorMessage: 'quota exceeded' })
    setEmailService(email)

    await onPasswordResetRequested(makeCtx({}), {
      type: 'auth:password-reset:requested',
      userId: 'u-1',
      email: 'u@e.c',
      resetToken: 'tok',
      expiresAt: 0,
      timestamp: 0,
    })

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('send failed'),
      expect.objectContaining({ purpose: 'password_reset', userId: 'u-1' }),
    )
  })

  it('bails when user row is missing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const email = makeEmailService()
    setEmailService(email)

    await onPasswordResetRequested(makeCtx({ user: null }), {
      type: 'auth:password-reset:requested',
      userId: 'u-x',
      email: 'x@e.c',
      resetToken: 'tok',
      expiresAt: 0,
      timestamp: 0,
    })

    expect(email.send).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('user not found'), expect.anything())
  })
})
