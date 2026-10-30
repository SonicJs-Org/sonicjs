import { describe, it, expect, vi, beforeEach } from 'vitest'
import { onPasswordResetCompleted } from './on-password-reset-completed'
import {
  setEmailService,
  resetEmailService,
} from '../../../../services/email/email-service-singleton'
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
        all: vi.fn(async () => ({
          results: [
            { key: 'siteName', value: JSON.stringify('SonicJS') },
            { key: 'adminEmail', value: JSON.stringify('admin@example.com') },
          ],
        })),
      })),
      first: vi.fn(async () => null),
      all: vi.fn(async () => ({ results: [] })),
    })),
  } as unknown as D1Database

  return {
    env: { DB: db, PUBLIC_URL: 'https://example.com' } as never,
    pluginId: 'email',
    plugins: { byId: new Map(), ordered: [] },
  } as unknown as SonicHookContext
}

function makeEmailService(): EmailService {
  return {
    send: vi.fn(async () => ({
      status: 'submitted',
      logId: 'log-1',
      cloudflareMessageId: 'cf-1',
    } as SendEmailResult)),
  }
}

beforeEach(() => {
  resetEmailService()
})

describe('onPasswordResetCompleted', () => {
  it('renders password-changed email and sends with timestamp', async () => {
    const email = makeEmailService()
    setEmailService(email)

    await onPasswordResetCompleted(makeCtx({}), {
      type: 'auth:password-reset:completed',
      userId: 'u-1',
      email: 'u@e.c',
      timestamp: 1700000000000,
    })

    const call = (email.send as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]
    expect(call).toMatchObject({
      to: 'u@e.c',
      purpose: 'password_changed',
      userId: 'u-1',
      templateName: 'auth.password-changed',
    })
    expect(call.html).toContain('2023-11-14') // Date.UTC(2023, 10, 14, ...) ≈ 1700000000000
    expect(call.subject).toMatch(/password was changed/i)
  })

  it('logs warning when send returns failed_at_send', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const email = makeEmailService()
    ;(email.send as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: 'failed_at_send',
      logId: 'log-fail',
      errorCode: 'send_rejected',
      errorMessage: 'mailbox full',
    })
    setEmailService(email)

    await onPasswordResetCompleted(makeCtx({}), {
      type: 'auth:password-reset:completed',
      userId: 'u-1',
      email: 'u@e.c',
      timestamp: 0,
    })

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('send failed'),
      expect.objectContaining({ purpose: 'password_changed', userId: 'u-1' }),
    )
  })

  it('bails when user row is missing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const email = makeEmailService()
    setEmailService(email)

    await onPasswordResetCompleted(makeCtx({ user: null }), {
      type: 'auth:password-reset:completed',
      userId: 'u-x',
      email: 'x@e.c',
      timestamp: 0,
    })

    expect(email.send).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('user not found'), expect.anything())
  })
})
