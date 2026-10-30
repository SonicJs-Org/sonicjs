import { describe, it, expect, vi, beforeEach } from 'vitest'
import { onRegistrationCompleted } from './on-registration-completed'
import {
  setEmailService,
  resetEmailService,
} from '../../../../services/email/email-service-singleton'
import type { EmailService, SendEmailResult } from '../../../sdk/types'
import type { SonicHookContext } from '../../../sdk/types'

function makeCtx(opts: {
  user?: { id: string; email: string; first_name: string | null } | null
  settingsRows?: { key: string; value: string }[]
  /** PR-EV: drives the `general.verificationRequired` short-circuit. */
  verificationRequired?: 'true' | 'false'
  /** PR-EV: simulate the verificationRequired SELECT throwing (pre-migration DB). */
  verificationRequiredThrows?: boolean
}): SonicHookContext {
  const userRow = opts.user === undefined ? { id: 'u-1', email: 'u@e.c', first_name: 'Marco' } : opts.user
  const settingsRows = opts.settingsRows ?? [{ key: 'siteName', value: JSON.stringify('SonicJS') }]

  const db = {
    prepare: vi.fn((sql: string) => ({
      bind: vi.fn(() => ({
        first: vi.fn(async () => {
          if (/FROM users/i.test(sql)) return userRow
          return null
        }),
        all: vi.fn(async () => ({ results: settingsRows })),
      })),
      first: vi.fn(async () => {
        if (/general.*verificationRequired/.test(sql)) {
          if (opts.verificationRequiredThrows) throw new Error('no settings table')
          return opts.verificationRequired
            ? { value: opts.verificationRequired }
            : null
        }
        return null
      }),
      all: vi.fn(async () => ({ results: settingsRows })),
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

describe('onRegistrationCompleted', () => {
  it('looks up the user, renders welcome email, calls getEmailService().send', async () => {
    const email = makeEmailService()
    setEmailService(email)
    const ctx = makeCtx({})

    await onRegistrationCompleted(ctx, {
      type: 'auth:registration:completed',
      userId: 'u-1',
      email: 'u@e.c',
      registrationSource: 'api',
      timestamp: 1700000000000,
    })

    expect(email.send).toHaveBeenCalledOnce()
    const call = (email.send as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]
    expect(call).toMatchObject({
      to: 'u@e.c',
      purpose: 'welcome',
      userId: 'u-1',
      templateName: 'auth.welcome',
    })
    expect(call.subject).toMatch(/Welcome to/i)
    expect(call.html).toContain('Hi Marco')
  })

  it('bails with structured warn when user row is missing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const email = makeEmailService()
    setEmailService(email)
    const ctx = makeCtx({ user: null })

    await onRegistrationCompleted(ctx, {
      type: 'auth:registration:completed',
      userId: 'u-missing',
      email: 'x@e.c',
      registrationSource: 'api',
      timestamp: 0,
    })

    expect(email.send).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('user not found'),
      expect.objectContaining({ userId: 'u-missing' }),
    )
  })

  it('logs a structured warn when send fails', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const email = makeEmailService({
      status: 'failed_at_send',
      errorCode: 'CF_DOWN',
      errorMessage: 'transport down',
    })
    setEmailService(email)

    await onRegistrationCompleted(makeCtx({}), {
      type: 'auth:registration:completed',
      userId: 'u-1',
      email: 'u@e.c',
      registrationSource: 'api',
      timestamp: 0,
    })

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('send failed'),
      expect.objectContaining({ errorCode: 'CF_DOWN', errorMessage: 'transport down' }),
    )
  })

  // PR-EV STEP 5.7
  it('short-circuits without sending when general.verificationRequired = "true"', async () => {
    const email = makeEmailService()
    setEmailService(email)

    await onRegistrationCompleted(
      makeCtx({ verificationRequired: 'true' }),
      {
        type: 'auth:registration:completed',
        userId: 'u-1',
        email: 'u@e.c',
        registrationSource: 'api',
        timestamp: 0,
      },
    )

    expect(email.send).not.toHaveBeenCalled()
  })

  it('sends welcome as before when general.verificationRequired = "false"', async () => {
    const email = makeEmailService()
    setEmailService(email)

    await onRegistrationCompleted(
      makeCtx({ verificationRequired: 'false' }),
      {
        type: 'auth:registration:completed',
        userId: 'u-1',
        email: 'u@e.c',
        registrationSource: 'api',
        timestamp: 0,
      },
    )

    expect(email.send).toHaveBeenCalledTimes(1)
  })

  it('fail-open: settings table missing → falls through and sends welcome (legacy behavior)', async () => {
    const email = makeEmailService()
    setEmailService(email)

    await onRegistrationCompleted(
      makeCtx({ verificationRequiredThrows: true }),
      {
        type: 'auth:registration:completed',
        userId: 'u-1',
        email: 'u@e.c',
        registrationSource: 'api',
        timestamp: 0,
      },
    )

    expect(email.send).toHaveBeenCalledTimes(1)
  })
})
