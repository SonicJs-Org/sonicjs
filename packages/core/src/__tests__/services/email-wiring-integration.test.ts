/**
 * Integration tests for EmailService wiring through the real app factory, and
 * the password-reset token-leak regression.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createSonicJSApp } from '../../app'
import {
  hasEmailService,
  getEmailService,
  resetEmailService,
} from '../../services/email/email-service-singleton'
import { resetHookSystem } from '../../plugins/hooks/hook-system-singleton'
import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../../services/email/types'

// Records every message it is asked to send.
function recordingProvider(): EmailProvider & { sent: NormalizedEmailMessage[] } {
  return {
    name: 'recording',
    sent: [] as NormalizedEmailMessage[],
    isConfigured: () => true,
    async send(message): Promise<SendResult> {
      ;(this as any).sent.push(message)
      return { ok: true, provider: 'recording', providerId: 'rec-1' }
    },
  }
}

// Permissive fake D1: returns `user` for any `FROM users` query, no-ops writes.
function fakeEnv(user: unknown): Record<string, unknown> {
  const stmt = (sql: string) => ({
    bind: (..._args: unknown[]) => ({
      first: async () => (/FROM users/i.test(sql) ? user : null),
      run: async () => ({ success: true }),
      all: async () => ({ results: [] }),
    }),
    first: async () => null,
    run: async () => ({ success: true }),
    all: async () => ({ results: [] }),
  })
  return {
    DB: { prepare: stmt, batch: async () => [], exec: async () => ({ count: 0 }) },
  }
}

beforeEach(() => {
  resetEmailService()
  resetHookSystem()
})

describe('EmailService wiring via createSonicJSApp', () => {
  it('initializes the configured provider on first request', async () => {
    const provider = recordingProvider()
    const app = createSonicJSApp({ email: { provider } })

    expect(hasEmailService()).toBe(false)
    await app.request('/health', {}, fakeEnv(null) as never)

    expect(hasEmailService()).toBe(true)
    expect(getEmailService().getProviderName()).toBe('recording')
  })
})

describe('password-reset no longer leaks the reset link (security regression)', () => {
  const user = { id: 'u1', email: 'user@example.com', first_name: 'Sam', last_name: 'Doe' }

  it('omits reset_link from the response and sends the email instead', async () => {
    const provider = recordingProvider()
    const app = createSonicJSApp({ email: { provider } })

    const res = await app.request(
      '/auth/request-password-reset',
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'email=user@example.com',
      },
      fakeEnv(user) as never
    )

    const body = (await res.json()) as Record<string, unknown>

    // The leak: a valid reset token must NOT appear in the API response.
    expect(body).not.toHaveProperty('reset_link')
    expect(JSON.stringify(body)).not.toContain('reset-password?token=')
    expect(body.success).toBe(true)

    // Instead, the link is delivered by email.
    expect(provider.sent).toHaveLength(1)
    const sent = provider.sent[0]!
    expect(sent.to).toEqual(['user@example.com'])
    expect(sent.flow).toBe('password-reset')
    expect(sent.html ?? '').toContain('/auth/reset-password?token=')
  })

  it('still returns the generic message (no enumeration) for an unknown email', async () => {
    const provider = recordingProvider()
    const app = createSonicJSApp({ email: { provider } })

    const res = await app.request(
      '/auth/request-password-reset',
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'email=nobody@example.com',
      },
      fakeEnv(null) as never
    )

    const body = (await res.json()) as Record<string, unknown>
    expect(body).not.toHaveProperty('reset_link')
    expect(body.success).toBe(true)
    expect(provider.sent).toHaveLength(0) // no user → no email
  })
})
