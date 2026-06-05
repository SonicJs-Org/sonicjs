import { describe, it, expect, vi, afterEach } from 'vitest'
import { EmailService, type EmailLogDb } from '../../services/email/email-service'
import { ResendProvider } from '../../services/email/providers/resend'
import { SendGridProvider } from '../../services/email/providers/sendgrid'
import { ConsoleProvider } from '../../services/email/providers/console'
import { resolveEmailProvider } from '../../services/email/resolve-provider'
import {
  getEmailService,
  setEmailService,
  hasEmailService,
  resetEmailService,
} from '../../services/email/email-service-singleton'
import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../../services/email/types'

afterEach(() => {
  vi.restoreAllMocks()
  resetEmailService()
})

// ── Fake email_log db ────────────────────────────────────────────────────────
function fakeDb(): { db: EmailLogDb; rows: Record<string, unknown>[] } {
  const rows: Record<string, unknown>[] = []
  const columns = [
    'id', 'to_email', 'from_email', 'subject', 'status', 'provider', 'provider_id',
    'error', 'flow', 'metadata', 'failed_at_send', 'delivery_state', 'delivery_synced_at', 'created_at',
  ]
  const db: EmailLogDb = {
    prepare() {
      return {
        bind(...values: unknown[]) {
          return {
            async run() {
              rows.push(Object.fromEntries(columns.map((c, i) => [c, values[i]])))
            },
          }
        },
      }
    },
  }
  return { db, rows }
}

// A provider that records what it received.
function recordingProvider(result: Partial<SendResult> = {}): EmailProvider & { last?: NormalizedEmailMessage } {
  return {
    name: 'recording',
    last: undefined as NormalizedEmailMessage | undefined,
    isConfigured: () => true,
    async send(message) {
      ;(this as any).last = message
      return { ok: true, provider: 'recording', providerId: 'rec-1', ...result }
    },
  }
}

describe('EmailService', () => {
  it('normalizes recipients and fills the default from-address', async () => {
    const provider = recordingProvider()
    const svc = new EmailService({ provider, defaultFrom: 'noreply@site.com' })

    await svc.send({ to: 'a@b.com', subject: 'Hi', text: 'yo' })

    expect(provider.last?.to).toEqual(['a@b.com'])
    expect(provider.last?.from).toBe('noreply@site.com')
  })

  it('lets a message override the from-address and accepts arrays', async () => {
    const provider = recordingProvider()
    const svc = new EmailService({ provider, defaultFrom: 'noreply@site.com' })

    await svc.send({ to: ['a@b.com', 'c@d.com'], from: 'custom@site.com', subject: 'Hi' })

    expect(provider.last?.to).toEqual(['a@b.com', 'c@d.com'])
    expect(provider.last?.from).toBe('custom@site.com')
  })

  it('applies defaultReplyTo when a message omits replyTo (and a message overrides it)', async () => {
    const provider = recordingProvider()
    const svc = new EmailService({ provider, defaultFrom: 'noreply@site.com', defaultReplyTo: 'support@site.com' })

    await svc.send({ to: 'a@b.com', subject: 'Hi' })
    expect(provider.last?.replyTo).toBe('support@site.com')

    await svc.send({ to: 'a@b.com', subject: 'Hi', replyTo: 'override@site.com' })
    expect(provider.last?.replyTo).toBe('override@site.com')
  })

  it('writes a sent row to email_log on success', async () => {
    const { db, rows } = fakeDb()
    const svc = new EmailService({
      provider: recordingProvider(),
      defaultFrom: 'noreply@site.com',
      db,
      now: () => 1717200000000,
      idFactory: () => 'log-1',
    })

    const result = await svc.send({ to: 'a@b.com', subject: 'Hi', flow: 'welcome' })

    expect(result.ok).toBe(true)
    expect(result.logId).toBe('log-1')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      id: 'log-1',
      to_email: 'a@b.com',
      from_email: 'noreply@site.com',
      status: 'sent',
      provider: 'recording',
      provider_id: 'rec-1',
      flow: 'welcome',
      failed_at_send: null,
      created_at: 1717200000000,
    })
  })

  it('writes a failed row with failed_at_send when the provider fails', async () => {
    const { db, rows } = fakeDb()
    const provider: EmailProvider = {
      name: 'flaky',
      isConfigured: () => true,
      async send() {
        return { ok: false, provider: 'flaky', error: 'boom' }
      },
    }
    const svc = new EmailService({ provider, defaultFrom: 'x@y.com', db, now: () => 999 })

    const result = await svc.send({ to: 'a@b.com', subject: 'Hi' })

    expect(result.ok).toBe(false)
    expect(rows[0]).toMatchObject({ status: 'failed', error: 'boom', failed_at_send: 999 })
  })

  it('surfaces a throwing provider as a structured failure (does not throw)', async () => {
    const provider: EmailProvider = {
      name: 'thrower',
      isConfigured: () => true,
      async send() {
        throw new Error('network down')
      },
    }
    const svc = new EmailService({ provider, defaultFrom: 'x@y.com' })
    const result = await svc.send({ to: 'a@b.com', subject: 'Hi' })
    expect(result).toMatchObject({ ok: false, provider: 'thrower', error: 'network down' })
  })

  it('does not fail the send when logging throws', async () => {
    const brokenDb: EmailLogDb = {
      prepare() {
        return { bind: () => ({ run: async () => { throw new Error('db gone') } }) }
      },
    }
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const svc = new EmailService({ provider: recordingProvider(), defaultFrom: 'x@y.com', db: brokenDb })
    const result = await svc.send({ to: 'a@b.com', subject: 'Hi' })
    expect(result.ok).toBe(true)
    expect(result.logId).toBeUndefined()
  })

  it('skips logging entirely when no db is supplied', async () => {
    const svc = new EmailService({ provider: recordingProvider(), defaultFrom: 'x@y.com' })
    const result = await svc.send({ to: 'a@b.com', subject: 'Hi' })
    expect(result.logId).toBeUndefined()
  })
})

describe('providers', () => {
  it('Resend reports unconfigured without an API key and configured with one', () => {
    expect(new ResendProvider().isConfigured()).toBe(false)
    expect(new ResendProvider({ apiKey: 'k' }).isConfigured()).toBe(true)
  })

  it('Resend posts to the API and returns the provider id', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ id: 'resend-123' }), { status: 200 })
    ) as unknown as typeof fetch
    const provider = new ResendProvider({ apiKey: 'k', fetchImpl })

    const result = await provider.send({ to: ['a@b.com'], from: 'x@y.com', subject: 'S', html: '<b>h</b>' })

    expect(result).toMatchObject({ ok: true, provider: 'resend', providerId: 'resend-123' })
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({ method: 'POST' })
    )
  })

  it('Resend returns ok:false on a non-2xx response', async () => {
    const fetchImpl = vi.fn(async () => new Response('bad request', { status: 422 })) as unknown as typeof fetch
    const provider = new ResendProvider({ apiKey: 'k', fetchImpl })
    const result = await provider.send({ to: ['a@b.com'], from: 'x@y.com', subject: 'S' })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('422')
  })

  it('SendGrid reads the message id header on success', async () => {
    const fetchImpl = vi.fn(
      async () => new Response(null, { status: 202, headers: { 'x-message-id': 'sg-9' } })
    ) as unknown as typeof fetch
    const provider = new SendGridProvider({ apiKey: 'k', fetchImpl })
    const result = await provider.send({ to: ['a@b.com'], from: 'x@y.com', subject: 'S', text: 't' })
    expect(result).toMatchObject({ ok: true, provider: 'sendgrid', providerId: 'sg-9' })
  })

  it('Console provider always succeeds and is always configured', async () => {
    const lines: string[] = []
    const provider = new ConsoleProvider({ log: (l) => lines.push(l) })
    expect(provider.isConfigured()).toBe(true)
    const result = await provider.send({ to: ['a@b.com'], from: 'x@y.com', subject: 'Hi', flow: 'test' })
    expect(result.ok).toBe(true)
    expect(lines[0]).toContain('a@b.com')
    expect(lines[0]).toContain('(test)')
  })
})

describe('resolveEmailProvider', () => {
  it('returns an explicit provider instance unchanged (use whatever you want)', () => {
    const custom = new ConsoleProvider()
    expect(resolveEmailProvider({ provider: custom })).toBe(custom)
  })

  it('auto-detects Resend from env', () => {
    const p = resolveEmailProvider({ env: { RESEND_API_KEY: 'k' } })
    expect(p.name).toBe('resend')
  })

  it('auto-detects SendGrid when only its key is present', () => {
    const p = resolveEmailProvider({ env: { SENDGRID_API_KEY: 'k' } })
    expect(p.name).toBe('sendgrid')
  })

  it('prefers Resend over SendGrid when both keys are present', () => {
    const p = resolveEmailProvider({ env: { RESEND_API_KEY: 'r', SENDGRID_API_KEY: 's' } })
    expect(p.name).toBe('resend')
  })

  it('falls back to console when no credentials are configured', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(resolveEmailProvider({ env: {} }).name).toBe('console')
  })

  it('degrades a named-but-unconfigured provider to console with a warning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const p = resolveEmailProvider({ providerName: 'resend', env: {} })
    expect(p.name).toBe('console')
    expect(warn).toHaveBeenCalled()
  })
})

describe('email-service singleton', () => {
  it('throws before set, returns after set', () => {
    expect(hasEmailService()).toBe(false)
    expect(() => getEmailService()).toThrow()
    const svc = new EmailService({ provider: new ConsoleProvider(), defaultFrom: 'x@y.com' })
    setEmailService(svc)
    expect(getEmailService()).toBe(svc)
  })
})
