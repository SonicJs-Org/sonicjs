import { describe, it, expect, vi, beforeEach } from 'vitest'
import { EmailServiceImpl } from './email-service'
import { EmailValidationError } from '../errors'

interface DbCall {
  sql: string
  binds: unknown[]
}

function makeDb(settings: string | null = JSON.stringify({ fromEmail: 'default@example.com', fromName: 'Default' })): {
  db: D1Database
  calls: DbCall[]
} {
  const calls: DbCall[] = []
  const db = {
    prepare: vi.fn((sql: string) => ({
      bind: vi.fn((...binds: unknown[]) => ({
        run: vi.fn(async () => {
          calls.push({ sql, binds })
          return {}
        }),
      })),
      first: vi.fn(async () => (settings === null ? null : { settings })),
    })),
  } as unknown as D1Database
  return { db, calls }
}

function makeBinding(behavior: 'ok' | 'throw' = 'ok', messageId = 'cf-test-1'): SendEmail {
  return {
    send: vi.fn(async () => {
      if (behavior === 'throw') {
        throw new Error('transport down')
      }
      return { messageId }
    }),
  } as unknown as SendEmail
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('EmailServiceImpl.send — validation', () => {
  it('throws EmailValidationError when purpose is missing', async () => {
    const { db } = makeDb()
    const svc = new EmailServiceImpl(makeBinding(), db)
    await expect(
      svc.send({
        to: 'r@e.c',
        subject: 's',
        text: 'b',
        purpose: '',
      }),
    ).rejects.toBeInstanceOf(EmailValidationError)
  })

  it('throws EmailValidationError when both html and text are missing', async () => {
    const { db } = makeDb()
    const svc = new EmailServiceImpl(makeBinding(), db)
    await expect(
      svc.send({
        to: 'r@e.c',
        subject: 's',
        purpose: 'test',
      }),
    ).rejects.toBeInstanceOf(EmailValidationError)
  })

  it('throws EmailValidationError on malformed `to` address', async () => {
    const { db } = makeDb()
    const svc = new EmailServiceImpl(makeBinding(), db)
    await expect(
      svc.send({
        to: 'not-an-email',
        subject: 's',
        text: 'b',
        purpose: 'test',
      }),
    ).rejects.toBeInstanceOf(EmailValidationError)
  })

  it('throws EmailValidationError when from is omitted AND settings have no fromEmail', async () => {
    const { db } = makeDb(null) // no settings row
    const svc = new EmailServiceImpl(makeBinding(), db)
    await expect(
      svc.send({
        to: 'r@e.c',
        subject: 's',
        text: 'b',
        purpose: 'test',
      }),
    ).rejects.toBeInstanceOf(EmailValidationError)
  })

  it('throws EmailValidationError on malformed cc address', async () => {
    const { db } = makeDb()
    const svc = new EmailServiceImpl(makeBinding(), db)
    await expect(
      svc.send({
        to: 'r@e.c',
        cc: ['valid@e.c', 'invalid'],
        subject: 's',
        text: 'b',
        purpose: 'test',
      }),
    ).rejects.toBeInstanceOf(EmailValidationError)
  })
})

describe('EmailServiceImpl.send — happy path', () => {
  it('uses settings.fromEmail when caller omits from, calls binding, returns submitted', async () => {
    const { db, calls } = makeDb()
    const binding = makeBinding('ok', 'cf-happy')
    const svc = new EmailServiceImpl(binding, db)

    const result = await svc.send({
      to: 'r@example.com',
      subject: 'hi',
      text: 'body',
      purpose: 'test',
    })

    expect(result.status).toBe('submitted')
    expect(result.cloudflareMessageId).toBe('cf-happy')
    expect(result.logId).toBeTruthy()
    expect(binding.send).toHaveBeenCalledWith(
      expect.objectContaining({
        to: 'r@example.com',
        from: 'default@example.com',
        subject: 'hi',
        text: 'body',
      }),
    )
    const insert = calls.find(c => /INSERT INTO email_log/i.test(c.sql))
    expect(insert).toBeTruthy()
    expect(insert?.sql).toMatch(/'submitted'/)
  })

  it('caller-supplied `from` overrides settings', async () => {
    const { db } = makeDb()
    const binding = makeBinding('ok')
    const svc = new EmailServiceImpl(binding, db)
    await svc.send({
      to: 'r@e.c',
      from: 'override@e.c',
      subject: 's',
      text: 'b',
      purpose: 'test',
    })
    expect(binding.send).toHaveBeenCalledWith(expect.objectContaining({ from: 'override@e.c' }))
  })

  it('settings.replyTo flows through to binding when caller omits replyTo', async () => {
    const { db } = makeDb(
      JSON.stringify({ fromEmail: 'd@e.c', replyTo: 'reply@e.c' }),
    )
    const binding = makeBinding('ok')
    const svc = new EmailServiceImpl(binding, db)
    await svc.send({ to: 'r@e.c', subject: 's', text: 'b', purpose: 'test' })
    expect(binding.send).toHaveBeenCalledWith(expect.objectContaining({ replyTo: 'reply@e.c' }))
  })

  it('passes BOTH html and text to the binding when both are provided', async () => {
    // Audit follow-up (2026-05-15): closes the P1 QA gap where no test
    // verified the binding receives both fields. The CF SendEmail
    // plain-object overload assembles multipart/alternative only when
    // both `html` and `text` are present on the payload object.
    const { db } = makeDb()
    const binding = makeBinding('ok')
    const svc = new EmailServiceImpl(binding, db)

    await svc.send({
      to: 'r@example.com',
      subject: 'subj',
      html: '<!doctype html><body><p>HTML alt</p></body></html>',
      text: 'Text alt',
      purpose: 'otp',
    })

    expect(binding.send).toHaveBeenCalledWith(
      expect.objectContaining({
        to: 'r@example.com',
        from: 'default@example.com',
        subject: 'subj',
        html: '<!doctype html><body><p>HTML alt</p></body></html>',
        text: 'Text alt',
      }),
    )
  })
})

describe('EmailServiceImpl.send — failure path', () => {
  it('returns failed_at_send and writes a failure row when binding throws', async () => {
    const { db, calls } = makeDb()
    const binding = makeBinding('throw')
    const svc = new EmailServiceImpl(binding, db)

    const result = await svc.send({
      to: 'r@e.c',
      subject: 's',
      text: 'b',
      purpose: 'test',
    })

    expect(result.status).toBe('failed_at_send')
    expect(result.errorMessage).toBe('transport down')
    expect(result.cloudflareMessageId).toBeUndefined()
    const insert = calls.find(c => /INSERT INTO email_log/i.test(c.sql))
    expect(insert?.sql).toMatch(/'failed_at_send'/)
    expect(insert?.binds).toContain('transport down')
  })
})

describe('EmailServiceImpl.send — context fields', () => {
  it('persists userId, purpose, templateName, templateVariables', async () => {
    const { db, calls } = makeDb()
    const svc = new EmailServiceImpl(makeBinding('ok'), db)
    await svc.send({
      to: 'r@e.c',
      subject: 's',
      text: 'b',
      purpose: 'otp',
      userId: 'u-42',
      templateName: 'auth.otp',
      templateVariables: { code: '123456' },
    })
    const insert = calls.find(c => /INSERT INTO email_log/i.test(c.sql))
    expect(insert?.binds).toContain('u-42')
    expect(insert?.binds).toContain('otp')
    expect(insert?.binds).toContain('auth.otp')
    expect(insert?.binds).toContain('{"code":"123456"}')
  })
})
