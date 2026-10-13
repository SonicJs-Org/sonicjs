/**
 * The password-reset link must point at this site, whatever `Origin` header the request carries.
 *
 * `/auth/request-password-reset` is anonymous and CSRF-exempt. It used to build the emailed link
 * from the `Origin` request header, so anyone could have a real reset token sent to a victim inside
 * a link to their own site, then use the token. Once a reset reaches Better Auth's credential row,
 * that is an account takeover.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import authRoutes from '../../routes/auth'
import { setEmailService, resetEmailService } from '../../services/email/email-service-singleton'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

const SITE = 'https://sonic.test'
const EVIL = 'https://evil.example'
const EMAIL = 'victim@reset.test'

let db: TestD1
let sent: Array<{ html: string; text: string }>

function makeApp(env: Record<string, unknown>) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    c.env = { DB: db, JWT_SECRET: 'test-jwt-secret-value-32-chars-long!!', ...env } as never
    await next()
  })
  app.route('/auth', authRoutes)
  return app
}

function requestReset(app: Hono, url = `${SITE}/auth/request-password-reset`) {
  return app.request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: EVIL },
    body: new URLSearchParams({ email: EMAIL }),
  })
}

function sentLink(): string {
  expect(sent).toHaveLength(1)
  const match = sent[0]!.text.match(/https?:\/\/\S+/)
  expect(match).toBeTruthy()
  return match![0]
}

beforeEach(() => {
  db = createTestD1()
  sent = []
  setEmailService({ send: vi.fn(async (msg: { html: string; text: string }) => void sent.push(msg)) } as never)
  db.raw
    .prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, role, is_active, created_at, updated_at)
       VALUES ('u-1', ?, 'Vic', 'Tim', 'viewer', 1, ?, ?)`,
    )
    .run(EMAIL, Date.now(), Date.now())
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  resetEmailService()
  db.close()
  vi.restoreAllMocks()
})

describe('password reset link origin', () => {
  it('uses BETTER_AUTH_URL, not the Origin header', async () => {
    const res = await requestReset(makeApp({ BETTER_AUTH_URL: `${SITE}/` }))
    expect(res.status).toBe(200)
    const link = sentLink()
    expect(link.startsWith(`${SITE}/auth/reset-password?token=`)).toBe(true)
    expect(link).not.toContain('evil.example')
  })

  it('falls back to the URL the request was served on, not the Origin header', async () => {
    const res = await requestReset(makeApp({}), 'https://cms.example.org/auth/request-password-reset')
    expect(res.status).toBe(200)
    const link = sentLink()
    expect(link.startsWith('https://cms.example.org/auth/reset-password?token=')).toBe(true)
    expect(link).not.toContain('evil.example')
  })
})
