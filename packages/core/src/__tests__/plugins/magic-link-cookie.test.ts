import { describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { csrfProtection, generateCsrfToken } from '../../middleware/csrf'
import { AuthManager } from '../../middleware/auth'
import { createMagicLinkAuthPlugin } from '../../plugins/available/magic-link-auth'

vi.mock('../../plugins/hooks/dispatch-event', () => ({ dispatchHookEvent: vi.fn() }))

const secret = 'magic-link-cookie-regression-secret'

// Exercise the actual legacy route and Hono response merging, without a server.
function application(valid = true) {
  const db = {
    prepare(sql: string) {
      return {
        bind() { return this },
        async first() {
          if (sql.includes('FROM magic_links')) return valid
            ? { id: 'link', user_email: 'user@example.com', expires_at: Date.now() + 60_000 }
            : null
          if (sql.includes('FROM auth_user')) return { id: 'user', email: 'user@example.com', role: 'viewer' }
          return null
        },
        async run() { return { success: true } },
      }
    },
  }
  const app = new Hono()
  app.use('*', csrfProtection())
  const route = createMagicLinkAuthPlugin().routes![0]!
  app.route(route.path, route.handler)
  return { app, env: { DB: db, JWT_SECRET: secret, JWT_EXPIRES_IN: '1h', ENVIRONMENT: 'production' } }
}

describe('legacy magic-link redirect cookies', () => {
  it.each(['production', 'development'])('preserves fresh-browser CSRF and auth cookies in %s', async environment => {
    const { app, env } = application()
    const response = await app.request('/auth/magic-link/verify?token=valid', {}, { ...env, ENVIRONMENT: environment })
    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toBe('/admin/dashboard?message=Successfully signed in')
    const cookies = response.headers.getSetCookie()
    expect(cookies).toHaveLength(2)
    expect(cookies.some(cookie => cookie.startsWith('csrf_token='))).toBe(true)
    const auth = cookies.find(cookie => cookie.startsWith('auth_token='))!
    expect(auth).toBeDefined()
    for (const attribute of ['HttpOnly', 'SameSite=Strict', 'Max-Age=3600', 'Path=/']) expect(auth).toContain(attribute)
    expect(auth.includes('; Secure')).toBe(environment === 'production')
    const token = auth.slice('auth_token='.length).split(';')[0]!
    expect(await AuthManager.verifyToken(token, secret)).toMatchObject({ userId: 'user', email: 'user@example.com', role: 'viewer' })
  })

  it('sets auth cookie when browser already has a valid CSRF cookie', async () => {
    const { app, env } = application()
    const csrf = await generateCsrfToken(secret)
    const response = await app.request('/auth/magic-link/verify?token=valid', { headers: { Cookie: `csrf_token=${csrf}` } }, env)
    expect(response.status).toBe(302)
    expect(response.headers.getSetCookie()).toHaveLength(1)
    expect(response.headers.getSetCookie()[0]).toMatch(/^auth_token=/)
  })

  it('rejects invalid links without minting an auth cookie', async () => {
    const { app, env } = application(false)
    const response = await app.request('/auth/magic-link/verify?token=invalid', {}, env)
    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toContain('/auth/login?error=')
    expect(response.headers.getSetCookie().some(cookie => cookie.startsWith('auth_token='))).toBe(false)
  })
})
