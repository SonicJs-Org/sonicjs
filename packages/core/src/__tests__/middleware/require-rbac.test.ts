import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { requireRbac } from '../../middleware/auth'

/**
 * Tests for the `requireRbac(resource, verb)` middleware — the dynamic
 * replacement for legacy `requireRole(...)` gates, and the gate that protects
 * the entire `/admin/*` surface (via `requireRbac('portal', 'access')`) and the
 * RBAC admin (via `requireRbac('rbac', 'manage')`).
 *
 * The RbacService is mocked so these isolate the middleware's decision logic:
 * auth presence, the DB-backed allow/deny call, and the API-vs-browser response
 * split. The grant-matching itself is covered in services/rbac.test.ts.
 */

const mockCan = vi.fn()

// Capture how RbacService is constructed so we can assert it's wired to c.env.DB.
const RbacServiceCtor = vi.fn()
vi.mock('../../services/rbac', () => ({
  RbacService: class {
    constructor(db: unknown) {
      RbacServiceCtor(db)
    }
    can = mockCan
  },
}))

type TestUser = { userId: string; email: string; role: string }

const DB = { __tag: 'fake-d1' }

/** Mount requireRbac on a route, optionally pre-setting a session user. */
function createApp(resource: string, verb: string, user?: TestUser) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    // app.ts's session middleware would normally set this from the cookie.
    if (user) c.set('user', user as any)
    await next()
  })
  app.get('/guarded', requireRbac(resource, verb), (c) => c.json({ ok: true }))
  // DB is provided as the request env (c.env) — the third arg to app.request.
  const request = (init?: RequestInit) => app.request('/guarded', init, { DB } as any)
  return { app, request }
}

const admin: TestUser = { userId: 'admin-1', email: 'admin@test.com', role: 'admin' }

describe('requireRbac middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('unauthenticated', () => {
    it('returns 401 JSON when no session user is present (API request)', async () => {
      const { request } = createApp('portal', 'access')
      const res = await request({ headers: { Accept: 'application/json' } })

      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'Authentication required' })
      // Permission check must not run without an authenticated user.
      expect(mockCan).not.toHaveBeenCalled()
    })

    it('redirects to login for browser (text/html) requests', async () => {
      const { request } = createApp('portal', 'access')
      const res = await request({ headers: { Accept: 'text/html' } })

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/auth/login')
    })
  })

  describe('authenticated but lacking the grant', () => {
    it('returns 403 JSON when can() resolves false', async () => {
      mockCan.mockResolvedValue(false)
      const { request } = createApp('rbac', 'manage', admin)
      const res = await request({ headers: { Accept: 'application/json' } })

      expect(res.status).toBe(403)
      expect(await res.json()).toEqual({ error: 'Insufficient permissions' })
    })

    it('redirects browser requests on denial', async () => {
      mockCan.mockResolvedValue(false)
      const { request } = createApp('rbac', 'manage', admin)
      const res = await request({ headers: { Accept: 'text/html' } })

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/auth/login')
    })
  })

  describe('authenticated with the grant', () => {
    it('passes through to the handler when can() resolves true', async () => {
      mockCan.mockResolvedValue(true)
      const { request } = createApp('portal', 'access', admin)
      const res = await request()

      expect(res.status).toBe(200)
      expect(await res.json()).toEqual({ ok: true })
    })

    it('checks the live grant for the signed-in user with the requested resource/verb', async () => {
      mockCan.mockResolvedValue(true)
      const { request } = createApp('portal', 'access', admin)
      await request()

      // RbacService is constructed from the request-scoped DB binding...
      expect(RbacServiceCtor).toHaveBeenCalledWith(DB)
      // ...and queried for exactly this user/resource/verb.
      expect(mockCan).toHaveBeenCalledWith('admin-1', 'portal', 'access')
    })

    it('passes the correct resource/verb for the rbac admin gate', async () => {
      mockCan.mockResolvedValue(true)
      const { request } = createApp('rbac', 'manage', admin)
      await request()

      expect(mockCan).toHaveBeenCalledWith('admin-1', 'rbac', 'manage')
    })
  })
})
