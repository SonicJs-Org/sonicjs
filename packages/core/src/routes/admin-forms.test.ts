import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { adminFormsRoutes } from './admin-forms'

// Prior to this fix, adminFormsRoutes was gated by requireAuth() only — any
// authenticated user of any role could manage forms and read submission data
// (the 'forms:manage' nav permission was never actually enforced; requirePermission
// is a no-op stub). This covers the requireRole(['admin','editor']) gate added
// alongside the escaping/is_public fixes.

function createMockDb() {
  return {
    prepare: vi.fn().mockImplementation(() => ({
      bind: vi.fn().mockReturnThis(),
      first: vi.fn().mockResolvedValue(null),
      all: vi.fn().mockResolvedValue({ results: [] }),
      run: vi.fn().mockResolvedValue({ success: true })
    }))
  }
}

function createTestApp(db: any, user: { userId: string; email: string; role: string } | undefined) {
  const app = new Hono()
  app.use('/admin/forms/*', async (c, next) => {
    c.env = { DB: db } as any
    if (user) c.set('user', { ...user, exp: 0, iat: 0 })
    await next()
  })
  app.route('/admin/forms', adminFormsRoutes)
  return app
}

describe('admin-forms.ts — RBAC gate', () => {
  it('rejects an authenticated non-admin/editor user with 403', async () => {
    const app = createTestApp(createMockDb(), { userId: 'u1', email: 'subscriber@example.com', role: 'subscriber' })
    const res = await app.request('/admin/forms', { headers: { Accept: 'application/json' } })
    expect(res.status).toBe(403)
  })

  it('rejects an unauthenticated request with 401', async () => {
    const app = createTestApp(createMockDb(), undefined)
    const res = await app.request('/admin/forms', { headers: { Accept: 'application/json' } })
    expect(res.status).toBe(401)
  })

  it('allows an admin past the gate', async () => {
    const app = createTestApp(createMockDb(), { userId: 'u1', email: 'admin@example.com', role: 'admin' })
    const res = await app.request('/admin/forms', { headers: { Accept: 'application/json' } })
    expect(res.status).toBe(200)
  })

  it('allows an editor past the gate', async () => {
    const app = createTestApp(createMockDb(), { userId: 'u1', email: 'editor@example.com', role: 'editor' })
    const res = await app.request('/admin/forms', { headers: { Accept: 'application/json' } })
    expect(res.status).toBe(200)
  })
})
