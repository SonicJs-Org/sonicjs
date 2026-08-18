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

function createSubmissionsMockDb(submissionDataJson: string) {
  return {
    prepare: vi.fn().mockImplementation((sql: string) => {
      if (sql.includes('FROM forms WHERE')) {
        return {
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ id: 'form-1', display_name: 'Test Form' })
        }
      }
      if (sql.includes('FROM form_submissions WHERE')) {
        return {
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [{ id: 'sub-1', submitted_at: 0, submission_data: submissionDataJson }]
          })
        }
      }
      return {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue(null),
        all: vi.fn().mockResolvedValue({ results: [] }),
        run: vi.fn().mockResolvedValue({ success: true })
      }
    })
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

describe('admin-forms.ts — GET /:id/submissions XSS regression', () => {
  // sanitizeDeep() (public-forms.ts) escapes submission VALUES at write time, but
  // never touched object KEYS — an anonymous public submitter fully controls both.
  // A malicious key survived storage unescaped and was dumped raw into this page's
  // <pre> via JSON.stringify. Any admin/editor opening submissions for that form
  // then executed it in their authenticated session. Regression for both the
  // render-time escapeHtml() and the sanitizeDeep() key-escaping fix.
  it('does not render an unescaped HTML tag from a submission data key', async () => {
    const maliciousKey = '<img src=x onerror=alert(document.cookie)>'
    const submissionDataJson = JSON.stringify({ [maliciousKey]: 'x' })
    const app = createTestApp(
      createSubmissionsMockDb(submissionDataJson),
      { userId: 'u1', email: 'admin@example.com', role: 'admin' }
    )

    const res = await app.request('/admin/forms/form-1/submissions')
    const html = await res.text()

    expect(res.status).toBe(200)
    expect(html).not.toContain(maliciousKey)
    expect(html).toContain('&lt;img src=x onerror=alert(document.cookie)&gt;')
  })
})
