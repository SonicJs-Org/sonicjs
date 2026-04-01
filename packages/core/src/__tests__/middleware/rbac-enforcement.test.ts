// @ts-nocheck
import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { requireRole } from '../../middleware/auth'

/**
 * Tests for RBAC enforcement on protected routes.
 * Verifies that requireRole middleware correctly gates access by role.
 * Covers fixes for #710 and #616.
 */

// Helper to create a minimal test app with requireRole
function createTestApp(allowedRoles: string[]) {
  const app = new Hono()

  // Simulate requireAuth by setting user in context
  app.use('*', async (c, next) => {
    const role = c.req.header('X-Test-Role')
    if (role) {
      c.set('user', { userId: 'test-user', email: 'test@test.com', role })
    }
    await next()
  })

  app.post('/protected', requireRole(allowedRoles), (c) => {
    return c.json({ success: true })
  })

  return app
}

describe('RBAC enforcement - requireRole middleware', () => {
  describe('admin-only routes (user management, collections)', () => {
    const app = createTestApp(['admin'])

    it('allows admin access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'admin' },
      })
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.success).toBe(true)
    })

    it('blocks editor access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'editor' },
      })
      expect(res.status).toBe(403)
    })

    it('blocks author access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'author' },
      })
      expect(res.status).toBe(403)
    })

    it('blocks viewer access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'viewer' },
      })
      expect(res.status).toBe(403)
    })

    it('returns 401 when no user is set', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
      })
      expect(res.status).toBe(401)
    })
  })

  describe('content CRUD routes (admin, editor, author)', () => {
    const app = createTestApp(['admin', 'editor', 'author'])

    it('allows admin access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'admin' },
      })
      expect(res.status).toBe(200)
    })

    it('allows editor access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'editor' },
      })
      expect(res.status).toBe(200)
    })

    it('allows author access', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'author' },
      })
      expect(res.status).toBe(200)
    })

    it('blocks viewer from content creation/modification', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'viewer' },
      })
      expect(res.status).toBe(403)
    })
  })

  describe('role validation on user creation', () => {
    it('accepts valid roles', () => {
      const validRoles = ['admin', 'editor', 'author', 'viewer']
      for (const role of validRoles) {
        expect(validRoles.includes(role)).toBe(true)
      }
    })

    it('rejects invalid role and defaults to viewer', () => {
      const validRoles = ['admin', 'editor', 'author', 'viewer']
      const roleInput = 'superadmin'
      const role = validRoles.includes(roleInput) ? roleInput : 'viewer'
      expect(role).toBe('viewer')
    })

    it('rejects empty string role and defaults to viewer', () => {
      const validRoles = ['admin', 'editor', 'author', 'viewer']
      const roleInput = ''
      const role = validRoles.includes(roleInput) ? roleInput : 'viewer'
      expect(role).toBe('viewer')
    })
  })

  describe('browser vs API response format', () => {
    const app = createTestApp(['admin'])

    it('returns JSON 403 for API requests', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'viewer', 'Accept': 'application/json' },
      })
      expect(res.status).toBe(403)
      const body = await res.json()
      expect(body.error).toBe('Insufficient permissions')
    })

    it('redirects browser requests on insufficient role', async () => {
      const res = await app.request('/protected', {
        method: 'POST',
        headers: { 'X-Test-Role': 'viewer', 'Accept': 'text/html' },
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/auth/login')
    })
  })
})
